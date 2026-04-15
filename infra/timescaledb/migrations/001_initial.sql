-- ══════════════════════════════════════════════════════════════════════════════
-- IDS – Initiales Datenbankschema
-- Wird beim ersten Start von TimescaleDB automatisch ausgeführt
-- ══════════════════════════════════════════════════════════════════════════════

-- Extensions
CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ──────────────────────────────────────────────────────────────────────────────
-- FLOWS
-- Aggregierte Netzwerkflüsse (5-Tupel + statistische Features)
-- Hypertable partitioniert nach start_ts
-- ──────────────────────────────────────────────────────────────────────────────
CREATE TABLE flows (
  flow_id      UUID        NOT NULL DEFAULT uuid_generate_v4(),
  start_ts     TIMESTAMPTZ NOT NULL,
  end_ts       TIMESTAMPTZ,
  src_ip       INET        NOT NULL,
  dst_ip       INET        NOT NULL,
  src_port     INT,
  dst_port     INT,
  proto        TEXT        NOT NULL,                 -- TCP | UDP | ICMP | ICMPv6 | OTHER
  ip_version   SMALLINT    NOT NULL DEFAULT 4,       -- 4 oder 6
  -- Volumen
  pkt_count    INT         NOT NULL DEFAULT 0,
  byte_count   BIGINT      NOT NULL DEFAULT 0,
  -- Alle weiteren statistischen Features als JSONB (flexibel erweiterbar)
  -- Struktur: pkt_size{mean,std,min,max}, iat{mean,std,min,max},
  --           tcp_flags{SYN,ACK,FIN,RST,PSH}, connection_state, entropy_iat, ...
  stats        JSONB,
  PRIMARY KEY (flow_id, start_ts)
);

SELECT create_hypertable('flows', 'start_ts');

-- Indizes für häufige Abfragen
CREATE INDEX ON flows (src_ip, start_ts DESC);
CREATE INDEX ON flows (dst_ip, start_ts DESC);
CREATE INDEX ON flows (proto,  start_ts DESC);

-- ──────────────────────────────────────────────────────────────────────────────
-- ALERTS
-- Alarme aus Signature-Engine, ML-Engine und Korrelation
-- Hypertable partitioniert nach ts
-- ──────────────────────────────────────────────────────────────────────────────
CREATE TABLE alerts (
  alert_id      UUID        NOT NULL DEFAULT uuid_generate_v4(),
  ts            TIMESTAMPTZ NOT NULL DEFAULT now(),
  flow_id       UUID,                                -- Referenz auf flows.flow_id (soft FK)
  -- Herkunft
  source        TEXT        NOT NULL                 -- signature | ml | correlation
                            CHECK (source IN ('signature', 'ml', 'correlation', 'test')),
  rule_id       TEXT,                               -- z.B. SCAN_001, TEST_001
  -- Klassifizierung
  severity      TEXT        NOT NULL
                            CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  score         FLOAT       NOT NULL DEFAULT 0.0    -- 0.0–1.0
                            CHECK (score >= 0.0 AND score <= 1.0),
  -- Netzwerk-Kontext
  src_ip        INET,
  dst_ip        INET,
  src_port      INT,
  dst_port      INT,
  proto         TEXT,
  ip_version    SMALLINT    DEFAULT 4,
  description   TEXT,
  -- ML-Erklärbarkeit: [{name, value, contribution}, ...]
  top_features  JSONB,
  -- DNS/Ping/GeoIP Anreicherung (wird async nachgereicht)
  enrichment    JSONB,
  -- PCAP-Header Referenz (MinIO Key)
  pcap_key      TEXT,
  pcap_available BOOLEAN    NOT NULL DEFAULT false,
  -- Feedback
  feedback      TEXT                                -- NULL | fp | tp
                            CHECK (feedback IS NULL OR feedback IN ('fp', 'tp')),
  feedback_ts   TIMESTAMPTZ,
  feedback_note TEXT,
  -- Testverkehr-Flag
  is_test       BOOLEAN     NOT NULL DEFAULT false,
  PRIMARY KEY (alert_id, ts)
);

SELECT create_hypertable('alerts', 'ts');

-- Indizes
CREATE INDEX ON alerts (src_ip,   ts DESC);
CREATE INDEX ON alerts (dst_ip,   ts DESC);
CREATE INDEX ON alerts (severity, ts DESC);
CREATE INDEX ON alerts (rule_id,  ts DESC);
CREATE INDEX ON alerts (source,   ts DESC);
-- Partial Index: offene Alerts (kein Feedback) – für Dashboard-Queue
CREATE INDEX ON alerts (ts DESC) WHERE feedback IS NULL AND is_test = false;

-- ──────────────────────────────────────────────────────────────────────────────
-- HOST_INFO
-- Cache für angereicherte IP-Informationen (DNS, GeoIP, ASN, Ping)
-- Wird vom Enrichment-Service befüllt und aktualisiert
-- ──────────────────────────────────────────────────────────────────────────────
CREATE TABLE host_info (
  ip           INET        PRIMARY KEY,
  hostname     TEXT,
  -- ASN: {number: int, org: str}
  asn          JSONB,
  -- GeoIP: {country: str, country_code: str, city: str, lat: float, lon: float}
  geo          JSONB,
  ping_ms      FLOAT,                               -- NULL = nicht erreichbar / nicht versucht
  last_seen    TIMESTAMPTZ,
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ──────────────────────────────────────────────────────────────────────────────
-- KNOWN_NETWORKS
-- Bekannte Netzwerke (CSV-Import) für bessere Darstellung im Dashboard
-- GiST-Index für effiziente IP → Netzwerk Lookups
-- ──────────────────────────────────────────────────────────────────────────────
CREATE TABLE known_networks (
  id           UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
  cidr         CIDR        NOT NULL UNIQUE,
  name         TEXT        NOT NULL,
  description  TEXT,
  color        TEXT        NOT NULL DEFAULT '#607D8B',
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- GiST-Index: erlaubt "cidr >> ip" Containment-Queries
CREATE INDEX idx_known_networks_cidr ON known_networks USING gist (cidr inet_ops);

-- ──────────────────────────────────────────────────────────────────────────────
-- SYSTEM_CONFIG
-- Betriebskonfiguration (Interfaces, Capture-Parameter, ML-Schwellenwerte)
-- Wird vom API-Backend gelesen/geschrieben, Services reagieren via LISTEN/NOTIFY
-- ──────────────────────────────────────────────────────────────────────────────
CREATE TABLE system_config (
  key          TEXT        PRIMARY KEY,
  value        JSONB       NOT NULL,
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Notify-Trigger: Services können via LISTEN 'config_changed' reagieren
CREATE OR REPLACE FUNCTION notify_config_change()
RETURNS trigger AS $$
BEGIN
  PERFORM pg_notify('config_changed', NEW.key);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER config_change_trigger
  AFTER INSERT OR UPDATE ON system_config
  FOR EACH ROW EXECUTE FUNCTION notify_config_change();

-- ──────────────────────────────────────────────────────────────────────────────
-- TRAINING_SAMPLES
-- Gelabelte Flows für ML-Retrain (aus Feedback + synthetischen Tests)
-- ──────────────────────────────────────────────────────────────────────────────
CREATE TABLE training_samples (
  id           UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
  flow_id      UUID        NOT NULL,
  alert_id     UUID,
  label        TEXT        NOT NULL                 -- normal | attack | unknown
                            CHECK (label IN ('normal', 'attack', 'unknown')),
  -- Feature-Vektor zum Zeitpunkt der Labeling (snapshot)
  features     JSONB       NOT NULL,
  source       TEXT        NOT NULL                 -- feedback | synthetic | bootstrap
                            CHECK (source IN ('feedback', 'synthetic', 'bootstrap')),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ON training_samples (label, created_at DESC);
CREATE INDEX ON training_samples (source, created_at DESC);

-- ──────────────────────────────────────────────────────────────────────────────
-- TEST_RUNS
-- Ergebnis-Protokoll der Dashboard-Tests (Rule Engine Checks)
-- Hypertable partitioniert nach started_at
-- ──────────────────────────────────────────────────────────────────────────────
CREATE TABLE test_runs (
  id            UUID        NOT NULL DEFAULT uuid_generate_v4(),
  scenario_id   TEXT        NOT NULL,
  started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at  TIMESTAMPTZ,
  status        TEXT        NOT NULL DEFAULT 'running'
                            CHECK (status IN ('running', 'completed', 'failed')),
  expected_rule TEXT,
  triggered     BOOLEAN,
  alert_id      UUID,
  latency_ms    INT,
  error         TEXT,
  PRIMARY KEY (id, started_at)
);

SELECT create_hypertable('test_runs', 'started_at');

-- ──────────────────────────────────────────────────────────────────────────────
-- DEFAULT-KONFIGURATION
-- Wird beim ersten Start eingefügt (ON CONFLICT ignoriert spätere Änderungen)
-- ──────────────────────────────────────────────────────────────────────────────
INSERT INTO system_config (key, value) VALUES
  ('interfaces', '{
    "mirror": "",
    "management": "",
    "management_ip": ""
  }'),
  ('capture', '{
    "snaplen": 128,
    "ring_buffer_mb": 64,
    "promiscuous": true
  }'),
  ('enrichment', '{
    "ping_timeout_ms": 1000,
    "dns_timeout_ms": 2000,
    "cache_ttl_s": 3600,
    "geoip_enabled": true
  }'),
  ('ml', '{
    "anomaly_threshold": 0.7,
    "min_training_samples": 1000,
    "model_type": "isolation_forest"
  }'),
  ('alerts', '{
    "dedup_window_s": 300,
    "threat_level_window_min": 15,
    "threat_level_weights": {"critical": 10, "high": 5, "medium": 2, "low": 1}
  }')
ON CONFLICT (key) DO NOTHING;

-- ──────────────────────────────────────────────────────────────────────────────
-- HILFSFUNKTION: IP → Netzwerk-Name
-- Gibt das spezifischste bekannte Netzwerk für eine IP zurück
-- ──────────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION get_network_for_ip(p_ip INET)
RETURNS TABLE (network_id UUID, cidr CIDR, name TEXT, color TEXT) AS $$
  SELECT id, cidr, name, color
  FROM known_networks
  WHERE cidr >> p_ip
  ORDER BY masklen(cidr) DESC
  LIMIT 1;
$$ LANGUAGE sql STABLE;
