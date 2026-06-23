-- Tap-Host-Profile: aggregierte Port-Profile, die ein Remote-Tap über den
-- mTLS-Uplink an den Master meldet, damit der host-role-detector auch Hosts
-- klassifizieren kann, die NUR der Tap sieht (der Master-Mirror sieht sie nie).
--
-- Der Tap forwarded bewusst keine rohen Flows (Volumen) — nur ein verdichtetes
-- Snapshot pro Host: servierte Ports + Flow-Count, Mode-MAC, first_seen. Der
-- master-uplink upsertet pro (tap_id, host_ip); der Detektor liest die Einträge
-- mit aktuellem updated_at und merged sie in seine Flow-basierte Aggregation.
--
-- ports-Shape: [{"port": int, "proto": "TCP|UDP|ICMP|...", "count": int}, ...]

CREATE TABLE IF NOT EXISTS tap_host_profiles (
  tap_id     TEXT        NOT NULL,
  host_ip    INET        NOT NULL,
  ports      JSONB       NOT NULL,
  mac        TEXT,
  first_seen TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tap_id, host_ip)
);

-- Detektor filtert auf Recency (updated_at >= now()-Fenster).
CREATE INDEX IF NOT EXISTS tap_host_profiles_updated
  ON tap_host_profiles (updated_at DESC);
