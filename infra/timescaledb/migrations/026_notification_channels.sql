-- ════════════════════════════════════════════════════════════════════════════
-- Migration 026 — Notification-Channels + Delivery-Log
--
-- Generisches Notification-Routing: pro User N Channels (Webhook/Email/ntfy
-- /…), pro Channel ein severity-Filter + optional rule_prefix + source-Filter.
-- type-Spalte ist bewusst extensible (kein strikter CHECK), damit Phase 2
-- (Cyjan-Cloud-Companion-App, FCM/APNs etc.) keine Schema-Migration braucht
-- sondern nur neuen Handler in notification-dispatcher.
-- ════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS notification_channels (
    id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             uuid        REFERENCES users(id) ON DELETE CASCADE,
    name                text        NOT NULL,                  -- 'Mein Handy via ntfy'
    type                text        NOT NULL,                  -- 'webhook'|'email'|'ntfy'|<future>
    config              jsonb       NOT NULL DEFAULT '{}'::jsonb,
    enabled             boolean     NOT NULL DEFAULT true,
    severity_min        text        NOT NULL DEFAULT 'high'
                        CHECK (severity_min IN ('low','medium','high','critical')),
    rule_prefix_filter  text,                                  -- 'SURICATA:' | 'MODBUS_' | NULL
    source_filter       text[],                                -- ['signature','ml','suricata','external'] oder NULL=all
    throttle_seconds    int         NOT NULL DEFAULT 30
                        CHECK (throttle_seconds >= 0),         -- min Pause zwischen Pushes
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    last_used           timestamptz
);

CREATE INDEX IF NOT EXISTS idx_notification_channels_enabled
  ON notification_channels(enabled) WHERE enabled = true;

CREATE INDEX IF NOT EXISTS idx_notification_channels_user
  ON notification_channels(user_id);


-- Audit-/Delivery-Log: pro Push-Versuch ein Eintrag. Hypertable weil das bei
-- aktivem Stack schnell tausende Rows/Tag werden kann.
CREATE TABLE IF NOT EXISTS notification_deliveries (
    id            bigserial,
    ts            timestamptz NOT NULL DEFAULT now(),
    channel_id    uuid        NOT NULL,                       -- soft-link, kein FK weil Channel-Delete soll Log behalten
    alert_id      uuid,                                        -- soft-link auf alerts.alert_id
    rule_id       text,                                        -- denormalisiert für Debugging ohne Join
    severity      text,                                        -- denormalisiert
    status        text        NOT NULL
                  CHECK (status IN ('sent','failed','rate_limited','filtered','disabled')),
    status_code   int,                                         -- HTTP-Code (webhook/ntfy) oder NULL
    latency_ms    int,
    error         text,                                        -- Truncated stacktrace bei failed
    PRIMARY KEY (id, ts)
);

SELECT create_hypertable('notification_deliveries', 'ts',
                          chunk_time_interval => interval '7 days',
                          if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_notification_deliveries_channel_ts
  ON notification_deliveries(channel_id, ts DESC);

CREATE INDEX IF NOT EXISTS idx_notification_deliveries_failed
  ON notification_deliveries(channel_id, ts DESC) WHERE status = 'failed';


-- Hilfs-Trigger: updated_at automatisch nachziehen
CREATE OR REPLACE FUNCTION notification_channels_touch_updated()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_notification_channels_updated ON notification_channels;
CREATE TRIGGER trg_notification_channels_updated
    BEFORE UPDATE ON notification_channels
    FOR EACH ROW EXECUTE FUNCTION notification_channels_touch_updated();
