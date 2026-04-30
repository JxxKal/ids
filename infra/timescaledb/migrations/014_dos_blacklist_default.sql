-- Migration 014: rule-tuner-Blacklist defaultmäßig auf DOS-Rules
--
-- Hintergrund: Quantile-basiertes Threshold-Tuning funktioniert für
-- SCAN/RECON-Rules sauber, weil die Verteilung normaler User klar von
-- Scanner-Verhalten getrennt ist (1-5 Ports vs. 50+ Ports).
--
-- Bei DOS-Rules (DOS_SYN_001, DOS_CONN_001, DOS_UDP_001, DOS_ICMP_001)
-- ist das anders: die Metriken syn_count/flow_rate/pps sind kontinuierlich,
-- der obere Tail normaler Auslastung (Streaming, VoIP, mDNS-Bursts, Game-
-- Server) überlappt direkt mit der unteren Kante schwacher Floods. P99,5
-- landet damit im "Top-0,5 % normaler Last", nicht im "Flood-Beginn".
-- Konkretes Beispiel das uns erwischt hat: DOS_UDP_001 wurde auf 4200 pps
-- intern getuned — Streaming-Server feuern damit als kritischer UDP-Flood.
--
-- Lösung V1: per Default in der Tuner-Blacklist führen. User kann sie
-- über die GUI bewusst rausnehmen (Trainings-Konfig → Blacklist) wenn
-- das Risiko bewusst gewünscht ist (z.B. niedrige-Bandbreite-OT-Netz wo
-- selbst 1000 pps verdächtig wäre).
--
-- V2 (siehe CLAUDE.md): per-Rule `tuner_quantile:`-Override im YAML
-- (DOS_* nutzt P99,99 statt 0,995) bzw. severity-basierter Floor-
-- Constraint (Threshold ≥ YAML_default × 0,5 für critical/high).
--
-- Idempotenz: nur updaten wenn blacklist aktuell leer/null ist —
-- User-customized Blacklists werden nicht überschrieben.
UPDATE system_config
SET value = jsonb_set(
        value,
        '{blacklist}',
        '["DOS_SYN_001","DOS_CONN_001","DOS_UDP_001","DOS_ICMP_001"]'::jsonb
    ),
    updated_at = now()
WHERE key = 'ml_tuning_config'
  AND (
        value->'blacklist' IS NULL
        OR jsonb_typeof(value->'blacklist') <> 'array'
        OR jsonb_array_length(value->'blacklist') = 0
      );
