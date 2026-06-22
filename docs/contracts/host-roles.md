# Contract: Host-Rollenerkennung (eingefroren — Phase 0)

Verbindliche Schnittstelle für die parallelen Implementierungs-Streams
(Detektor, API, Frontend, Reverse-Channel, Katalog-Content). **Nicht ändern,
ohne alle Streams zu informieren.**

V1-Scope (mit User abgestimmt): **Port-Profile + MAC-OUI**. L7-Fingerprints
(S7comm/HTTP/TLS) sind V2 (`fingerprint`-Feld bleibt im Schema, in V1 ungenutzt).

---

## 1. `host_info.detected_roles` JSONB-Shape

```jsonc
{
  "roles": {
    "domain_controller": {
      "confidence": 0.94,             // [0,1]
      "source": "auto",              // "auto" | "manual"
      "ports": [{"port": 88, "proto": "TCP"}, {"port": 389, "proto": "TCP"}],
      "evidence": ["port:88/TCP", "port:389/TCP", "flag:dns(53)", "oui:Dell"],
      "flags": ["dns"],
      "flow_count": 4821,
      "since": "2026-06-15T03:20:00Z",        // erste Detektion, stabil über Cycles
      "last_confirmed": "2026-06-22T14:45:00Z"
    }
  },
  "manual": {
    "plc_s7": {"locked": true, "set_by": "admin", "set_at": "2026-06-21T11:00:00Z"}
  },
  "evaluated_at": "2026-06-22T14:45:00Z"
}
```

Regeln:
- `source="manual"` ⇒ Detektor fasst die Rolle **nie** an (kein Update, kein Entfernen).
- `manual[role_id].locked=true` ⇒ Lock. **Reset** = Eintrag aus `manual` raus + `source` zurück auf `auto`; der nächste Detektor-Cycle übernimmt.
- Eine nicht mehr matchende `auto`-Rolle wird beim Cycle entfernt; eine `manual`-Rolle nie.
- Mehrfachrollen = mehrere Keys in `roles` (Set).
- `detected_roles = NULL` ⇒ Host nie evaluiert.
- Schreiben via asyncpg/psycopg2: **dict direkt** (jsonb-Codec), KEIN `json.dumps` + `::jsonb`.

## 2. Katalog-YAML (`signature-engine/rules/host-roles/*.yml`)

```yaml
- id: domain_controller
  label: "Domain Controller"
  category: identity
  match:
    required_ports:                  # ALLE müssen serviert sein
      - {port: 88,  proto: TCP}
      - {port: 389, proto: TCP}
      - {port: 445, proto: TCP}
    any_ports:                       # mind. min_any aus der Liste
      min_any: 1
      ports:
        - {port: 636,  proto: TCP}
        - {port: 3268, proto: TCP}
    optional_flags:                  # setzen evidence/flags, kein Match-Zwang
      - {flag: dns, port: 53, proto: ANY}
  min_flows_per_port: 3
  base_confidence: 0.85
  confidence_bonus: {per_optional_port: 0.03, long_lived: 0.05}
  fingerprint: null                  # V2
  mac_oui: []                        # V1: OUI-Präfixe (z.B. ["00:0E:8C"]) heben confidence
```

Keys eingefroren: `id, label, category, match{required_ports, any_ports{min_any,ports}, optional_flags}, min_flows_per_port, base_confidence, confidence_bonus{per_optional_port,long_lived}, fingerprint, mac_oui`.
`proto` ∈ `{TCP, UDP, ANY}`. `served` = Port, auf dem der Host als Responder auftrat (dst_ip=Host, connection_state ∈ ESTABLISHED|CLOSED).

## 3. MAC-Datenpfad (V1, für MAC-OUI)

- flow-aggregator schreibt pro Flow `stats.src_mac` und `stats.dst_mac` (aus dem Paket-Model, das die MACs bereits trägt) — **kein** Sniffer- und kein Schema-Change (`stats` ist JSONB).
- Detektor leitet die Mode-MAC pro Host ab (`src_mac` wenn Host=src, `dst_mac` wenn Host=dst), bildet das OUI-Präfix (erste 3 Oktette) und matcht `mac_oui` der Katalog-Rollen → `confidence`-Bonus + `evidence:["oui:<vendor|prefix>"]`. MAC nur für lokale L2-Hosts aussagekräftig (geroutet = Router-MAC).

## 4. API-Contract (`/api/hosts`)

```
GET /api/hosts/role-catalog
  → 200 [ {"id","label","category"}, ... ]

GET /api/hosts            (+ optional ?role=<role_id> Filter)
GET /api/hosts/{ip}
  → HostResponse zusätzlich mit:  "detected_roles": <Shape oben> | null

PUT /api/hosts/{ip}/roles        (require_admin)
  Body: {"role_id": "<id>", "action": "set" | "reset" | "remove"}
    set    → roles[id]={source:"manual",confidence:1.0,...}, manual[id]={locked:true,set_by,set_at}
    reset  → manual[id] entfernt, source→auto (oder Eintrag weg, wenn aktuell nicht gematcht)
    remove → auto-Rolle einmalig entfernen (kein Lock)
  → 200 HostResponse (mit aktualisierten detected_roles)
```

## 5. Detektor

Master-only Service `host-role-detector/` (Compose-Vorlage `rule-tuner`). Cadence
`DETECT_INTERVAL_S=1800`, Fenster `DETECT_WINDOW_DAYS=7`, `ROLE_MIN_CONFIDENCE=0.6`.
Aggregation (served ports + Mode-MAC pro Host) aus `flows`; Matching gegen Katalog;
manual-Locks respektieren; alleiniger Schreiber von `detected_roles`.
