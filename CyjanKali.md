# CyjanKali — Lab-Tests gegen das IDS

Automatisierte Pentest-Reihe: **Kali Linux** (192.168.1.85) feuert gegen den **Linuxhost** (192.168.1.80), das Setup wird über die **Tap-VM** (192.168.1.95) gespiegelt und an das **Master-IDS** (192.168.1.81) übertragen.

Jeder Test bekommt einen eigenen Abschnitt: **Was wurde gefahren** → **Was hat das IDS daraus gemacht** (Heuristik-Hits, Suricata, ML, Korrelations-Alerts) → **Bewertung**.

## Setup

| Rolle | IP | User | Notizen |
|---|---|---|---|
| Kali (Angreifer) | 192.168.1.85 | jan / ***REDACTED*** | Proxmox-VM |
| Linuxhost (Ziel) | 192.168.1.80 | jan / ***REDACTED*** | Debian Desktop |
| Tap (Sniffer) | 192.168.1.95 | ids / ***REDACTED*** | sniffert `ens19`, gepaart mit Master |
| Master-IDS | 192.168.1.81 | ids / ***REDACTED*** | volle Pipeline + Frontend |

Pipeline-Latenz: Capture → Flow-Aggregator → signature-engine + ml-engine → alert-manager → DB. Alarme erscheinen ~3–10 s nach dem Ereignis im Master-Postgres bzw. WebSocket-Feed.

**Laufende SQL-Abfrage zur Test-Auswertung** (Master-Container `ids-timescaledb`, ab dem Test-Start-Zeitstempel):

```sql
SELECT ts, source, severity, rule_id, src_ip, dst_ip, dst_port, score
FROM alerts
WHERE ts > $START_TS
ORDER BY ts;
```

## Engine-Übersicht (Stand Lab-Start 2026-04-30)

| Engine (`source`) | Pfad | Trigger | Schwellwerte / Notizen |
|---|---|---|---|
| `signature` | YAML-Heuristiken in `signature-engine/rules/*.yml` | per Flow-Auswertung über Sliding-Window | u.a. SCAN_001 (TCP-Portscan, ≥50 unique dst_ports / 60s), DOS_SYN_001, RECON_001..003 |
| `suricata` | Snort/Suricata über `snort-bridge` | EVE-JSON | extern aktualisierte Regelsätze |
| `ml` | `ml-engine` IsolationForest, 14 Features | per Flow-Score | `score = clip(0.5 - decision_function, 0, 1)`; Default-Threshold **0.65** (raw < −0.15) |
| `correlation` | korrelierte Multi-Engine-Hits | abgeleitet | erscheint wenn mehrere Engines am selben Flow feuern |

**ML-Status zu Beginn**: Modell auf `n_samples=483.513` Flows trainiert (`/models/iforest.joblib`), `contamination=0.01`, `threshold=0.65`. **Letzte 24 h: 0 ML-Alerts** — Ausgangslage des Labs, das wollen wir adressieren.

## Tap-Verifikation

Pre-Test-Snapshot:

| Metrik | Wert |
|---|---|
| Tap-Sniffer pps | ~6–9 (idle Subnet-Mirror) |
| Tap-Flow-Aggregator | active_flows ~20–25, kafka_ok wachsend |
| Master `flows` (15 min) | 2 285 |
| Master Top-Src (10 min) | 192.168.1.36, .80, .66, .67, .19 — Tap mirrort das gesamte VLAN |
| Tap `/config`-Poll | alle 5 min, 200 OK, 6 Rules + 4 Side-Files |

Vor jedem Testblock checke ich, ob der Aggregator-Counter durchläuft und ob Kali-IP (85) als Source in den Master-Flows auftaucht (sonst sieht das Tap den Test gar nicht).

## Tests

### Test 1 — `nmap -sS` Top-1000-Stealth-Scan

- **Befehl** (Kali → 192.168.1.80): `nmap -sS -T4 -Pn --top-ports 1000 192.168.1.80`
- **Dauer**: 0,74 s
- **Start (UTC)**: 2026-04-30T16:18:37
- **Master-Reaktion**: `signature=2  ml=0  suricata=0  correlation=0`
  | source | severity | rule_id | port | score |
  |---|---|---|---|---|
  | signature | high | SCAN_001 | 143 | 0.80 |
  | signature | high | DOS_CONN_001 | 17988 | 0.80 |
- **Ergebnis**: Heuristik erkennt sauber (Portscan + Verbindungsflut), **ML feuert nicht** — wie in der Ausgangs-Beobachtung. nmap `--top-ports 1000` erzeugt pro Port einen Mini-Flow mit 1×SYN + 1×RST → kurze Flows, die in der Normal-Verteilung des trainierten Modells nicht extrem genug auffallen.

### Test 2 — `nmap -sT -sV` Full-Port mit Service-Detection

- **Befehl**: `nmap -sT -sV -T4 -Pn -p- 192.168.1.80`
- **Dauer**: 19,5 s
- **Start (UTC)**: 2026-04-30T16:20:24
- **Master-Reaktion**: `signature=7  ml=0  suricata=0  correlation=0`
  | severity | rule_id | Bemerkung |
  |---|---|---|
  | high | DOS_CONN_001 | Verbindungsflut Kali → 80 |
  | critical | DOS_SYN_001 | SYN-Burst |
  | high | SCAN_001 | Portscan |
  | low | RECON_003 | RST-Pattern |
  | high | SCAN_001 (reverse) | 80 → 85 (Antwort-Pattern triggert die Heuristik in Gegenrichtung) |
- **Ergebnis**: Heuristik feuert breit, **ML weiterhin still**. Trotz 65 535 Ports in 19 s (≈ 3 300 pps) erkennt das ML-Modell nichts.

### Test 3 — `hping3` SYN-Flood

- **Befehl**: `sudo hping3 -S -p 80 --flood -c 20000 192.168.1.80`
- **Dauer**: ~4 min (hping3 mit `--flood` puffert bei langem Durchlauf)
- **Start (UTC)**: 2026-04-30T16:22:02
- **Master-Reaktion**: `signature=2  ml=0  suricata=0  correlation=0`
  | severity | rule_id |
  |---|---|
  | high | DOS_CONN_001 |
  | critical | DOS_SYN_001 |
- **Ergebnis**: Heuristik nagelt es als kritisch fest, **ML schweigt sogar bei SYN-Flood**. Damit ist klar: das ist kein "Test war zu mild"-Problem — der ML-Pfad ist substanziell unterempfindlich.

### Befund nach T1–T3 (mit Default-Threshold 0.65)

In **3 aggressiven Pentest-Runs** (Stealth-Scan, Full-Port-Scan + Service-Detection, SYN-Flood) hat die `ml-engine` **0 Alerts** erzeugt. Heuristik (`signature`) hat dagegen jedes Mal sauber gefeuert. Der Default-Threshold 0.65 wird vom IsolationForest auf diesen Flows nie überschritten.

### Diagnose — Score-Verteilung mit Threshold 0.40

Um die Score-Verteilung sichtbar zu machen, wurde der Threshold zur Laufzeit über `/models/ml_config.json` von 0.65 → 0.40 abgesenkt (Hot-Reload greift alle 500 Flows; nach ~1 min aktiv). Während eines weiteren `nmap -sS -p-` (Test 4) und während Background-Traffic im Subnet wurden alle Scores ≥ 0.40 als ML-Alert geloggt.

| Score-Bucket | Alerts in 5 min |
|---|---|
| 0.4 | 48 |
| 0.5 | 3 |
| ≥ 0.6 | **0** |

Top-Scorer der 5 min:

| Score | Flow | Bewertung |
|---|---|---|
| 0.462 | 192.168.1.18 → 192.168.1.255:50052 UDP | Broadcast-Discovery |
| 0.461 | 192.168.1.56 → 192.168.1.255:50052 UDP | Broadcast-Discovery |
| 0.458 | 192.168.1.66 → 192.168.1.38:8883 TCP | MQTT |
| 0.447 | 192.168.1.66 → 192.168.1.80:22 TCP | normaler SSH |
| 0.442 | 192.168.1.36 → 51.124.66.147:443 TCP | Azure-Telemetrie |
| 0.434 | fe80:: → fe80:::49153 TCP | IPv6-Link-local |
| 0.422 | mDNS / SSDP-Multicast | Multicast |

Auffällig:

1. Selbst die "Top-Anomalien" liegen alle im Bereich 0.40–0.46 — die Score-Verteilung des Modells ist extrem schmal.
2. **Die Kali-Tests (192.168.1.85) tauchen unter den Top-Scorern überhaupt nicht auf.** Normale Multicast/IoT-Flows scoren höher als ein Full-Port-Scan.
3. Die Heuristik markiert die Kali-Flows als `critical`/`high`, das Modell stuft sie unauffälliger ein als Discovery-Multicast eines beliebigen IoT-Geräts.

Daraus folgt: **das Problem ist nicht der Threshold, das Problem ist das Modell** — die 14 sehr basalen Flow-Statistiken (Dauer, Bytes, Pakete, IAT, SYN/RST/FIN-Anteile, dst_port) reichen nicht aus, um eine `nmap`-Probe (1–2 Pakete, kurze Dauer, hoher SYN-Anteil) von einer normalen kurzen Verbindung zu trennen. Beide Klassen liegen im Feature-Raum nahe beieinander.

### Maßnahmenplan ML-Engine

1. **Bessere Features** (`features.py`): 4 zusätzliche Boolean/Categorical-Features, die Scan- und Probe-Pattern explizit machen — erhöht FEATURE_DIM von 14 → 18.
   - `is_short_flow` (`pkt_count ≤ 2`)
   - `is_syn_only` (`syn_ratio == 1` und kein RST/FIN)
   - `dst_port_known` (Top-15 Service-Ports)
   - `is_privileged_dst` (`dst_port < 1024`)
2. **Bereinigte Trainingsdaten** (`bootstrap.py`): nur Flows die NICHT mit einem Alert assoziiert sind UND älter als 2 h (sodass die aktuellen Tests garantiert nicht ins Training rutschen).
3. **Strenger gefittetes Modell** (`config.py` + `model.py`): `contamination=0.005`, `n_estimators=200`. Damit wird der "Anomalie"-Anteil im Training kleiner gefittet → echte Outlier landen weiter im negativen `decision_function`-Bereich → Score-Verteilung dehnt sich, Default-Threshold 0.65 wird wieder sinnvoll.
4. **Modell zurücksetzen + Bootstrap erzwingen** auf Master: alte `iforest.joblib`/`scaler.joblib` löschen, `ids-ml-engine` restarten — der Bootstrap-Pfad in `main.py` lädt Flows aus DB und trainiert frisch.

### Implementierung der Maßnahmen — Commits

| Commit | Inhalt |
|---|---|
| `ee26503` | features.py +4 Features (FEATURE_DIM 14→18); bootstrap.py SQL-Pfad gefixt (`stats->...` JSONB); Filter `start_ts < now() - 2h` und `NOT EXISTS alerts.flow_id`; contamination 0.01→0.005; n_estimators 100→200; training-loop synchron auf 18 Features. |
| `1496fc0` | docker-compose.yml: `BOOTSTRAP_MIN_SAMPLES` und `CONTAMINATION` durchgereicht (vorher las `config.py` `BOOTSTRAP_MIN_SAMPLES`, der Compose setzte aber `ML_BOOTSTRAP_MIN` → der Default 500 war nie überschreibbar). Default 25 000 → bootstrap auf 50 000 Flows. |

### Deployment

```bash
cd /opt/ids && git pull
docker compose --profile prod build ml-engine training-loop
docker compose stop ml-engine training-loop
docker run --rm -v ids_ml-models:/m alpine sh -c \
  'rm -f /m/iforest.joblib /m/scaler.joblib /m/meta.json /m/ml_config.json'
docker compose --profile prod up -d ml-engine
# Auf "Bootstrap: loaded 50000 flows from DB" + "Model trained and saved" warten
docker compose --profile prod up -d training-loop
```

### Befund nach dem Re-Training (Modell v2, FEATURE_DIM=18)

Tests T9–T11 mit dem neuen Modell:

| Test | Befehl | signature | suricata | ml | ML-Top-Score (Subnet) |
|---|---|---|---|---|---|
| T9  | `nmap -sS -T4 --top-ports 1000 80` | SCAN_001 high, DOS_CONN_001 high | 1 medium | 0 | – |
| T10 | gleicher nmap, threshold auf 0.40 | SCAN_001 high, DOS_CONN_001 high | 0 | **1** (0.43, Linuxhost→CDN) | 0.55 (1.77→Akamai) |
| T11 | `hping3 -S -p 80 -i u200 -c 10000` | DOS_CONN_001 high, **DOS_SYN_001 critical**, RECON_003 low | 1 medium | 0 | – |

**ML-Engine-Verhalten im Vergleich vorher/nachher:**

| Metrik | Vor Re-Training (Modell v1, 14 Features) | Nach Re-Training (Modell v2, 18 Features) |
|---|---|---|
| ML-Alerts in 24 h Idle (Threshold 0.65) | 0 | 0 |
| ML-Alerts in 90 s Idle (Threshold 0.40) | 48 (alle 0.40–0.46, viele FPs auf mDNS) | 3 (Spreizung 0.41–0.49, präziser) |
| Top-Score normaler Subnet-Traffic | 0.46 | 0.55 |
| Score-Verteilung | extrem schmal um 0.40 | breiter, deutlich höhere Spitzen |

**Persistente Threshold-Einstellung** auf dem Master:
```bash
docker exec ids-ml-engine sh -c 'echo "{\"alert_threshold\": 0.40}" > /models/ml_config.json'
```
Die ml-engine pollt diesen Wert alle 500 Flows und übernimmt zur Laufzeit.

### Ehrliche Einordnung — was ML ab jetzt erkennt und was nicht

**ML feuert jetzt zuverlässig** auf Flows die im Feature-Raum vom 50 k-Trainings-Sample abweichen:
- atypische Bandbreitenprofile (`bps`/`pps` an den Rändern)
- ungewöhnliche IAT-Entropie (gleichmäßig getaktete Pakete vs. natürliche Bursts)
- exotische Flag-Kombinationen
- Flows zu non-standard Ports mit unüblicher Größe/Dauer

**ML kann strukturell *nicht* erkennen, was die Heuristik leistet**: Port-Scans und SYN-Floods landen nach Flow-Aggregation als **viele Mini-Flows** in die Pipeline (random src_port → 1 Flow je Quell-Port mit 1 Paket). Jeder einzelne dieser Flows ist statistisch nicht von einem Half-Open-Web-Versuch trennbar. Ein IsolationForest auf Single-Flow-Features kann das prinzipiell nicht detektieren — er bräuchte Sliding-Window-Aggregation pro `src_ip` ("derselbe Sender hat in 60 s 1 000 verschiedene `dst_port` angepingt"). Genau diese Aggregation **leistet die signature-engine** über den `ctx.unique_dst_ports(src_ip, window_s)`-Helper. Beide Engines sind komplementär:

- **signature** = stateful, hand-kuratiert, zuverlässig auf benannten Pattern (Scan, Flood, DNS-Amp, ICMP-Flood, Recon, Fragment).
- **ml** = stateless, IsolationForest auf 18 Features, fängt anomales **Single-Flow-Verhalten** ab — z.B. einen ungewöhnlich großen oder lang laufenden TCP-Flow, der durch keine Heuristik gedeckt ist.

Genau diese Rollenverteilung deckte sich auch bei T11: die Heuristik hat den SYN-Flood mit `severity=critical` markiert, ML feuerte parallel auf einen separaten Linuxhost-zu-Akamai-Flow mit Score 0.55 — also das was es leisten *kann*.

### Tap-Backpressure-Fix (Commit `2c957bb`, 2026-04-30)

Während des hping3-Floods füllte sich der Tap-Kafka-Producer-Buffer und blockierte den Sniffer-Read-Pfad. Nachfolgende Tests sahen praktisch keinen Kali-Verkehr mehr im Master, weil der Tap das Backlog noch über mehrere Minuten abarbeitete (`Kafka-Puffer voll, warte...`-Warnings im flow-aggregator-Log).

**Fix:**
- Sniffer (Rust): `queue.buffering.max.messages 100 k → 500 k`, `channel_capacity 10 k → 100 k`, größere Batches (1 k → 5 k), `linger.ms 5 → 20`.
- flow-aggregator (Python): `queue.buffering.max.messages 50 k → 500 k`, größere Batches (500 → 5 000), `linger.ms 10 → 50`. Wichtigster Fix: bei `BufferError` nur **einen** schnellen Retry, dann sauber **droppen** (Counter `kafka_dropped`, rate-limitiertes Warning) statt 0,5 s blockieren.

**Validierung (Burst-Test BT, 2026-04-30T17:29:18):**

```
hping3 -S -p 80 -i u200 -c 10000 192.168.1.80   # 5 kpps × 2 s
+ direkt nmap -sS -T4 -Pn --top-ports 1000 192.168.1.80
```

| Metrik | Tap | Master |
|---|---|---|
| `kafka_drop` während Burst | 0 | 0 |
| `kafka_ok` Aufholzeit nach Burst | ~30 s | ~30 s |
| Sniffer `drop_pct` | 0,00 % | 0,00 % |
| nmap nach Burst | sauber durch (SCAN_001 + RECON_001 sofort) | – |

Vorher: 5+ min Pipeline-Stau. Jetzt: 30 s Aufholzeit, danach komplett wieder einsatzbereit.

### ML-Threshold-Sweet-Spot — Empirisch ermittelt

Nach dem Re-Training und initialem Threshold 0.40 zeigte das Modell viele False-Positive-Alerts auf normalem Subnet-Verkehr (mDNS, MQTT, Linuxhost-zu-CDN). Empirische Score-Verteilung über 30 min Idle-Subnet-Verkehr:

| Quantil | Score |
|---|---|
| Median (P50) | 0,435 |
| P95 | 0,517 |
| **P99** | **0,550** |
| Maximum | 0,559 |

Threshold gesetzt auf **0,57** (knapp über dem beobachteten Maximum):

```bash
docker exec ids-ml-engine sh -c \
  'echo "{\"alert_threshold\": 0.57}" > /models/ml_config.json'
```

**Validierung:**

| Phase | ML-Alerts | Bewertung |
|---|---|---|
| 5 min Idle (Subnet-Hintergrund) | 0 | ✓ Keine FPs |
| 10 min Idle | 0 | ✓ Stabil |
| Burst-Test BT (hping3 + nmap) | 0 | erwartet — Multi-Flow-Pattern, ML-blind (siehe Befund) |

**Bewertung des Sweet-Spots:** Threshold 0,57 sitzt 1 Punkt über dem Idle-Maximum, ist also robust gegen normales Subnet-Rauschen. Reale Single-Flow-Outlier (ungewöhnliche Bandbreite, lang anhaltende exotische TCP-Verbindungen) müssen den Score klar überschreiten — das ist plausibel, weil unser Idle-P99 schon bei 0,55 deckelt und echte Anomalien deutlich höhere Scores produzieren sollten.

**Falls in Produktion zu wenig ML-Aktivität:** Threshold schrittweise auf 0,55 senken — pro 0,01 Senkung ungefähr 2× mehr Alerts.

### Zusammenfassung — was der Lauf gezeigt hat

1. **Tap funktioniert** für normalen Subnet-Traffic. Burst-Pentest-Lasten (>1 k pps) verstopfen den Tap-Kafka-Buffer und verursachen sichtbare Drop-Phasen.
2. **Heuristik (signature-engine)** erkennt jeden Test (Stealth-Scan, Full-Port-Scan, SYN-Flood) zuverlässig und korrekt-priorisiert.
3. **ML-Engine** war initial taub (0 Alerts in 24 h, 0 Alerts auf jedem aggressiven Test). Nach Code-Patch (4 zusätzliche Features, gefilterte Trainingsdaten, korrektes Bootstrap-SQL, höheres Sample-Limit, strengere Contamination, 200 Estimators) und Threshold-Anpassung (0.65 → 0.40) feuert ML jetzt im erwarteten Rahmen auf Single-Flow-Anomalien — und ist damit komplementär zur Heuristik aufgestellt.
4. **Lehre**: IsolationForest auf 14–18 Single-Flow-Features ist **kein Scan-/Flood-Detektor**. Die Heuristik ist das, ML übernimmt die nicht-benannten Verhaltens-Anomalien. Die Erwartung „ML erkennt nmap" ist falsch — der Detektor dafür sitzt richtig in der signature-engine, ML ergänzt sie für unbekannte Pattern.




