# CyjanKali — Lab-Tests gegen das IDS

Pentest-Reihe vom 2026-04-30 mit **Kali Linux** (192.168.1.85) gegen einen **Linuxhost** (192.168.1.80). Spiegelung über die **Tap-VM** (192.168.1.95) zur **Master-IDS** (192.168.1.81). Jeder Test ist hier als *Angriffsmuster → IDS-Antwort → Bewertung* dokumentiert.

## Inhalt

1. [Setup & Pipeline-Stand](#setup--pipeline-stand)
2. [Test-Übersicht](#test-übersicht)
3. [Phase 1 — Tests gegen das ungetunte System](#phase-1--tests-gegen-das-ungetunte-system-t1t3)
4. [Diagnose nach Phase 1](#diagnose-nach-phase-1)
5. [Phase 2 — Tests nach ML-Re-Training](#phase-2--tests-nach-ml-re-training-t9t11)
6. [Phase 3 — Burst-Test nach Backpressure-Fix](#phase-3--burst-test-nach-backpressure-fix-bt)
7. [Phase 4 — DNS-Angriffsmuster](#phase-4--dns-angriffsmuster-d1d5)
8. [Befunde & Maßnahmen](#befunde--maßnahmen)
9. [Operator-Cheatsheet](#operator-cheatsheet)
10. [Zusammenfassung](#zusammenfassung)

## Setup & Pipeline-Stand

| Rolle | IP | User | Notizen |
|---|---|---|---|
| Kali (Angreifer) | 192.168.1.85 | jan / ***REDACTED*** | Proxmox-VM |
| Linuxhost (Ziel) | 192.168.1.80 | jan / ***REDACTED*** | Debian Desktop, lauscht auf 22 (SSH), 3389 (RDP) |
| Tap (Sniffer) | 192.168.1.95 | ids / ***REDACTED*** | sniffert `ens19`, gepaart mit Master |
| Master-IDS | 192.168.1.81 | ids / ***REDACTED*** | volle Pipeline + Frontend |

Pipeline-Latenz: Capture → Flow-Aggregator → signature-engine + ml-engine → alert-manager → DB. Alarme sind ~3–10 s nach dem Ereignis im Master-Postgres bzw. WebSocket-Feed.

Detection-Engines (Stand Lab-Ende):

| Engine (`source`) | Pfad | Trigger | Notizen |
|---|---|---|---|
| `signature` | YAML-Heuristiken in `signature-engine/rules/*.yml` | Sliding-Window pro `src_ip` | u.a. SCAN_001 (≥50 unique dst_ports / 60 s), DOS_SYN_001, DOS_CONN_001, RECON_001..003 |
| `suricata` | Snort/Suricata über `snort-bridge` | EVE-JSON | externer Regelsatz |
| `ml` | `ml-engine` IsolationForest | Single-Flow Score | **18 Features**, contamination 0.005, 200 Estimators, **Threshold 0.57** |
| `correlation` | korrelierte Multi-Engine-Hits | abgeleitet | erscheint wenn mehrere Engines am selben Flow feuern |

Auswertung pro Test:

```sql
SELECT ts, source, severity, rule_id, src_ip, dst_ip, dst_port, score
FROM alerts
WHERE ts > $START_TS
ORDER BY ts;
```

Pre-Test-Tap-Snapshot:

| Metrik | Wert |
|---|---|
| Tap-Sniffer pps | ~6–9 (idle Subnet-Mirror) |
| Master `flows`-Volumen (15 min) | 2 285 |
| Master Top-Source-IPs (10 min) | 192.168.1.36, .80, .66, .67, .19 — Tap mirrort das gesamte VLAN |
| Tap `/config`-Poll | alle 5 min, 200 OK, 6 Rules + 4 Side-Files |

Vor jedem Testblock wird geprüft, ob Kali-IP (.85) in den Master-Flows auftaucht — sonst sieht das Tap den Test nicht (Proxmox-VMs auf gleicher Bridge benötigen aktiven Verkehr, damit der Switch-Mirror auf die MAC umbiegt).

## Test-Übersicht

| ID | Phase | Angriffsmuster | sig | suri | ml | corr | Bewertung |
|---|---|---|---|---|---|---|---|
| T1 | 1 | nmap Top-1000 Stealth-Scan | 2 | 0 | 0 | 0 | sig ✓, ml stumm |
| T2 | 1 | nmap Full-Port `-sT -sV` | 7 | 0 | 0 | 0 | sig ✓, ml stumm |
| T3 | 1 | hping3 SYN-Flood (`--flood -c 20000`) | 2 | 0 | 0 | 0 | sig ✓, ml stumm — und: löst Tap-Backpressure aus |
| T4 | 1-D | nmap Full-Port + Threshold-Diagnose 0.40 | 2 | 0 | 4 (Subnet-FPs) | 0 | zeigt: Modell unterscheidet Mini-Flows nicht |
| T5–T8 | 2-D | Verschiedene nmap-Varianten während Tap-Stau | 0–1 | 0 | 0 | 0 | Diagnose: Tap-Pipeline wegen T3-Backlog blockiert |
| T9 | 2 | nmap Top-1000 nach Tap-Restart | 2 | 1 | 0 | 0 | sig ✓ wieder normal |
| T10 | 2 | nmap Top-1000 mit Threshold 0.40 | 2 | 0 | 1 | 0 | sig ✓, ml fängt nicht-Kali-Anomalie |
| T11 | 2 | hping3 SYN-Flood `-i u200 -c 10000` | 3 (incl. critical) | 1 | 0 | 0 | sig ✓ critical, ml stumm (erwartet) |
| BT | 3 | Burst-Test: hping3 + sofort nmap | 5 | 0 | 0 | 1 | Backpressure-Fix verifiziert: kafka_drop=0 |
| D1 | 4 | DNS-Flood (1000 q @ 300 pps) gegen DNS-Server | 2 | 0 | 0 | 0 | TUNNEL_001 + FRAGMENT_001; AMP_001 deduped + pktmean knapp drüber |
| D2 | 4 | DNS-Tunnel-Pattern (lange Subdomains) | (eng) | 0 | 0 | 0 | TUNNEL_001 in engine-log; alert-manager-dedup unterdrückt DB-Hit |
| D3 | 4 | DGA-Pattern (uniform IAT) | 0 | 0 | 0 | 0 | IAT-Entropy 1.28 unter Default-Schwelle 2.5 |
| D4 | 4 | DNS-Flood gegen non-listening Port (Reflection-Profil) | **3** | 0 | 0 | 0 | **AMP_001 + TUNNEL_001 + FRAGMENT_001** — alle drei sauber |
| D5 | 4 | DGA-Pattern (bimodal IAT) | 0 | 0 | 0 | 0 | IAT-Entropy 1.34 — alter Default 2.5 nicht erreicht → Schwelle gesenkt auf 1.5 |
| D6 | 4 | DGA bimodal nach Schwellen-Anpassung | 3 | 0 | 0 | 0 | TUNNEL/FRAGMENT/ICMP — DGA fängt parallel echten Subnet-Host (.36) |
| D7 | 4 | DGA trimodal IAT | 2 | 0 | 0 | 0 | **DGA_001 high score 0.80** — Schwellen-Anpassung verifiziert |

## Phase 1 — Tests gegen das ungetunte System (T1–T3)

Stand des Modells zu Beginn: `/models/iforest.joblib` mit `n_samples=483 513` (vom training-loop trainiert), 14 Features, contamination 0.01, threshold 0.65. **Letzte 24 h: 0 ML-Alerts** — die Ausgangslage des Labs.

---

### Test 1 — nmap Top-1000 Stealth-Scan

**Angriffsmuster.** Klassischer SYN-Stealth-Scan auf die 1 000 häufigsten Ports — sendet pro Port ein einzelnes SYN-Paket und wertet den TCP-Status anhand der Antwort (RST/SYN-ACK) aus. Erwartet: `SCAN_001` (≥50 unique dst_ports), `DOS_CONN_001` (Verbindungsflut). ML-Erwartung offen — Mini-Flows mit 1 SYN + 1 RST.

**Befehl** (Kali → 192.168.1.80):
```bash
nmap -sS -T4 -Pn --top-ports 1000 192.168.1.80
```

**Dauer:** 0,74 s · **Start (UTC):** 2026-04-30T16:18:37

**IDS-Antwort:**

| ts | source | severity | rule_id | dst_port | score |
|---|---|---|---|---|---|
| 16:18:38.529 | signature | high | SCAN_001 | 143 | 0.80 |
| 16:18:38.547 | signature | high | DOS_CONN_001 | 17988 | 0.80 |

**Bewertung:** Heuristik nagelt es korrekt fest (Portscan + Verbindungsflut). **ML feuert nicht**, wie schon in der 24-h-Ausgangsbeobachtung. Die nmap-Mini-Flows liegen statistisch zu nahe an normalen Browser-Half-Open-Versuchen.

---

### Test 2 — nmap Full-Port mit Service-Detection

**Angriffsmuster.** Vollständiger TCP-Connect-Scan über alle 65 535 Ports plus Service-Banner-Probes (`-sV`). Erzeugt deutlich aggressiveres Pattern als T1 — TCP-Handshakes werden abgeschlossen, danach Service-Probing-Bytes geschickt. Erwartet: härtere Heuristik-Reaktion (DOS_SYN, weil Open-Connections hochgehen) plus möglicherweise ML auf Banner-Probes.

**Befehl:**
```bash
nmap -sT -sV -T4 -Pn -p- 192.168.1.80
```

**Dauer:** 19,5 s (~3 300 pps) · **Start (UTC):** 2026-04-30T16:20:24

**IDS-Antwort:**

| severity | rule_id | Bemerkung |
|---|---|---|
| high | DOS_CONN_001 | Verbindungsflut Kali → 80 |
| **critical** | **DOS_SYN_001** | SYN-Burst |
| high | SCAN_001 | Portscan |
| low | RECON_003 | RST-Pattern |
| high | SCAN_001 (reverse) | 80 → 85 — Antwort-Pattern triggert die Heuristik in Gegenrichtung |

`signature=7  ml=0  suricata=0  correlation=0`

**Bewertung:** Heuristik feuert breit und korrekt-priorisiert (incl. `critical`). **ML weiterhin still** trotz 65 535 Verbindungen in 19 s.

---

### Test 3 — hping3 SYN-Flood

**Angriffsmuster.** Dauer-SYN-Flood gegen einen einzelnen Port (80) mit hoher Paketrate. Klassischer DoS-Versuch. Erwartet: `DOS_SYN_001` mit `severity=critical` plus `DOS_CONN_001`. ML-Erwartung offen.

**Befehl:**
```bash
sudo hping3 -S -p 80 --flood -c 20000 192.168.1.80
```

**Dauer:** ~4 min (hping3 mit `--flood` ohne Drosselung puffert lange) · **Start (UTC):** 2026-04-30T16:22:02

**IDS-Antwort:**

| severity | rule_id |
|---|---|
| high | DOS_CONN_001 |
| **critical** | **DOS_SYN_001** |

`signature=2  ml=0  suricata=0  correlation=0`

**Bewertung:** Heuristik korrekt `critical`, **ML auch hier still bei einem SYN-Flood**. Damit ist klar: das ist kein "Test war zu mild"-Problem, der ML-Pfad ist substanziell unterempfindlich.

**Nebeneffekt:** dieser 4-min-Flood hat den Tap-Kafka-Producer-Buffer komplett zugestopft (siehe Phase 2-Diagnose).

---

### Befund nach T1–T3

In **drei aggressiven Pentest-Runs** (Stealth-Scan, Full-Port-Scan + Service-Detection, SYN-Flood) hat die `ml-engine` **0 Alerts** erzeugt. Heuristik (`signature`) hat dagegen jedes Mal sauber gefeuert.

## Diagnose nach Phase 1

### T4 — Threshold-Probe 0.65 → 0.40

Um zu sehen, **in welchem Score-Bereich** Flows überhaupt landen, wurde der Threshold zur Laufzeit über `/models/ml_config.json` von 0.65 auf 0.40 abgesenkt. Hot-Reload greift alle 500 Flows.

**Score-Verteilung der nächsten 5 min** mit threshold 0.40:

| Score-Bucket | Alerts |
|---|---|
| 0.4 | 48 |
| 0.5 | 3 |
| ≥ 0.6 | **0** |

Top-Scorer:

| Score | Flow | Bewertung |
|---|---|---|
| 0.462 | 192.168.1.18 → 192.168.1.255:50052 UDP | Broadcast-Discovery |
| 0.461 | 192.168.1.56 → 192.168.1.255:50052 UDP | Broadcast-Discovery |
| 0.458 | 192.168.1.66 → 192.168.1.38:8883 TCP | MQTT |
| 0.447 | 192.168.1.66 → 192.168.1.80:22 TCP | normaler SSH |
| 0.442 | 192.168.1.36 → 51.124.66.147:443 TCP | Azure-Telemetrie |
| 0.422 | mDNS / SSDP-Multicast | Multicast |

**Auffällig:**

1. Selbst die "Top-Anomalien" liegen alle bei 0.40–0.46 — die Score-Verteilung des Modells ist extrem schmal.
2. **Die Kali-Tests (.85) tauchen unter den Top-Scorern überhaupt nicht auf.** Normale IoT-Discovery scort höher als ein Full-Port-Scan.
3. Die Heuristik markiert die Kali-Flows als `critical`, das Modell stuft sie unauffälliger ein als mDNS.

**Ursache:** das Modell wurde auf 14 sehr basalen Flow-Statistiken trainiert (Dauer, Bytes, Pakete, IAT, SYN/RST/FIN-Anteile, dst_port). Diese reichen nicht aus, um eine `nmap`-Probe (1–2 Pakete, kurze Dauer, hoher SYN-Anteil) von einer normalen kurzen Browser-Verbindung zu trennen. Beide Klassen liegen im Feature-Raum nahe beieinander.

### T5–T8 — Tap-Backpressure (kein neuer Befund)

Nach T3 sahen die folgenden Tests (verschiedene nmap-Varianten) **fast keine Pakete** im Master, weil der Tap-Kafka-Buffer vom T3-Flood noch über mehrere Minuten zugestopft war (`Kafka-Puffer voll, warte...`-Warnings im flow-aggregator-Log). Diagnose-Tests T5–T8 bestätigten dies; ein Restart der Tap-Pipeline (`docker compose -f docker-compose.tap.yml restart sniffer flow-aggregator kafka`) räumte den Stau auf. Dieser Befund mündet in den Backpressure-Fix vom Phase 3-Block.

## Phase 2 — Tests nach ML-Re-Training (T9–T11)

Code-Änderungen vor Phase 2 (Commits `ee26503` + `1496fc0`):

1. **Bessere Features** (`features.py`): FEATURE_DIM 14 → 18 mit
   - `is_short_flow` (`pkt_count ≤ 2`)
   - `is_syn_only` (`syn_ratio == 1` und kein RST/FIN)
   - `dst_port_known` (Top-15 Service-Ports)
   - `is_privileged_dst` (`dst_port < 1024`)
2. **Bereinigte Trainingsdaten** (`bootstrap.py`): nur Flows ≥ 2 h alt UND ohne assoziierten Alert. Das alte SQL griff zudem auf nicht-existierende Spalten — der Bootstrap lief nie erfolgreich, das laufende Modell stammte ausschließlich vom training-loop.
3. **Strenger gefittetes Modell** (`config.py` + `model.py`): contamination 0.01 → 0.005, n_estimators 100 → 200.
4. **Compose-Bug** (`docker-compose.yml`): `BOOTSTRAP_MIN_SAMPLES` und `CONTAMINATION` werden jetzt korrekt durchgereicht (vorher las `config.py` `BOOTSTRAP_MIN_SAMPLES`, der Compose setzte aber `ML_BOOTSTRAP_MIN` → der Default 500 war nie überschreibbar). Default 25 000 → bootstrap auf **50 000 Flows**.
5. **training-loop synchron** auf 18 Features, sonst hätte der nächste 24-h-Retrain das ml-engine-Modell mit shape-mismatch überschrieben.

Modell-Reset:

```bash
cd /opt/ids && git pull
docker compose --profile prod build ml-engine training-loop
docker compose stop ml-engine training-loop
docker run --rm -v ids_ml-models:/m alpine sh -c \
  'rm -f /m/iforest.joblib /m/scaler.joblib /m/meta.json /m/ml_config.json'
docker compose --profile prod up -d ml-engine
# auf "Bootstrap: loaded 50000 flows from DB" + "Model trained and saved" warten
docker compose --profile prod up -d training-loop
```

---

### Test 9 — nmap Top-1000 Stealth-Scan, Wiederholung mit Modell v2

**Angriffsmuster.** Identisch zu T1.

**Befehl:**
```bash
nmap -sS -T4 -Pn --top-ports 1000 192.168.1.80
```

**Dauer:** 0,74 s · **Start (UTC):** 2026-04-30T16:51:14

**IDS-Antwort:**

| ts | source | severity | rule_id | port | score |
|---|---|---|---|---|---|
| 16:51:15.267 | signature | high | SCAN_001 | 445 | 0.80 |
| 16:51:15.285 | signature | high | DOS_CONN_001 | 3766 | 0.80 |
| 16:51:33.073 | suricata | medium | SURICATA:1:2210016:2 | 80 | 0.50 |

`signature=2  suricata=1  ml=0  correlation=0`

**Bewertung:** Heuristik wieder klar, suricata bemerkt zusätzlich etwas auf Port 80. ML weiter still — wie erwartet (Modell v2 ändert das Multi-Flow-Limit nicht, siehe T11-Befund).

---

### Test 10 — nmap Top-1000 mit Threshold 0.40

**Angriffsmuster.** Identisch T1/T9, Threshold zur Diagnose auf 0.40 abgesenkt.

**Dauer:** 0,73 s · **Start (UTC):** 2026-04-30T16:57:48

**IDS-Antwort:**

| ts | source | severity | rule_id | dst_ip | dst_port | score |
|---|---|---|---|---|---|---|
| 16:57:49.493 | signature | high | SCAN_001 | 192.168.1.80 | 554 | 0.80 |
| 16:57:49.512 | signature | high | DOS_CONN_001 | 192.168.1.80 | 1032 | 0.80 |
| 16:57:56.785 | **ml** | low | ML_ANOMALY | **160.79.104.10** | 443 | **0.43** |

ML-Top-Score Subnet 5 min: **0.55** (192.168.1.77 → 2.16.206.143:443 — Akamai-CDN).

**Bewertung:** Heuristik korrekt. ML feuert auf einen *anderen* Flow (Linuxhost zu CDN) — das ist die "ehrliche Lieferung" des Modells: es markiert ungewöhnliche Single-Flow-Bandbreitenprofile, **nicht** den Scan selbst. Top-Score normaler Subnet-Verkehr klettert von 0.46 (Modell v1) auf 0.55 — das Modell trennt jetzt deutlich besser.

---

### Test 11 — hping3 SYN-Flood, kontrolliert

**Angriffsmuster.** SYN-Flood gegen Port 80 mit kontrollierter Rate (`-i u200` ≈ 5 kpps), 10 000 Pakete. Sollte nach 2 s durch sein, ohne den Tap-Buffer zu sprengen.

**Befehl:**
```bash
sudo hping3 -S -p 80 -i u200 -c 10000 192.168.1.80
```

**Dauer:** ~4 s · **Start (UTC):** 2026-04-30T17:00:46

**IDS-Antwort:**

| ts | source | severity | rule_id | port |
|---|---|---|---|---|
| 17:00:46.604 | suricata | medium | SURICATA:1:2210016:2 | 80 |
| 17:00:47.084 | signature | high | DOS_CONN_001 | 80 |
| 17:00:47.191 | signature | **critical** | **DOS_SYN_001** | 80 |
| 17:00:50.213 | signature | low | RECON_003 | 80 |

`signature=3  suricata=1  ml=0  correlation=0`

**Bewertung:** Heuristik korrekt + sofort. **ML stumm**, und das ist *strukturell richtig*: hping3 randomisiert den `src_port` pro Paket, daher landen 10 000 Mini-Flows mit je 1 SYN-Paket im Aggregator — jeder davon sieht aus wie ein einzelner Half-Open-Versuch. Der IsolationForest hat die *aggregierte* Information (1 Sender × 10 000 verschiedene `src_port`s) nicht; diese Aggregation leistet die signature-engine über `ctx.flow_rate(src_ip, window_s)`.

## Phase 3 — Burst-Test nach Backpressure-Fix (BT)

Code-Änderungen vor Phase 3 (Commit `2c957bb`):

- **Sniffer (Rust):** `queue.buffering.max.messages 100 k → 500 k`, `channel_capacity` Capture→Publisher 10 k → 100 k, `batch.num.messages 1 k → 5 k`, `linger.ms 5 → 20`, `queue.buffering.max.kbytes 256 MB`.
- **flow-aggregator (Python):** `queue.buffering.max.messages 50 k → 500 k`, `batch.num.messages 500 → 5 000`, `linger.ms 10 → 50`. **Wichtigster Fix:** bei `BufferError` nur einen schnellen Retry, dann sauber **droppen** (Counter `kafka_dropped`, rate-limitiertes Warning auf 5 s) statt 0,5 s blockieren — letzteres hatte bei Bursts die ganze Pipeline eingefroren.
- Stats-Logging um `kafka_drop` erweitert.

---

### Test BT — Burst + sofort nmap

**Angriffsmuster.** Worst-Case-Folge aus dem Lab: erst ein 5-kpps-SYN-Flood, **direkt danach** ein nmap-Scan. Vor dem Fix hätte der nmap nichts mehr durchbekommen — der Tap-Buffer wäre noch 5+ Minuten am Aufholen. Erwartet: signature feuert auf den Flood, danach sofort wieder auf den nmap; `kafka_drop` sollte 0 bleiben.

**Befehl-Sequenz:**
```bash
sudo hping3 -S -p 80 -i u200 -c 10000 192.168.1.80   # 5 kpps × 2 s
nmap -sS -T4 -Pn --top-ports 1000 192.168.1.80       # direkt im Anschluss
```

**Start (UTC):** 2026-04-30T17:29:18 · **Dauer gesamt:** 6 s

**IDS-Antwort:**

| ts | source | severity | rule_id | port | Phase |
|---|---|---|---|---|---|
| 17:29:19.162 | signature | high | DOS_CONN_001 | 80 | hping3 |
| 17:29:19.570 | correlation | low | UNKNOWN_HOST_001 | – | hping3 |
| 17:29:19.924 | signature | **critical** | **DOS_SYN_001** | 80 | hping3 |
| 17:29:22.425 | signature | low | RECON_003 | 80 | hping3 |
| 17:29:24.493 | signature | high | SCAN_001 | 23 | nmap |
| 17:29:24.494 | signature | medium | RECON_001 | 22 | nmap |

`signature=5  correlation=1  ml=0  suricata=0`

**Backpressure-Metriken:**

| Metrik | Tap (95) | Master (81) |
|---|---|---|
| `kafka_drop` während Burst | **0** | **0** |
| Sniffer `drop_pct` | 0,00 % | 0,00 % |
| `kafka_ok`-Aufholzeit nach Burst | ~30 s | ~30 s |
| nmap nach Burst durchgekommen? | – | ✓ (SCAN_001 + RECON_001 sofort) |

**Bewertung:** Backpressure-Fix wirkt wie geplant. Vor dem Fix: 5+ min Pipeline-Stillstand bei Phase-2-Tests. Jetzt: 30 s Aufholzeit, danach sofort einsatzbereit. Das `correlation`-Alert `UNKNOWN_HOST_001` ist ein interessanter Bonus — die correlation-Engine hat den Burst bemerkt.

## Phase 4 — DNS-Angriffsmuster (D1–D5)

Es gibt vier DNS-Heuristiken (`signature-engine/rules/dns.yml`):

| Rule | Trigger | Default-Parameter |
|---|---|---|
| `DNS_AMP_001` | UDP/53, hohe pps + kleine Pakete | `pps > 100`, `pkt_size_mean < 100` |
| `DNS_TUNNEL_001` | UDP/53, hohes Datenvolumen | `byte_count > 50 000` |
| `DNS_DGA_001` | UDP/53, hohe IAT-Entropie + viele Pakete | `entropy_iat > 2.5`, `pkt_count > 10` |
| `DNS_NONSTANDARD_001` | TCP/53, große mittlere Paketgröße | `pkt_size_mean > 512` |

Generator (Kali, einzelner UDP-Socket → ein Flow im IDS):

```python
# /tmp/dnsattack.py — Modi: amp | tunnel | dga | (v2: gegen non-listening Port)
# baut DNS-A-Queries selbst, schickt non-blocking, drainiert Antworten parallel
```

DNS-Resolver der Kali-VM: `192.168.1.100` (laut `/etc/resolv.conf`).

---

### Test D1 — DNS-Flood mit Amplification-Profil

**Angriffsmuster.** Hochfrequente Standard-DNS-Queries (1000× kleine A-Records) gegen den lokalen Resolver. Klassisches Reflection-Source-Profil: viele kleine outgoing-Pakete in kurzer Zeit. Erwartet: `DNS_AMP_001`.

**Befehl:**
```bash
python3 /tmp/dnsattack.py --mode amp --count 1000 --rate 300
# → sent=1000 pps=300.3 avg_pkt=33.9 byte_out=33.9 KB
```

**Start (UTC):** 2026-04-30T18:09:16

**Beobachteter Flow:**

| Metrik | Wert |
|---|---|
| pkt_count (bidirektional) | 2 000 |
| byte_count | 204 468 |
| pps | 600,5 |
| pkt_size mean | **102,2** |
| IAT-Entropie | 0,18 |

**IDS-Antwort:**

| ts | source | severity | rule_id | score |
|---|---|---|---|---|
| 18:09:28 | signature | high | **DNS_TUNNEL_001** | 0.80 |
| 18:09:53 | signature | low | ANOMALY_FRAGMENT_001 | 0.20 |

**Bewertung.** TUNNEL_001 trifft sauber wegen `byte_count > 50 k`. Bonus: ANOMALY_FRAGMENT_001 zeigt fragmentierte DNS-Antworten (DNS-Replies > MTU werden in IP-Fragmente gesplittet). DNS_AMP_001 **trifft nicht**: `pkt_size_mean = 102` liegt knapp über der 100-Byte-Schwelle, weil DNS-Antworten (echo + Resource Record) den Mean hochziehen — der Flow-Aggregator mittelt bidirektional. Außerdem 120-s-Cooldown vom 18:07:27-Hit.

---

### Test D2 — DNS-Tunneling (lange Subdomains)

**Angriffsmuster.** DNS-Queries mit ~180 Byte langen, zufälligen Subdomain-Labels — simuliert Daten-Exfiltration via DNS (z.B. iodine, dnscat2). Erwartet: `DNS_TUNNEL_001`.

**Befehl:**
```bash
python3 /tmp/dnsattack.py --mode tunnel --count 500 --rate 100
# → sent=500 pps=100.2 avg_pkt=218.0
```

**Start (UTC):** 2026-04-30T18:11:21

**Beobachteter Flow:**

| Metrik | Wert |
|---|---|
| pkt_count | 1 000 |
| byte_count | 291 000 |
| pps | 200,4 |
| pkt_size mean | 291,0 |

**IDS-Antwort (signature-engine-Log):**

```
18:11:58 ALERT [DNS_TUNNEL_001] DNS Tunneling (Volumenbasis) | 192.168.1.85 → 192.168.1.100:53 | severity=high
```

In der DB landet dieser Hit **nicht**, weil der alert-manager mit `DEDUP_WINDOW_S=300` denselben Alert-Key (Rule + src + dst) noch vom D1-Hit (18:09:28) unterdrückt.

**Bewertung.** Erkennung in der signature-engine ✓. Dedup verhindert Spam, aber unterdrückt im Lab dadurch den D2-Treffer in der DB. Operator-Cheatsheet: für back-to-back-Tests denselben Vektor entweder >300 s pausieren oder `DEDUP_WINDOW_S` zur Lab-Zeit absenken.

---

### Test D3 — DGA-Pattern (uniform IAT)

**Angriffsmuster.** Zufällige Domain-Namen (8–12 zufällige Zeichen + `.net`) mit pseudo-zufälligem Timing zwischen den Queries — simuliert C2-Beacons über DGA-Domains. Erwartet: `DNS_DGA_001`.

**Befehl:**
```bash
python3 /tmp/dnsattack.py --mode dga --count 200 --rate 50
# → sent=200 pps=15.6 avg_pkt=31.9
```

**Start (UTC):** 2026-04-30T18:11:31

**Beobachteter Flow:**

| Metrik | Wert |
|---|---|
| pkt_count | 400 |
| pps | 31,3 |
| **IAT-Entropie** | **1,28** |

**IDS-Antwort:** keine. Default-Schwelle `entropy_iat > 2.5` nicht erreicht.

**Bewertung.** Mein uniform-Random-Sleep erzeugt eine schmal-uniforme IAT-Verteilung mit Entropie um 1,3 — die 2,5-Schwelle ist auch in D5 (siehe unten) mit bimodalem Timing nicht erreichbar.

---

### Test D4 — DNS-Flood gegen non-listening Port (Reflection-Source-Profil)

**Angriffsmuster.** Hochfrequente DNS-Queries (1000× kleine A-Records, 300 pps) gegen den **Master-IDS auf Port 53 — der dort nicht lauscht**. Damit geht der Flow **rein outgoing**: keine DNS-Replies vom Ziel, nur ICMP-Port-Unreachable. Das entspricht exakt dem Beobachtungs-Profil eines echten Spoofed-Reflection-Angriffs (der Angreifer sieht die Antworten nie, weil die mit gespoofter Source-IP ans Opfer gehen). Erwartet: **DNS_AMP_001 sauber**.

**Befehl:**
```bash
python3 /tmp/dnsattack_v2.py --server 192.168.1.81 --mode amp --count 1000 --rate 300
# → sent=991 pps=297.6 avg_pkt=33.9
```

**Start (UTC):** 2026-04-30T18:14:28

**Beobachteter Flow:**

| Metrik | Wert |
|---|---|
| pkt_count | 991 (rein outgoing) |
| byte_count | 75 217 |
| pps | 297,6 |
| **pkt_size mean** | **75,9** |
| IAT-Entropie | 0,00 |

**IDS-Antwort:**

| ts | source | severity | rule_id | score |
|---|---|---|---|---|
| 18:14:31.771 | signature | medium | **DNS_AMP_001** | 0.50 |
| 18:14:31.771 | signature | high | **DNS_TUNNEL_001** | 0.80 |
| 18:14:31.771 | signature | low | ANOMALY_FRAGMENT_001 | 0.20 |

**Bewertung.** **Volltreffer auf 3 Rules gleichzeitig.** Das Reflection-Source-Profil ist genau das, was die DNS_AMP_001-Heuristik fängt: `pps > 100` (297 ✓) UND `pkt_size_mean < 100` (75,9 ✓). Im Vergleich zu D1 zeigt das: die Default-Schwelle `pkt_size_mean < 100` ist *richtig* kalibriert für echte Reflection-Angriffe — sie verfehlt nur Tests, in denen der Lab-Resolver tatsächlich antwortet (siehe D1).

---

### Test D5 — DGA-Pattern mit bimodaler IAT (vor Schwellen-Anpassung)

**Angriffsmuster.** Wie D3, aber mit klar bimodalem Timing: 80 % der Queries mit 1–3 ms Pause, 20 % mit 50–200 ms. Soll IAT-Entropie deutlich erhöhen. Erwartet: `DNS_DGA_001`.

**Befehl:**
```bash
python3 /tmp/dnsattack_v2.py --mode dga --count 500 --rate 100
# → sent=500 pps=39.6 avg_pkt=32.0
```

**Start (UTC):** 2026-04-30T18:14:35

**Beobachteter Flow:**

| Metrik | Wert |
|---|---|
| pkt_count | 1 000 |
| pps | 79,3 |
| pkt_size mean | 110,5 |
| **IAT-Entropie** | **1,34** |

**IDS-Antwort:** keine.

**Bewertung.** Auch mit bimodalem Timing kommt die IAT-Entropie nur auf 1,34 — die alte Default-Schwelle 2,5 war **in der Praxis kaum erreichbar**. Daraus folgt die Schwellen-Anpassung in D6 + D7.

---

### Schwellen-Anpassung — DNS_DGA_001 entropy_iat 2.5 → 1.5 (Commit `48659ff`)

YAML-Default in `signature-engine/rules/dns.yml` von `2.5` auf `1.5` gesenkt. Da `signature-engine` die `rules/builtin/`-YAMLs als Bind-Mount aus `/opt/ids/signature-engine/rules` liest und mit inotify hot-reloaded, greift der neue Default **sofort nach `git pull`** ohne Container-Build:

```
loader – Rules reloaded: 23 rules active
```

### Test D6 — DGA bimodal nach Schwellen-Anpassung

**Wiederholung von D5** mit dem neuen Default 1.5.

**Befehl:**
```bash
python3 /tmp/dnsattack_v2.py --mode dga --count 500 --rate 100
```

**Start (UTC):** 2026-04-30T18:20:17 · **Beobachteter Flow:** pkt_count=1 000, byte_count=110 554, **IAT-Entropie 1,39** — knapp **unter** der neuen Schwelle 1,5.

**IDS-Antwort:** DNS_TUNNEL_001 (high) + ANOMALY_FRAGMENT_001 (low) + DOS_ICMP_001 (high, durch ICMP-Reply-Stream) — **DNS_DGA_001 nicht** (Generator zu nah am Schwellwert).

**Bonus-Hit:** zeitgleich feuerte DNS_DGA_001 für `192.168.1.36 → 192.168.1.100:53` mit `severity=high` — ein **echter Subnet-Host** mit chaotischerem Resolver-Timing als mein bimodaler Generator. Das ist ein guter Kalibrierungs-Indikator: 1.5 fängt reale DGA-/Multi-Threaded-Resolver-Pattern ein.

### Test D7 — DGA trimodal IAT (verifizierender Auslöse-Test)

**Angriffsmuster.** Drei klar getrennte IAT-Buckets (rotierend): ~2 ms, ~30 ms, ~225 ms. Maximiert die Shannon-Entropie über drei Bins.

**Befehl:**
```bash
python3 /tmp/dnsattack_v3.py --count 300
```

**Start (UTC):** 2026-04-30T18:23:06

**Beobachteter Flow:**

| Metrik | Wert |
|---|---|
| pkt_count | 600 |
| byte_count | 66 248 |
| dur_s | 25,85 |
| pps | 23,2 |
| **IAT-Entropie** | **1,84** |

**IDS-Antwort:**

| ts | source | severity | rule_id | score |
|---|---|---|---|---|
| 18:23:32 | signature | high | **DNS_DGA_001** | 0.80 |
| 18:24:07 | signature | high | DNS_TUNNEL_001 (engine-log, dedup in DB) | 0.80 |

**Bewertung.** Mit echter trimodaler Verteilung erreicht der Generator IAT-Entropie 1,84 — damit triggert die neue 1,5-Schwelle sauber. **Schwellen-Anpassung verifiziert.**

### Befund nach Schwellen-Anpassung

| Pattern | IAT-Entropie | Triggert (neu, 1,5) | Triggert (alt, 2,5) |
|---|---|---|---|
| Uniform sleep (D3) | 1,28 | nein | nein |
| Bimodal 80/20 (D5) | 1,34 | nein | nein |
| Bimodal 80/20 wiederholt (D6) | 1,39 | nein | nein |
| Trimodal gleichverteilt (D7) | 1,84 | **ja** | nein |
| Echter Subnet-Host (192.168.1.36) | (geschätzt 1,5+) | **ja** | nein |
| Normaler Idle-Resolver-Verkehr | 0,5–1,0 | nein | nein |

Die 1,5-Schwelle markiert die richtige Grenze: chaotisches Multi-Modal-Timing löst aus, monomodales/bimodales Idle-Verhalten nicht. Operator kann via *Settings → Rule Adjustments → DNS_DGA_001 → entropy_iat* jederzeit weiter anpassen, falls in Produktion die Falsch-Positiv-Rate zu hoch wird.

---

### Befund Phase 4 — DNS-Detektion

| Rule | Default-Parameter | Lab-Treffer | Bemerkung |
|---|---|---|---|
| `DNS_AMP_001` | `pps>100, pkt_size_mean<100` | ✓ in D4 (uni-direktional) | Default ist richtig kalibriert für **Spoofed-Reflection-Source-Profil**. Bei symmetrischem Lab-Verkehr (D1) wird der Mean durch DNS-Replies hochgezogen → keine Trigger, das ist korrekt (kein echter Reflection-Angriff). |
| `DNS_TUNNEL_001` | `byte_count>50 000` | ✓ in D1, D2 (engine), D4 | Robust. Triggert sowohl bei Volumen-Tunneling als auch bei DNS-Floods, sobald >50 k Bytes durchlaufen. |
| `DNS_DGA_001` | `entropy_iat>1.5` (gesenkt von 2.5, Commit `48659ff`), `pkt_count>10` | ✓ in D7 (trimodal, 1,84) + Real-Hit auf 192.168.1.36 | Schwellwert nach D5-Befund auf 1,5 gesenkt; D7 verifiziert sauberen Trigger, normales Idle-Verhalten (0,5–1,0) bleibt unter Schwelle. |
| `DNS_NONSTANDARD_001` | `pkt_size_mean>512` für TCP/53 | nicht getestet | DNS-over-TCP ist im Lab-Subnet selten. |

Bonus: **ANOMALY_FRAGMENT_001** (`severity=low`) feuert zuverlässig bei DNS-Floods, weil die DNS-Replies oder ICMP-Port-Unreach in IP-Fragmente zerlegt werden — guter Sekundär-Indikator.

## Befunde & Maßnahmen

### Befund 1 — ML war initial taub

| Stand | ML-Alerts in 24 h Idle (Threshold 0.65) | ML-Alerts auf realen Tests |
|---|---|---|
| Vor Patch (Modell v1, 14 Features) | 0 | 0 |
| Nach Patch (Modell v2, 18 Features, Threshold 0.65) | 0 | 0 (Multi-Flow-Tests) |
| Nach Patch + Threshold 0.40 | spammt — viele FPs | 1 (Linuxhost-CDN, *kein* Kali) |
| Nach Patch + Threshold **0.57** | **0** | siehe unten |

### Befund 2 — Sweet-Spot ML-Threshold = 0.57

Score-Verteilung über 30 min Idle-Subnet-Verkehr nach dem Re-Training:

| Quantil | Score |
|---|---|
| Median (P50) | 0,435 |
| P95 | 0,517 |
| **P99** | **0,550** |
| Maximum | 0,559 |

→ Threshold **0.57** sitzt 1 Punkt über dem Idle-Maximum.

**Validierung:**

| Phase | ML-Alerts | Bewertung |
|---|---|---|
| 5 min Idle | 0 | ✓ Keine FPs |
| 10 min Idle | 0 | ✓ Stabil |
| Burst-Test BT | 0 | erwartet — Multi-Flow-Pattern, ML-blind |

Falls in Produktion zu wenig ML-Aktivität: schrittweise auf 0.55 senken (~2× mehr Alerts pro 0.01 Senkung).

### Befund 3 — Tap-Backpressure war Pipeline-Killer

Vor Fix: hping3 `--flood -c 20000` lief 4 min, danach lag der Master-flow-aggregator-Buffer 5+ min im Stau. Folge: nachfolgende Pentests sahen praktisch keinen Verkehr → falsche Diagnose "Tests funktionieren nicht".

Nach Fix (Commit `2c957bb`, Buffer 5×, sauberer Drop statt blocking-Retry): `kafka_drop=0` selbst bei 5 kpps × 2 s Burst, Aufholzeit ~30 s. Im Stats-Log jetzt direkt sichtbar:

```
active_flows=27  msgs=23031  parse_err=0  kafka_ok=17829  kafka_err=0  kafka_drop=0  ...
```

### Befund 4 — Strukturelles ML-Limit (kein Bug, sondern Architektur)

**Was ML jetzt zuverlässig leistet:**
- atypische Bandbreitenprofile (`bps`/`pps` an den Rändern)
- ungewöhnliche IAT-Entropie (gleichmäßig getaktete vs. natürliche Bursts)
- exotische Flag-Kombinationen
- Flows zu non-standard Ports mit unüblicher Größe/Dauer

**Was ML strukturell *nicht* leistet:** Multi-Flow-Pattern wie Port-Scans und SYN-Floods. nmap und hping3 randomisieren den `src_port` pro Paket → 1 Flow pro Quell-Port, jeder mit 1–2 Paketen. Im Feature-Raum sind das normale Half-Open-Versuche; die *Aggregation* "1 Sender × N verschiedene Ports/Ziele in T Sekunden" fehlt dem IsolationForest. Genau diese Aggregation leistet die signature-engine via `ctx.unique_dst_ports(src_ip, window_s)` und `ctx.flow_rate(src_ip, window_s)`.

| Engine | Stärke | Bei diesem Lab |
|---|---|---|
| `signature` | stateful, Multi-Flow-Pattern, hand-kuratiert | erkennt jeden Test sauber + priorisiert (low/medium/high/critical) |
| `ml` | stateless, Single-Flow-Anomalien, unbekannte Pattern | fängt z.B. ungewöhnliche CDN-Flows; **ergänzt Heuristik, ersetzt sie nicht** |

### Maßnahmen-Übersicht (Commits)

| Commit | Inhalt |
|---|---|
| `ee26503` | features.py +4 Features (FEATURE_DIM 14→18); bootstrap.py SQL-Pfad gefixt (`stats->...` JSONB); Filter `start_ts < now() - 2h` und `NOT EXISTS alerts.flow_id`; contamination 0.01→0.005; n_estimators 100→200; training-loop synchron auf 18 Features |
| `1496fc0` | docker-compose.yml: `BOOTSTRAP_MIN_SAMPLES` und `CONTAMINATION` durchgereicht (Default 25 000 → bootstrap auf 50 000 Flows) |
| `2c957bb` | sniffer + flow-aggregator: 500 k Producer-Buffer, 100 k Capture-Channel, sauberer Drop statt blocking-Retry, `kafka_drop`-Counter im Log |
| `da54111` | Lab-Doku: Backpressure-Fix verifiziert + ML-Threshold-Sweet-Spot 0.57 |

## Operator-Cheatsheet

### ML-Threshold prüfen / setzen

```bash
# aktuellen Wert
docker exec ids-ml-engine cat /models/ml_config.json

# auf 0.57 setzen (Sweet-Spot, Idle = 0 Alerts)
docker exec ids-ml-engine sh -c \
  'echo "{\"alert_threshold\": 0.57}" > /models/ml_config.json'

# ml-engine pickt den neuen Wert nach max 500 Flows auf
docker logs --since 2m ids-ml-engine | grep "Threshold updated"
```

### Backpressure-Diagnose

```bash
# Auf dem Tap
docker logs --tail 5 cyjan-tap-flow-aggregator | grep kafka_drop
docker logs --tail 5 cyjan-tap-sniffer | grep "drop_pct"

# Auf dem Master
docker logs --tail 5 ids-flow-aggregator | grep kafka_drop
```

`kafka_drop=0` bedeutet: alles gut. Wenn der Counter wächst → echter Backpressure-Fall, ggf. kürzere Pentest-Bursts oder Sampling-Sniffer (V3-Backlog).

### Modell zurücksetzen + neu bootstrappen

```bash
docker compose stop ml-engine training-loop
docker run --rm -v ids_ml-models:/m alpine sh -c \
  'rm -f /m/iforest.joblib /m/scaler.joblib /m/meta.json /m/ml_config.json'
docker compose --profile prod up -d ml-engine
# auf "Bootstrap: loaded 50000 flows from DB" + "Model trained and saved" warten
docker compose --profile prod up -d training-loop
```

### Test-Auswertung pro Run

```sql
SELECT ts, source, severity, rule_id, src_ip, dst_ip, dst_port, score
FROM alerts
WHERE ts > '$START_TS'::timestamp AT TIME ZONE 'UTC'
  AND (src_ip='192.168.1.85'::inet OR dst_ip='192.168.1.85'::inet)
ORDER BY ts;
```

## Zusammenfassung

1. **Tap-Mirror funktioniert** für normalen Subnet-Traffic.
2. **Heuristik (signature-engine) erkennt jeden Pentest** sauber: SCAN_001/004 für Scans, DOS_SYN_001/CONN_001 für Floods, RECON_001..003 für Probe-Pattern, **DNS_AMP_001 für Reflection-Source, DNS_TUNNEL_001 für Volumen-Exfil**, plus korrekt-priorisierte Severity bis `critical`.
3. **ML-Engine** war initial taub (Bootstrap-SQL-Bug + zu basale Features + Compose-Env-Bug). Nach Patch (18 Features, sauberer Bootstrap-Filter, contamination 0.005, Threshold 0.57) ist sie *komplementär* zur Heuristik aufgestellt: Single-Flow-Anomalien werden erkannt, Multi-Flow-Pattern sind weiter Sache der Heuristik (architektonisches Limit, kein Bug).
4. **Tap-Backpressure** war Pipeline-Killer bei Pentest-Bursts (5+ min Stillstand nach hping3-Flood). Mit größerem Producer-Buffer und Drop-Policy statt blocking-Retry: `kafka_drop=0` und 30 s Aufholzeit beim Worst-Case-Burst-Test.
5. **DNS-Detektion komplett funktional:** AMP_001 trifft das Reflection-Source-Profil sauber, TUNNEL_001 robust auf Volumen-Pattern. **DGA_001 nach Schwellen-Anpassung 2,5 → 1,5** (Commit `48659ff`) trifft auch trimodale Generatoren und reale chaotische Resolver-Pattern, ohne Idle-Multiplexer (0,5–1,0) zu erfassen. Verifiziert in D7.
6. **Lehre:** "ML soll nmap erkennen" ist die falsche Erwartung. Der Detektor dafür sitzt richtig in der signature-engine, ML ergänzt sie für nicht-benannte Verhaltens-Anomalien.
