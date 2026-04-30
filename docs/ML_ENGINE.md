# ML-Engine — Dokumentation

> Cyjan IDS hat **drei** lernende Komponenten, die unterschiedliche Aspekte
> der Erkennung adressieren und sich gegenseitig ergänzen:
>
> 1. **ML-Engine (IsolationForest)** — anomaliebasierte Detektion auf Flow-Features.
> 2. **Rule-Tuner (Reservoir + Quantile)** — passt Schwellwerte tunbarer
>    Heuristiken an die Verteilung im konkreten Netzwerk an.
> 3. **Adaptive Suppression** — drosselt FP-Pattern, die nicht über
>    Schwellwert-Tuning erreicht werden können (z.B. Suricata-SIDs,
>    pattern-only Heuristiken).

## Inhalt

- [0. Überblick: Drei Lern-Komponenten und ihr Zusammenspiel](#0-überblick-drei-lern-komponenten-und-ihr-zusammenspiel)
- [1. Architektur-Überblick (ML-Engine)](#1-architektur-überblick)
- [2. Flow-Feature-Extraktion](#2-flow-feature-extraktion)
- [3. Anomalie-Modell (IsolationForest)](#3-anomalie-modell-isolationforest)
- [4. Lifecycle: Bootstrap → Inference → Retrain](#4-lifecycle-bootstrap--inference--retrain)
- [5. Score-zu-Severity-Mapping](#5-score-zu-severity-mapping)
- [6. Feedback-Loop (FP/TP → Training)](#6-feedback-loop-fptp--training)
- [7. Adaptive Suppression (Layer 1 + Layer 2)](#7-adaptive-suppression-layer-1--layer-2)
- [8. Konfiguration (ENV + Runtime-Config)](#8-konfiguration-env--runtime-config)
- [9. Betrieb & Debugging](#9-betrieb--debugging)
- [10. Rule-Tuner: ML-Threshold-Anpassung für Heuristiken](#10-rule-tuner-ml-threshold-anpassung-für-heuristiken)
- [11. Zusammenspiel rule-tuner ↔ Suppression](#11-zusammenspiel-rule-tuner--suppression)

---

## 0. Überblick: Drei Lern-Komponenten und ihr Zusammenspiel

Cyjan IDS lernt an drei Stellen **gleichzeitig**, ohne dass die Modelle
sich gegenseitig stören. Jede Komponente hat ein klar abgegrenztes
Wirkungsfeld:

| Komponente       | Was es lernt                                          | Worauf es wirkt                                                   |
|------------------|-------------------------------------------------------|-------------------------------------------------------------------|
| **ML-Engine**    | Was sieht "normaler" Flow im Feature-Raum aus?        | Erzeugt **neue** Alerts (`source=ml`) bei Anomalien.              |
| **rule-tuner**   | Welche Werte sehen tunbare Heuristik-Metriken (P99,5)?| Passt **bestehende Heuristik-Schwellwerte** an (z.B. SCAN_001 port_count). |
| **Suppression**  | Welche Alert-Pattern flooded gerade ohne TP-Tag?      | Drosselt **bestehende Alerts** zu `severity=low` — pro IP-Paar.   |

Die drei greifen **nicht** auf dieselben Hebel:

```
                ┌─────────────────────────────────────────────────┐
                │  Flow-Aggregator                                 │
                └──────────────┬──────────────────────────────────┘
                               │ flows
                ┌──────────────▼──────────────┐  ┌─────────────────┐
                │  signature-engine            │  │  ML-Engine       │
                │  (Heuristik-Rules + YAML)   │  │  (IsolationFor.) │
                └──────┬──────────────────────┘  └────────┬────────┘
   metric-Sample (1%)  │ alerts-raw                       │ alerts-raw
   ┌──── rule-metrics ─┘ + tunable=bool                   │ source=ml
   │
   ▼                              ┌────────────────────────┴────────────┐
┌──────────┐                      │           Alert-Manager              │
│rule-tuner│                      │           ┌──────────────────────┐   │
│(Reservoir│                      │           │   Suppression        │   │
│ +Quantile│  PUT /api/sig-rules/ │           │   (skip wenn ml      │   │
│ +Bounds) │ ──overrides──────────┼──── auto-fp-────source=external,│   │
└────┬─────┘                      │  feedback   tunable=true)        │   │
     │                            │           │                      │   │
     │ liest alerts.feedback,     │           │ tag 'auto-fp-pattern'│   │
     │ inkl. auto-suppression     │           │ → severity=low       │   │
     │                            │           └──────────────────────┘   │
     ▼                            └─────────────────┬────────────────────┘
  /sig-rules/_overrides.json                        │
  (Threshold pro Param,                             ▼
   scope-aware extern/intern,                  TimescaleDB alerts
   Provenance ml/manual)                       Frontend AlertFeed
```

**Wer macht was bei welchem Alert?**

- **`source=ml`** (vom IsolationForest): Suppression skip, rule-tuner irrelevant. Nur ML-Engine retrain via `feedback`-Topic.
- **`source=signature`, Heuristik mit `metric:`** (z.B. SCAN_001): rule-tuner aktiv, Suppression skip. Auto-FP-Feedback wird in `alerts.feedback` geschrieben, damit der Tuner es als FP-Bound aufnimmt. Loop-Schließung.
- **`source=signature`, Heuristik ohne `metric:`** (z.B. SCAN_005 Xmas, ANOMALY_FRAGMENT_001): rule-tuner irrelevant (nicht tunbar), Suppression aktiv.
- **`source=signature`, `rule_id` startet mit `SURICATA:`**: rule-tuner irrelevant (Pattern-Rule), Suppression aktiv. Statisches `_suricata_overrides.json` ist die manuelle Severity/Disable-Schiene.
- **`source=external`** (IRMA/ASSET::*): externe Aussagen, keine Detection-Noise. Suppression skip, rule-tuner irrelevant.

**Konsequenz** für jeden, der Alerts triagt:
- Eine `SCAN_001`-Flood bekommt der rule-tuner durch Threshold-Hochsetzen unter Kontrolle. Severity bleibt erhalten — **echte Treffer mit hohem unique_dst_ports kommen weiter als `high` durch**, niedrige Werte feuern gar nicht erst.
- Eine `ANOMALY_FRAGMENT_001`-Flood greift Suppression als `severity=low` ab. Der Spike-Durchbruch (Z-Score ≥ 2.0) bringt echte Anomalien zurück.
- Eine `SURICATA:1:9000001:1`-Flood: gleiches Spiel wie ANOMALY — Suppression macht's leise, statisch könnte man die SID auch im UI auf `severity=low` schieben.

---

## 1. Architektur-Überblick

Die ML-Engine besteht aus **drei kooperierenden Services**:

```
┌────────────────────┐   flows    ┌───────────────┐   alerts-raw    ┌──────────────┐
│  Flow-Aggregator   │ ─────────► │  ML-Engine    │ ──────────────► │ Alert-Manager│
│  (Python)          │            │  (Python)     │                 │              │
└────────────────────┘            └───────┬───────┘                 └──────┬───────┘
                                          │                                │
                                          │ scoring (Online)               │ Suppression
                                          │                                │ (Layer 1+2)
                                          ▼                                ▼
                                  ┌────────────────┐               ┌──────────────┐
                                  │  /models       │               │  TimescaleDB │
                                  │ scaler.joblib  │◄──────────────│  alerts      │
                                  │ iforest.joblib │  Retrain      │  flows       │
                                  │ meta.json      │  (24h)        │  training_   │
                                  └────────────────┘               │  samples     │
                                          ▲                        └──────────────┘
                                          │
                                  ┌───────┴────────┐
                                  │ Training-Loop  │
                                  │ (Python)       │
                                  └────────────────┘
```

### Service-Verantwortlichkeiten

| Service          | Rolle                                                                                       |
|------------------|---------------------------------------------------------------------------------------------|
| **ml-engine**    | Live-Inference: scored jeden Flow mit dem gespeicherten Modell, pflegt Scaler inkrementell. |
| **training-loop**| Semi-supervised Retrain alle 24h: erstellt neues Modell aus DB-Flows + Feedback-Samples.    |
| **alert-manager**| Schreibt Alerts in DB, applied [adaptive Suppression](#7-adaptive-suppression-layer-1--layer-2). |

Alle drei teilen sich das gleiche Docker-Volume `ml-models:/models`, in dem
`scaler.joblib`, `iforest.joblib` und `meta.json` liegen. Atomarer Modell-Swap
(tmp-Datei + rename) erlaubt Retrain ohne Service-Neustart.

---

## 2. Flow-Feature-Extraktion

Jeder Flow wird zu einem **14-dimensionalen Feature-Vektor** (`float32`):

| #  | Feature          | Beschreibung                                      | Beispiel (normaler DNS-Flow) |
|----|------------------|---------------------------------------------------|------------------------------|
| 0  | `duration_s`     | Flow-Dauer in Sekunden                            | 0.04                         |
| 1  | `pkt_count`      | Anzahl Pakete                                     | 2                            |
| 2  | `byte_count`     | Anzahl Bytes gesamt                               | 180                          |
| 3  | `pps`            | Pakete pro Sekunde                                | 50                           |
| 4  | `bps`            | Bytes pro Sekunde                                 | 4500                         |
| 5  | `pkt_size_mean`  | Mittlere Paketgröße                               | 90                           |
| 6  | `pkt_size_std`   | Standardabweichung Paketgröße                     | 5                            |
| 7  | `iat_mean`       | Mittlere Inter-Arrival-Time (IAT)                 | 0.02                         |
| 8  | `iat_std`        | Standardabweichung IAT                            | 0.001                        |
| 9  | `entropy_iat`    | Shannon-Entropie der IAT-Verteilung               | 2.1                          |
| 10 | `syn_ratio`      | Anteil SYN-Flags an TCP-Paketen                   | 0.0 (UDP)                    |
| 11 | `rst_ratio`      | Anteil RST-Flags                                  | 0.0                          |
| 12 | `fin_ratio`      | Anteil FIN-Flags                                  | 0.0                          |
| 13 | `dst_port_norm`  | `dst_port / 65535` (0 wenn kein Port)             | 0.00081 (=53)                |

**Design-Entscheidungen:**
- Die **Welford-basierten Statistiken** (mean/std) werden bereits im
  Flow-Aggregator online berechnet — das hält die ML-Engine state-los
  bezüglich historischer Daten.
- **Shannon-Entropie der IAT** ist der aussagekräftigste Einzelwert
  für C2-Beaconing und Tunneling (regelmäßige Paket-Abstände = niedrige
  Entropie = verdächtig).
- **Keine Payload-Features**: das gesamte IDS arbeitet header-only
  (128-Byte-Snaplen), kompatibel mit SSL-verschlüsseltem Traffic.
- `NaN`/`Inf` werden defensiv durch 0 ersetzt.

**Quelle**: [`ml-engine/src/features.py`](../ml-engine/src/features.py)

---

## 3. Anomalie-Modell (IsolationForest)

**Algorithmus:** `sklearn.ensemble.IsolationForest` mit StandardScaler-Vorverarbeitung.

### Warum IsolationForest?

- **Kein Labeling nötig** für den Normalbetrieb → passt zum
  unsupervised Charakter eines IDS.
- **Schnelle Inference** (~0.5 ms pro Flow auf üblicher Hardware).
- **Robust gegenüber hochdimensionalen Daten** und dominanten Dimensionen.
- **Semi-supervised erweiterbar**: wenn FP/TP-Labels verfügbar sind, kann
  der Training-Loop sie als Outlier-Samples einspeisen (s. Abschnitt 6).

### Modell-Parameter

| Parameter        | Wert                      | Bemerkung                                   |
|------------------|---------------------------|---------------------------------------------|
| `n_estimators`   | 100                       | Anzahl Trees                                |
| `contamination`  | 0.01 (default, konfig.)   | Erwarteter Anomalie-Anteil (siehe §8)       |
| `random_state`   | 42                        | Reproduzierbarkeit                          |
| `n_jobs`         | -1                        | Alle CPU-Kerne                              |

### Score-Berechnung

```
raw = iforest.decision_function(X_scaled)[0]   # positiv=normal, negativ=anomal
score = clip(0.5 - raw, 0.0, 1.0)              # auf [0, 1] normiert
```

- `score ≈ 0.0` → hochwahrscheinlich normal
- `score ≈ 1.0` → stark anomal
- `score = -1.0` → Modell noch nicht trainiert (passthrough)

**Quelle**: [`ml-engine/src/model.py`](../ml-engine/src/model.py)

---

## 4. Lifecycle: Bootstrap → Inference → Retrain

### 4.1 Bootstrap (Cold-Start)

Beim ersten Start:

1. ML-Engine sucht `scaler.joblib` + `iforest.joblib` im `/models`-Volume.
2. Fehlen diese, wird ein Bootstrap aus der DB angestoßen:
   - `SELECT * FROM flows ORDER BY end_ts DESC LIMIT ML_BOOTSTRAP_MIN × 2`
   - Minimum `ML_BOOTSTRAP_MIN` Flows (default: **500**) nötig.
   - Weniger als das → **Passthrough-Mode** (alle Flows durchlassen, bis
     genug Daten gesammelt sind).
3. Modell wird trainiert und persistiert.

### 4.2 Inference (Live-Loop)

```
for each flow ∈ Kafka-Topic "flows":
    score = model.score(flow)
    if score ≥ ALERT_THRESHOLD:         # default 0.65
        publish alert to "alerts-raw"
    model.add_to_buffer(flow)            # für inkrementellen Scaler-Fit
    if buffer_size ≥ PARTIAL_FIT_INTERVAL:
        model.partial_fit_scaler()       # StandardScaler inkrementell anpassen
```

- **PARTIAL_FIT_INTERVAL** (default: 200): Scaler wird alle N Flows an
  neue Verteilungen angepasst → Drift-Toleranz ohne Full-Retrain.
- **IsolationForest selbst** wird NICHT per `partial_fit` angepasst
  (unterstützt sklearn nicht) — dafür ist der Training-Loop da.

### 4.3 Retrain (24h-Zyklus)

Der **training-loop-Service** läuft unabhängig und triggert alle
`RETRAIN_INTERVAL_S` (default: **86400s = 24h**):

1. Lade Flows aus DB: `SELECT FROM flows WHERE end_ts > NOW() - 7 days LIMIT 100000`
2. Lade Labels aus `training_samples`:
   - `label = 'normal'` → als inlier hinzufügen
   - `label = 'attack'` → als outlier, contamination anpassen
3. Full-Training neuer IsolationForest.
4. **Atomarer Swap**: `scaler.tmp.joblib` → `scaler.joblib` per rename.
5. ML-Engine lädt das neue Modell beim nächsten Restart oder via
   `/api/ml/retrain` manuell.

**Trigger-Möglichkeiten:**
- Automatisch alle 24h
- `POST /api/ml/retrain` (UI-Button "Modell jetzt neu trainieren")
- `contamination`-Änderung via UI triggert sofort einen Retrain

**Quelle**: [`training-loop/src/trainer.py`](../training-loop/src/trainer.py)

---

## 5. Score-zu-Severity-Mapping

| Score-Range     | Severity   | Default-Behandlung         |
|-----------------|------------|----------------------------|
| `≥ 0.90`        | `critical` | Alert, volle Sichtbarkeit  |
| `0.80 – 0.89`   | `high`     | Alert                      |
| `0.70 – 0.79`   | `medium`   | Alert                      |
| `0.65 – 0.69`   | `low`      | Alert                      |
| `< 0.65`        | —          | Kein Alert (unter Schwelle)|

Der Schwellwert `ALERT_THRESHOLD` ist **runtime-konfigurierbar**:
- UI-Slider in *Einstellungen → KI/ML-Engine → Filter-Konfiguration*
- Schreibt `/models/ml_config.json` — wird vom ml-engine alle 500 Flows
  neu eingelesen (kein Restart nötig).

---

## 6. Feedback-Loop (FP/TP → Training)

### User-Interaktion

In der Alert-Detail-Ansicht kann der Analyst zwei Labels vergeben:

| Button             | Semantik                                                                                      |
|--------------------|-----------------------------------------------------------------------------------------------|
| **✓ False Positive** | "Dieser Alert ist kein Angriff." Severity wird auf `low` gesetzt, Tag `auto-suppressed`.      |
| **⚠ True Positive**  | "Dieser Alert ist ein bestätigter Angriff." Entfernt das Muster aus der Lernliste (s. §7).   |

### Daten-Fluss

```
UI PATCH /api/alerts/{id}/feedback
   ↓
API updated alerts-Tabelle: feedback='fp', severity='low'
   ↓
API produziert auf Kafka-Topic "feedback"
   ↓
   ├─→ training-loop konsumiert (für nächstes Retrain)
   │    ├─ 'fp' → training_samples INSERT (label='normal')
   │    └─ 'tp' → training_samples INSERT (label='attack')
   │
   └─→ alert-manager konsumiert
        └─ SuppressionCache.refresh() wird SOFORT getriggert
           (sonst erst nach 60s periodisch)
```

### Training-Sample-Tabelle

```sql
CREATE TABLE training_samples (
  sample_id   UUID PRIMARY KEY,
  alert_id    UUID REFERENCES alerts(alert_id),
  flow_id     TEXT,
  features    JSONB,              -- Feature-Vektor aus flows
  label       TEXT,               -- 'normal' | 'attack'
  source      TEXT,               -- 'feedback' | 'manual'
  created_at  TIMESTAMPTZ
);
```

Der Training-Loop zieht diese Tabelle beim nächsten Retrain, gewichtet
attack-Samples als Outlier und passt die `contamination`-Rate automatisch an.

---

## 7. Adaptive Suppression (Layer 1 + Layer 2)

Die Suppression-Schicht im **alert-manager** entscheidet bei jedem neuen
Alert, ob er auf Severity `low` herabgestuft wird. **Sie ist die Brücke
zwischen ML-Engine und Signatur-Engine** — sie unterdrückt wiederkehrende
Fehlalarme beider Quellen ohne dass die Rules selbst angepasst werden müssen.

### Layer 1 — Manual FP (Tag: `auto-suppressed`)

**Trigger:** User markiert einen Alert als False Positive.

**SQL:**
```sql
SELECT DISTINCT
    rule_id,
    host(LEAST(src_ip, dst_ip))    AS ip_a,
    host(GREATEST(src_ip, dst_ip)) AS ip_b
FROM alerts
WHERE feedback = 'fp'
```

**Matching:**
- `(rule_id, ip_pair)` — bidirektional sortiert, damit Request und Response
  als dieselbe Session behandelt werden.
- `host(inet)` statt `::text` (ohne `/32`-Suffix), damit DB-Keys mit den
  Kafka-Alert-IPs matchen.

**Effekt:** Suppression bleibt bis zum TP-Override aktiv — **aber** bei
Baseline-Spike (z ≥ Z_THRESHOLD) wird sie automatisch aufgehoben. Eine
früher als FP markierte Verbindung kann später zum Angriffspfad werden
(C2, Exfil) — ein plötzlicher Anstieg muss der Analyst dann sehen.

### Layer 2 — ML-Adaptive (Tag: `ml-suppressed`)

**Kernidee:** Pro `(rule_id, ip_pair)` wird aus den letzten **14 Tagen**
(konfigurierbar) eine stündliche Baseline gelernt. Suppression greift nur,
wenn die **aktuelle Stunde statistisch unauffällig** ist.

**SQL-Kernquery** (vereinfacht):

```sql
WITH hourly AS (
  SELECT rule_id, ip_pair, date_trunc('hour', ts) AS hb, COUNT(*) AS cnt
  FROM alerts
  WHERE ts > NOW() - 14 days AND ts < date_trunc('hour', NOW())
  GROUP BY 1,2,3
),
baseline AS (
  SELECT rule_id, ip_pair,
         AVG(cnt)    AS mean_h,
         STDDEV(cnt) AS std_h,
         COUNT(*)    AS hours
  FROM hourly
  GROUP BY 1,2
  HAVING COUNT(*) >= 24    -- min. 24 Stunden Baseline nötig
),
recent AS (
  SELECT rule_id, ip_pair, COUNT(*) AS cnt_1h
  FROM alerts
  WHERE ts > NOW() - 1 hour
  GROUP BY 1,2
)
SELECT baseline.*, recent.cnt_1h,
       (cnt_1h - mean_h) / NULLIF(std_h, 0) AS z_score
FROM baseline LEFT JOIN recent USING(rule_id, ip_pair)
WHERE no TP feedback AND not in manual_fp
```

**Suppression-Entscheidung:**

```python
if z_score < Z_THRESHOLD:     # default 2.0
    return "learned"           # → Severity auf 'low', Tag 'ml-suppressed'
else:                          # Spike!
    return None                # → Alert kommt mit Original-Severity durch
```

### Zweistufiger Schutz

| Schutzmaßnahme        | Wirkung                                                                           |
|-----------------------|-----------------------------------------------------------------------------------|
| **TP-Feedback**       | Entfernt Muster beim nächsten Cache-Refresh komplett aus der Lernliste.          |
| **Spike-Durchbruch**  | z ≥ 2 → Alert kommt durch. **Gilt für beide Layer**: auch manuelle FPs werden bei plötzlichem Anstieg wieder sichtbar.|
| **Manual FP Priorität**| Wenn kein Spike: Layer 1 dominiert Layer 2. Ein FP-Markierung bleibt im ruhigen Betrieb wirksam.|

### Classify-Logik (im Code)

```python
def classify(rule_id, src_ip, dst_ip):
    key = session_key(rule_id, src_ip, dst_ip)
    stat = self._stats.get(key)   # Baseline für ALLE Muster

    # 1. Spike-Durchbruch – gilt für Layer 1 UND Layer 2
    if stat and stat.z_score >= Z_THRESHOLD:
        return None                # Alert durchlassen

    # 2. Manual FP
    if key in self._manual:
        return "manual"             # Tag auto-suppressed

    # 3. ML-Learned
    if stat:                       # z < threshold bereits geprüft
        return "learned"            # Tag ml-suppressed

    return None
```

### Gilt für **alle Severities**

Seit der letzten Version (`v1.0.17`+) ist der ursprüngliche Guardrail
`severity NOT IN ('critical','high')` **aufgehoben**. Rationale:

- Ein kritischer Alert der 100×/h konstant auftritt ohne TP-Feedback ist
  höchstwahrscheinlich **kein** Angriff, sondern eine Fehlkalibrierung
  der Signatur-Regel oder legitimer Verkehr.
- Die zwei Schutzmaßnahmen oben verhindern, dass ein echter Angriff
  silently weggefiltert wird.

**Quelle**: [`alert-manager/src/suppression.py`](../alert-manager/src/suppression.py)

---

## 8. Konfiguration (ENV + Runtime-Config)

### ENV-Variablen

| Variable                          | Service       | Default | Wirkung                                               |
|-----------------------------------|---------------|---------|-------------------------------------------------------|
| `ML_BOOTSTRAP_MIN`                | ml-engine     | 500     | Minimum Flows für initiales Training                  |
| `CONTAMINATION`                   | ml-engine     | 0.01    | Erwarteter Anomalie-Anteil im Trainingsset            |
| `PARTIAL_FIT_INTERVAL`            | ml-engine     | 200     | Scaler-Update alle N Flows                            |
| `RETRAIN_INTERVAL_S`              | training-loop | 86400   | Full-Retrain-Zyklus (24h)                             |
| `SUPPRESSION_LEARN_WINDOW_D`      | alert-manager | 14      | Baseline-Lookback-Fenster (Tage)                      |
| `SUPPRESSION_MIN_HOURS`           | alert-manager | 24      | Min. Stunden mit Daten, bevor ein Muster gelernt ist  |
| `SUPPRESSION_Z_THRESHOLD`         | alert-manager | 2.0     | Spike-Detection-Schwelle                              |

### Runtime-Config (kein Neustart nötig)

Die Datei `/models/ml_config.json` wird vom ml-engine alle 500 Flows
(ca. alle 10-60 Sekunden) neu eingelesen:

```json
{
  "alert_threshold":        0.65,   // Score-Schwelle für Alerts
  "contamination":          0.01,   // triggert sofortigen Retrain
  "bootstrap_min_samples":  500,
  "partial_fit_interval":   200
}
```

**UI**: *Einstellungen → KI/ML-Engine → Filter-Konfiguration* mit Slidern
und Presets (OT/SCADA, IT-Netz).

---

## 9. Betrieb & Debugging

### Wichtige Log-Meldungen

**ml-engine:**
```
ML engine ready | model_ready=True | threshold=0.65
Training on 1234 flows …
Model loaded from /models (n_samples=12345)
Scaler partial_fit: n_samples now 12545
[a1b2c3d4] ML_ANOMALY | 10.0.0.5 → 10.0.0.10 | severity=medium score=0.74
```

**alert-manager:**
```
Suppression cache: 12 manuell (fp) + 34 ML-gelernt
                    [28 aktiv suppressed, 6 spike-through]
                    (window=14d min_hours=24 z=2.0)
Feedback-Event empfangen (alert=1a2b3c4d, fb=fp) → force refresh
Suppression (manual): DNS_AMP_001 192.168.1.230 → 192.168.1.1 → low
```

**training-loop:**
```
Retraining: 45000 normal + 127 attack samples | contamination=0.028
Model saved to /models (n=45127)
Retrain complete (took 8.3s, next in 23h59m)
```

### Metriken-Endpoints

| Endpoint                            | Liefert                                                  |
|-------------------------------------|----------------------------------------------------------|
| `GET /api/ml/status`                | Phase, Modell-Meta, letzter Retrain, Trainings-Samples   |
| `GET /api/ml/config`                | Aktuelle Runtime-Config                                  |
| `GET /api/ml/learned-patterns`      | Baseline-Liste pro Muster mit z-Score und Status         |
| `POST /api/ml/retrain`              | Triggert Sofort-Retrain                                  |
| `PATCH /api/ml/config`              | Setzt Runtime-Config                                     |

### Phase-Indicator im UI

Sichtbar unter *Einstellungen → KI/ML-Engine → Status*:

| Phase          | Bedeutung                                                                 |
|----------------|---------------------------------------------------------------------------|
| `passthrough`  | Zu wenige Flows für Bootstrap → alle Flows passieren ohne Scoring.        |
| `learning`     | Modell trainiert, Scaler wird kontinuierlich angepasst — aktiv aber nicht vollständig kalibriert. |
| `active`       | Vollständig trainiert, stabil.                                            |

### Typische Troubleshooting-Pfade

**"ML-Engine erzeugt keine Alerts":**
- `ML Status` checken: Phase `passthrough`? → mehr Flows sammeln.
- `ALERT_THRESHOLD` zu hoch? Default 0.65 ist konservativ, für sensitive
  Netze auf 0.55 senken.

**"Zu viele ML-Alerts (Flood)":**
- `contamination` zu niedrig → Modell markiert zu viel als anomal.
- OT-Preset (contamination=0.005) verwenden.

**"FP-Markierung greift nicht für nachfolgende Alerts":**
- Log-Check: `Suppression (manual): ... → low` sollte erscheinen.
- `/api/ml/learned-patterns` aufrufen: taucht das Muster auf?
- `suppression cache` im Log: `N manuell (fp)` > 0?

**"Kritischer Alert wird nicht gelernt obwohl häufig":**
- Bis `v1.0.16` war das Absicht (safety guardrail) — seit `v1.0.17`
  gilt die Suppression für alle Severities.
- Mindestens 24h Baseline nötig — erst dann erscheint das Muster in
  `learned-patterns`.

### Modell-Dateien inspizieren

```bash
docker compose exec ml-engine python -c "
import joblib
m = joblib.load('/models/iforest.joblib')
print(f'n_estimators={m.n_estimators} contamination={m.contamination_}')
"
```

---

## 10. Rule-Tuner: ML-Threshold-Anpassung für Heuristiken

### 10.1 Was er macht — und was nicht

Der `rule-tuner`-Service (Master-only, Compose-Profil `prod`) lernt die
Verteilung der Metrik-Werte hinter jeder **tunbaren** Heuristik-Rule und
setzt deren Schwellwerte automatisch so, dass sie zur konkreten Verteilung
des Netzes passen. Im Gegensatz zur ML-Engine erzeugt er **keine neuen
Alerts** — er passt nur Schwellwerte bestehender Rules an.

Eine Heuristik ist tunbar, wenn ihr YAML-File mindestens einen Parameter
mit `metric:`-Deklaration hat. Beispiel `SCAN_001`:

```yaml
parameters:
  port_count:
    type: int
    default: 50
    min: 5
    max: 65535
    metric: unique_dst_ports   # ← markiert als rule-tuner-verwaltet
  window_s:
    type: int
    default: 60
    # kein metric: → manuell-only
eligibility: |
  flow.get('proto') == 'TCP' and flow.get('tcp_flags_abs', {}).get('SYN', 0) > 0
```

Pattern-only Heuristiken ohne `parameters:`-Block (SCAN_005 Xmas, SCAN_006 NULL,
ANOMALY_FRAGMENT_001) sind **nicht tunbar** — dort hilft nur Suppression
oder manuelles `severity`-Override.

### 10.2 Daten-Pipeline

```
signature-engine                      rule-tuner
─────────────────                     ─────────────
für jeden Flow                        Kafka-Consumer
  └─ eligibility-Filter                  └─ rule-metrics
      (z.B. nur TCP+SYN für SCAN_001)        ├─ Reservoir-Sampling pro
  └─ compute_metrics()                       │     (rule, param, scope)
      └─ 1% Bernoulli-Sample                 │     [Algorithm R, 10k cap]
          → Kafka rule-metrics               │
                                             ├─ alle 60s: persist Quantile
                                             │     (P50/P99/P995/P999)
                                             │     in rule_baselines
                                             │
                                             └─ State-Loop (alle 30s):
  alerts-raw                                       liest /api/sig-rules/ml/status
  └─ alert-manager                                 │
      └─ feedback (manuell + auto-FP)              ├─ training: nur sammeln
          → DB alerts.feedback,                    ├─ tuning: alle 6h
            alerts.metric_values                   │   ├─ liest alerts.feedback
                                                   │   │     mit metric_values
                                                   │   ├─ Quantil × 1.05
                                                   │   ├─ FP-Bound (max+1)
                                                   │   ├─ TP-Bound (min)
                                                   │   ├─ schema-clamp + cast
                                                   │   └─ PUT /api/sig-rules/
                                                   │         overrides
                                                   │         source=ml
                                                   │
                                                   └─ paused/idle: nichts
```

### 10.3 State-Maschine

Der Tuner lebt in einem von vier States. Übergänge sind teils user-, teils
automatik-getrieben:

| State      | User-Aktion → State          | Tuner-Verhalten                                  |
|------------|------------------------------|--------------------------------------------------|
| `idle`     | start-training → `training`  | Sampling läuft, kein Override-Write.             |
| `training` | pause → `paused`             | Sammelt Reservoir-Samples bis `training_until`.  |
|            | (auto: training_until ≤ now → `tuning` + erster Override-Write) |          |
| `tuning`   | pause → `paused`             | Alle 6 h: Quantile→Override aus aktuellem Reservoir. |
| `paused`   | resume → vorheriger State    | Sampling steht still, keine Schreibe.            |

UI: *Einstellungen → Regelwerk → Regel-Anpassungen → ML-Tuning*. Live-Status
mit Restzeit, Sample-Count, Start/Pause/Resume.

### 10.4 Schwellwert-Algorithmus

Pro `(rule, param)` und Scope (`internal`/`external`/`global`):

1. **Quantil**: P99,5 aus dem Reservoir (Default; per `quantile`-Config änderbar).
2. **Safety-Margin**: × 1.05 — knappe Treffer alarmieren nicht versehentlich.
3. **FP/TP-Constraints** (Phase 4.5): wenn ≥ 3 Markierungen für die Rule existieren:
   - `threshold ≥ max(metric_values_at_FP) + 1` (FP-Untergrenze, int) bzw. `+ epsilon` (float).
   - `threshold ≤ min(metric_values_at_TP)` (TP-Obergrenze).
   - Konflikt (FP+1 > TP_min) → alten Wert behalten + Warning.
4. **Schema-Clamp**: gegen min/max aus YAML.
5. **`max_change_per_cycle`-Klemme** (außer first-apply nach Trainingsende):
   neuer Wert in `[old × (1-mc), old × (1+mc)]`, Default mc=0.20.

`scope_split_enabled=true`: separate Werte für `value` (extern) und
`value_internal` (intern). signature-engine wählt zur Laufzeit anhand
`flow.src_ip ∈ known_networks`.

### 10.5 Manueller Lock

Pro Param hat der Override eine `source`-Provenance:
- `source: "ml"` — vom Tuner gesetzt, wird beim nächsten Cycle aktualisiert.
- `source: "manual"` — User hat im UI editiert. Tuner **fasst diesen Param nicht
  an**, bis der User in der UI den ↺-Reset-Button drückt (entfernt den Skalar-Override
  → fällt zurück auf YAML-Default → Tuner schreibt im nächsten Cycle wieder mit
  `source=ml`).
- Skalar-Form ohne Provenance (Bestandsdaten von vor Phase 1) gilt als impliziter
  manual-Lock — sicherer Default.

UI rendert Badges: `tunbar` (grau), `ML` (grün), `manuell` (amber). Tabellen-
zeilen-Header zeigen `ML×n` / `✎×n`-Counter ohne Aufklappen.

### 10.6 Konfiguration

| Env (rule-tuner)        | Default | Bedeutung                                                   |
|-------------------------|---------|-------------------------------------------------------------|
| `RESERVOIR_SIZE`        | 10000   | Algorithm-R-Reservoir pro `(rule, param, scope)`.           |
| `PERSIST_INTERVAL_S`    | 60      | UPSERT in `rule_baselines`.                                 |
| `STATE_POLL_INTERVAL_S` | 30      | Polling von `/api/sig-rules/ml/status`.                     |
| `TUNING_CYCLE_S`        | 21600   | Tuner-Cycle-Cadence (= 6 h).                                |
| `MIN_SAMPLES`           | 100     | Min-Sample-Count pro Scope, sonst kein Threshold-Update.    |

Trainingskonfig (DB `system_config.ml_tuning_config`, GUI-editierbar):
`window_s` (Trainingsdauer), `quantile`, `scope_split_enabled`,
`max_change_per_cycle`, `blacklist[]`, `target_alert_rate_per_hour`.

---

## 11. Zusammenspiel rule-tuner ↔ Suppression

### 11.1 Aufgabenteilung

Beide Komponenten beobachten dasselbe Symptom (Alerts mit hoher Frequenz),
greifen aber an unterschiedlichen Stellen ein:

| Aspekt                          | rule-tuner                  | Suppression                       |
|---------------------------------|-----------------------------|-----------------------------------|
| **Greift wann?**                | Cycle (alle 6h) bzw. nach Training-Ende | Pro Alert, sofort.    |
| **Wirkt auf**                   | Schwellwerte tunbarer Heuristiken | Severity-Tag pro `(rule, ip-paar)`. |
| **Behält Severity?**            | Ja (Rule feuert nur über Threshold) | Nein (degradiert auf `low`).  |
| **Skaliert mit Pattern-Anzahl** | Linear in Anzahl `metric:`-deklarierter Params | Pro IP-Paar — passt sich an. |
| **Wirkt auf Suricata?**         | Nein                        | Ja                                |
| **Wirkt auf ML-Engine-Alerts?** | Nein                        | Ja (V1) → **Nein** (Phase 7)      |

### 11.2 Kollisions-Zonen — und wie sie aufgelöst sind

Vor Phase 7 liefen rule-tuner und Suppression parallel auf denselben Heuristik-
Alerts und konnten gegenseitig Schaden anrichten:

- Tuner setzt Threshold passend → Heuristik feuert nur noch bei echten Anomalien.
- Suppression sieht "trotzdem ein paar FPs in den letzten 14 Tagen" → setzt
  Severity auf `low`.
- Echter Treffer kommt durch (Threshold ist sauber), wird aber von Suppression
  als `low` markiert → Analyst sieht ihn im Noise-Slum.

**Phase 7 Skip-Liste** (`alert-manager/src/main.py`): Suppression-Action wird übersprungen für:

```python
suppress_eligible = (
    source not in ("ml", "external")  # ML-Engine + IRMA: kein zweites ML-Filter
    and not alert.tunable             # rule-tuner ist zuständig
)
```

Die Suppression-CLASSIFY-Logik läuft trotzdem für tunable Rules — der
Output wird aber nicht als severity-Drop angewandt, sondern als
**Auto-FP-Feedback** in `alerts.feedback` geschrieben:

```python
alert["feedback"]      = "fp"
alert["feedback_note"] = f"auto-suppression:{kind}"  # 'manual' oder 'learned'
alert["tags"]         += ["auto-fp-pattern"]
```

### 11.3 Loop-Schließung: Suppression-Signal als rule-tuner-Input

Der `rule-tuner` liest in `_load_feedback_metrics()` alle Alerts mit
`feedback IS NOT NULL AND metric_values IS NOT NULL` und nutzt sie für die
FP/TP-Bounds (siehe 10.4). Auto-Suppression-Markierungen sind dort
inkludiert — der Tuner sieht sie als FP-Hinweis und hebt den Threshold
beim nächsten Cycle so an, dass diese Pattern nicht mehr feuern.

Damit verstärken sich beide Loops gegenseitig:

1. Heuristik fired auf 192.168.1.66 → SCAN_001-Alert.
2. Suppression-Cache lernt das als Pattern (kein TP-Mark, häufig).
3. Layer-2-Klassifikation `learned` triggert.
4. alert-manager: tunable=true → kein severity=low. Stattdessen feedback='fp', tag 'auto-fp-pattern'.
5. Alert mit metric_values + feedback='fp' in DB.
6. rule-tuner Cycle: addiert metric_value zu fp_max für SCAN_001/port_count.
7. Threshold steigt → SCAN_001 feuert für dieses Pattern nicht mehr.
8. Reale Scans aus anderen Quellen mit `unique_dst_ports > new_threshold` feuern
   weiter mit voller Severity.

**User-Override**: setzt der User explizit `feedback='tp'` über die UI, ersetzt
das den Auto-FP-Stand (gleiche Spalte, jüngeres `feedback_ts`). Beim nächsten
Tuner-Cycle wird der Wert in TP-Bound-Berechnung einbezogen — bremst eine
fälschliche Threshold-Erhöhung.

### 11.4 Anti-Pattern: was wir bewusst NICHT tun

- **Suppression auf ML-Engine-Output**: einer der Detektoren (IsolationForest)
  wird nicht durch einen anderen ML-Filter (Suppression) gedrosselt. Sonst
  gehen Anomalien doppelt verloren.
- **Suppression auf `source=external` (IRMA)**: externe Aussagen sind keine
  Detection-Noise und gehören nicht in eine Frequenz-basierte Drosselung.
- **Tuner-Threshold-Override** für nicht-`metric:`-Params: weder `window_s`
  noch pattern-only Rules werden vom Tuner angefasst.
- **Auto-TP-Feedback**: Suppression schreibt **nur FP**, niemals TP. Eine
  Spike-Durchbruch-Klassifikation bedeutet "Pattern hat sich verändert,
  Analyst muss schauen" — nicht "Pattern ist ein TP".

### 11.5 Diagnose-Pfade

**"Heuristik feuert weiter trotz Tuner-Lauf":**
- `_overrides.json` checken — hat der Param `source: "ml"`?
- `last_tuning_at` im UI — wann war der letzte Cycle?
- `MIN_SAMPLES` (default 100) für die Scope erreicht? Tunner-Logs zeigen
  "Tuning-Cycle ohne Updates" wenn nicht.
- `fp_seen` / `tp_seen` in der ml-Metadata des Override-Eintrags — ggf.
  konfligierende Markierungen?

**"Auto-FP-Pattern landet am User trotz Suppression-Skip":**
- Erwartet — der Alert wird mit `feedback='fp'` + `tag='auto-fp-pattern'`
  gespeichert. UI-Filter "False Positive" zeigt ihn. Severity bleibt
  original — der User kann jederzeit auf `tp` flippen, wenn es ein echter
  Treffer war.

**"Suppression unterdrückt einen echten TP einer tunbaren Heuristik":**
- Sollte nach Phase 7 nicht mehr passieren. Falls doch: prüfen ob
  `alert.tunable` korrekt vom signature-engine gesetzt wird (Test:
  `docker compose logs signature-engine` und Alert mit `metric:`-Param
  im YAML inspizieren).

---

**Related Docs:**
- [README.md](../README.md) — Gesamtarchitektur
- [CLAUDE.md](../CLAUDE.md) — Development-Workflow
