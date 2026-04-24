# ML-Engine — Dokumentation

> Die ML-Engine ist das lernende Herzstück von Cyjan IDS. Sie ergänzt die
> signaturbasierte Erkennung um **anomaliebasierte Detektion** und
> **adaptive Fehlalarm-Filterung**.

## Inhalt

- [1. Architektur-Überblick](#1-architektur-überblick)
- [2. Flow-Feature-Extraktion](#2-flow-feature-extraktion)
- [3. Anomalie-Modell (IsolationForest)](#3-anomalie-modell-isolationforest)
- [4. Lifecycle: Bootstrap → Inference → Retrain](#4-lifecycle-bootstrap--inference--retrain)
- [5. Score-zu-Severity-Mapping](#5-score-zu-severity-mapping)
- [6. Feedback-Loop (FP/TP → Training)](#6-feedback-loop-fptp--training)
- [7. Adaptive Suppression (Layer 1 + Layer 2)](#7-adaptive-suppression-layer-1--layer-2)
- [8. Konfiguration (ENV + Runtime-Config)](#8-konfiguration-env--runtime-config)
- [9. Betrieb & Debugging](#9-betrieb--debugging)

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

**Related Docs:**
- [README.md](../README.md) — Gesamtarchitektur
- [CLAUDE.md](../CLAUDE.md) — Development-Workflow
