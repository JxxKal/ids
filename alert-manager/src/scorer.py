"""
Severity-Scoring: kombiniert Regel-Severity und ML-Score zu einem
einheitlichen numerischen Score (0.0–1.0).

Für Signature-Alerts (source = "signature"):
  severity → base_score (critical=1.0, high=0.8, medium=0.5, low=0.2)

Für ML-Alerts (source = "ml"):
  score aus dem Alert direkt verwenden (bereits 0.0–1.0)

Kombinierter Score wird im Alert als "score"-Feld gesetzt.
"""
from __future__ import annotations

_SEVERITY_SCORE = {
    "critical": 1.0,
    "high":     0.8,
    "medium":   0.5,
    "low":      0.2,
}


def enrich_score(alert: dict) -> dict:
    """
    Fügt/überschreibt 'score' im Alert-Dict und normiert 'severity'.
    Gibt das modifizierte Dict zurück (in-place).
    """
    source = alert.get("source", "signature")

    if source == "ml":
        # ML-Engine liefert bereits einen Float-Score
        score = float(alert.get("score") or 0.0)
    else:
        severity = (alert.get("severity") or "low").lower()
        score = _SEVERITY_SCORE.get(severity, 0.2)

    alert["score"] = round(score, 4)

    # Severity aus Score normieren (für Konsistenz bei ML-Alerts)
    if source == "ml":
        alert["severity"] = _score_to_severity(score)

    return alert


def _score_to_severity(score: float) -> str:
    if score >= 0.90:
        return "critical"
    if score >= 0.80:
        return "high"
    if score >= 0.70:
        return "medium"
    return "low"
