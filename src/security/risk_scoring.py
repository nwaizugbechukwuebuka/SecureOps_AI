"""Aggregate and combine detection signals into risk scores.

This module provides small, well documented utilities used by the
pipelines to compute a 0..1 normalized risk score.
"""
from __future__ import annotations

from typing import Mapping, Tuple


def score_risk(
    anomaly_score: float,
    threat_probability: float,
    weights: Mapping[str, float] | None = None,
) -> Tuple[float, str]:
    """Compute a combined risk score and categorical label.

    Returns (score, label) where score is in [0.0, 1.0] and label is one
    of ``low``, ``medium``, or ``high``.
    """
    weights = weights or {"anomaly": 0.6, "threat": 0.4}
    a = max(0.0, min(1.0, float(anomaly_score)))
    t = max(0.0, min(1.0, float(threat_probability)))
    score = a * weights.get("anomaly", 0.6) + t * weights.get("threat", 0.4)
    label = "high" if score >= 0.75 else ("medium" if score >= 0.4 else "low")
    return score, label


def aggregate_risk_score(threat_prob: float, anomaly_score: float) -> float:
    """Alternative normalized aggregator used by response pipelines.

    The function normalizes anomaly signals and combines them with a
    threat probability using fixed weights.
    """
    norm_anom = float(1.0 - (1.0 / (1.0 + anomaly_score)))
    combined = 0.7 * float(threat_prob) + 0.3 * norm_anom
    return max(0.0, min(1.0, combined))


__all__ = ["score_risk", "aggregate_risk_score"]

