from __future__ import annotations
"""Simple anomaly detection using z-score."""
from typing import List
from collections import namedtuple

AnomalyResult = namedtuple("AnomalyResult", ["score", "is_anomaly"])

def zscore_anomaly_score(values: List[float]) -> float:
    mean = sum(values) / len(values)
    std = (sum((x - mean) ** 2 for x in values) / len(values)) ** 0.5
    return max(abs(x - mean) / std if std else 0.0 for x in values)

def detect_anomaly(values: List[float], threshold: float = 2.0) -> AnomalyResult:
    score = zscore_anomaly_score(values)
    return AnomalyResult(score=score, is_anomaly=score > threshold)

__all__ = ["zscore_anomaly_score", "detect_anomaly", "AnomalyResult"]
"""Explainable z-score based anomaly detection for numeric vectors.
"""

import logging
from dataclasses import dataclass
from typing import Dict, Any, Sequence

import numpy as np


LOG = logging.getLogger("secureops.ai.anomaly")


@dataclass
class AnomalyResult:
    score: float
    is_anomaly: bool
    explanation: Dict[str, float]


def zscore_anomaly_score(values: Sequence[Any][float]) -> float:
    arr = np.asarray(values, dtype=float)
    if arr.size == 0:
        return 0.0
    mean = float(arr.mean())
    std = float(arr.std(ddof=0)) or 1.0
    z = np.abs((arr - mean) / std)
    return float(z.mean())


def detect_anomaly(
    feature_vector: Sequence[Any], threshold: float = 1.5
) -> AnomalyResult:
    arr = np.asarray(feature_vector, dtype=float)
    score = zscore_anomaly_score(arr)
    explanations: Dict[str, float] = {}
    mean = arr.mean() if arr.size else 0.0
    std = arr.std() if arr.size else 1.0
    for i, v in enumerate(arr):
        explanations[f"dim_{i}"] = float(abs((v - mean) / (std or 1.0)))

    is_anom = score >= threshold
    LOG.debug("Anomaly detect -> score=%s, anomaly=%s", score, is_anom)
    return AnomalyResult(score=score, is_anomaly=is_anom, explanation=explanations)


__all__ = ["AnomalyResult", "detect_anomaly", "zscore_anomaly_score"]

