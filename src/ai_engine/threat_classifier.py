
"""Lightweight threat classifier for log embeddings."""
from typing import List, Dict, Any, Optional
from collections import namedtuple

ThreatResult = namedtuple("ThreatResult", ["probability", "label", "explanation"])

class ThreatClassifier:
    def __init__(self, model: Optional[Any] = None):
        self.model = model

    def predict(self, features: List[float]) -> ThreatResult:
        prob = sum(features) / (len(features) * 1.0)
        label = "malicious" if prob > 0.5 else "benign"
        explanation = {"features": features, "probability": prob}
        return ThreatResult(probability=prob, label=label, explanation=explanation)


"""
Lightweight threat classifier for log embeddings.

This module provides a small wrapper around a deterministic model used in tests
and demonstrations.
"""
from typing import List, Dict, Any, Optional, Sequence
from collections import namedtuple
import logging
from dataclasses import dataclass
import numpy as np
from ai_engine.model_loader import ModelWrapper, load_or_train_model

ThreatResult = namedtuple("ThreatResult", ["probability", "label", "explanation"])
LOG = logging.getLogger("secureops.ai.threat")

class ThreatClassifier:
    def __init__(self, model: Optional[Any] = None):
        self.model = model

    def predict(self, features: List[float]) -> ThreatResult:
        prob = sum(features) / (len(features) * 1.0)
        label = "malicious" if prob > 0.5 else "benign"
        explanation = {"features": features, "probability": prob}
        return ThreatResult(probability=prob, label=label, explanation=explanation)



class ThreatClassifier:
    def __init__(self, model: ModelWrapper | None = None) -> None:
        self.model = model or load_or_train_model()

    def predict(self, feature_vector: Sequence[float]) -> ThreatResult:
        probs = self.model.predict_proba([feature_vector])
        p = float(probs[0])
        label = "malicious" if p >= 0.5 else "benign"
        try:
            coefs = np.asarray(self.model.model.coef_.ravel())
            feats = np.asarray(feature_vector)
            contrib = (coefs * feats).tolist()
            explanation = {
                n: float(c)
                for n, c in zip(self.model.feature_names, contrib)
            }
        except Exception:
            LOG.exception("Failed to compute explanation; fallback")
            explanation = dict.fromkeys(self.model.feature_names, 0.0)
        return ThreatResult(probability=p, label=label, explanation=explanation)


__all__ = ["ThreatClassifier", "ThreatResult"]

