from __future__ import annotations

import logging
from collections import namedtuple
from typing import Sequence

import numpy as np

from ai_engine.model_loader import ModelWrapper, load_or_train_model

"""
Lightweight threat classifier for log embeddings.
This module provides a small wrapper around a deterministic model
used in tests and demonstrations.
"""


ThreatResult = namedtuple("ThreatResult", ["probability", "label", "explanation"])
LOG = logging.getLogger("secureops.ai.threat")


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

            explanation = {name: float(score) for name, score in zip(self.model.feature_names, contrib)}
        except Exception:
            LOG.exception("Failed to compute explanation; fallback")
            explanation = {name: 0.0 for name in self.model.feature_names}

        return ThreatResult(probability=p, label=label, explanation=explanation)


__all__ = ["ThreatClassifier", "ThreatResult"]
