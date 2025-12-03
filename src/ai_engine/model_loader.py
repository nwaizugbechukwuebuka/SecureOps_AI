from __future__ import annotations

import logging
import os
import pickle
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Sequence

import numpy as np
from sklearn.linear_model import LogisticRegression

"""
Deterministic local model loader using sklearn.

Trains a small LogisticRegression on synthetic data and caches it to `model_local.pkl`.
Provides a ModelWrapper with `predict_proba`.
"""

LOG = logging.getLogger("secureops.ai.model_loader")

ArrayLike2D = Sequence[Sequence[float]]


@dataclass
class ModelWrapper:
    model: Any
    feature_names: List[str]

    def predict_proba(self, x: ArrayLike2D) -> List[float]:
        arr = np.asarray(x)
        probs = self.model.predict_proba(arr)
        return [float(p[1]) for p in probs]


def _get_model_path() -> Path:
    return Path(os.getcwd()) / "model_local.pkl"


def _train_dummy_model(random_seed: int = 42) -> ModelWrapper:

    rng = np.random.default_rng(random_seed)
    x = rng.normal(size=(200, 4))

    coef = np.array([1.2, -0.8, 0.5, 0.2])
    logits = x.dot(coef) + rng.normal(scale=0.1, size=x.shape[0])
    y = (logits > 0).astype(int)

    clf = LogisticRegression(random_state=random_seed)
    clf.fit(x, y)

    feature_names = ["f1", "f2", "f3", "f4"]
    return ModelWrapper(model=clf, feature_names=feature_names)


def load_or_train_model(force_train: bool = False) -> ModelWrapper:
    path = _get_model_path()

    if path.exists() and not force_train:
        try:
            with open(path, "rb") as fh:
                wrapper = pickle.load(fh)
                LOG.info("Loaded local model from %s", path)
                return wrapper
        except Exception:
            LOG.exception("Failed to load persisted model. Retraining.")

    wrapper = _train_dummy_model()

    try:
        with open(path, "wb") as fh:
            pickle.dump(wrapper, fh)
            LOG.info("Saved model to %s", path)
    except Exception:
        LOG.exception("Failed to persist model to disk")

    return wrapper


__all__ = ["ModelWrapper", "load_or_train_model"]
