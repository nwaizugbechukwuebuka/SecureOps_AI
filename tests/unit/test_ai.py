
import sys
from pathlib import Path

# Ensure src is importable when running tests from repository root
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from ai_engine.anomaly_detection import zscore_anomaly_score, detect_anomaly
from ai_engine.log_embeddings import embed_text
from ai_engine.threat_classifier import ThreatClassifier


def test_zscore_and_detect():
    v = [1.0, 1.0, 1.0, 1.0]
    score = zscore_anomaly_score(v)
    assert isinstance(score, float)
    res = detect_anomaly(v, threshold=0.0)
    assert res.is_anomaly is True


def test_embeddings_deterministic():
    a = embed_text("hello world", dim=8)
    b = embed_text("hello world", dim=8)
    assert a == b
    assert len(a) == 8


def test_threat_classifier_with_stub(stub_model):
    # instantiate ThreatClassifier with provided stub model
    tc = ThreatClassifier(model=stub_model)
    feature_vector = [0.1, 0.2, 0.3, 0.4]
    tr = tc.predict(feature_vector)
    assert hasattr(tr, "probability")
    assert tr.label in {"malicious", "benign"}
    assert isinstance(tr.explanation, dict)


def test_embed_text_returns_vector():
    vec = embed_text("this is a test")
    assert hasattr(vec, "__iter__")
    assert len(vec) > 0
    assert all(isinstance(x, float) for x in vec)
