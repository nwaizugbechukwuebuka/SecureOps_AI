import logging
from typing import AsyncIterator, Dict, Iterable

from ai_engine.anomaly_detection import detect_anomaly
from ai_engine.log_embeddings import embed_text
from ai_engine.threat_classifier import ThreatClassifier

"""Detection pipeline: embeddings -> anomaly detection -> threat classification."""


async def run_detection(records: Iterable[Dict], classifier: ThreatClassifier = None) -> AsyncIterator[Dict]:
    classifier = classifier or ThreatClassifier()
    for rec in records:
        emb = embed_text(rec.get("message", str(rec)), dim=4)
        anomaly = detect_anomaly(emb)
        threat = classifier.predict(emb)
        yield {
            "record": rec,
            "embedding": emb,
            "anomaly": anomaly,
            "threat": threat,
        }


"""
Detection pipeline: embeddings -> anomaly detection -> threat classification.
"""


LOG = logging.getLogger("secureops.pipelines.detection")


async def run_detection(records: Iterable[Dict], classifier: ThreatClassifier = None) -> AsyncIterator[Dict]:
    classifier = classifier or ThreatClassifier()
    for rec in records:
        text = rec.get("message") or rec.get("event") or str(rec)
        emb = embed_text(text, dim=4)
        anomaly = detect_anomaly(emb)
        threat = classifier.predict(emb)
        yield {
            "record": rec,
            "embedding": emb,
            "anomaly": anomaly,
            "threat": threat,
        }


__all__ = ["run_detection"]
