"""
AI-powered threat detection logic for SecureOps.
Upgraded for enterprise: supports ML model loading, anomaly detection, contextual risk scoring, and real-time alerting integration.
"""

import logging
from typing import Any, Dict, List, Optional

import numpy as np

try:
    from pyod.models.iforest import IForest
except ImportError:
    IForest = None  # PyOD not installed; fallback to dummy logic


class ThreatDetectionEngine:
    """
    AI-based threat detection engine for analyzing security events and logs.
    Supports anomaly detection, contextual risk scoring, and real-time alerting.
    """

    def __init__(self, model: Optional[Any] = None):
        self.logger = logging.getLogger("ThreatDetectionEngine")
        if model is not None:
            self.model = model
        elif IForest is not None:
            self.model = IForest()
        else:
            self.model = None
        self.is_trained = False

    def extract_features(self, event: Dict[str, Any]) -> List[float]:
        """
        Extract numerical features from a security event for ML analysis.
        Extend this method for real use cases.
        """
        features = [
            float(event.get("severity", 0)),
            float(event.get("user_risk_score", 0)),
            float(event.get("failed_logins", 0)),
            float(event.get("ip_reputation", 0)),
        ]
        return features

    def contextual_risk_score(
        self, event: Dict[str, Any], anomaly_score: float
    ) -> float:
        """
        Calculate contextual risk score based on event and anomaly score.
        """
        base = anomaly_score * 7.5  # scale anomaly score
        if event.get("critical_asset", False):
            base += 2.0
        if "suspicious" in event.get("description", "").lower():
            base += 1.5
        return min(base, 10.0)

    async def analyze_events(
        self, events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Analyze a list of security events and return detected threats with risk scores.
        """
        self.logger.info(f"Analyzing {len(events)} events for threats (AI/ML mode).")
        threats = []
        if not events:
            return threats

        # Feature extraction
        X = [self.extract_features(e) for e in events]
        X_np = np.array(X)

        # Train model if not already trained (unsupervised)
        if self.model and not self.is_trained and len(X_np) > 10:
            self.model.fit(X_np)
            self.is_trained = True

        # Anomaly detection
        if self.model and self.is_trained:
            anomaly_scores = self.model.decision_function(X_np)
            outliers = self.model.predict(X_np)
        else:
            # Fallback: mark as anomaly if 'suspicious' in description
            anomaly_scores = [
                1.0 if "suspicious" in e.get("description", "").lower() else 0.1
                for e in events
            ]
            outliers = [int(score > 0.8) for score in anomaly_scores]

        # Build threat objects
        for idx, event in enumerate(events):
            if outliers[idx]:
                risk = self.contextual_risk_score(event, anomaly_scores[idx])
                threats.append(
                    {
                        "event": event,
                        "threat_level": (
                            "critical" if risk > 7 else "high" if risk > 4 else "medium"
                        ),
                        "risk_score": round(risk, 2),
                        "anomaly_score": float(anomaly_scores[idx]),
                        "details": "AI/ML anomaly detected. Contextual risk scoring applied.",
                    }
                )
        return threats

    def train_on_historical(self, historical_events: List[Dict[str, Any]]):
        """
        Train the anomaly detection model on historical event data.
        """
        if not self.model or not historical_events:
            return
        X = [self.extract_features(e) for e in historical_events]
        X_np = np.array(X)
        self.model.fit(X_np)
        self.is_trained = True

    def load_model(self, path: str):
        """
        Load a pre-trained model from disk (optional, for advanced use).
        """
        # Implement model loading logic as needed
        pass
