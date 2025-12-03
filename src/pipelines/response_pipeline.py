import logging
from typing import Dict, Iterable, List

from integrators.slack_notifier import SlackNotifier
from security.risk_scoring import aggregate_risk_score

"""
Response pipeline: create actions from detection results and optionally notify.
"""


LOG = logging.getLogger("secureops.pipelines.response")


async def run_response(detections: Iterable[Dict], notifier: SlackNotifier = None, dry_run: bool = True) -> List[Dict]:
    """
    Process detection results, compute risk scores, and send notifications.
    """

    notifier = notifier or SlackNotifier(dry_run=dry_run)
    actions: List[Dict] = []

    for det in detections:
        threat = det.get("threat")
        anomaly = det.get("anomaly")

        score = aggregate_risk_score(
            threat.probability if threat else 0.0,
            anomaly.score if anomaly else 0.0,
        )

        action = {
            "id": det.get("record", {}).get("id") or "local",
            "score": score,
            "suggestion": "investigate" if score >= 0.6 else "monitor",
            "dry_run": dry_run,
        }

        actions.append(action)

        await notifier.notify(
            channel="#alerts",
            message=(f"Alert {action['id']}: " f"score={score:.2f} " f"suggestion={action['suggestion']}"),
        )

    return actions


__all__ = ["run_response"]
