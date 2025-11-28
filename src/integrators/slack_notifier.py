"""Slack notification stub."""


class SlackNotifier:
    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run

    async def notify(self, channel: str, message: str):
        if self.dry_run:
            print(f"[DRY RUN] Slack: {channel}: {message}")
        else:
            # Integrate with Slack API here
            pass


__all__ = ["SlackNotifier"]
"""Dry-run capable Slack notifier (mocked).

In dry-run mode it logs messages instead of sending them.
"""

import asyncio
import logging
from typing import Optional

LOG = logging.getLogger("secureops.integrators.slack")


class SlackNotifier:
    def __init__(self, webhook_url: Optional[str] = None, dry_run: bool = True) -> None:
        self.webhook_url = webhook_url
        self.dry_run = dry_run

    async def notify(self, channel: str, message: str) -> None:
        if self.dry_run:
            LOG.info("[dry-run] Slack notify to %s: %s", channel, message)
            await asyncio.sleep(0)
            return
        LOG.info("Pretending to send to Slack: %s - %s", channel, message)
        await asyncio.sleep(0)


__all__ = ["SlackNotifier"]
