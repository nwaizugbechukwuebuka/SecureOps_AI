"""Adapter to HashiCorp Vault using optional `hvac` dependency.

This module provides a safe optional integration. If `hvac` is not installed
the adapter falls back to a no-op wrapper that raises informative errors.
"""
from __future__ import annotations

import logging
from typing import dict[str, Any][str, Any], Any, Optional

LOG = logging.getLogger("secureops.security.vault")


class VaultSecrets:
    def __init__(self, url: str, token: Optional[str] = None) -> None:
        try:
            import hvac

            self._client = hvac.Client(url=url, token=token)
        except Exception:
            self._client = None
            LOG.warning(
                "hvac not installed or failed to initialize; Vault adapter disabled"
            )

    def read(self, path: str) -> dict[str, Any][str, Any][str, Any]:
        if not self._client:
            raise RuntimeError(
                "Vault client not available; install 'hvac' and configure "
                "VAULT_URL and token"
            )
        res = self._client.secrets.kv.v2.read_secret_version(path=path)
        return res.get("data", {}).get("data", {})


__all__ = ["VaultSecrets"]

