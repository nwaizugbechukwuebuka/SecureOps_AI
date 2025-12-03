from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

import yaml

"""Lightweight secrets manager that reads a safe template and overlays env vars.

This should not store or expose real secrets in the repository.
"""


LOG = logging.getLogger("secureops.security.secrets")


@dataclass
class SecretsManager:
    values: Dict[str, Any]

    @classmethod
    def load(cls, template_path: str | Path | None = None) -> "SecretsManager":
        template_path = Path(template_path or "secrets_template.yaml")
        data: Dict[str, Any] = {}
        if template_path.exists():
            try:
                with template_path.open("r", encoding="utf8") as fh:
                    data = yaml.safe_load(fh) or {}
            except Exception:
                LOG.exception("Failed reading secrets template")
        for k in list(data.keys()):
            env_val = os.environ.get(k)
            if env_val is not None:
                data[k] = env_val
        return cls(values=data)

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, os.environ.get(key, default))


__all__ = ["SecretsManager"]
