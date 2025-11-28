"""File utilities: atomic write, JSON and YAML helpers."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml


def atomic_write(
    path: str | Path,
    data: str,
    mode: str = "w",
    encoding: str = "utf8",
) -> None:
    p = Path(path)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(data, encoding=encoding)
    tmp.replace(p)


def read_json(path: str | Path) -> Any:
    p = Path(path)
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf8"))


def write_json(path: str | Path, obj: Any) -> None:
    atomic_write(path, json.dumps(obj, indent=2), mode="w")


def read_yaml(path: str | Path) -> Any:
    p = Path(path)
    if not p.exists():
        return None
    with p.open("r", encoding="utf8") as fh:
        return yaml.safe_load(fh)


def write_yaml(path: str | Path, data: Any) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf8") as fh:
        yaml.safe_dump(data, fh)


__all__ = [
    "atomic_write",
    "read_json",
    "write_json",
    "read_yaml",
    "write_yaml",
]

