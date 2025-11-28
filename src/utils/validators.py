"""Validators used across the project (pydantic-compatible helpers)."""
from __future__ import annotations

from typing import Any, Sequence[Any]


def ensure_list(x) -> Sequence[Any]:
    if x is None:
        return []
    if isinstance(x, (list, tuple)):
        return list(x)
    return [x]


def ensure_non_empty_str(value: Any) -> str:
    if value is None:
        raise ValueError("value cannot be None")
    s = str(value).strip()
    if not s:
        raise ValueError("string cannot be empty")
    return s


__all__ = ["ensure_list", "ensure_non_empty_str"]

