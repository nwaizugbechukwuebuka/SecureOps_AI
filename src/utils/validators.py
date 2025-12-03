from __future__ import annotations

from typing import Any, Sequence

"""Validators used across the project (pydantic-compatible helpers)."""


def ensure_list(x: Any) -> Sequence[Any]:
    """Ensure the input is returned as a list."""
    if x is None:
        return []
    if isinstance(x, (list, tuple)):
        return list(x)
    return [x]


def ensure_non_empty_str(value: Any) -> str:
    """Ensure the input is a non-empty string."""
    if value is None:
        raise ValueError("value cannot be None")
    s = str(value).strip()
    if not s:
        raise ValueError("string cannot be empty")
    return s


__all__ = ["ensure_list", "ensure_non_empty_str"]
