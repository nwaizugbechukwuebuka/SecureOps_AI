from __future__ import annotations

import hashlib
from typing import List

import numpy as np

"""
Mocked deterministic embedding utilities for logs.
Embeddings are small, hash-based vectors suitable for local testing.
"""


def embed_text(text: str, dim: int = 16) -> List[float]:
    """Convert text into a small deterministic vector for testing."""
    h = hashlib.blake2b(text.encode("utf8"), digest_size=dim)
    arr = np.frombuffer(h.digest(), dtype=np.uint8).astype(float)
    return (arr / 255.0).tolist()


def embed_batch(texts: List[str], dim: int = 16) -> List[List[float]]:
    """Embed a batch of texts."""
    return [embed_text(t, dim=dim) for t in texts]


__all__ = ["embed_text", "embed_batch"]
