"""Text embedding utilities for log/event data."""
from typing import List
import hashlib

def embed_text(text: str, dim: int = 8) -> List[float]:
    """Deterministically embed text for anomaly/threat detection."""
    h = hashlib.sha256(text.encode()).digest()
    return [float(b) / 255.0 for b in h[:dim]]




"""Mocked deterministic embedding utilities for logs.

Embeddings are small, hash-based vectors suitable for local testing.
"""

import hashlib
from typing import List
import numpy as np

def embed_text(text: str, dim: int = 16) -> List[float]:
    h = hashlib.blake2b(text.encode("utf8"), digest_size=dim)
    arr = np.frombuffer(h.digest(), dtype=np.uint8).astype(float)
    return (arr / 255.0).tolist()

def embed_batch(texts: List[str], dim: int = 16) -> List[List[float]]:
    return [embed_text(t, dim=dim) for t in texts]

__all__ = ["embed_text", "embed_batch"]

