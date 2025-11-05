"""
General helper utilities for SecureOps.
"""
from typing import Any, Dict, List
import datetime

class Helpers:
    """
    Common helper functions for data formatting, time, etc.
    """
    @staticmethod
    def current_utc_time() -> str:
        return datetime.datetime.utcnow().isoformat() + "Z"

    @staticmethod
    def safe_get(d: Dict, key: Any, default: Any = None) -> Any:
        return d.get(key, default)

    @staticmethod
    def flatten_list(nested_list: List[List[Any]]) -> List[Any]:
        return [item for sublist in nested_list for item in sublist]
