"""
Pytest suite for Helpers.
"""
from secureops_ai.src.utils.helpers import Helpers

def test_current_utc_time():
    result = Helpers.current_utc_time()
    assert result.endswith("Z")

def test_safe_get():
    d = {"a": 1}
    assert Helpers.safe_get(d, "a") == 1
    assert Helpers.safe_get(d, "b", 2) == 2

def test_flatten_list():
    nested = [[1, 2], [3], []]
    flat = Helpers.flatten_list(nested)
    assert flat == [1, 2, 3]


def test_safe_get_edge_cases():
    from secureops_ai.src.utils.helpers import Helpers
    d = {"a": None}
    # Should return None, not default, if key exists but value is None
    assert Helpers.safe_get(d, "a", 5) is None
    # Should return default if key missing
    assert Helpers.safe_get(d, "b", 5) == 5


def test_flatten_list_empty():
    from secureops_ai.src.utils.helpers import Helpers
    assert Helpers.flatten_list([]) == []
    assert Helpers.flatten_list([[]]) == []
