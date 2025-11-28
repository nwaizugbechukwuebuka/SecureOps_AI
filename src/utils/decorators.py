"""Common decorators used by pipelines and integrators.

This module exposes both synchronous and asynchronous retry/timing
decorators used across the project.
"""
from __future__ import annotations

import asyncio
import functools
import logging
import time
from typing import Callable, Any, TypeVar

F = TypeVar("F", bound=Callable[..., Any])

LOG = logging.getLogger("secureops.utils.decorators")


def retry(times: int = 3, delay: float = 0.5) -> None:
    def _decorator(fn: F) -> F:
        def _wrapped(*args, **kwargs) -> None:
            last = None
            for _ in range(times):
                try:
                    return fn(*args, **kwargs)
                except Exception as e:
                    last = e
                    time.sleep(delay)
            raise last

        return _wrapped  # type: ignore

    return _decorator


def async_retry(retries: int = 3, delay: float = 0.1) -> None:
    def _decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        async def _wrapped(*args, **kwargs) -> None:
            last_exc = None
            for i in range(retries):
                try:
                    return await func(*args, **kwargs)
                except Exception as exc:  # pragma: no cover
                    last_exc = exc
                    LOG.debug(
                        "Retry %s for %s after error: %s",
                        i + 1,
                        func.__name__,
                        exc,
                    )
                    await asyncio.sleep(delay)
            raise last_exc

        return _wrapped

    return _decorator


def async_timed(func: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(func)
    async def _wrapped(*args, **kwargs) -> None:
        start = time.time()
        try:
            return await func(*args, **kwargs)
        finally:
            LOG.debug("%s took %.3fs", func.__name__, time.time() - start)

    return _wrapped


__all__ = ["retry", "async_retry", "async_timed"]

