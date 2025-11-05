"""
Background task utilities for SecureOps (FastAPI/Celery compatible).
"""
from typing import Callable, Any
import logging
import asyncio

class BackgroundTaskManager:
    """
    Manages background tasks for FastAPI or Celery integration.
    """
    def __init__(self, app=None):
        self.logger = logging.getLogger("BackgroundTaskManager")
        self.app = app

    async def run_in_background(self, func: Callable[..., Any], *args, **kwargs):
        """
        Run a function as a background task (FastAPI or asyncio).
        """
        self.logger.info(f"Scheduling background task: {func.__name__}")
        if asyncio.iscoroutinefunction(func):
            asyncio.create_task(func(*args, **kwargs))
        else:
            loop = asyncio.get_event_loop()
            loop.run_in_executor(None, func, *args, **kwargs)

# Example for FastAPI integration:
# from fastapi import BackgroundTasks
# def some_task(): ...
# background_tasks.add_task(some_task)
