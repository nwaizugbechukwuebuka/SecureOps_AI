"""
Workflow executor for SecureOps tasks and pipelines.
"""
from typing import Any, Dict, Callable, List
import logging
import asyncio

class WorkflowExecutor:
    """
    Executes a sequence of tasks (sync or async) as a workflow pipeline.
    """
    def __init__(self):
        self.logger = logging.getLogger("WorkflowExecutor")

    async def execute(self, tasks: List[Callable[..., Any]], *args, **kwargs) -> List[Any]:
        """
        Execute a list of tasks in sequence. Supports async and sync callables.
        """
        results = []
        for task in tasks:
            self.logger.info(f"Executing task: {task.__name__}")
            if asyncio.iscoroutinefunction(task):
                result = await task(*args, **kwargs)
            else:
                result = task(*args, **kwargs)
            results.append(result)
        return results
