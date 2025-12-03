from __future__ import annotations

import openai

import logging
from typing import Any, Dict, Optional

"""Optional OpenAI connector (uses `openai` package when installed).

This module provides a thin wrapper so production deployments can opt-in
to using OpenAI; the code is defensive if `openai` is not installed.
"""



LOG = logging.getLogger("secureops.ai.llm_openai")


class OpenAILLM:
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gpt-4o-mini",
    ) -> None:
        try:

            self._openai = openai
        except Exception:  # pragma: no cover - optional dependency
            self._openai = None
        self.api_key = api_key
        self.model = model

    async def analyze(self, prompt: str) -> Dict[str, Any]:
        """
        Calls OpenAI ChatCompletion API and returns a dictionary with id, persona,
        prompt snippet, and suggestion.
        """
        if not self._openai:
            LOG.error("OpenAI SDK not installed; cannot call external LLM")
            raise RuntimeError("openai package is not available")

        # synchronous call wrapped in thread if needed by runtime; keep simple here
        self._openai.api_key = self.api_key
        resp = self._openai.ChatCompletion.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
        )
        text = resp.choices[0].message.content
        return {
            "id": resp.id,
            "persona": "openai",
            "prompt_snippet": prompt[:240],
            "suggestion": text,
        }


__all__ = ["OpenAILLM"]
