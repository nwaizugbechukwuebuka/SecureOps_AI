import logging
from typing import Any
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from security.auth import require_token

LOG = logging.getLogger("secureops.api.ai")
router = APIRouter()

class AnalyzeRequest(BaseModel):
    prompt: str


class AnalyzeResponse(BaseModel):
    id: str
    persona: str
    prompt_snippet: str
    suggestion: str

@router.post("/analyze", response_model=AnalyzeResponse, dependencies=[Depends(require_token)])
async def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    """Run the LLM security agent against the provided prompt."""
    from ai_engine.llm_security_agent import LLMSecurityAgent
    agent = LLMSecurityAgent()
    resp = await agent.analyze(request.prompt)
    return resp

