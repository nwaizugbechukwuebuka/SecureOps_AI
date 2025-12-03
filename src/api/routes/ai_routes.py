import logging
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from src.ai_engine.llm_security_agent import LLMSecurityAgent
from src.security.auth import require_token

LOG = logging.getLogger("secureops.api.ai")
router = APIRouter()


class AnalyzeRequest(BaseModel):
    prompt: str


class AnalyzeResponse(BaseModel):
    id: str
    persona: str
    prompt_snippet: str
    suggestion: str


@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    dependencies=[Depends(require_token)]
)
async def analyze(payload: AnalyzeRequest) -> AnalyzeResponse:
    """Run the LLM security agent against the provided prompt."""

    agent = LLMSecurityAgent()
    resp = await agent.analyze(payload.prompt)
    return resp
