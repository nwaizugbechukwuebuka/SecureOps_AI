from fastapi import APIRouter, Depends
from app.services.ai_service import AIService
from app.models.ai_models import AIAnalysisRequest, AIAnalysisResult

router = APIRouter()

@router.post("/ai/analyze", response_model=AIAnalysisResult, tags=["AI Analysis"])
def analyze(request: AIAnalysisRequest):
    return AIService().analyze(request)
