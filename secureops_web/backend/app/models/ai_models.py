from pydantic import BaseModel

class AIAnalysisRequest(BaseModel):
    data: str

class AIAnalysisResult(BaseModel):
    result: str
