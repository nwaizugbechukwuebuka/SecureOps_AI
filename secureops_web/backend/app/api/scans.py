from fastapi import APIRouter, Depends
from app.services.scan_service import ScanService
from app.models.scan_models import ScanRequest, ScanResult

router = APIRouter()

@router.post("/scan", response_model=ScanResult, tags=["Scans"])
def scan(request: ScanRequest):
    return ScanService().run_scan(request)
