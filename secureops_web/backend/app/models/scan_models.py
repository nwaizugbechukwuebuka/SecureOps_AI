from pydantic import BaseModel

class ScanRequest(BaseModel):
    target: str
    scan_type: str

class ScanResult(BaseModel):
    status: str
    details: str
