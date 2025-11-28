from app.models.scan_models import ScanRequest, ScanResult

class ScanService:
    def run_scan(self, request: ScanRequest) -> ScanResult:
        # Placeholder scan logic
        return ScanResult(status="completed", details="Scan successful.")
