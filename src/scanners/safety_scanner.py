import json
import subprocess
from typing import List, Optional

from .common import ScanResult, Vulnerability


class SafetyScanner:
    """Scanner for Python dependencies using the safety CLI tool."""

    def __init__(self, safety_path: str = "safety"):
        self.safety_path = safety_path

    async def scan_requirements(self, requirements_file: str) -> ScanResult:
        try:
            result = subprocess.run(
                [
                    self.safety_path,
                    "check",
                    "--full-report",
                    "--json",
                    "-r",
                    requirements_file,
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0 and not result.stdout:
                return ScanResult(
                    success=False, error=result.stderr or "Safety scan failed"
                )
            vulns = []
            try:
                data = json.loads(result.stdout)
                for item in data:
                    vulns.append(
                        Vulnerability(
                            id=str(item.get("id", "")),
                            package=item.get("package", ""),
                            version=item.get("vulnerable", ""),
                            severity="HIGH",  # Safety does not provide severity, default to HIGH
                            description=item.get("advisory", ""),
                        )
                    )
            except Exception as e:
                return ScanResult(
                    success=False, error=f"Failed to parse safety output: {e}"
                )
            return ScanResult(success=True, vulnerabilities=vulns)
        except Exception as e:
            return ScanResult(success=False, error=str(e))

    async def scan_environment(self, venv_path: str) -> ScanResult:
        # This is a stub for scanning a virtual environment directory
        # You may need to activate the venv and run safety from within it
        return ScanResult(success=False, error="scan_environment not implemented")
