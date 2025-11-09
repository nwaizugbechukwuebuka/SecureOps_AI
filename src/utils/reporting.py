"""
Reporting utilities for SecureOps (PDF, CSV, JSON report generation).
"""

from typing import List, Dict, Any
import json
import csv
import io


class Reporting:
    """
    Utilities for generating reports in various formats.
    """

    @staticmethod
    def to_json(data: Any) -> str:
        return json.dumps(data, indent=2)

    @staticmethod
    def to_csv(data: List[Dict[str, Any]]) -> str:
        if not data:
            return ""
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
        return output.getvalue()

    @staticmethod
    def to_txt(data: Any) -> str:
        return str(data)
