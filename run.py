# run.py
import os
import sys
from pathlib import Path

# Ensure src is in the Python path
src_path = str(Path(__file__).resolve().parent / "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

# Set environment variables
os.environ["PROMETHEUS_ENABLED"] = "true"

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.fastapi_app:create_app", host="127.0.0.1", port=8005, reload=True)
