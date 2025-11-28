#!/usr/bin/env bash
# Start the FastAPI app using uvicorn (development)
set -euo pipefail

# Ensure the `src` package path is visible to Python when running locally
export PYTHONPATH="${PYTHONPATH:-}:$(pwd)/src"

echo "Starting SecureOps_AI (uvicorn) on 127.0.0.1:8000"
uvicorn api.fastapi_app:create_app --factory --host 127.0.0.1 --port 8000 --reload
