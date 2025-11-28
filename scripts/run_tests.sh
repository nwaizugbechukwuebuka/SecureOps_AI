#!/usr/bin/env bash
# Run test suite from repository root
set -euo pipefail

export PYTHONPATH="${PYTHONPATH:-}:$(pwd)/src"
echo "Running pytest..."
pytest -q
