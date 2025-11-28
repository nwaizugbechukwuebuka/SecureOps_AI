# Deployment Guide

This guide provides a minimal path to deploy SecureOps_AI.

1. Prepare environment
   - Ensure Python 3.10+ installed.
   - Install dependencies: `pip install -r requirements.txt`.

2. Environment variables
   - `SECUREOPS_SECRET`: HMAC secret for API tokens.
   - `SLACK_WEBHOOK`: optional for notifications.

3. Run with systemd (example)
   - Create a unit file referencing `python -m src.main` or use `uvicorn api.fastapi_app:create_app --factory`.

4. Containerize
   - Build a small Dockerfile that installs requirements and runs uvicorn.

5. CI/CD
   - Use the provided GitHub workflows as a starting point for tests, scans and deploy.
