# SecureOps_AI Architecture

This document describes the high-level architecture for SecureOps_AI.

Overview
- Async-first FastAPI service exposing ingestion, detection and response pipelines.
- Local deterministic ML model (scikit-learn) used for threat classification.
- Modular integrators for SIEM, CloudTrail and Azure logs.
- Simple secrets manager and HMAC-based token authentication for demo purposes.

Components
- API: `api.fastapi_app` provides endpoints and background tasks.
- AI Engine: `ai_engine` contains model loader, anomaly detection, embeddings and a small LLM stub.
- Pipelines: `pipelines/*` orchestrate ingest → detect → respond asynchronously.
- Integrators: `integrators/*` provide mock connectors to external systems.

Data Flow
1. Ingest connectors yield event records.
2. Events are embedded and checked for anomalies.
3. Classifier assigns threat scores; response pipeline notifies and logs findings.

Deployment
- Designed to run behind a process manager (systemd) or container orchestration (Kubernetes).
- Uses environment variables for secrets and `config/settings.yaml` for defaults.
