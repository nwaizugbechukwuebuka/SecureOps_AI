# API Reference

Base URL: `/` (FastAPI app created via `api.fastapi_app.create_app`)

Endpoints

- `GET /health/`
  - Returns: `{ "status": "ok" }`

- `POST /scan/run`
  - Protected: requires `X-API-Token` header
  - Starts ingest → detect → response pipelines and returns a summary object.

- `POST /ai/analyze`
  - Protected: requires `X-API-Token`
  - Body: `{ "prompt": "..." }`
  - Response: deterministic analysis from `LLMSecurityAgent` stub.

Authentication
- Token-based HMAC verification header `X-API-Token`. Generate a dev token via helper in `security.crypto`.

Examples

Health check using `curl`:

```bash
curl -v http://127.0.0.1:8000/health/
```
