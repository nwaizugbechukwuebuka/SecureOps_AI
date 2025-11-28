# Threat Model (STRIDE + LINDDUN)

This document summarizes threats considered for SecureOps_AI and mitigations.

STRIDE
- Spoofing: use HMAC token verification to avoid unauthenticated API calls.
- Tampering: validate and sanitize inputs in pipelines; sign persisted artifacts where appropriate.
- Repudiation: include logging/audit trails for pipeline actions.
- Information disclosure: secrets template, do not store secrets in repo; use environment variables in production.
- Denial of Service: rate limits and backpressure should be added at API gateway in production.
- Elevation of Privilege: least privilege for any service accounts.

LINDDUN (Privacy)
- Linkability: minimal persistent identifiers; logs should be redacted where necessary.
- Identifiability: avoid logging PII from ingested events.
- Non-repudiation: signed audit trail for critical operations.

Mitigations
- Use secure storage for secrets, e.g., Azure Key Vault, AWS Secrets Manager.
- Add network-level protections and rate limiting for public deployments.
