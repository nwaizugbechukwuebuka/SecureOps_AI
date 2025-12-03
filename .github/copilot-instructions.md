# Copilot Instructions for SecureOps_AI

## Project Overview

SecureOps_AI is an enterprise-grade security automation and ML-powered threat detection platform. It analyzes cloud, SIEM, and SaaS logs for misconfigurations, anomalies, and vulnerabilities with real-time risk scoring, alerting, and compliance reporting.

## Technology Stack

- **Backend**: Python 3.11+, FastAPI
- **ML**: scikit-learn for threat classification
- **Database**: PostgreSQL
- **Caching**: Redis
- **Queue**: Celery + Redis
- **Containerization**: Docker, Kubernetes
- **Authentication**: JWT, OAuth 2.0

## Project Structure

```
src/
├── api/              # FastAPI routes and application
├── ai_engine/        # ML models, anomaly detection, embeddings
├── pipelines/        # Ingest → Detect → Respond workflows
├── integrators/      # SIEM, CloudTrail, Azure connectors
├── security/         # Auth, crypto, secrets management
└── utils/            # Shared utilities

tests/
├── unit/             # Unit tests
├── integration/      # Integration tests
└── conftest.py       # Pytest fixtures

docs/                 # Documentation
config/               # Configuration files
```

## Coding Standards

### Python Style
- Use **Black** for code formatting (line length: 88)
- Use **Ruff** for linting with rules: E, F, W, C, N
- Use **mypy** for type checking
- Follow PEP 8 naming conventions:
  - `snake_case` for functions, variables, modules
  - `PascalCase` for classes
  - `UPPER_CASE` for constants

### Type Annotations
- Always include type hints for function parameters and return values
- Use `typing` module for complex types (List, Dict, Optional, Union)
- Run `mypy` to validate type correctness

### Documentation
- Use docstrings for all public functions, classes, and modules
- Follow Google-style docstring format
- Include Args, Returns, and Raises sections where applicable

## Development Workflow

### Setting Up Environment
```bash
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
```

### Running Tests
```bash
export PYTHONPATH=$PWD/src
pytest tests/ -q
pytest tests/ --cov=src --cov-report=html  # With coverage
```

### Running the Application
```bash
uvicorn src.api.fastapi_app:create_app --factory --reload --port 8000
```

### Docker Development
```bash
docker-compose up -d
```

## Security Guidelines

- Never commit secrets or credentials to the repository
- Use environment variables or HashiCorp Vault for secrets management
- Follow OWASP Top 10 security practices
- Use the `secrets_manager.py` or `secrets_manager_vault.py` for credential handling
- All API endpoints should include proper authentication and authorization
- Validate and sanitize all user inputs
- Use parameterized queries to prevent SQL injection

## Testing Requirements

- Write unit tests for all new functionality
- Maintain test coverage above 90%
- Use pytest fixtures from `tests/conftest.py`
- Include both positive and negative test cases
- Run security scans with `bandit -r src/`

## API Development

- Follow RESTful API design principles
- Use appropriate HTTP status codes
- Include request/response validation with Pydantic models
- Add API routes in `src/api/routes/`
- Document endpoints with OpenAPI/Swagger annotations

## ML/AI Components

- Models are located in `src/ai_engine/`
- Use scikit-learn for threat classification
- Keep model training and inference separate
- Version control trained models appropriately

## Configuration

- Use `config/settings.yaml` for default configuration
- Override settings with environment variables
- Store sensitive configuration in `.env` (never commit this file)
- Reference `config/secrets_template.yaml` for secret structure

## Pull Request Guidelines

- Write clear, descriptive commit messages
- Reference issue numbers in commits when applicable
- Ensure all tests pass before requesting review
- Include tests for new functionality
- Update documentation for API changes

## Common Commands

| Task           | Command                                                        |
| -------------- | -------------------------------------------------------------- |
| Run tests      | `pytest tests/ -q`                                             |
| Format code    | `black src/ tests/`                                            |
| Lint code      | `ruff check src/ tests/`                                       |
| Type check     | `mypy src/`                                                    |
| Security scan  | `bandit -r src/`                                               |
| Start server   | `uvicorn src.api.fastapi_app:create_app --factory --reload`    |
