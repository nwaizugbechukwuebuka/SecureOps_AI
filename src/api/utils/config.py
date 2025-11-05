"""
Configuration management for SecureOps application.
"""

import os
import secrets
from functools import lru_cache
from typing import Any, Dict, List, Optional

<<<<<<< HEAD
from pydantic_settings import BaseSettings
from pydantic import EmailStr, Field, HttpUrl, validator


class Settings(BaseSettings):
    # External Log Forwarding / SIEM Integration
    log_forward_elk_enabled: bool = Field(default=False, env="LOG_FORWARD_ELK_ENABLED")
    log_forward_elk_host: Optional[str] = Field(default=None, env="LOG_FORWARD_ELK_HOST")
    log_forward_elk_port: Optional[int] = Field(default=9200, env="LOG_FORWARD_ELK_PORT")
    log_forward_datadog_enabled: bool = Field(default=False, env="LOG_FORWARD_DATADOG_ENABLED")
    log_forward_datadog_api_key: Optional[str] = Field(default=None, env="LOG_FORWARD_DATADOG_API_KEY")
    log_forward_syslog_enabled: bool = Field(default=False, env="LOG_FORWARD_SYSLOG_ENABLED")
    log_forward_syslog_host: Optional[str] = Field(default=None, env="LOG_FORWARD_SYSLOG_HOST")
    log_forward_syslog_port: Optional[int] = Field(default=514, env="LOG_FORWARD_SYSLOG_PORT")
=======
from pydantic import BaseSettings, EmailStr, Field, HttpUrl, validator


class Settings(BaseSettings):
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
    """Application settings and configuration."""

    # Application
    app_name: str = Field(default="SecureOps", env="APP_NAME")
    app_version: str = Field(default="1.0.0", env="APP_VERSION")
    environment: str = Field(default="development", env="ENVIRONMENT")
    debug: bool = Field(default=False, env="DEBUG")

    # API Configuration
    api_host: str = Field(default="0.0.0.0", env="API_HOST")
    api_port: int = Field(default=8000, env="API_PORT")
    api_prefix: str = Field(default="/api/v1", env="API_PREFIX")
    docs_url: str = Field(default="/docs", env="DOCS_URL")
    redoc_url: str = Field(default="/redoc", env="REDOC_URL")

    # Security
    secret_key: str = Field(
        default_factory=lambda: secrets.token_urlsafe(32), env="SECRET_KEY"
    )
    algorithm: str = Field(default="HS256", env="ALGORITHM")
    access_token_expire_minutes: int = Field(
        default=60, env="ACCESS_TOKEN_EXPIRE_MINUTES"
    )
    refresh_token_expire_days: int = Field(default=7, env="REFRESH_TOKEN_EXPIRE_DAYS")

    # CORS
    cors_origins: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:8080"], env="CORS_ORIGINS"
    )
    cors_credentials: bool = Field(default=True, env="CORS_CREDENTIALS")
    cors_methods: List[str] = Field(default=["*"], env="CORS_METHODS")
    cors_headers: List[str] = Field(default=["*"], env="CORS_HEADERS")

    # Database
    database_url: str = Field(
        default="postgresql://secureops:secureops@localhost:5432/secureops",
        env="DATABASE_URL",
    )
    async_database_url: str = Field(
        default="postgresql+asyncpg://secureops:secureops@localhost:5432/secureops",
        env="ASYNC_DATABASE_URL",
    )
    database_echo: bool = Field(default=False, env="DATABASE_ECHO")

    # Redis (for Celery and caching)
    redis_url: str = Field(default="redis://localhost:6379/0", env="REDIS_URL")
    cache_ttl: int = Field(default=3600, env="CACHE_TTL")  # seconds

    # Celery
    celery_broker_url: str = Field(
        default="redis://localhost:6379/1", env="CELERY_BROKER_URL"
    )
    celery_result_backend: str = Field(
        default="redis://localhost:6379/2", env="CELERY_RESULT_BACKEND"
    )
    celery_task_serializer: str = Field(default="json", env="CELERY_TASK_SERIALIZER")
    celery_result_serializer: str = Field(
        default="json", env="CELERY_RESULT_SERIALIZER"
    )

    # CI/CD Platform Integrations
    # GitHub
    github_app_id: Optional[str] = Field(default=None, env="GITHUB_APP_ID")
    github_private_key: Optional[str] = Field(default=None, env="GITHUB_PRIVATE_KEY")
    github_webhook_secret: Optional[str] = Field(
        default=None, env="GITHUB_WEBHOOK_SECRET"
    )

    # GitLab
    gitlab_url: str = Field(default="https://gitlab.com", env="GITLAB_URL")
    gitlab_token: Optional[str] = Field(default=None, env="GITLAB_TOKEN")
    gitlab_webhook_secret: Optional[str] = Field(
        default=None, env="GITLAB_WEBHOOK_SECRET"
    )

    # Jenkins
    jenkins_url: Optional[str] = Field(default=None, env="JENKINS_URL")
    jenkins_username: Optional[str] = Field(default=None, env="JENKINS_USERNAME")
    jenkins_token: Optional[str] = Field(default=None, env="JENKINS_TOKEN")

    # Azure DevOps
    azure_organization: Optional[str] = Field(default=None, env="AZURE_ORGANIZATION")
    azure_personal_access_token: Optional[str] = Field(
        default=None, env="AZURE_PERSONAL_ACCESS_TOKEN"
    )

    # Security Scanner Configuration
    # Bandit
    bandit_config_file: Optional[str] = Field(default=None, env="BANDIT_CONFIG_FILE")
    bandit_excluded_paths: List[str] = Field(
        default=["tests/", "venv/"], env="BANDIT_EXCLUDED_PATHS"
    )

    # Safety (Python dependencies)
    safety_api_key: Optional[str] = Field(default=None, env="SAFETY_API_KEY")
    safety_db_url: Optional[str] = Field(default=None, env="SAFETY_DB_URL")

    # Semgrep
    semgrep_config: str = Field(default="auto", env="SEMGREP_CONFIG")
    semgrep_rules: List[str] = Field(default=["p/security-audit"], env="SEMGREP_RULES")

    # Trivy (container scanning)
    trivy_cache_dir: str = Field(default="/tmp/trivy", env="TRIVY_CACHE_DIR")
    trivy_timeout: int = Field(default=300, env="TRIVY_TIMEOUT")  # seconds

    # Docker
    docker_registry_url: Optional[str] = Field(default=None, env="DOCKER_REGISTRY_URL")
    docker_registry_username: Optional[str] = Field(
        default=None, env="DOCKER_REGISTRY_USERNAME"
    )
    docker_registry_password: Optional[str] = Field(
        default=None, env="DOCKER_REGISTRY_PASSWORD"
    )

    # Notification Settings
    # Email (SMTP)
    smtp_server: Optional[str] = Field(default=None, env="SMTP_SERVER")
    smtp_port: int = Field(default=587, env="SMTP_PORT")
    smtp_username: Optional[str] = Field(default=None, env="SMTP_USERNAME")
    smtp_password: Optional[str] = Field(default=None, env="SMTP_PASSWORD")
    smtp_use_tls: bool = Field(default=True, env="SMTP_USE_TLS")
    email_from: Optional[EmailStr] = Field(default=None, env="EMAIL_FROM")

    # Slack
    slack_webhook_url: Optional[HttpUrl] = Field(default=None, env="SLACK_WEBHOOK_URL")
    slack_token: Optional[str] = Field(default=None, env="SLACK_TOKEN")
    slack_channel: str = Field(default="#security-alerts", env="SLACK_CHANNEL")

    # SendGrid
    sendgrid_api_key: Optional[str] = Field(default=None, env="SENDGRID_API_KEY")

    # Monitoring and Logging
    # Sentry
    sentry_dsn: Optional[str] = Field(default=None, env="SENTRY_DSN")
    sentry_environment: str = Field(default="development", env="SENTRY_ENVIRONMENT")

    # Prometheus
    prometheus_metrics_enabled: bool = Field(
        default=True, env="PROMETHEUS_METRICS_ENABLED"
    )
    prometheus_metrics_port: int = Field(default=8001, env="PROMETHEUS_METRICS_PORT")

    # Logging
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_format: str = Field(default="json", env="LOG_FORMAT")  # json or text
    log_file: Optional[str] = Field(default=None, env="LOG_FILE")

    # File Storage
    upload_directory: str = Field(
        default="/tmp/secureops/uploads", env="UPLOAD_DIRECTORY"
    )
    max_upload_size: int = Field(
        default=100 * 1024 * 1024, env="MAX_UPLOAD_SIZE"
    )  # 100MB

    # Rate Limiting
    rate_limit_requests: int = Field(default=100, env="RATE_LIMIT_REQUESTS")
    rate_limit_window: int = Field(default=3600, env="RATE_LIMIT_WINDOW")  # seconds

    # Webhook Configuration
    webhook_timeout: int = Field(default=30, env="WEBHOOK_TIMEOUT")  # seconds
    webhook_retry_attempts: int = Field(default=3, env="WEBHOOK_RETRY_ATTEMPTS")
    webhook_retry_delay: int = Field(default=5, env="WEBHOOK_RETRY_DELAY")  # seconds

    # Scanning Configuration
    scan_timeout: int = Field(default=1800, env="SCAN_TIMEOUT")  # 30 minutes
    concurrent_scans: int = Field(default=3, env="CONCURRENT_SCANS")
    scan_results_retention_days: int = Field(
        default=90, env="SCAN_RESULTS_RETENTION_DAYS"
    )

    # Alert Configuration
    alert_batch_size: int = Field(default=50, env="ALERT_BATCH_SIZE")
    alert_processing_interval: int = Field(
        default=60, env="ALERT_PROCESSING_INTERVAL"
    )  # seconds

    # Compliance Configuration
    compliance_frameworks: List[str] = Field(
        default=["OWASP", "NIST", "SOC2", "GDPR"], env="COMPLIANCE_FRAMEWORKS"
    )

    # Feature Flags
    enable_vulnerability_auto_resolution: bool = Field(
        default=False, env="ENABLE_VULNERABILITY_AUTO_RESOLUTION"
    )
    enable_compliance_reporting: bool = Field(
        default=True, env="ENABLE_COMPLIANCE_REPORTING"
    )
    enable_real_time_scanning: bool = Field(
        default=True, env="ENABLE_REAL_TIME_SCANNING"
    )
    enable_ml_risk_scoring: bool = Field(default=False, env="ENABLE_ML_RISK_SCORING")

<<<<<<< HEAD
    @validator("slack_webhook_url", pre=True)
    def empty_str_to_none(cls, v):
        """Convert empty strings to None for optional URL fields."""
        if v == "":
            return None
        return v

=======
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
    @validator("cors_origins", pre=True)
    def parse_cors_origins(cls, v):
        """Parse CORS origins from string or list."""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v

    @validator("bandit_excluded_paths", pre=True)
    def parse_bandit_excluded_paths(cls, v):
        """Parse excluded paths from string or list."""
        if isinstance(v, str):
            return [path.strip() for path in v.split(",")]
        return v

    @validator("semgrep_rules", pre=True)
    def parse_semgrep_rules(cls, v):
        """Parse semgrep rules from string or list."""
        if isinstance(v, str):
            return [rule.strip() for rule in v.split(",")]
        return v

    @validator("compliance_frameworks", pre=True)
    def parse_compliance_frameworks(cls, v):
        """Parse compliance frameworks from string or list."""
        if isinstance(v, str):
            return [framework.strip() for framework in v.split(",")]
        return v

    @validator("environment")
    def validate_environment(cls, v):
        """Validate environment value."""
        allowed = ["development", "staging", "production", "test"]
        if v not in allowed:
            raise ValueError(f"Environment must be one of {allowed}")
        return v

    @validator("log_level")
    def validate_log_level(cls, v):
        """Validate log level value."""
        allowed = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in allowed:
            raise ValueError(f"Log level must be one of {allowed}")
        return v.upper()

    @validator("algorithm")
    def validate_algorithm(cls, v):
        """Validate JWT algorithm."""
        allowed = ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512"]
        if v not in allowed:
            raise ValueError(f"Algorithm must be one of {allowed}")
        return v

    def get_database_url_sync(self) -> str:
        """Get synchronous database URL."""
        return self.database_url.replace("+asyncpg", "")

    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.environment == "production"

    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.environment == "development"

    def is_testing(self) -> bool:
        """Check if running in test environment."""
        return self.environment == "test"

    def get_scanner_configs(self) -> Dict[str, Dict[str, Any]]:
        """Get scanner-specific configurations."""
        return {
            "bandit": {
                "config_file": self.bandit_config_file,
                "excluded_paths": self.bandit_excluded_paths,
            },
            "safety": {
                "api_key": self.safety_api_key,
                "db_url": self.safety_db_url,
            },
            "semgrep": {
                "config": self.semgrep_config,
                "rules": self.semgrep_rules,
            },
            "trivy": {
                "cache_dir": self.trivy_cache_dir,
                "timeout": self.trivy_timeout,
            },
        }

    def get_notification_configs(self) -> Dict[str, Dict[str, Any]]:
        """Get notification service configurations."""
        return {
            "email": {
                "smtp_server": self.smtp_server,
                "smtp_port": self.smtp_port,
                "smtp_username": self.smtp_username,
                "smtp_password": self.smtp_password,
                "smtp_use_tls": self.smtp_use_tls,
                "email_from": self.email_from,
            },
            "slack": {
                "webhook_url": (
                    str(self.slack_webhook_url) if self.slack_webhook_url else None
                ),
                "token": self.slack_token,
                "channel": self.slack_channel,
            },
            "sendgrid": {
                "api_key": self.sendgrid_api_key,
            },
        }

    def get_ci_cd_configs(self) -> Dict[str, Dict[str, Any]]:
        """Get CI/CD platform configurations."""
        return {
            "github": {
                "app_id": self.github_app_id,
                "private_key": self.github_private_key,
                "webhook_secret": self.github_webhook_secret,
            },
            "gitlab": {
                "url": self.gitlab_url,
                "token": self.gitlab_token,
                "webhook_secret": self.gitlab_webhook_secret,
            },
            "jenkins": {
                "url": self.jenkins_url,
                "username": self.jenkins_username,
                "token": self.jenkins_token,
            },
            "azure": {
                "organization": self.azure_organization,
                "personal_access_token": self.azure_personal_access_token,
            },
        }

<<<<<<< HEAD
    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8", 
        "case_sensitive": False,
        "extra": "ignore"  # Ignore extra fields instead of raising validation errors
    }
=======
    class Config:
        """Pydantic configuration."""

        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3


# Development settings override
class DevelopmentSettings(Settings):
    """Development-specific settings."""

    environment: str = "development"
    debug: bool = True
    database_echo: bool = True
    log_level: str = "DEBUG"


# Production settings override
class ProductionSettings(Settings):
    """Production-specific settings."""

    environment: str = "production"
    debug: bool = False
    database_echo: bool = False
    log_level: str = "INFO"

    # Override sensitive defaults for production
    cors_origins: List[str] = []  # Must be explicitly set
    docs_url: Optional[str] = None  # Disable docs in production
    redoc_url: Optional[str] = None  # Disable redoc in production


# Testing settings override
class TestingSettings(Settings):
    """Testing-specific settings."""

    environment: str = "test"
    debug: bool = True
    database_url: str = "postgresql://test:test@localhost:5432/secureops_test"
    async_database_url: str = (
        "postgresql+asyncpg://test:test@localhost:5432/secureops_test"
    )
    redis_url: str = "redis://localhost:6379/15"  # Use different Redis DB for tests
    access_token_expire_minutes: int = 1  # Short expiry for tests


@lru_cache()
def get_settings() -> Settings:
    """
    Get application settings based on environment.

    Returns:
        Settings: Application settings instance
    """
    env = os.getenv("ENVIRONMENT", "development").lower()

    if env == "production":
        return ProductionSettings()
    elif env == "test":
        return TestingSettings()
    else:
        return DevelopmentSettings()


# Global settings instance
settings = get_settings()


def reload_settings():
    """Reload settings (useful for testing)."""
    get_settings.cache_clear()
    global settings
    settings = get_settings()


# Environment validation
def validate_environment():
    """Validate that required environment variables are set for the current environment."""
    settings = get_settings()
    errors = []
<<<<<<< HEAD
    warnings = []

    # Production-specific validations (strict)
=======

    # Production-specific validations
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
    if settings.is_production():
        required_vars = [
            ("SECRET_KEY", settings.secret_key),
            ("DATABASE_URL", settings.database_url),
            ("REDIS_URL", settings.redis_url),
        ]

        for var_name, var_value in required_vars:
            if not var_value or var_value == getattr(Settings(), var_name, None):
                errors.append(f"{var_name} must be set in production")

<<<<<<< HEAD
        # Validate that SECRET_KEY is set via environment variable in production
        import os
        if not os.getenv("SECRET_KEY"):
            errors.append("SECRET_KEY must be set via environment variable in production")

        # Strict CI/CD validation for production
        ci_cd_platforms = []
        if settings.github_app_id:
            ci_cd_platforms.append("GitHub")
            if not settings.github_private_key or not settings.github_webhook_secret:
                errors.append(
                    "GitHub integration requires APP_ID, PRIVATE_KEY, and WEBHOOK_SECRET"
                )

        if settings.gitlab_token:
            ci_cd_platforms.append("GitLab")

        if settings.jenkins_url:
            ci_cd_platforms.append("Jenkins")
            if not settings.jenkins_username or not settings.jenkins_token:
                errors.append("Jenkins integration requires URL, USERNAME, and TOKEN")

        if settings.azure_organization:
            ci_cd_platforms.append("Azure DevOps")
            if not settings.azure_personal_access_token:
                errors.append(
                    "Azure DevOps integration requires ORGANIZATION and PERSONAL_ACCESS_TOKEN"
                )

        if not ci_cd_platforms:
            errors.append("At least one CI/CD platform integration should be configured")

    # Development/staging validations (warnings only)
    else:
        # Check CI/CD integrations but only warn for development
        ci_cd_platforms = []
        if settings.github_app_id:
            ci_cd_platforms.append("GitHub")
            if not settings.github_private_key or not settings.github_webhook_secret:
                warnings.append(
                    "GitHub integration incomplete - missing PRIVATE_KEY or WEBHOOK_SECRET"
                )

        if settings.gitlab_token:
            ci_cd_platforms.append("GitLab")

        if settings.jenkins_url:
            ci_cd_platforms.append("Jenkins")
            if not settings.jenkins_username or not settings.jenkins_token:
                warnings.append("Jenkins integration incomplete - missing USERNAME or TOKEN")

        if settings.azure_organization:
            ci_cd_platforms.append("Azure DevOps")
            if not settings.azure_personal_access_token:
                warnings.append(
                    "Azure DevOps integration incomplete - missing PERSONAL_ACCESS_TOKEN"
                )

        if not ci_cd_platforms:
            warnings.append("No CI/CD platform integrations configured (optional for development)")

        # Warn about missing environment variables in development
        import os
        if not os.getenv("SECRET_KEY"):
            warnings.append("SECRET_KEY not set via environment variable (using generated key for development)")

    # Print warnings to console (non-blocking)
    if warnings:
        import sys
        print(f"\n⚠️  Configuration Warnings ({settings.environment} mode):", file=sys.stderr)
        for warning in warnings:
            print(f"  - {warning}", file=sys.stderr)
        print("", file=sys.stderr)

    # Only raise errors for critical issues (production) or fundamental problems
=======
        # Validate that default passwords/secrets are changed
        if settings.secret_key == Settings().secret_key:
            errors.append("SECRET_KEY must be changed from default value")

    # CI/CD integration validations
    ci_cd_platforms = []
    if settings.github_app_id:
        ci_cd_platforms.append("GitHub")
        if not settings.github_private_key or not settings.github_webhook_secret:
            errors.append(
                "GitHub integration requires APP_ID, PRIVATE_KEY, and WEBHOOK_SECRET"
            )

    if settings.gitlab_token:
        ci_cd_platforms.append("GitLab")

    if settings.jenkins_url:
        ci_cd_platforms.append("Jenkins")
        if not settings.jenkins_username or not settings.jenkins_token:
            errors.append("Jenkins integration requires URL, USERNAME, and TOKEN")

    if settings.azure_organization:
        ci_cd_platforms.append("Azure DevOps")
        if not settings.azure_personal_access_token:
            errors.append(
                "Azure DevOps integration requires ORGANIZATION and PERSONAL_ACCESS_TOKEN"
            )

    if not ci_cd_platforms:
        errors.append("At least one CI/CD platform integration should be configured")

>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
    if errors:
        raise ValueError(
            f"Configuration errors:\n" + "\n".join(f"- {error}" for error in errors)
        )

    return True
