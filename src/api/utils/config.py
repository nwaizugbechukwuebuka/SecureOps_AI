"""Application configuration and settings."""

import os
import secrets
from functools import lru_cache
from typing import List, Optional

try:
    from pydantic_settings import BaseSettings
except ImportError:
    from pydantic import BaseSettings

from pydantic import Field, field_validator


class Settings(BaseSettings):
    """Application settings and configuration."""

    # Application
    app_name: str = Field(default="SecureOps", env="APP_NAME")
    app_version: str = Field(default="2.0.0", env="APP_VERSION")
    environment: str = Field(default="development", env="ENVIRONMENT")
    debug: bool = Field(default=False, env="DEBUG")

    # Server
    host: str = Field(default="0.0.0.0", env="HOST")
    port: int = Field(default=8000, env="PORT")
    api_host: str = Field(default="0.0.0.0", env="API_HOST")
    api_port: str = Field(default="8000", env="API_PORT")

    # Security
    secret_key: str = Field(default="dev-secret-key", env="SECRET_KEY")
    access_token_expire_minutes: int = Field(
        default=30, env="ACCESS_TOKEN_EXPIRE_MINUTES"
    )
    algorithm: str = Field(default="HS256", env="ALGORITHM")
    secure_ssl_redirect: str = Field(default="false", env="SECURE_SSL_REDIRECT")
    secure_hsts_seconds: str = Field(default="31536000", env="SECURE_HSTS_SECONDS")
    secure_content_type_nosniff: str = Field(
        default="true", env="SECURE_CONTENT_TYPE_NOSNIFF"
    )
    secure_browser_xss_filter: str = Field(
        default="true", env="SECURE_BROWSER_XSS_FILTER"
    )

    # Database
    database_url: str = Field(default="sqlite:///./secureops.db", env="DATABASE_URL")
    async_database_url: str = Field(
        default="sqlite+aiosqlite:///./secureops.db", env="ASYNC_DATABASE_URL"
    )

    # Redis
    redis_url: str = Field(default="redis://localhost:6379/0", env="REDIS_URL")

    # Celery
    celery_broker_url: str = Field(
        default="redis://redis:6379/1", env="CELERY_BROKER_URL"
    )
    celery_result_backend: str = Field(
        default="redis://redis:6379/2", env="CELERY_RESULT_BACKEND"
    )

    # CORS
    allowed_origins: List[str] = Field(default=["*"], env="ALLOWED_ORIGINS")
    allowed_hosts: List[str] = Field(default=["*"], env="ALLOWED_HOSTS")

    # Logging
    log_level: str = Field(default="INFO", env="LOG_LEVEL")

    # External Log Forwarding
    log_forward_elk_enabled: bool = Field(default=False, env="LOG_FORWARD_ELK_ENABLED")
    log_forward_elk_host: Optional[str] = Field(
        default=None, env="LOG_FORWARD_ELK_HOST"
    )
    log_forward_elk_port: Optional[int] = Field(
        default=9200, env="LOG_FORWARD_ELK_PORT"
    )
    log_forward_splunk_enabled: bool = Field(
        default=False, env="LOG_FORWARD_SPLUNK_ENABLED"
    )
    log_forward_splunk_host: Optional[str] = Field(
        default=None, env="LOG_FORWARD_SPLUNK_HOST"
    )
    log_forward_splunk_port: Optional[int] = Field(
        default=8088, env="LOG_FORWARD_SPLUNK_PORT"
    )
    log_forward_splunk_token: Optional[str] = Field(
        default=None, env="LOG_FORWARD_SPLUNK_TOKEN"
    )

    # GitHub Integration
    github_token: Optional[str] = Field(default=None, env="GITHUB_TOKEN")
    github_webhook_secret: Optional[str] = Field(
        default=None, env="GITHUB_WEBHOOK_SECRET"
    )

    # GitLab Integration
    gitlab_token: Optional[str] = Field(default=None, env="GITLAB_TOKEN")
    gitlab_url: str = Field(default="https://gitlab.com", env="GITLAB_URL")

    # Jenkins Integration
    jenkins_url: Optional[str] = Field(default=None, env="JENKINS_URL")
    jenkins_username: Optional[str] = Field(default=None, env="JENKINS_USERNAME")
    jenkins_token: Optional[str] = Field(default=None, env="JENKINS_TOKEN")

    # Security Scanning
    enable_dependency_scanning: bool = Field(
        default=True, env="ENABLE_DEPENDENCY_SCANNING"
    )
    enable_secret_scanning: bool = Field(default=True, env="ENABLE_SECRET_SCANNING")
    enable_docker_scanning: bool = Field(default=True, env="ENABLE_DOCKER_SCANNING")

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v

    @field_validator("allowed_hosts", mode="before")
    @classmethod
    def parse_allowed_hosts(cls, v):
        if isinstance(v, str):
            return [host.strip() for host in v.split(",")]
        return v

    def is_production(self) -> bool:
        return self.environment.lower() == "production"

    def is_development(self) -> bool:
        return self.environment.lower() == "development"

    @property
    def SECRET_KEY(self) -> str:
        """Alias for secret_key to maintain backward compatibility."""
        return self.secret_key

    class Config:
        env_file = ".env"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


def validate_environment():
    """Validate environment configuration."""
    settings = get_settings()

    # Basic validation for critical settings
    if settings.is_production():
        if settings.secret_key == "dev-secret-key":
            raise ValueError("SECRET_KEY must be set for production")

    if not settings.database_url:
        raise ValueError("DATABASE_URL must be configured")


# Global settings instance
settings = get_settings()
