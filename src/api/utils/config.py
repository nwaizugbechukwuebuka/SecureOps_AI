"""Application configuration and settings."""

import os
import secrets
from functools import lru_cache
from typing import List, Optional

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict
except ImportError:
    from pydantic import BaseSettings
    # Fallback for older pydantic versions
    class SettingsConfigDict(dict):
        pass

from pydantic import Field, field_validator


class Settings(BaseSettings):
    """Application settings and configuration."""

    try:
        model_config = SettingsConfigDict(
            env_file=".env",
            case_sensitive=False
        )
    except:
        # Fallback for older pydantic versions
        class Config:
            env_file = ".env"
            case_sensitive = False

    # Application
    app_name: str = Field(default="SecureOps")
    app_version: str = Field(default="2.0.0")
    environment: str = Field(default="development")
    debug: bool = Field(default=False)

    # Server
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8000)
    api_host: str = Field(default="0.0.0.0")
    api_port: str = Field(default="8000")

    # Security
    secret_key: str = Field(default="dev-secret-key")
    access_token_expire_minutes: int = Field(default=30)
    algorithm: str = Field(default="HS256")
    secure_ssl_redirect: str = Field(default="false")
    secure_hsts_seconds: str = Field(default="31536000")
    secure_content_type_nosniff: str = Field(default="true")
    secure_browser_xss_filter: str = Field(default="true")

    # Database
    database_url: str = Field(default="sqlite:///./secureops.db")
    async_database_url: str = Field(default="sqlite+aiosqlite:///./secureops.db")

    # Redis
    redis_url: str = Field(default="redis://localhost:6379/0")

    # Celery
    celery_broker_url: str = Field(default="redis://redis:6379/1")
    celery_result_backend: str = Field(default="redis://redis:6379/2")

    # CORS
    allowed_origins: List[str] = Field(default=["*"])
    allowed_hosts: List[str] = Field(default=["*"])

    # Logging
    log_level: str = Field(default="INFO")

    # External Log Forwarding
    log_forward_elk_enabled: bool = Field(default=False)
    log_forward_elk_host: Optional[str] = Field(default=None)
    log_forward_elk_port: Optional[int] = Field(default=9200)
    log_forward_splunk_enabled: bool = Field(default=False)
    log_forward_splunk_host: Optional[str] = Field(
        default=None, env="LOG_FORWARD_SPLUNK_HOST"
    )
    log_forward_splunk_port: Optional[int] = Field(
        default=8088, env="LOG_FORWARD_SPLUNK_PORT"
    )
    log_forward_splunk_token: Optional[str] = Field(default=None)

    # GitHub Integration
    github_token: Optional[str] = Field(default=None)
    github_webhook_secret: Optional[str] = Field(default=None)

    # GitLab Integration
    gitlab_token: Optional[str] = Field(default=None)
    gitlab_url: str = Field(default="https://gitlab.com")

    # Jenkins Integration
    jenkins_url: Optional[str] = Field(default=None)
    jenkins_username: Optional[str] = Field(default=None)
    jenkins_token: Optional[str] = Field(default=None)

    # Security Scanning
    enable_dependency_scanning: bool = Field(default=True)
    enable_secret_scanning: bool = Field(default=True)
    enable_docker_scanning: bool = Field(default=True)

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
    def jwt_secret_key(self) -> str:
        """Alias for secret_key to maintain backward compatibility."""
        return self.secret_key


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
