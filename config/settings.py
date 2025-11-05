"""
Centralized configuration for SecureOps.
Loads environment variables, DB, AWS, and other settings.
"""
import os
from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional

class Settings(BaseSettings):
    # App
    app_name: str = Field(default="SecureOps")
    environment: str = Field(default="production")
    debug: bool = Field(default=False)
    log_level: str = Field(default="INFO")
    log_format: str = Field(default="json")
    app_version: str = Field(default="1.0.0")

    # Database
    db_url: str = Field(default_factory=lambda: os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/secureops"))

    # AWS
    aws_access_key_id: Optional[str] = Field(default=None)
    aws_secret_access_key: Optional[str] = Field(default=None)
    aws_region: str = Field(default="us-east-1")
    s3_bucket: Optional[str] = Field(default=None)
    kms_key_id: Optional[str] = Field(default=None)

    # Redis
    redis_url: str = Field(default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379/0"))

    # Sentry
    sentry_dsn: Optional[str] = Field(default=None)
    sentry_environment: str = Field(default="production")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()
