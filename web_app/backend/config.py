"""
Configuration settings for SecureOps AI Backend
Environment variables and application settings
"""

import os
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """Application settings with environment variable support"""

    model_config = {"extra": "ignore", "env_file": ".env", "env_file_encoding": "utf-8", "case_sensitive": False}

    # Application Info
    app_name: str = "SecureOps AI Backend"
    app_version: str = "1.0.0"
    debug: bool = False

    # Server Configuration
    host: str = "0.0.0.0"
    port: int = 8001
    reload: bool = True
    log_level: str = "info"

    # Database Configuration
    database_url: str = "sqlite:///./secureops.db"
    database_echo: bool = False

    # Security Configuration
    secret_key: str = "your-secret-key-change-in-production-please"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30

    # Frontend Configuration
    frontend_url: str = "http://localhost:3010"
    cors_origins: str = (
        "http://localhost:3010,http://localhost:3000,http://127.0.0.1:3010,http://127.0.0.1:3000,https://nwaizugbechukwuebuka.github.io,https://*.github.io,https://secureops-ai-frontend.vercel.app"
    )

    @property
    def cors_origins_list(self) -> list:
        """Parse CORS origins string into list"""
        if isinstance(self.cors_origins, str):
            return [origin.strip() for origin in self.cors_origins.split(",")]
        return self.cors_origins

    # Redis Configuration (for future use)
    redis_url: str = "redis://localhost:6379"

    # API Configuration
    api_prefix: str = "/api"
    docs_url: str = "/docs"
    redoc_url: str = "/redoc"

    # File Storage
    upload_dir: str = "./uploads"
    max_file_size: int = 10 * 1024 * 1024  # 10MB

    # Logging
    log_file: str = "./logs/secureops.log"
    log_max_size: int = 10 * 1024 * 1024  # 10MB
    log_backup_count: int = 5

    # Security Settings
    bcrypt_rounds: int = 12
    password_min_length: int = 6
    session_timeout: int = 3600  # 1 hour in seconds

    # Rate Limiting
    rate_limit_requests: int = 100
    rate_limit_window: int = 60  # seconds

    # WebSocket Configuration
    websocket_ping_interval: int = 20
    websocket_ping_timeout: int = 10

    # Development Settings
    fake_data: bool = True  # Generate fake data for development
    auto_reload: bool = True


# Create global settings instance
settings = Settings()

# Database URL variants for different environments


def get_database_url() -> str:
    """Get database URL with environment-specific defaults"""
    db_url = settings.database_url

    # Override with environment variable if set
    if os.getenv("DATABASE_URL"):
        db_url = os.getenv("DATABASE_URL")

    # Development PostgreSQL override
    if os.getenv("USE_POSTGRESQL", "").lower() == "true":
        db_host = os.getenv("DB_HOST", "localhost")
        db_port = os.getenv("DB_PORT", "5432")
        db_user = os.getenv("DB_USER", "secureops")
        db_password = os.getenv("DB_PASSWORD", "secureops123")
        db_name = os.getenv("DB_NAME", "secureops_db")
        db_url = f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"

    return db_url


# Logging configuration
LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {"format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"},
        "detailed": {"format": "%(asctime)s - %(name)s - %(levelname)s - %(module)s - %(funcName)s - %(message)s"},
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": "INFO",
            "formatter": "default",
            "stream": "ext://sys.stdout",
        },
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "level": "DEBUG",
            "formatter": "detailed",
            "filename": settings.log_file,
            "maxBytes": settings.log_max_size,
            "backupCount": settings.log_backup_count,
        },
    },
    "loggers": {
        "": {"level": "INFO", "handlers": ["console", "file"], "propagate": False},
        "secureops": {"level": "DEBUG", "handlers": ["console", "file"], "propagate": False},
        "uvicorn": {"level": "INFO", "handlers": ["console"], "propagate": False},
    },
}

# CORS settings
CORS_SETTINGS = {
    "allow_origins": settings.cors_origins_list,
    "allow_credentials": True,
    "allow_methods": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    "allow_headers": [
        "Accept",
        "Accept-Language",
        "Content-Language",
        "Content-Type",
        "Authorization",
        "X-Requested-With",
        "X-CSRF-Token",
    ],
}

# Default admin user configuration
DEFAULT_ADMIN = {
    "username": "admin",
    "email": "admin@secureops.ai",
    "full_name": "System Administrator",
    "password": "admin123",
    "is_admin": True,
    "is_active": True,
    "role": "admin",
}

DEFAULT_DEMO_USER = {
    "username": "demo",
    "email": "demo@secureops.ai",
    "full_name": "Demo User",
    "password": "demo123",
    "is_admin": False,
    "is_active": True,
    "role": "user",
}
