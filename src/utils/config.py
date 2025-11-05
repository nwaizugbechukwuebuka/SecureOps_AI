"""
Configuration Management Module

This module handles configuration loading, validation, and management
for the SecureOps platform. Supports environment variables, config files,
and runtime configuration updates.

Author: Chukwuebuka Tobiloba Nwaizugbe
Date: 2024
"""

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


@dataclass
class DatabaseConfig:
    """Database configuration settings."""

    url: str = "sqlite:///./secureops.db"
    pool_size: int = 5
    max_overflow: int = 10
    pool_timeout: int = 30
    pool_recycle: int = 3600
    echo: bool = False


@dataclass
class RedisConfig:
    """Redis configuration settings."""

    url: str = "redis://localhost:6379/0"
    host: str = "localhost"
    port: int = 6379
    db: int = 0
    password: Optional[str] = None
    ssl: bool = False


@dataclass
class CeleryConfig:
    """Celery configuration settings."""

    broker_url: str = "redis://localhost:6379/1"
    result_backend: str = "redis://localhost:6379/1"
    task_serializer: str = "json"
    result_serializer: str = "json"
    accept_content: List[str] = field(default_factory=lambda: ["json"])
    timezone: str = "UTC"
    enable_utc: bool = True


@dataclass
class EmailConfig:
    """Email configuration settings."""

    host: str = "smtp.gmail.com"
    port: int = 587
    username: Optional[str] = None
    password: Optional[str] = None
    from_address: str = "noreply@secureops.com"
    use_tls: bool = True
    use_ssl: bool = False


@dataclass
class SecurityConfig:
    """Security configuration settings."""

    secret_key: str = "default-secret-key-change-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    password_hash_algorithm: str = "bcrypt"
    password_min_length: int = 8
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 15


@dataclass
class ScannerConfig:
    """Scanner configuration settings."""

    timeout_seconds: int = 3600
    max_concurrent_scans: int = 3
    temp_directory: str = "/tmp/secureops_scans"
    result_retention_days: int = 90
    enable_container_scanning: bool = True
    enable_dependency_scanning: bool = True
    enable_secret_scanning: bool = True
    enable_policy_checking: bool = True


@dataclass
class IntegrationConfig:
    """External integration configuration."""

    github_token: Optional[str] = None
    gitlab_token: Optional[str] = None
    azure_devops_token: Optional[str] = None
    jenkins_url: Optional[str] = None
    jenkins_username: Optional[str] = None
    jenkins_token: Optional[str] = None
    slack_webhook_url: Optional[str] = None
    teams_webhook_url: Optional[str] = None


@dataclass
class APIConfig:
    """API configuration settings."""

    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False
    reload: bool = False
    workers: int = 1
    max_request_size: int = 16 * 1024 * 1024  # 16MB
    cors_origins: List[str] = field(default_factory=lambda: ["http://localhost:3000"])
    api_v1_prefix: str = "/api/v1"


@dataclass
class LoggingConfig:
    """Logging configuration settings."""

    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file_path: Optional[str] = None
    max_bytes: int = 10485760  # 10MB
    backup_count: int = 5
    enable_json_logging: bool = False


class Settings:
    """Main settings class that aggregates all configuration."""

    def __init__(self):
        """Initialize settings by loading from environment and config files."""
        self._load_settings()

    def _load_settings(self):
        """Load settings from various sources."""
        # Load from environment variables first
        self._load_from_environment()

        # Load from config file if it exists
        config_file = os.getenv("SECUREOPS_CONFIG_FILE", "config.json")
        if os.path.exists(config_file):
            self._load_from_file(config_file)

        # Apply any runtime overrides
        self._apply_overrides()

    def _load_from_environment(self):
        """Load configuration from environment variables."""
        # Database configuration
        self.database = DatabaseConfig(
            url=os.getenv("DATABASE_URL", "sqlite:///./secureops.db"),
            pool_size=int(os.getenv("DB_POOL_SIZE", "5")),
            max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "10")),
            echo=os.getenv("DB_ECHO", "false").lower() == "true",
        )

        # Redis configuration
        self.redis = RedisConfig(
            url=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
            host=os.getenv("REDIS_HOST", "localhost"),
            port=int(os.getenv("REDIS_PORT", "6379")),
            db=int(os.getenv("REDIS_DB", "0")),
            password=os.getenv("REDIS_PASSWORD"),
            ssl=os.getenv("REDIS_SSL", "false").lower() == "true",
        )

        # Celery configuration
        self.celery = CeleryConfig(
            broker_url=os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/1"),
            result_backend=os.getenv(
                "CELERY_RESULT_BACKEND", "redis://localhost:6379/1"
            ),
        )

        # Email configuration
        self.email = EmailConfig(
            host=os.getenv("EMAIL_HOST", "smtp.gmail.com"),
            port=int(os.getenv("EMAIL_PORT", "587")),
            username=os.getenv("EMAIL_USERNAME"),
            password=os.getenv("EMAIL_PASSWORD"),
            from_address=os.getenv("EMAIL_FROM", "noreply@secureops.com"),
            use_tls=os.getenv("EMAIL_USE_TLS", "true").lower() == "true",
        )

        # Security configuration
        self.security = SecurityConfig(
            secret_key=os.getenv(
                "SECRET_KEY", "default-secret-key-change-in-production"
            ),
            access_token_expire_minutes=int(
                os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")
            ),
            refresh_token_expire_days=int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7")),
        )

        # Scanner configuration
        self.scanner = ScannerConfig(
            timeout_seconds=int(os.getenv("SCANNER_TIMEOUT", "3600")),
            max_concurrent_scans=int(os.getenv("MAX_CONCURRENT_SCANS", "3")),
            temp_directory=os.getenv("SCANNER_TEMP_DIR", "/tmp/secureops_scans"),
        )

        # Integration configuration
        self.integration = IntegrationConfig(
            github_token=os.getenv("GITHUB_TOKEN"),
            gitlab_token=os.getenv("GITLAB_TOKEN"),
            azure_devops_token=os.getenv("AZURE_DEVOPS_TOKEN"),
            jenkins_url=os.getenv("JENKINS_URL"),
            jenkins_username=os.getenv("JENKINS_USERNAME"),
            jenkins_token=os.getenv("JENKINS_TOKEN"),
            slack_webhook_url=os.getenv("SLACK_WEBHOOK_URL"),
            teams_webhook_url=os.getenv("TEAMS_WEBHOOK_URL"),
        )

        # API configuration
        self.api = APIConfig(
            host=os.getenv("API_HOST", "0.0.0.0"),
            port=int(os.getenv("API_PORT", "8000")),
            debug=os.getenv("API_DEBUG", "false").lower() == "true",
            workers=int(os.getenv("API_WORKERS", "1")),
        )

        # Logging configuration
        self.logging = LoggingConfig(
            level=os.getenv("LOG_LEVEL", "INFO"),
            file_path=os.getenv("LOG_FILE"),
            enable_json_logging=os.getenv("JSON_LOGGING", "false").lower() == "true",
        )

        # Additional settings
        self.environment = os.getenv("ENVIRONMENT", "development")
        self.version = os.getenv("VERSION", "1.0.0")
        self.app_name = os.getenv("APP_NAME", "SecureOps")

        # File paths and directories
        self.base_dir = Path(__file__).parent.parent.parent
        self.data_dir = Path(os.getenv("DATA_DIR", self.base_dir / "data"))
        self.log_dir = Path(os.getenv("LOG_DIR", self.base_dir / "logs"))
        self.temp_dir = Path(self.scanner.temp_directory)
        self.archive_dir = Path(os.getenv("ARCHIVE_DIR", self.base_dir / "archives"))
        self.cache_dir = Path(os.getenv("CACHE_DIR", self.base_dir / "cache"))

        # Ensure directories exist
        self._ensure_directories()

    def _load_from_file(self, config_file: str):
        """Load configuration from JSON file."""
        try:
            with open(config_file, "r") as f:
                config_data = json.load(f)

            # Update settings with config file values
            self._update_from_dict(config_data)

        except Exception as e:
            print(f"Warning: Could not load config file {config_file}: {e}")

    def _update_from_dict(self, config_dict: Dict[str, Any]):
        """Update settings from dictionary."""
        for section, values in config_dict.items():
            if hasattr(self, section) and isinstance(values, dict):
                section_obj = getattr(self, section)
                for key, value in values.items():
                    if hasattr(section_obj, key):
                        setattr(section_obj, key, value)

    def _apply_overrides(self):
        """Apply any runtime configuration overrides."""
        # Create convenience properties for backward compatibility
        self.DATABASE_URL = self.database.url
        self.REDIS_URL = self.redis.url
        self.CELERY_BROKER_URL = self.celery.broker_url
        self.CELERY_RESULT_BACKEND = self.celery.result_backend
        self.SECRET_KEY = self.security.secret_key
        self.EMAIL_HOST = self.email.host
        self.EMAIL_PORT = self.email.port
        self.EMAIL_USERNAME = self.email.username
        self.EMAIL_PASSWORD = self.email.password
        self.EMAIL_FROM = self.email.from_address
        self.EMAIL_USE_TLS = self.email.use_tls
        self.GITHUB_TOKEN = self.integration.github_token
        self.GITLAB_TOKEN = self.integration.gitlab_token
        self.AZURE_DEVOPS_TOKEN = self.integration.azure_devops_token
        self.AZURE_DEVOPS_URL = os.getenv("AZURE_DEVOPS_URL")
        self.JENKINS_URL = self.integration.jenkins_url
        self.SLACK_WEBHOOK_URL = self.integration.slack_webhook_url
        self.TEAMS_WEBHOOK_URL = self.integration.teams_webhook_url
        self.LOG_LEVEL = self.logging.level
        self.TEMP_DIR = str(self.temp_dir)
        self.ARCHIVE_DIR = str(self.archive_dir)
        self.CACHE_DIR = str(self.cache_dir)

    def _ensure_directories(self):
        """Ensure required directories exist."""
        directories = [
            self.data_dir,
            self.log_dir,
            self.temp_dir,
            self.archive_dir,
            self.cache_dir,
        ]

        for directory in directories:
            try:
                directory.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                print(f"Warning: Could not create directory {directory}: {e}")

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value by key."""
        return getattr(self, key, default)

    def set(self, key: str, value: Any):
        """Set a configuration value."""
        setattr(self, key, value)

    def to_dict(self) -> Dict[str, Any]:
        """Convert settings to dictionary representation."""
        result = {}

        for attr_name in dir(self):
            if not attr_name.startswith("_") and not callable(getattr(self, attr_name)):
                attr_value = getattr(self, attr_name)

                # Convert dataclass objects to dictionaries
                if hasattr(attr_value, "__dict__"):
                    result[attr_name] = attr_value.__dict__
                else:
                    result[attr_name] = attr_value

        return result

    def validate(self) -> List[str]:
        """Validate configuration and return list of issues."""
        issues = []

        # Validate required settings
        if self.security.secret_key == "default-secret-key-change-in-production":
            issues.append(
                "SECRET_KEY should be changed from default value in production"
            )

        if self.environment == "production":
            if self.api.debug:
                issues.append("API debug mode should be disabled in production")

            if not self.database.url.startswith(("postgresql://", "mysql://")):
                issues.append("Production environment should use PostgreSQL or MySQL")

        # Validate email configuration if notifications are enabled
        if self.email.username and not self.email.password:
            issues.append("Email password required when username is set")

        # Validate integration tokens
        integrations = {
            "GitHub": self.integration.github_token,
            "GitLab": self.integration.gitlab_token,
            "Azure DevOps": self.integration.azure_devops_token,
            "Jenkins": self.integration.jenkins_url,
        }

        active_integrations = [name for name, value in integrations.items() if value]
        if not active_integrations:
            issues.append(
                "No CI/CD integrations configured - limited functionality available"
            )

        return issues

    def reload(self):
        """Reload configuration from sources."""
        self._load_settings()


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Get the global settings instance."""
    return settings


def reload_settings():
    """Reload the global settings."""
    global settings
    settings.reload()


def validate_configuration() -> List[str]:
    """Validate current configuration and return issues."""
    return settings.validate()


# Configuration utilities


def get_database_url() -> str:
    """Get the database URL."""
    return settings.database.url


def is_production() -> bool:
    """Check if running in production environment."""
    return settings.environment.lower() == "production"


def is_development() -> bool:
    """Check if running in development environment."""
    return settings.environment.lower() == "development"


def get_log_level() -> str:
    """Get the configured log level."""
    return settings.logging.level


def get_scanner_timeout() -> int:
    """Get the scanner timeout in seconds."""
    return settings.scanner.timeout_seconds


def get_max_concurrent_scans() -> int:
    """Get the maximum number of concurrent scans."""
    return settings.scanner.max_concurrent_scans


def get_temp_directory() -> str:
    """Get the temporary directory path."""
    return settings.scanner.temp_directory


# Export commonly used settings for convenience
DATABASE_URL = settings.DATABASE_URL
REDIS_URL = settings.REDIS_URL
SECRET_KEY = settings.SECRET_KEY
ENVIRONMENT = settings.environment
