"""
Centralized configuration for SecureOps AI Platform.
Comprehensive settings that interconnect all system components:
- Database and caching configuration  
- Celery task system settings
- Security and authentication
- CI/CD integrations 
- Scanner configurations
- Monitoring and alerting
- Third-party service integrations

Author: Chukwuebuka Tobiloba Nwaizugbe
Date: 2024
"""

import os
from typing import List, Optional, Dict, Any
from pydantic import Field, validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Comprehensive settings for SecureOps AI Platform."""
    
    # ====== APPLICATION SETTINGS ======
    app_name: str = Field(default="SecureOps AI Platform")
    app_version: str = Field(default="2.0.0")
    environment: str = Field(default="production")
    debug: bool = Field(default=False)
    log_level: str = Field(default="INFO")
    log_format: str = Field(default="json")
    secret_key: str = Field(default_factory=lambda: os.getenv("SECRET_KEY", "super-secret-key-change-in-production"))
    
    # ====== DATABASE CONFIGURATION ======
    database_url: str = Field(
        default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///./secureops.db")
    )
    database_pool_size: int = Field(default=20)
    database_max_overflow: int = Field(default=30)
    database_pool_timeout: int = Field(default=30)
    database_pool_recycle: int = Field(default=3600)
    
    # ====== REDIS/CACHING CONFIGURATION ======
    redis_url: str = Field(
        default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379/0")
    )
    cache_ttl: int = Field(default=300)  # 5 minutes
    cache_prefix: str = Field(default="secureops")
    
    # ====== CELERY TASK SYSTEM ======
    celery_broker_url: str = Field(
        default_factory=lambda: os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/1")
    )
    celery_result_backend: str = Field(
        default_factory=lambda: os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/2")
    )
    celery_task_serializer: str = Field(default="json")
    celery_result_serializer: str = Field(default="json")
    celery_result_expires: int = Field(default=7200)  # 2 hours
    celery_task_time_limit: int = Field(default=3600)  # 1 hour
    celery_task_soft_time_limit: int = Field(default=3300)  # 55 minutes
    celery_max_tasks_per_child: int = Field(default=1000)
    celery_always_eager: bool = Field(default=False)
    celery_log_file: Optional[str] = Field(default=None)
    
    # ====== SECURITY SETTINGS ======
    jwt_secret_key: str = Field(
        default_factory=lambda: os.getenv("JWT_SECRET_KEY", "jwt-secret-key-change-me")
    )
    jwt_algorithm: str = Field(default="HS256")
    jwt_access_token_expire_minutes: int = Field(default=60)
    jwt_refresh_token_expire_days: int = Field(default=7)
    password_min_length: int = Field(default=8)
    bcrypt_rounds: int = Field(default=12)
    session_secret_key: str = Field(
        default_factory=lambda: os.getenv("SESSION_SECRET_KEY", "session-secret-change-me")
    )
    
    # ====== CORS CONFIGURATION ======
    cors_origins: List[str] = Field(default=["*"])
    cors_allow_credentials: bool = Field(default=True)
    cors_allow_methods: List[str] = Field(default=["*"])
    cors_allow_headers: List[str] = Field(default=["*"])
    
    # ====== SCANNER CONFIGURATIONS ======
    # Dependency scanning
    dependency_scan_timeout: int = Field(default=600)  # 10 minutes
    dependency_scan_concurrent_limit: int = Field(default=3)
    supported_package_managers: List[str] = Field(
        default=["npm", "pip", "maven", "gradle", "composer", "bundler", "go", "cargo"]
    )
    
    # Docker scanning
    docker_scan_timeout: int = Field(default=900)  # 15 minutes
    docker_scan_concurrent_limit: int = Field(default=2)
    docker_registry_url: Optional[str] = Field(default=None)
    docker_registry_username: Optional[str] = Field(default=None)
    docker_registry_password: Optional[str] = Field(default=None)
    
    # Secret scanning
    secret_scan_timeout: int = Field(default=300)  # 5 minutes
    secret_scan_concurrent_limit: int = Field(default=5)
    secret_patterns_file: str = Field(default="patterns/secret_patterns.json")
    secret_exclude_patterns: List[str] = Field(default=["*.log", "*.tmp", "node_modules/*"])
    
    # Compliance scanning
    compliance_scan_timeout: int = Field(default=1200)  # 20 minutes  
    compliance_frameworks: List[str] = Field(
        default=["OWASP", "CIS", "NIST", "SOX", "HIPAA", "GDPR"]
    )
    
    # ====== CI/CD INTEGRATION SETTINGS ======
    # GitHub Actions
    github_app_id: Optional[str] = Field(default=None)
    github_private_key: Optional[str] = Field(default=None)
    github_webhook_secret: Optional[str] = Field(default=None)
    github_api_url: str = Field(default="https://api.github.com")
    github_timeout: int = Field(default=30)
    
    # GitLab CI
    gitlab_api_token: Optional[str] = Field(default=None)
    gitlab_webhook_secret: Optional[str] = Field(default=None)
    gitlab_api_url: str = Field(default="https://gitlab.com/api/v4")
    gitlab_timeout: int = Field(default=30)
    
    # Azure DevOps
    azure_personal_access_token: Optional[str] = Field(default=None)
    azure_webhook_secret: Optional[str] = Field(default=None)
    azure_organization: Optional[str] = Field(default=None)
    azure_api_version: str = Field(default="6.0")
    azure_timeout: int = Field(default=30)
    
    # Jenkins
    jenkins_url: Optional[str] = Field(default=None)
    jenkins_username: Optional[str] = Field(default=None)
    jenkins_api_token: Optional[str] = Field(default=None)
    jenkins_webhook_secret: Optional[str] = Field(default=None)
    jenkins_timeout: int = Field(default=30)
    
    # ====== ALERT AND NOTIFICATION SETTINGS ======
    # Email notifications
    email_enabled: bool = Field(default=False)
    smtp_server: Optional[str] = Field(default=None)
    smtp_port: int = Field(default=587)
    smtp_username: Optional[str] = Field(default=None)
    smtp_password: Optional[str] = Field(default=None)
    smtp_use_tls: bool = Field(default=True)
    email_from_address: str = Field(default="alerts@secureops.ai")
    
    # Slack notifications
    slack_enabled: bool = Field(default=False)
    slack_webhook_url: Optional[str] = Field(default=None)
    slack_channel: str = Field(default="#security-alerts")
    slack_username: str = Field(default="SecureOps AI")
    
    # Teams notifications
    teams_enabled: bool = Field(default=False)
    teams_webhook_url: Optional[str] = Field(default=None)
    
    # PagerDuty integration
    pagerduty_enabled: bool = Field(default=False)
    pagerduty_service_key: Optional[str] = Field(default=None)
    pagerduty_api_url: str = Field(default="https://events.pagerduty.com")
    
    # ====== MONITORING AND HEALTH CHECK SETTINGS ======
    health_check_interval: int = Field(default=300)  # 5 minutes
    metrics_enabled: bool = Field(default=True)
    metrics_endpoint: str = Field(default="/metrics")
    monitoring_retention_days: int = Field(default=30)
    
    # ====== DATA RETENTION AND CLEANUP ======
    default_retention_days: int = Field(default=30)
    vulnerability_retention_days: int = Field(default=90)
    log_retention_days: int = Field(default=7)
    temp_file_max_age_hours: int = Field(default=24)
    max_cleanup_batch_size: int = Field(default=1000)
    database_maintenance_interval_hours: int = Field(default=24)
    
    # ====== PERFORMANCE SETTINGS ======
    max_concurrent_scans: int = Field(default=5)
    scan_queue_timeout: int = Field(default=3600)  # 1 hour
    api_rate_limit_per_minute: int = Field(default=100)
    max_file_size_mb: int = Field(default=100)
    max_repository_size_gb: int = Field(default=5)
    
    # ====== THIRD-PARTY SERVICE INTEGRATIONS ======
    # AWS Services
    aws_access_key_id: Optional[str] = Field(default=None)
    aws_secret_access_key: Optional[str] = Field(default=None)
    aws_region: str = Field(default="us-east-1")
    s3_bucket: Optional[str] = Field(default=None)
    kms_key_id: Optional[str] = Field(default=None)
    
    # Sentry for error monitoring
    sentry_dsn: Optional[str] = Field(default=None)
    sentry_environment: str = Field(default="production")
    sentry_traces_sample_rate: float = Field(default=0.1)
    
    # OpenAI for AI features
    openai_api_key: Optional[str] = Field(default=None)
    openai_model: str = Field(default="gpt-4")
    openai_max_tokens: int = Field(default=2000)
    
    # ====== FRONTEND SETTINGS ======
    frontend_url: str = Field(default="http://localhost:3000")
    api_base_url: str = Field(default="http://localhost:8000")
    websocket_url: str = Field(default="ws://localhost:8000/ws")
    
    # ====== WEBHOOK SETTINGS ======
    webhook_timeout: int = Field(default=30)
    webhook_retry_attempts: int = Field(default=3)
    webhook_retry_delay: int = Field(default=5)
    
    @validator('cors_origins', pre=True)
    def validate_cors_origins(cls, v):
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(',') if origin.strip()]
        return v
    
    @validator('supported_package_managers', pre=True)
    def validate_package_managers(cls, v):
        if isinstance(v, str):
            return [pm.strip() for pm in v.split(',') if pm.strip()]
        return v
    
    @validator('compliance_frameworks', pre=True) 
    def validate_compliance_frameworks(cls, v):
        if isinstance(v, str):
            return [fw.strip() for fw in v.split(',') if fw.strip()]
        return v

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        env_prefix = ""
        case_sensitive = False
        
        # Example environment variable mappings
        fields = {
            'database_url': {'env': 'DATABASE_URL'},
            'redis_url': {'env': 'REDIS_URL'},
            'celery_broker_url': {'env': 'CELERY_BROKER_URL'},
            'celery_result_backend': {'env': 'CELERY_RESULT_BACKEND'},
            'jwt_secret_key': {'env': 'JWT_SECRET_KEY'},
            'github_app_id': {'env': 'GITHUB_APP_ID'},
            'github_private_key': {'env': 'GITHUB_PRIVATE_KEY'},
            'github_webhook_secret': {'env': 'GITHUB_WEBHOOK_SECRET'},
            'gitlab_api_token': {'env': 'GITLAB_API_TOKEN'},
            'azure_personal_access_token': {'env': 'AZURE_PAT'},
            'jenkins_api_token': {'env': 'JENKINS_API_TOKEN'},
            'smtp_password': {'env': 'SMTP_PASSWORD'},
            'slack_webhook_url': {'env': 'SLACK_WEBHOOK_URL'},
            'aws_access_key_id': {'env': 'AWS_ACCESS_KEY_ID'},
            'aws_secret_access_key': {'env': 'AWS_SECRET_ACCESS_KEY'},
            'sentry_dsn': {'env': 'SENTRY_DSN'},
            'openai_api_key': {'env': 'OPENAI_API_KEY'}
        }


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Get the global settings instance."""
    return settings


# Database URL variants for different environments
def get_database_url(environment: str = None) -> str:
    """Get database URL based on environment."""
    env = environment or settings.environment
    
    if env == "test":
        return "sqlite:///./test_secureops.db"
    elif env == "development":
        return settings.database_url.replace("postgresql://", "postgresql+asyncpg://")
    else:
        return settings.database_url


# Feature flags for conditional functionality
class FeatureFlags:
    """Feature flags to enable/disable functionality based on configuration."""
    
    @staticmethod
    def ai_features_enabled() -> bool:
        """Check if AI features are enabled."""
        return bool(settings.openai_api_key)
    
    @staticmethod  
    def github_integration_enabled() -> bool:
        """Check if GitHub integration is enabled."""
        return bool(settings.github_app_id and settings.github_private_key)
    
    @staticmethod
    def gitlab_integration_enabled() -> bool:
        """Check if GitLab integration is enabled."""
        return bool(settings.gitlab_api_token)
    
    @staticmethod
    def azure_integration_enabled() -> bool:
        """Check if Azure DevOps integration is enabled."""
        return bool(settings.azure_personal_access_token)
    
    @staticmethod
    def jenkins_integration_enabled() -> bool:
        """Check if Jenkins integration is enabled."""
        return bool(settings.jenkins_url and settings.jenkins_api_token)
    
    @staticmethod
    def email_notifications_enabled() -> bool:
        """Check if email notifications are enabled."""
        return settings.email_enabled and bool(settings.smtp_server)
    
    @staticmethod
    def slack_notifications_enabled() -> bool:
        """Check if Slack notifications are enabled."""
        return settings.slack_enabled and bool(settings.slack_webhook_url)
    
    @staticmethod
    def aws_services_enabled() -> bool:
        """Check if AWS services are enabled."""
        return bool(settings.aws_access_key_id and settings.aws_secret_access_key)
    
    @staticmethod
    def monitoring_enabled() -> bool:
        """Check if monitoring features are enabled."""
        return settings.metrics_enabled


# Configuration validation
def validate_configuration():
    """Validate critical configuration settings."""
    errors = []
    
    # Check required secrets
    if settings.environment == "production":
        if settings.secret_key == "super-secret-key-change-in-production":
            errors.append("SECRET_KEY must be changed in production")
        
        if settings.jwt_secret_key == "jwt-secret-key-change-me":
            errors.append("JWT_SECRET_KEY must be changed in production")
    
    # Check database configuration
    if not settings.database_url:
        errors.append("DATABASE_URL is required")
    
    # Check Celery configuration
    if not settings.celery_broker_url:
        errors.append("CELERY_BROKER_URL is required")
    
    if errors:
        raise ValueError(f"Configuration validation failed: {'; '.join(errors)}")
    
    return True
