"""
Configuration management utilities for Flask application.

This module provides enterprise-grade configuration management with environment variable
handling, configuration validation, and settings management. Implements the migration
from Node.js JSON configuration files to Python modules with comprehensive validation
and environment-specific loading capabilities.

Features:
    - Environment variable management using python-dotenv 1.0+
    - Configuration validation and type safety
    - Environment-specific configuration loading (dev/staging/production)
    - Enterprise security integration (Auth0, AWS, monitoring)
    - Flask application factory pattern support
    - Database and cache configuration management
    - External service integration configuration
"""

import os
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

from dotenv import load_dotenv


# Configuration validation functions (basic implementations until validators.py is available)
def validate_url(url: str) -> bool:
    """Validate URL format."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def validate_email(email: str) -> bool:
    """Basic email validation."""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_port(port: Union[str, int]) -> bool:
    """Validate port number."""
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False


class ConfigurationError(Exception):
    """Configuration-related errors."""
    pass


class ValidationError(Exception):
    """Configuration validation errors."""
    pass


@dataclass
class DatabaseConfig:
    """Database configuration settings."""
    host: str = "localhost"
    port: int = 27017
    name: str = "app_db"
    username: Optional[str] = None
    password: Optional[str] = None
    connection_timeout: int = 10000
    max_pool_size: int = 50
    wait_queue_timeout: int = 30000
    server_selection_timeout: int = 10000
    replica_set: Optional[str] = None
    auth_source: str = "admin"
    ssl: bool = False
    ssl_cert_reqs: str = "required"
    
    @property
    def uri(self) -> str:
        """Generate MongoDB connection URI."""
        if self.username and self.password:
            auth = f"{self.username}:{self.password}@"
        else:
            auth = ""
        
        options = [
            f"authSource={self.auth_source}",
            f"connectTimeoutMS={self.connection_timeout}",
            f"maxPoolSize={self.max_pool_size}",
            f"waitQueueTimeoutMS={self.wait_queue_timeout}",
            f"serverSelectionTimeoutMS={self.server_selection_timeout}",
        ]
        
        if self.replica_set:
            options.append(f"replicaSet={self.replica_set}")
        
        if self.ssl:
            options.append("ssl=true")
            options.append(f"ssl_cert_reqs={self.ssl_cert_reqs}")
        
        options_str = "&".join(options)
        return f"mongodb://{auth}{self.host}:{self.port}/{self.name}?{options_str}"
    
    def validate(self) -> None:
        """Validate database configuration."""
        if not self.host:
            raise ValidationError("Database host is required")
        
        if not validate_port(self.port):
            raise ValidationError(f"Invalid database port: {self.port}")
        
        if not self.name:
            raise ValidationError("Database name is required")
        
        if self.max_pool_size <= 0:
            raise ValidationError("Max pool size must be positive")


@dataclass
class RedisConfig:
    """Redis cache configuration settings."""
    host: str = "localhost"
    port: int = 6379
    db: int = 0
    password: Optional[str] = None
    socket_timeout: float = 30.0
    socket_connect_timeout: float = 10.0
    max_connections: int = 50
    retry_on_timeout: bool = True
    health_check_interval: int = 30
    ssl: bool = False
    ssl_cert_reqs: str = "required"
    
    @property
    def url(self) -> str:
        """Generate Redis connection URL."""
        scheme = "rediss" if self.ssl else "redis"
        auth = f":{self.password}@" if self.password else ""
        return f"{scheme}://{auth}{self.host}:{self.port}/{self.db}"
    
    def validate(self) -> None:
        """Validate Redis configuration."""
        if not self.host:
            raise ValidationError("Redis host is required")
        
        if not validate_port(self.port):
            raise ValidationError(f"Invalid Redis port: {self.port}")
        
        if self.db < 0:
            raise ValidationError("Redis database number must be non-negative")
        
        if self.max_connections <= 0:
            raise ValidationError("Max connections must be positive")


@dataclass
class Auth0Config:
    """Auth0 authentication configuration."""
    domain: str = ""
    client_id: str = ""
    client_secret: str = ""
    audience: str = ""
    algorithm: str = "RS256"
    issuer_base_url: str = ""
    token_url: str = ""
    userinfo_url: str = ""
    jwks_uri: str = ""
    connection_timeout: float = 10.0
    read_timeout: float = 30.0
    
    def validate(self) -> None:
        """Validate Auth0 configuration."""
        if not self.domain:
            raise ValidationError("Auth0 domain is required")
        
        if not self.client_id:
            raise ValidationError("Auth0 client ID is required")
        
        if not self.client_secret:
            raise ValidationError("Auth0 client secret is required")
        
        if self.issuer_base_url and not validate_url(self.issuer_base_url):
            raise ValidationError("Invalid Auth0 issuer base URL")


@dataclass
class AWSConfig:
    """AWS services configuration."""
    region: str = "us-east-1"
    access_key_id: Optional[str] = None
    secret_access_key: Optional[str] = None
    session_token: Optional[str] = None
    s3_bucket: str = ""
    max_pool_connections: int = 50
    retries_max_attempts: int = 3
    retries_mode: str = "adaptive"
    connect_timeout: float = 10.0
    read_timeout: float = 30.0
    
    def validate(self) -> None:
        """Validate AWS configuration."""
        if not self.region:
            raise ValidationError("AWS region is required")
        
        if self.s3_bucket and not self.s3_bucket.replace("-", "").replace(".", "").isalnum():
            raise ValidationError("Invalid S3 bucket name format")


@dataclass
class LoggingConfig:
    """Logging configuration settings."""
    level: str = "INFO"
    format: str = "json"
    enable_structured_logging: bool = True
    log_file: Optional[str] = None
    max_file_size: int = 10485760  # 10MB
    backup_count: int = 5
    enable_audit_logging: bool = True
    audit_log_file: Optional[str] = None
    
    def validate(self) -> None:
        """Validate logging configuration."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.level.upper() not in valid_levels:
            raise ValidationError(f"Invalid log level: {self.level}")
        
        valid_formats = ["json", "text"]
        if self.format.lower() not in valid_formats:
            raise ValidationError(f"Invalid log format: {self.format}")


@dataclass
class MonitoringConfig:
    """Monitoring and observability configuration."""
    enable_metrics: bool = True
    metrics_port: int = 9090
    enable_health_checks: bool = True
    health_check_path: str = "/health"
    readiness_check_path: str = "/health/ready"
    liveness_check_path: str = "/health/live"
    enable_performance_monitoring: bool = True
    apm_service_name: str = "flask-app"
    enable_prometheus: bool = True
    
    def validate(self) -> None:
        """Validate monitoring configuration."""
        if self.enable_metrics and not validate_port(self.metrics_port):
            raise ValidationError(f"Invalid metrics port: {self.metrics_port}")


@dataclass
class SecurityConfig:
    """Security configuration settings."""
    secret_key: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    jwt_secret_key: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    jwt_algorithm: str = "HS256"
    jwt_access_token_expires: int = 3600  # 1 hour
    jwt_refresh_token_expires: int = 86400  # 24 hours
    password_hash_rounds: int = 12
    session_cookie_secure: bool = True
    session_cookie_httponly: bool = True
    session_cookie_samesite: str = "Lax"
    csrf_enabled: bool = True
    cors_origins: List[str] = field(default_factory=list)
    rate_limit_enabled: bool = True
    rate_limit_default: str = "100 per hour"
    
    def validate(self) -> None:
        """Validate security configuration."""
        if len(self.secret_key) < 32:
            raise ValidationError("Secret key must be at least 32 characters")
        
        if len(self.jwt_secret_key) < 32:
            raise ValidationError("JWT secret key must be at least 32 characters")
        
        valid_samesite = ["Strict", "Lax", "None"]
        if self.session_cookie_samesite not in valid_samesite:
            raise ValidationError(f"Invalid SameSite value: {self.session_cookie_samesite}")


@dataclass
class FlaskConfig:
    """Flask framework configuration."""
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False
    testing: bool = False
    threaded: bool = True
    processes: int = 1
    max_content_length: int = 16777216  # 16MB
    send_file_max_age_default: int = 43200  # 12 hours
    permanent_session_lifetime: int = 3600  # 1 hour
    session_refresh_each_request: bool = True
    
    def validate(self) -> None:
        """Validate Flask configuration."""
        if not validate_port(self.port):
            raise ValidationError(f"Invalid Flask port: {self.port}")
        
        if self.max_content_length <= 0:
            raise ValidationError("Max content length must be positive")


class BaseConfig(ABC):
    """Abstract base configuration class."""
    
    def __init__(self):
        """Initialize configuration with environment variables."""
        self.load_environment()
        self.database = DatabaseConfig()
        self.redis = RedisConfig()
        self.auth0 = Auth0Config()
        self.aws = AWSConfig()
        self.logging = LoggingConfig()
        self.monitoring = MonitoringConfig()
        self.security = SecurityConfig()
        self.flask = FlaskConfig()
        self._load_configuration()
        self.validate()
    
    @abstractmethod
    def load_environment(self) -> None:
        """Load environment-specific settings."""
        pass
    
    def _load_configuration(self) -> None:
        """Load configuration from environment variables."""
        # Database configuration
        self.database.host = os.getenv("DATABASE_HOST", self.database.host)
        self.database.port = int(os.getenv("DATABASE_PORT", self.database.port))
        self.database.name = os.getenv("DATABASE_NAME", self.database.name)
        self.database.username = os.getenv("DATABASE_USERNAME")
        self.database.password = os.getenv("DATABASE_PASSWORD")
        self.database.replica_set = os.getenv("DATABASE_REPLICA_SET")
        self.database.ssl = os.getenv("DATABASE_SSL", "false").lower() == "true"
        
        # Redis configuration
        self.redis.host = os.getenv("REDIS_HOST", self.redis.host)
        self.redis.port = int(os.getenv("REDIS_PORT", self.redis.port))
        self.redis.db = int(os.getenv("REDIS_DB", self.redis.db))
        self.redis.password = os.getenv("REDIS_PASSWORD")
        self.redis.ssl = os.getenv("REDIS_SSL", "false").lower() == "true"
        
        # Auth0 configuration
        self.auth0.domain = os.getenv("AUTH0_DOMAIN", "")
        self.auth0.client_id = os.getenv("AUTH0_CLIENT_ID", "")
        self.auth0.client_secret = os.getenv("AUTH0_CLIENT_SECRET", "")
        self.auth0.audience = os.getenv("AUTH0_AUDIENCE", "")
        self.auth0.issuer_base_url = os.getenv("AUTH0_ISSUER_BASE_URL", "")
        
        # AWS configuration
        self.aws.region = os.getenv("AWS_REGION", self.aws.region)
        self.aws.access_key_id = os.getenv("AWS_ACCESS_KEY_ID")
        self.aws.secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY")
        self.aws.session_token = os.getenv("AWS_SESSION_TOKEN")
        self.aws.s3_bucket = os.getenv("AWS_S3_BUCKET", "")
        
        # Security configuration
        self.security.secret_key = os.getenv("SECRET_KEY", self.security.secret_key)
        self.security.jwt_secret_key = os.getenv("JWT_SECRET_KEY", self.security.jwt_secret_key)
        self.security.session_cookie_secure = os.getenv("SESSION_COOKIE_SECURE", "true").lower() == "true"
        self.security.csrf_enabled = os.getenv("CSRF_ENABLED", "true").lower() == "true"
        
        # Flask configuration
        self.flask.host = os.getenv("FLASK_HOST", self.flask.host)
        self.flask.port = int(os.getenv("FLASK_PORT", self.flask.port))
        self.flask.debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
        
        # Logging configuration
        self.logging.level = os.getenv("LOG_LEVEL", self.logging.level)
        self.logging.log_file = os.getenv("LOG_FILE")
        self.logging.audit_log_file = os.getenv("AUDIT_LOG_FILE")
        
        # Monitoring configuration
        self.monitoring.enable_metrics = os.getenv("ENABLE_METRICS", "true").lower() == "true"
        self.monitoring.apm_service_name = os.getenv("APM_SERVICE_NAME", self.monitoring.apm_service_name)
        
        # CORS origins from environment
        cors_origins = os.getenv("CORS_ORIGINS", "")
        if cors_origins:
            self.security.cors_origins = [origin.strip() for origin in cors_origins.split(",")]
    
    def validate(self) -> None:
        """Validate all configuration sections."""
        validation_errors = []
        
        try:
            self.database.validate()
        except ValidationError as e:
            validation_errors.append(f"Database config: {e}")
        
        try:
            self.redis.validate()
        except ValidationError as e:
            validation_errors.append(f"Redis config: {e}")
        
        try:
            self.auth0.validate()
        except ValidationError as e:
            validation_errors.append(f"Auth0 config: {e}")
        
        try:
            self.aws.validate()
        except ValidationError as e:
            validation_errors.append(f"AWS config: {e}")
        
        try:
            self.logging.validate()
        except ValidationError as e:
            validation_errors.append(f"Logging config: {e}")
        
        try:
            self.monitoring.validate()
        except ValidationError as e:
            validation_errors.append(f"Monitoring config: {e}")
        
        try:
            self.security.validate()
        except ValidationError as e:
            validation_errors.append(f"Security config: {e}")
        
        try:
            self.flask.validate()
        except ValidationError as e:
            validation_errors.append(f"Flask config: {e}")
        
        if validation_errors:
            raise ConfigurationError(f"Configuration validation failed: {'; '.join(validation_errors)}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary format."""
        return {
            "database": self.database.__dict__,
            "redis": self.redis.__dict__,
            "auth0": {k: v for k, v in self.auth0.__dict__.items() if k != "client_secret"},
            "aws": {k: v for k, v in self.aws.__dict__.items() if k not in ["access_key_id", "secret_access_key", "session_token"]},
            "logging": self.logging.__dict__,
            "monitoring": self.monitoring.__dict__,
            "security": {k: v for k, v in self.security.__dict__.items() if k not in ["secret_key", "jwt_secret_key"]},
            "flask": self.flask.__dict__,
        }


class DevelopmentConfig(BaseConfig):
    """Development environment configuration."""
    
    def load_environment(self) -> None:
        """Load development environment settings."""
        # Load from .env file in project root
        env_path = Path(__file__).parent.parent.parent / ".env"
        load_dotenv(env_path)
        
        # Development-specific defaults
        self.environment = "development"
        
    def __post_init__(self):
        """Set development-specific defaults."""
        super().__init__()
        self.flask.debug = True
        self.logging.level = "DEBUG"
        self.security.session_cookie_secure = False
        self.monitoring.enable_performance_monitoring = False


class StagingConfig(BaseConfig):
    """Staging environment configuration."""
    
    def load_environment(self) -> None:
        """Load staging environment settings."""
        # Load from .env.staging file
        env_path = Path(__file__).parent.parent.parent / ".env.staging"
        load_dotenv(env_path)
        
        # Staging-specific defaults
        self.environment = "staging"


class ProductionConfig(BaseConfig):
    """Production environment configuration."""
    
    def load_environment(self) -> None:
        """Load production environment settings."""
        # Load from .env.production file if exists
        env_path = Path(__file__).parent.parent.parent / ".env.production"
        load_dotenv(env_path)
        
        # Production-specific defaults
        self.environment = "production"
    
    def __post_init__(self):
        """Set production-specific defaults."""
        super().__init__()
        self.flask.debug = False
        self.logging.level = "INFO"
        self.security.session_cookie_secure = True
        self.monitoring.enable_performance_monitoring = True


class TestingConfig(BaseConfig):
    """Testing environment configuration."""
    
    def load_environment(self) -> None:
        """Load testing environment settings."""
        # Load from .env.testing file
        env_path = Path(__file__).parent.parent.parent / ".env.testing"
        load_dotenv(env_path)
        
        # Testing-specific defaults
        self.environment = "testing"
    
    def __post_init__(self):
        """Set testing-specific defaults."""
        super().__init__()
        self.flask.testing = True
        self.flask.debug = False
        self.database.name = "test_db"
        self.redis.db = 1  # Use separate Redis DB for testing
        self.security.csrf_enabled = False
        self.logging.level = "WARNING"


# Configuration factory for Flask application factory pattern
config_map = {
    "development": DevelopmentConfig,
    "staging": StagingConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}


def create_config(environment: Optional[str] = None) -> BaseConfig:
    """
    Create configuration instance based on environment.
    
    Args:
        environment: Target environment name. If None, uses FLASK_ENV environment variable.
        
    Returns:
        Configuration instance for the specified environment.
        
    Raises:
        ConfigurationError: If the environment is invalid or configuration validation fails.
    """
    if environment is None:
        environment = os.getenv("FLASK_ENV", "development")
    
    if environment not in config_map:
        raise ConfigurationError(f"Invalid environment: {environment}. Valid options: {list(config_map.keys())}")
    
    try:
        config_class = config_map[environment]
        return config_class()
    except Exception as e:
        raise ConfigurationError(f"Failed to create {environment} configuration: {e}")


def get_database_uri(config: BaseConfig) -> str:
    """
    Get database URI from configuration.
    
    Args:
        config: Configuration instance.
        
    Returns:
        MongoDB connection URI.
    """
    return config.database.uri


def get_redis_url(config: BaseConfig) -> str:
    """
    Get Redis URL from configuration.
    
    Args:
        config: Configuration instance.
        
    Returns:
        Redis connection URL.
    """
    return config.redis.url


def get_flask_config_dict(config: BaseConfig) -> Dict[str, Any]:
    """
    Get Flask configuration dictionary.
    
    Args:
        config: Configuration instance.
        
    Returns:
        Flask configuration dictionary with all necessary settings.
    """
    return {
        # Flask core settings
        "DEBUG": config.flask.debug,
        "TESTING": config.flask.testing,
        "SECRET_KEY": config.security.secret_key,
        "MAX_CONTENT_LENGTH": config.flask.max_content_length,
        "SEND_FILE_MAX_AGE_DEFAULT": config.flask.send_file_max_age_default,
        "PERMANENT_SESSION_LIFETIME": config.flask.permanent_session_lifetime,
        "SESSION_REFRESH_EACH_REQUEST": config.flask.session_refresh_each_request,
        
        # Session configuration
        "SESSION_COOKIE_SECURE": config.security.session_cookie_secure,
        "SESSION_COOKIE_HTTPONLY": config.security.session_cookie_httponly,
        "SESSION_COOKIE_SAMESITE": config.security.session_cookie_samesite,
        
        # Security settings
        "WTF_CSRF_ENABLED": config.security.csrf_enabled,
        
        # Database configuration
        "MONGODB_URI": config.database.uri,
        "MONGODB_DB": config.database.name,
        
        # Redis configuration
        "REDIS_URL": config.redis.url,
        
        # JWT configuration
        "JWT_SECRET_KEY": config.security.jwt_secret_key,
        "JWT_ALGORITHM": config.security.jwt_algorithm,
        "JWT_ACCESS_TOKEN_EXPIRES": config.security.jwt_access_token_expires,
        "JWT_REFRESH_TOKEN_EXPIRES": config.security.jwt_refresh_token_expires,
        
        # Auth0 configuration
        "AUTH0_DOMAIN": config.auth0.domain,
        "AUTH0_CLIENT_ID": config.auth0.client_id,
        "AUTH0_CLIENT_SECRET": config.auth0.client_secret,
        "AUTH0_AUDIENCE": config.auth0.audience,
        
        # AWS configuration
        "AWS_REGION": config.aws.region,
        "AWS_S3_BUCKET": config.aws.s3_bucket,
        
        # CORS configuration
        "CORS_ORIGINS": config.security.cors_origins,
        
        # Rate limiting
        "RATELIMIT_ENABLED": config.security.rate_limit_enabled,
        "RATELIMIT_DEFAULT": config.security.rate_limit_default,
    }


def validate_environment_file(env_file: Path) -> bool:
    """
    Validate that an environment file exists and is readable.
    
    Args:
        env_file: Path to environment file.
        
    Returns:
        True if file is valid, False otherwise.
    """
    try:
        return env_file.exists() and env_file.is_file() and os.access(env_file, os.R_OK)
    except Exception:
        return False


# Export configuration utilities for Flask application factory pattern
__all__ = [
    "BaseConfig",
    "DevelopmentConfig",
    "StagingConfig", 
    "ProductionConfig",
    "TestingConfig",
    "create_config",
    "get_database_uri",
    "get_redis_url",
    "get_flask_config_dict",
    "validate_environment_file",
    "ConfigurationError",
    "ValidationError",
]