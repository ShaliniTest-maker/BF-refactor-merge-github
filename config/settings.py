"""
Core Flask Application Configuration Module

This module provides the central configuration infrastructure for the Flask application,
implementing enterprise-grade configuration management with environment-specific overrides,
secure secret management, and comprehensive Flask extension configuration.

This replaces Node.js JSON configuration files with Python-based configuration classes
using python-dotenv for secure environment variable management as specified in Section 0.2.4.

Key Features:
- Flask 2.3+ application factory pattern configuration (Section 3.2.1)
- python-dotenv 1.0+ environment variable management (Section 0.2.4)
- Secure secret key management with validation (Section 6.4.1)
- Flask extensions configuration for CORS, RESTful APIs, rate limiting (Section 3.2.1)
- Environment-specific configuration inheritance (Section 8.1.2)
- Enterprise security settings and compliance (Section 6.4.3)
- Performance monitoring and observability integration (Section 3.6.1)

Dependencies:
- python-dotenv 1.0+ for environment variable management
- Flask 2.3+ for web framework configuration
- cryptography 41.0+ for secure key management
- Enterprise monitoring and security library configurations

Author: Flask Migration Team
Version: 1.0.0
Migration Phase: Node.js to Python/Flask Migration (Section 0.1.1)
"""

import os
import secrets
import base64
from pathlib import Path
from typing import Dict, Any, Optional, Union, List
from datetime import timedelta
from dotenv import load_dotenv, find_dotenv
import logging

# Configure basic logging for configuration module
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ConfigurationError(Exception):
    """Custom exception for configuration validation errors."""
    pass


class EnvironmentManager:
    """
    Secure environment variable management using python-dotenv with comprehensive
    validation and security checks as specified in Section 6.4.3.
    
    This class provides secure loading and validation of environment variables
    with proper error handling and security constraint enforcement.
    """
    
    def __init__(self, env_file: Optional[str] = None):
        """
        Initialize environment manager with secure configuration loading.
        
        Args:
            env_file: Optional path to .env file, defaults to auto-discovery
        """
        self.env_file = env_file or find_dotenv()
        self.logger = logging.getLogger(f"{__name__}.EnvironmentManager")
        self._load_environment_variables()
        self._validate_environment_file_security()
    
    def _load_environment_variables(self) -> None:
        """
        Load environment variables from .env file with error handling.
        
        Raises:
            ConfigurationError: When environment loading fails
        """
        try:
            # Load environment variables with override=False to preserve existing values
            load_dotenv(self.env_file, override=False)
            self.logger.info("Environment variables loaded successfully")
            
        except Exception as e:
            error_msg = f"Failed to load environment variables: {str(e)}"
            self.logger.error(error_msg)
            raise ConfigurationError(error_msg)
    
    def _validate_environment_file_security(self) -> None:
        """
        Validate environment file security settings and permissions.
        
        Checks file permissions on Unix systems to ensure secure configuration
        as specified in Section 6.4.3 security requirements.
        """
        if not self.env_file or not os.path.exists(self.env_file):
            return
        
        # Check file permissions on Unix systems
        if os.name == 'posix':
            try:
                env_path = Path(self.env_file)
                file_mode = oct(env_path.stat().st_mode)[-3:]
                
                if file_mode not in ['600', '644']:
                    self.logger.warning(
                        f"Environment file permissions ({file_mode}) may be too permissive. "
                        f"Recommended: 600 for production security."
                    )
            except Exception as e:
                self.logger.warning(f"Could not check environment file permissions: {str(e)}")
    
    def get_required_env(self, key: str, var_type: type = str) -> Any:
        """
        Get required environment variable with type validation.
        
        Args:
            key: Environment variable name
            var_type: Expected variable type for validation
            
        Returns:
            Validated environment variable value
            
        Raises:
            ConfigurationError: When required variable is missing or invalid
        """
        value = os.getenv(key)
        if value is None:
            raise ConfigurationError(f"Required environment variable '{key}' not found")
        
        try:
            if var_type == bool:
                return value.lower() in ('true', '1', 'yes', 'on')
            elif var_type == int:
                return int(value)
            elif var_type == float:
                return float(value)
            else:
                return var_type(value)
        except (ValueError, TypeError) as e:
            raise ConfigurationError(f"Environment variable '{key}' has invalid type: {str(e)}")
    
    def get_optional_env(self, key: str, default: Any = None, var_type: type = str) -> Any:
        """
        Get optional environment variable with default value and type validation.
        
        Args:
            key: Environment variable name
            default: Default value if variable is not set
            var_type: Expected variable type for validation
            
        Returns:
            Environment variable value or default
        """
        value = os.getenv(key)
        if value is None:
            return default
        
        try:
            if var_type == bool:
                return value.lower() in ('true', '1', 'yes', 'on')
            elif var_type == int:
                return int(value)
            elif var_type == float:
                return float(value)
            else:
                return var_type(value)
        except (ValueError, TypeError):
            self.logger.warning(f"Invalid type for '{key}', using default: {default}")
            return default


class BaseConfig:
    """
    Base Flask application configuration class implementing core settings
    and security standards as specified in Section 3.2.1 and Section 6.4.1.
    
    This class provides the foundation configuration that all environment-specific
    configurations inherit from, ensuring consistent security and performance settings.
    """
    
    def __init__(self):
        """Initialize base configuration with environment manager."""
        self.env_manager = EnvironmentManager()
        self._configure_base_settings()
        self._configure_security_settings()
        self._configure_database_settings()
        self._configure_cache_settings()
        self._configure_auth_settings()
        self._configure_monitoring_settings()
        self._configure_external_services()
        self._configure_flask_extensions()
        self._validate_configuration()
    
    def _configure_base_settings(self) -> None:
        """Configure core Flask application settings."""
        # Flask Application Settings
        self.SECRET_KEY = self._generate_or_get_secret_key()
        self.FLASK_ENV = self.env_manager.get_optional_env('FLASK_ENV', 'production')
        self.DEBUG = self.env_manager.get_optional_env('FLASK_DEBUG', False, bool)
        self.TESTING = self.env_manager.get_optional_env('FLASK_TESTING', False, bool)
        
        # Application Metadata
        self.APP_NAME = self.env_manager.get_optional_env('APP_NAME', 'Flask Migration App')
        self.APP_VERSION = self.env_manager.get_optional_env('APP_VERSION', '1.0.0')
        
        # Server Configuration
        self.HOST = self.env_manager.get_optional_env('FLASK_HOST', '0.0.0.0')
        self.PORT = self.env_manager.get_optional_env('FLASK_PORT', 8000, int)
        
        # Session Configuration (Flask-Session integration)
        self.PERMANENT_SESSION_LIFETIME = timedelta(
            hours=self.env_manager.get_optional_env('SESSION_LIFETIME_HOURS', 24, int)
        )
        self.SESSION_COOKIE_SECURE = True  # Force HTTPS for session cookies
        self.SESSION_COOKIE_HTTPONLY = True  # Prevent XSS attacks
        self.SESSION_COOKIE_SAMESITE = 'Lax'  # CSRF protection
        
        # Request Configuration
        self.MAX_CONTENT_LENGTH = self.env_manager.get_optional_env(
            'MAX_CONTENT_LENGTH', 16 * 1024 * 1024, int  # 16MB default
        )
        
        # JSON Configuration
        self.JSON_SORT_KEYS = True
        self.JSONIFY_PRETTYPRINT_REGULAR = self.DEBUG
    
    def _generate_or_get_secret_key(self) -> str:
        """
        Generate or retrieve Flask secret key with enterprise security standards.
        
        This method implements secure secret key management as specified in Section 6.4.1,
        ensuring cryptographically secure keys for session management and CSRF protection.
        
        Returns:
            Secure Flask secret key
            
        Raises:
            ConfigurationError: When secret key generation or validation fails
        """
        try:
            # Try to get from environment first (production)
            secret_key = os.getenv('SECRET_KEY')
            
            if secret_key:
                # Validate existing secret key
                if len(secret_key) < 32:
                    raise ConfigurationError(
                        "SECRET_KEY must be at least 32 characters for security"
                    )
                return secret_key
            
            # Generate secure secret key for development
            if self.env_manager.get_optional_env('FLASK_ENV', 'production') == 'development':
                logger.warning(
                    "Generating temporary secret key for development. "
                    "Set SECRET_KEY environment variable for production."
                )
                return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8')
            
            # Require secret key for production
            raise ConfigurationError(
                "SECRET_KEY environment variable is required for production deployment"
            )
            
        except Exception as e:
            raise ConfigurationError(f"Secret key configuration failed: {str(e)}")
    
    def _configure_security_settings(self) -> None:
        """
        Configure comprehensive security settings for Flask-Talisman and related
        security extensions as specified in Section 6.4.3.
        """
        # HTTPS/TLS Configuration (Flask-Talisman)
        self.FORCE_HTTPS = self.env_manager.get_optional_env('FORCE_HTTPS', True, bool)
        self.SSL_DISABLE = self.env_manager.get_optional_env('SSL_DISABLE', False, bool)
        
        # HTTP Strict Transport Security (HSTS)
        self.HSTS_MAX_AGE = self.env_manager.get_optional_env('HSTS_MAX_AGE', 31536000, int)  # 1 year
        self.HSTS_INCLUDE_SUBDOMAINS = True
        self.HSTS_PRELOAD = True
        
        # Content Security Policy (CSP)
        self.CSP_POLICY = {
            'default-src': "'self'",
            'script-src': [
                "'self'",
                "'unsafe-inline'",  # Required for some Flask operations
                "https://cdn.auth0.com"  # Auth0 integration
            ],
            'style-src': [
                "'self'",
                "'unsafe-inline'"  # Required for Flask admin interfaces
            ],
            'img-src': [
                "'self'",
                "data:",
                "https:"
            ],
            'connect-src': [
                "'self'",
                "https://*.auth0.com",  # Auth0 API endpoints
                "https://*.amazonaws.com"  # AWS services
            ],
            'font-src': "'self'",
            'object-src': "'none'",
            'base-uri': "'self'",
            'frame-ancestors': "'none'",
            'upgrade-insecure-requests': True
        }
        
        # Feature Policy Configuration
        self.FEATURE_POLICY = {
            'geolocation': "'none'",
            'microphone': "'none'",
            'camera': "'none'",
            'accelerometer': "'none'",
            'gyroscope': "'none'",
            'payment': "'none'"
        }
        
        # Referrer Policy
        self.REFERRER_POLICY = 'strict-origin-when-cross-origin'
        
        # Additional Security Headers
        self.X_FRAME_OPTIONS = 'DENY'
        self.X_CONTENT_TYPE_OPTIONS = 'nosniff'
        self.X_XSS_PROTECTION = '1; mode=block'
    
    def _configure_database_settings(self) -> None:
        """
        Configure MongoDB and database connection settings using PyMongo 4.5+
        and Motor 3.3+ as specified in Section 3.4.1.
        """
        # MongoDB Configuration
        self.MONGODB_URI = self.env_manager.get_optional_env(
            'MONGODB_URI', 
            'mongodb://localhost:27017/flask_app'
        )
        self.MONGODB_DATABASE = self.env_manager.get_optional_env('MONGODB_DATABASE', 'flask_app')
        
        # MongoDB Connection Pool Settings
        self.MONGODB_SETTINGS = {
            'host': self.MONGODB_URI,
            'connect': True,
            'maxPoolSize': self.env_manager.get_optional_env('MONGODB_MAX_POOL_SIZE', 50, int),
            'minPoolSize': self.env_manager.get_optional_env('MONGODB_MIN_POOL_SIZE', 5, int),
            'maxIdleTimeMS': self.env_manager.get_optional_env('MONGODB_MAX_IDLE_TIME', 30000, int),
            'serverSelectionTimeoutMS': self.env_manager.get_optional_env('MONGODB_SERVER_TIMEOUT', 5000, int),
            'socketTimeoutMS': self.env_manager.get_optional_env('MONGODB_SOCKET_TIMEOUT', 30000, int),
            'connectTimeoutMS': self.env_manager.get_optional_env('MONGODB_CONNECT_TIMEOUT', 10000, int),
        }
        
        # TLS/SSL Configuration for MongoDB
        if self.env_manager.get_optional_env('MONGODB_TLS_ENABLED', False, bool):
            self.MONGODB_SETTINGS.update({
                'tls': True,
                'tlsCAFile': self.env_manager.get_optional_env('MONGODB_TLS_CA_FILE'),
                'tlsCertificateKeyFile': self.env_manager.get_optional_env('MONGODB_TLS_CERT_FILE'),
                'tlsAllowInvalidCertificates': self.env_manager.get_optional_env(
                    'MONGODB_TLS_ALLOW_INVALID', False, bool
                ),
                'tlsAllowInvalidHostnames': self.env_manager.get_optional_env(
                    'MONGODB_TLS_ALLOW_INVALID_HOSTNAMES', False, bool
                )
            })
    
    def _configure_cache_settings(self) -> None:
        """
        Configure Redis cache settings using redis-py 5.0+ and Flask-Session
        for distributed session management as specified in Section 3.4.2.
        """
        # Redis Configuration
        self.REDIS_HOST = self.env_manager.get_optional_env('REDIS_HOST', 'localhost')
        self.REDIS_PORT = self.env_manager.get_optional_env('REDIS_PORT', 6379, int)
        self.REDIS_PASSWORD = self.env_manager.get_optional_env('REDIS_PASSWORD')
        self.REDIS_DB = self.env_manager.get_optional_env('REDIS_DB', 0, int)
        
        # Redis Connection Pool Configuration
        self.REDIS_CONNECTION_POOL_KWARGS = {
            'host': self.REDIS_HOST,
            'port': self.REDIS_PORT,
            'password': self.REDIS_PASSWORD,
            'db': self.REDIS_DB,
            'decode_responses': True,
            'max_connections': self.env_manager.get_optional_env('REDIS_MAX_CONNECTIONS', 50, int),
            'retry_on_timeout': True,
            'socket_timeout': self.env_manager.get_optional_env('REDIS_SOCKET_TIMEOUT', 30.0, float),
            'socket_connect_timeout': self.env_manager.get_optional_env('REDIS_CONNECT_TIMEOUT', 10.0, float),
            'health_check_interval': self.env_manager.get_optional_env('REDIS_HEALTH_CHECK_INTERVAL', 30, int)
        }
        
        # Flask-Session Configuration
        self.SESSION_TYPE = 'redis'
        self.SESSION_USE_SIGNER = True
        self.SESSION_KEY_PREFIX = 'session:'
        self.SESSION_PERMANENT = False
        
        # Session Encryption Configuration
        self.SESSION_ENCRYPTION_KEY = self.env_manager.get_optional_env('SESSION_ENCRYPTION_KEY')
        if self.SESSION_ENCRYPTION_KEY:
            try:
                # Validate base64-encoded encryption key
                decoded_key = base64.b64decode(self.SESSION_ENCRYPTION_KEY)
                if len(decoded_key) != 32:  # AES-256 requires 32-byte key
                    raise ConfigurationError(
                        "SESSION_ENCRYPTION_KEY must be a base64-encoded 32-byte key"
                    )
            except Exception as e:
                raise ConfigurationError(f"Invalid SESSION_ENCRYPTION_KEY: {str(e)}")
    
    def _configure_auth_settings(self) -> None:
        """
        Configure authentication settings for Auth0 integration and JWT processing
        using PyJWT 2.8+ as specified in Section 6.4.1.
        """
        # Auth0 Configuration
        self.AUTH0_DOMAIN = self.env_manager.get_optional_env('AUTH0_DOMAIN')
        self.AUTH0_CLIENT_ID = self.env_manager.get_optional_env('AUTH0_CLIENT_ID')
        self.AUTH0_CLIENT_SECRET = self.env_manager.get_optional_env('AUTH0_CLIENT_SECRET')
        self.AUTH0_AUDIENCE = self.env_manager.get_optional_env('AUTH0_AUDIENCE')
        
        # JWT Configuration
        self.JWT_SECRET_KEY = self.env_manager.get_optional_env('JWT_SECRET_KEY', self.SECRET_KEY)
        self.JWT_ALGORITHM = self.env_manager.get_optional_env('JWT_ALGORITHM', 'RS256')
        self.JWT_EXPIRATION_DELTA = timedelta(
            hours=self.env_manager.get_optional_env('JWT_EXPIRATION_HOURS', 24, int)
        )
        self.JWT_REFRESH_EXPIRATION_DELTA = timedelta(
            days=self.env_manager.get_optional_env('JWT_REFRESH_EXPIRATION_DAYS', 30, int)
        )
        
        # JWT Validation Cache Settings
        self.JWT_CACHE_ENABLED = self.env_manager.get_optional_env('JWT_CACHE_ENABLED', True, bool)
        self.JWT_CACHE_TTL = self.env_manager.get_optional_env('JWT_CACHE_TTL', 300, int)  # 5 minutes
        
        # Flask-Login Configuration
        self.LOGIN_DISABLED = self.env_manager.get_optional_env('LOGIN_DISABLED', False, bool)
        self.REMEMBER_COOKIE_DURATION = timedelta(
            days=self.env_manager.get_optional_env('REMEMBER_COOKIE_DAYS', 7, int)
        )
        self.REMEMBER_COOKIE_SECURE = True
        self.REMEMBER_COOKIE_HTTPONLY = True
    
    def _configure_monitoring_settings(self) -> None:
        """
        Configure monitoring and observability settings for Prometheus metrics
        and structured logging as specified in Section 3.6.1.
        """
        # Prometheus Metrics Configuration
        self.PROMETHEUS_METRICS_ENABLED = self.env_manager.get_optional_env(
            'PROMETHEUS_METRICS_ENABLED', True, bool
        )
        self.PROMETHEUS_METRICS_PORT = self.env_manager.get_optional_env(
            'PROMETHEUS_METRICS_PORT', 9090, int
        )
        
        # Health Check Configuration
        self.HEALTH_CHECK_ENABLED = self.env_manager.get_optional_env(
            'HEALTH_CHECK_ENABLED', True, bool
        )
        
        # Structured Logging Configuration (structlog 23.1+)
        self.LOG_LEVEL = self.env_manager.get_optional_env('LOG_LEVEL', 'INFO')
        self.LOG_FORMAT = self.env_manager.get_optional_env('LOG_FORMAT', 'json')
        self.LOG_FILE = self.env_manager.get_optional_env('LOG_FILE')
        
        # APM Configuration
        self.APM_ENABLED = self.env_manager.get_optional_env('APM_ENABLED', False, bool)
        self.APM_SERVICE_NAME = self.env_manager.get_optional_env('APM_SERVICE_NAME', self.APP_NAME)
        self.APM_ENVIRONMENT = self.env_manager.get_optional_env('APM_ENVIRONMENT', self.FLASK_ENV)
    
    def _configure_external_services(self) -> None:
        """
        Configure external service integration settings for AWS, HTTP clients,
        and third-party APIs as specified in Section 3.2.3.
        """
        # AWS Configuration (boto3 1.28+)
        self.AWS_ACCESS_KEY_ID = self.env_manager.get_optional_env('AWS_ACCESS_KEY_ID')
        self.AWS_SECRET_ACCESS_KEY = self.env_manager.get_optional_env('AWS_SECRET_ACCESS_KEY')
        self.AWS_DEFAULT_REGION = self.env_manager.get_optional_env('AWS_DEFAULT_REGION', 'us-east-1')
        self.AWS_KMS_KEY_ARN = self.env_manager.get_optional_env('AWS_KMS_KEY_ARN')
        
        # S3 Configuration
        self.S3_BUCKET_NAME = self.env_manager.get_optional_env('S3_BUCKET_NAME')
        self.S3_REGION = self.env_manager.get_optional_env('S3_REGION', self.AWS_DEFAULT_REGION)
        
        # HTTP Client Configuration (requests/httpx)
        self.HTTP_TIMEOUT = self.env_manager.get_optional_env('HTTP_TIMEOUT', 30.0, float)
        self.HTTP_RETRIES = self.env_manager.get_optional_env('HTTP_RETRIES', 3, int)
        self.HTTP_BACKOFF_FACTOR = self.env_manager.get_optional_env('HTTP_BACKOFF_FACTOR', 1.0, float)
        
        # Circuit Breaker Configuration
        self.CIRCUIT_BREAKER_ENABLED = self.env_manager.get_optional_env(
            'CIRCUIT_BREAKER_ENABLED', True, bool
        )
        self.CIRCUIT_BREAKER_FAILURE_THRESHOLD = self.env_manager.get_optional_env(
            'CIRCUIT_BREAKER_FAILURE_THRESHOLD', 5, int
        )
        self.CIRCUIT_BREAKER_TIMEOUT = self.env_manager.get_optional_env(
            'CIRCUIT_BREAKER_TIMEOUT', 60, int
        )
    
    def _configure_flask_extensions(self) -> None:
        """
        Configure Flask extensions including CORS, rate limiting, and RESTful API
        support as specified in Section 3.2.1.
        """
        # Flask-CORS Configuration (4.0+)
        self.CORS_ORIGINS = self._get_cors_origins()
        self.CORS_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
        self.CORS_ALLOW_HEADERS = [
            'Authorization',
            'Content-Type',
            'X-Requested-With',
            'X-CSRF-Token',
            'Accept',
            'Origin'
        ]
        self.CORS_EXPOSE_HEADERS = [
            'X-RateLimit-Limit',
            'X-RateLimit-Remaining',
            'X-RateLimit-Reset'
        ]
        self.CORS_SUPPORTS_CREDENTIALS = True
        self.CORS_MAX_AGE = 600  # 10 minutes preflight cache
        
        # Flask-Limiter Configuration (3.5+)
        self.RATELIMIT_ENABLED = self.env_manager.get_optional_env('RATELIMIT_ENABLED', True, bool)
        self.RATELIMIT_STORAGE_URL = f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB + 1}"
        self.RATELIMIT_DEFAULT = self.env_manager.get_optional_env(
            'RATELIMIT_DEFAULT', '1000 per hour, 100 per minute'
        )
        self.RATELIMIT_HEADERS_ENABLED = True
        
        # Flask-RESTful Configuration (0.3.10+)
        self.RESTFUL_JSON = {
            'sort_keys': True,
            'indent': 2 if self.DEBUG else None,
            'separators': (',', ': ') if self.DEBUG else (',', ':')
        }
        
        # Flask-Migrate Configuration (if using database migrations)
        self.SQLALCHEMY_TRACK_MODIFICATIONS = False
        self.SQLALCHEMY_RECORD_QUERIES = self.DEBUG
    
    def _get_cors_origins(self) -> List[str]:
        """
        Get CORS origins configuration based on environment.
        
        This method provides environment-specific CORS origin policies
        as specified in Section 6.4.2 for security.
        
        Returns:
            List of allowed CORS origins
        """
        # Base production origins
        origins = [
            'https://app.company.com',
            'https://admin.company.com'
        ]
        
        # Add development origins for non-production environments
        if self.FLASK_ENV == 'development':
            origins.extend([
                'http://localhost:3000',
                'http://localhost:8080',
                'https://localhost:3000',
                'https://localhost:8080',
                'https://dev.company.com'
            ])
        elif self.FLASK_ENV == 'staging':
            origins.extend([
                'https://staging.company.com',
                'https://staging-admin.company.com'
            ])
        
        # Allow custom CORS origins from environment
        custom_origins = self.env_manager.get_optional_env('CORS_ORIGINS')
        if custom_origins:
            origins.extend([origin.strip() for origin in custom_origins.split(',')])
        
        return origins
    
    def _validate_configuration(self) -> None:
        """
        Validate configuration settings for consistency and security compliance.
        
        This method performs comprehensive validation of configuration settings
        to ensure enterprise security and compliance requirements are met.
        
        Raises:
            ConfigurationError: When configuration validation fails
        """
        validation_errors = []
        
        # Validate production requirements
        if self.FLASK_ENV == 'production':
            if self.DEBUG:
                validation_errors.append("DEBUG must be False in production")
            
            if self.SECRET_KEY == 'dev-secret-key' or len(self.SECRET_KEY) < 32:
                validation_errors.append("Production requires secure SECRET_KEY (32+ characters)")
            
            if not self.FORCE_HTTPS:
                validation_errors.append("HTTPS must be enforced in production")
            
            if not self.AUTH0_DOMAIN or not self.AUTH0_CLIENT_ID:
                validation_errors.append("Auth0 configuration required for production")
        
        # Validate security settings
        if self.SESSION_COOKIE_SECURE and not self.FORCE_HTTPS:
            validation_errors.append("SESSION_COOKIE_SECURE requires HTTPS enforcement")
        
        # Validate database configuration
        if not self.MONGODB_URI:
            validation_errors.append("MongoDB URI is required")
        
        # Validate Redis configuration for session management
        if self.SESSION_TYPE == 'redis' and not all([self.REDIS_HOST, self.REDIS_PORT]):
            validation_errors.append("Redis configuration required for session management")
        
        # Validate JWT configuration
        if self.AUTH0_DOMAIN and not self.JWT_SECRET_KEY:
            validation_errors.append("JWT_SECRET_KEY required when Auth0 is configured")
        
        if validation_errors:
            error_message = "Configuration validation failed:\n" + "\n".join(
                f"- {error}" for error in validation_errors
            )
            raise ConfigurationError(error_message)
        
        logger.info("Configuration validation completed successfully")
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert configuration to dictionary for debugging and introspection.
        
        Note: Sensitive values are masked for security.
        
        Returns:
            Dictionary representation of configuration
        """
        config_dict = {}
        sensitive_keys = {
            'SECRET_KEY', 'JWT_SECRET_KEY', 'AUTH0_CLIENT_SECRET',
            'REDIS_PASSWORD', 'AWS_SECRET_ACCESS_KEY', 'SESSION_ENCRYPTION_KEY'
        }
        
        for key, value in self.__dict__.items():
            if key.startswith('_'):
                continue
            
            if key in sensitive_keys:
                config_dict[key] = '***MASKED***'
            elif isinstance(value, (str, int, float, bool, list, dict)):
                config_dict[key] = value
            else:
                config_dict[key] = str(value)
        
        return config_dict


class DevelopmentConfig(BaseConfig):
    """
    Development environment configuration with debug settings and relaxed security.
    
    This configuration extends BaseConfig with development-specific settings
    for local development and testing as specified in Section 8.1.2.
    """
    
    def __init__(self):
        """Initialize development configuration."""
        super().__init__()
        self._configure_development_overrides()
    
    def _configure_development_overrides(self) -> None:
        """Configure development-specific settings."""
        # Enable debug mode for development
        self.DEBUG = True
        self.TESTING = False
        
        # Relaxed security for development
        self.FORCE_HTTPS = False
        self.SESSION_COOKIE_SECURE = False
        
        # Extended session timeout for development
        self.PERMANENT_SESSION_LIFETIME = timedelta(hours=48)
        
        # Enhanced logging for development
        self.LOG_LEVEL = 'DEBUG'
        self.JSONIFY_PRETTYPRINT_REGULAR = True
        
        # Disable rate limiting for development
        self.RATELIMIT_ENABLED = False
        
        # Extended CORS origins for development
        self.CORS_ORIGINS.extend([
            'http://localhost:3000',
            'http://localhost:8080',
            'http://127.0.0.1:3000',
            'http://127.0.0.1:8080'
        ])
        
        logger.info("Development configuration loaded with debug settings")


class StagingConfig(BaseConfig):
    """
    Staging environment configuration with production-like settings.
    
    This configuration provides production-equivalent settings for staging
    environment testing and validation as specified in Section 8.1.2.
    """
    
    def __init__(self):
        """Initialize staging configuration."""
        super().__init__()
        self._configure_staging_overrides()
    
    def _configure_staging_overrides(self) -> None:
        """Configure staging-specific settings."""
        # Production-like security but with extended debugging
        self.DEBUG = False
        self.TESTING = False
        
        # Enhanced logging for staging validation
        self.LOG_LEVEL = 'INFO'
        
        # Staging-specific CORS origins
        self.CORS_ORIGINS.extend([
            'https://staging.company.com',
            'https://staging-admin.company.com'
        ])
        
        # Relaxed rate limiting for staging testing
        self.RATELIMIT_DEFAULT = '2000 per hour, 200 per minute'
        
        logger.info("Staging configuration loaded with production-like settings")


class ProductionConfig(BaseConfig):
    """
    Production environment configuration with enterprise security and performance.
    
    This configuration implements full enterprise-grade security settings,
    performance optimizations, and compliance controls as specified in Section 6.4.3.
    """
    
    def __init__(self):
        """Initialize production configuration."""
        super().__init__()
        self._configure_production_overrides()
        self._validate_production_requirements()
    
    def _configure_production_overrides(self) -> None:
        """Configure production-specific settings."""
        # Strict production settings
        self.DEBUG = False
        self.TESTING = False
        
        # Enhanced security for production
        self.FORCE_HTTPS = True
        self.SESSION_COOKIE_SECURE = True
        self.SESSION_COOKIE_SAMESITE = 'Strict'
        
        # Production logging
        self.LOG_LEVEL = 'WARNING'
        self.JSONIFY_PRETTYPRINT_REGULAR = False
        
        # Strict rate limiting for production
        self.RATELIMIT_DEFAULT = '1000 per hour, 100 per minute, 10 per second'
        
        # Production performance settings
        self.MONGODB_SETTINGS.update({
            'maxPoolSize': 100,
            'minPoolSize': 20,
            'serverSelectionTimeoutMS': 3000,
            'socketTimeoutMS': 20000
        })
        
        # Enhanced Redis connection pool for production
        self.REDIS_CONNECTION_POOL_KWARGS.update({
            'max_connections': 100,
            'socket_timeout': 20.0,
            'health_check_interval': 60
        })
        
        logger.info("Production configuration loaded with enterprise security settings")
    
    def _validate_production_requirements(self) -> None:
        """Validate production-specific requirements."""
        required_production_vars = [
            'SECRET_KEY', 'AUTH0_DOMAIN', 'AUTH0_CLIENT_ID', 'AUTH0_CLIENT_SECRET',
            'MONGODB_URI', 'REDIS_HOST', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY'
        ]
        
        missing_vars = []
        for var in required_production_vars:
            if not getattr(self, var, None) and not os.getenv(var):
                missing_vars.append(var)
        
        if missing_vars:
            raise ConfigurationError(
                f"Production deployment requires these environment variables: {', '.join(missing_vars)}"
            )


class TestingConfig(BaseConfig):
    """
    Testing environment configuration for unit and integration tests.
    
    This configuration provides isolated settings for automated testing
    with mock services and in-memory databases.
    """
    
    def __init__(self):
        """Initialize testing configuration."""
        super().__init__()
        self._configure_testing_overrides()
    
    def _configure_testing_overrides(self) -> None:
        """Configure testing-specific settings."""
        # Testing mode settings
        self.TESTING = True
        self.DEBUG = True
        
        # Disable external services for testing
        self.RATELIMIT_ENABLED = False
        self.APM_ENABLED = False
        self.PROMETHEUS_METRICS_ENABLED = False
        
        # Use in-memory databases for testing
        self.MONGODB_URI = 'mongodb://localhost:27017/test_flask_app'
        self.REDIS_DB = 15  # Use separate Redis DB for testing
        
        # Simplified authentication for testing
        self.JWT_CACHE_ENABLED = False
        self.LOGIN_DISABLED = True
        
        # Relaxed security for testing
        self.FORCE_HTTPS = False
        self.SESSION_COOKIE_SECURE = False
        
        # Fast sessions for testing
        self.PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
        
        logger.info("Testing configuration loaded with isolated settings")


# Configuration factory function
def get_config(config_name: Optional[str] = None) -> BaseConfig:
    """
    Configuration factory function to get environment-specific configuration.
    
    This function implements the configuration factory pattern for Flask applications
    as specified in Section 3.2.1, providing environment-specific configuration
    instances based on the FLASK_ENV environment variable.
    
    Args:
        config_name: Optional configuration name override
        
    Returns:
        Environment-specific configuration instance
        
    Raises:
        ConfigurationError: When invalid configuration name is provided
    """
    config_name = config_name or os.getenv('FLASK_ENV', 'production')
    
    config_mapping = {
        'development': DevelopmentConfig,
        'staging': StagingConfig,
        'production': ProductionConfig,
        'testing': TestingConfig
    }
    
    config_class = config_mapping.get(config_name.lower())
    if not config_class:
        available_configs = ', '.join(config_mapping.keys())
        raise ConfigurationError(
            f"Invalid configuration name '{config_name}'. "
            f"Available configurations: {available_configs}"
        )
    
    try:
        config_instance = config_class()
        logger.info(f"Configuration '{config_name}' loaded successfully")
        return config_instance
    except Exception as e:
        raise ConfigurationError(f"Failed to load configuration '{config_name}': {str(e)}")


# Default configuration instance
config = get_config()

# Configuration exports for application factory
__all__ = [
    'BaseConfig',
    'DevelopmentConfig', 
    'StagingConfig',
    'ProductionConfig',
    'TestingConfig',
    'get_config',
    'config',
    'EnvironmentManager',
    'ConfigurationError'
]