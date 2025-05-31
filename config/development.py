"""
Development Environment Configuration Module

This module provides development-specific configuration settings for the Flask application,
extending base configuration with development-friendly settings, debug configurations,
and relaxed security settings while maintaining core security principles.

This configuration is designed for local development and testing environments,
providing enhanced debugging capabilities, extended CORS origins, and optimized
development workflows per Section 8.1.2 Environment Management requirements.

Key Features:
- Development-specific Flask configuration with debug mode enabled
- Extended CORS origins for local development including localhost variations
- Relaxed security settings for development convenience while maintaining safety
- Enhanced logging and debugging configurations for development workflow
- Local service endpoint configurations for development infrastructure
- Development-friendly session and authentication settings
- Performance optimizations for development iteration speed

Dependencies:
- config.settings.BaseConfig for core configuration inheritance
- python-dotenv 1.0+ for development environment variable management
- Flask-CORS 4.0+ for development CORS policy configuration
- Flask-Talisman 1.1.0+ for security header enforcement (relaxed for dev)
- structlog 23.1+ for enhanced development logging

Author: Flask Migration Team
Version: 1.0.0
Migration Phase: Node.js to Python/Flask Migration (Section 0.1.1)
Environment: Development (Section 8.1.2)
"""

import os
import logging
from datetime import timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path

# Import base configuration
from config.settings import BaseConfig, EnvironmentManager, ConfigurationError
from config.database import DatabaseManager
from config.auth import AuthenticationConfig
from config.security import SecurityConfig
from config.logging import LoggingConfig
from config.monitoring import MonitoringConfig
from config.external_services import ExternalServicesConfig

# Configure logging for development configuration
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/development.log') if Path('logs').exists() else logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class DevelopmentConfig(BaseConfig):
    """
    Development environment configuration extending BaseConfig with development-specific
    settings, enhanced debugging capabilities, and relaxed security configurations
    per Section 8.1.2 Environment Management requirements.
    
    This configuration provides:
    - Development-optimized Flask settings with debug mode enabled
    - Extended CORS origins for local development workflows
    - Relaxed security settings for development convenience
    - Enhanced logging and debugging configurations
    - Local service endpoint configurations
    - Development-friendly authentication and session management
    """
    
    def __init__(self):
        """Initialize development configuration with development-specific overrides."""
        # Initialize base configuration first
        super().__init__()
        
        # Apply development-specific overrides
        self._configure_development_flask_settings()
        self._configure_development_security()
        self._configure_development_cors()
        self._configure_development_database()
        self._configure_development_cache()
        self._configure_development_auth()
        self._configure_development_monitoring()
        self._configure_development_external_services()
        self._configure_development_logging()
        self._configure_development_performance()
        
        # Validate development configuration
        self._validate_development_config()
        
        logger.info("Development configuration initialized successfully")
    
    def _configure_development_flask_settings(self) -> None:
        """Configure Flask application settings optimized for development workflow."""
        # Enable debug mode for development
        self.DEBUG = True
        self.TESTING = False
        self.FLASK_ENV = 'development'
        
        # Development server configuration
        self.HOST = self.env_manager.get_optional_env('FLASK_HOST', '127.0.0.1')
        self.PORT = self.env_manager.get_optional_env('FLASK_PORT', 8000, int)
        
        # Enhanced development features
        self.JSONIFY_PRETTYPRINT_REGULAR = True
        self.JSON_SORT_KEYS = True
        self.SEND_FILE_MAX_AGE_DEFAULT = 0  # Disable caching for development
        
        # Development-friendly file upload settings
        self.MAX_CONTENT_LENGTH = 32 * 1024 * 1024  # 32MB for development uploads
        
        # Template and static file settings for development
        self.TEMPLATES_AUTO_RELOAD = True
        self.EXPLAIN_TEMPLATE_LOADING = True
        
        # Development error handling
        self.PROPAGATE_EXCEPTIONS = True
        self.PRESERVE_CONTEXT_ON_EXCEPTION = True
        
        logger.debug("Flask development settings configured")
    
    def _configure_development_security(self) -> None:
        """Configure relaxed security settings for development while maintaining safety."""
        # Relaxed HTTPS enforcement for local development
        self.FORCE_HTTPS = False
        self.SSL_DISABLE = True
        
        # Relaxed session cookie security for HTTP development
        self.SESSION_COOKIE_SECURE = False
        self.SESSION_COOKIE_SAMESITE = 'Lax'  # More permissive for development
        self.REMEMBER_COOKIE_SECURE = False
        
        # Extended session lifetime for development convenience
        self.PERMANENT_SESSION_LIFETIME = timedelta(hours=48)  # Longer for dev sessions
        self.REMEMBER_COOKIE_DURATION = timedelta(days=14)  # Extended for convenience
        
        # Development-friendly Content Security Policy
        self.CSP_POLICY = {
            'default-src': "'self'",
            'script-src': [
                "'self'",
                "'unsafe-inline'",  # Allow inline scripts for development
                "'unsafe-eval'",    # Allow eval for development tools
                "http://localhost:*",
                "https://localhost:*",
                "https://cdn.auth0.com"
            ],
            'style-src': [
                "'self'",
                "'unsafe-inline'",  # Allow inline styles for development
                "http://localhost:*",
                "https://localhost:*"
            ],
            'img-src': [
                "'self'",
                "data:",
                "http://localhost:*",
                "https://localhost:*",
                "https:"
            ],
            'connect-src': [
                "'self'",
                "http://localhost:*",
                "https://localhost:*",
                "ws://localhost:*",   # WebSocket support for dev tools
                "wss://localhost:*",  # Secure WebSocket support
                "https://*.auth0.com",
                "https://*.amazonaws.com"
            ],
            'font-src': [
                "'self'",
                "http://localhost:*",
                "https://localhost:*"
            ],
            'object-src': "'none'",
            'base-uri': "'self'",
            'frame-ancestors': "'self' http://localhost:* https://localhost:*",  # Allow framing for dev tools
            'upgrade-insecure-requests': False  # Disable for HTTP development
        }
        
        # Relaxed feature policy for development tools
        self.FEATURE_POLICY = {
            'geolocation': "'self'",  # Allow for location-based testing
            'microphone': "'self'",   # Allow for media testing
            'camera': "'self'",       # Allow for media testing
            'accelerometer': "'self'",
            'gyroscope': "'self'",
            'payment': "'none'"
        }
        
        # Development security headers (relaxed)
        self.HSTS_MAX_AGE = 0  # Disable HSTS for development
        self.X_FRAME_OPTIONS = 'SAMEORIGIN'  # Allow same-origin framing
        
        logger.debug("Development security settings configured with relaxed policies")
    
    def _configure_development_cors(self) -> None:
        """Configure extended CORS origins for development environment."""
        # Development CORS origins including all localhost variations
        development_origins = [
            # Standard development servers
            'http://localhost:3000',
            'http://localhost:3001',
            'http://localhost:8000',
            'http://localhost:8080',
            'http://localhost:8081',
            'http://localhost:9000',
            'http://localhost:9001',
            
            # Secure localhost variations
            'https://localhost:3000',
            'https://localhost:3001',
            'https://localhost:8000',
            'https://localhost:8080',
            'https://localhost:8081',
            'https://localhost:9000',
            'https://localhost:9001',
            
            # 127.0.0.1 variations
            'http://127.0.0.1:3000',
            'http://127.0.0.1:3001',
            'http://127.0.0.1:8000',
            'http://127.0.0.1:8080',
            'http://127.0.0.1:8081',
            'http://127.0.0.1:9000',
            'http://127.0.0.1:9001',
            
            # Development domain variations
            'http://dev.localhost',
            'https://dev.localhost',
            'http://local.dev',
            'https://local.dev',
            'http://app.local',
            'https://app.local',
            
            # Company development domains
            'http://dev.company.com',
            'https://dev.company.com',
            'http://local.company.com',
            'https://local.company.com'
        ]
        
        # Add custom development origins from environment
        custom_origins = self.env_manager.get_optional_env('DEV_CORS_ORIGINS')
        if custom_origins:
            additional_origins = [origin.strip() for origin in custom_origins.split(',')]
            development_origins.extend(additional_origins)
        
        # Extend base CORS configuration with development origins
        self.CORS_ORIGINS = self._get_cors_origins() + development_origins
        
        # Remove duplicates while preserving order
        seen = set()
        self.CORS_ORIGINS = [x for x in self.CORS_ORIGINS if not (x in seen or seen.add(x))]
        
        # Development-friendly CORS configuration
        self.CORS_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
        self.CORS_ALLOW_HEADERS = [
            'Authorization',
            'Content-Type',
            'X-Requested-With',
            'X-CSRF-Token',
            'X-Auth-Token',
            'Accept',
            'Origin',
            'Cache-Control',
            'X-Dev-Tools',  # Custom header for development tools
            'X-Debug-Mode'  # Custom header for debugging
        ]
        self.CORS_EXPOSE_HEADERS = [
            'X-RateLimit-Limit',
            'X-RateLimit-Remaining',
            'X-RateLimit-Reset',
            'X-Debug-Info',     # Expose debug information
            'X-Performance-Metrics'  # Expose performance data
        ]
        self.CORS_SUPPORTS_CREDENTIALS = True
        self.CORS_MAX_AGE = 60  # Shorter cache for development changes
        
        logger.debug(f"Development CORS configured with {len(self.CORS_ORIGINS)} origins")
    
    def _configure_development_database(self) -> None:
        """Configure database settings optimized for development environment."""
        # Development MongoDB configuration
        self.MONGODB_URI = self.env_manager.get_optional_env(
            'MONGODB_URI', 
            'mongodb://localhost:27017/flask_app_dev'
        )
        self.MONGODB_DATABASE = self.env_manager.get_optional_env(
            'MONGODB_DATABASE', 
            'flask_app_dev'
        )
        
        # Relaxed MongoDB connection settings for development
        self.MONGODB_SETTINGS.update({
            'maxPoolSize': 20,  # Smaller pool for development
            'minPoolSize': 2,
            'maxIdleTimeMS': 60000,  # Longer idle time for development
            'serverSelectionTimeoutMS': 10000,  # Longer timeout for development
            'socketTimeoutMS': 60000,  # Longer socket timeout
            'connectTimeoutMS': 20000,  # Longer connect timeout
        })
        
        # Disable TLS for local development MongoDB
        if 'localhost' in self.MONGODB_URI or '127.0.0.1' in self.MONGODB_URI:
            self.MONGODB_SETTINGS.pop('tls', None)
            self.MONGODB_SETTINGS.pop('tlsCAFile', None)
            self.MONGODB_SETTINGS.pop('tlsCertificateKeyFile', None)
        
        logger.debug("Development database settings configured")
    
    def _configure_development_cache(self) -> None:
        """Configure Redis cache settings for development environment."""
        # Development Redis configuration
        self.REDIS_HOST = self.env_manager.get_optional_env('REDIS_HOST', 'localhost')
        self.REDIS_PORT = self.env_manager.get_optional_env('REDIS_PORT', 6379, int)
        self.REDIS_PASSWORD = self.env_manager.get_optional_env('REDIS_PASSWORD')  # Optional for dev
        self.REDIS_DB = self.env_manager.get_optional_env('REDIS_DB', 0, int)
        
        # Development Redis connection pool settings
        self.REDIS_CONNECTION_POOL_KWARGS.update({
            'max_connections': 20,  # Smaller pool for development
            'socket_timeout': 60.0,  # Longer timeout for development debugging
            'socket_connect_timeout': 20.0,
            'health_check_interval': 60,  # Less frequent health checks
            'retry_on_timeout': True,
            'decode_responses': True
        })
        
        # Development session configuration
        self.SESSION_REDIS_DB = self.env_manager.get_optional_env('SESSION_REDIS_DB', 1, int)
        
        # Disable Redis password for local development if not set
        if self.REDIS_HOST in ['localhost', '127.0.0.1'] and not self.REDIS_PASSWORD:
            self.REDIS_CONNECTION_POOL_KWARGS.pop('password', None)
        
        logger.debug("Development cache settings configured")
    
    def _configure_development_auth(self) -> None:
        """Configure authentication settings for development environment."""
        # Development Auth0 configuration (can use test credentials)
        self.AUTH0_DOMAIN = self.env_manager.get_optional_env(
            'AUTH0_DOMAIN', 
            'dev-flask-app.auth0.com'
        )
        self.AUTH0_CLIENT_ID = self.env_manager.get_optional_env('AUTH0_CLIENT_ID')
        self.AUTH0_CLIENT_SECRET = self.env_manager.get_optional_env('AUTH0_CLIENT_SECRET')
        self.AUTH0_AUDIENCE = self.env_manager.get_optional_env(
            'AUTH0_AUDIENCE', 
            'https://dev-flask-api'
        )
        
        # Development JWT configuration with relaxed settings
        self.JWT_SECRET_KEY = self.env_manager.get_optional_env(
            'JWT_SECRET_KEY', 
            'dev-jwt-secret-key-not-for-production'
        )
        self.JWT_ALGORITHM = self.env_manager.get_optional_env('JWT_ALGORITHM', 'HS256')  # Simpler for dev
        self.JWT_EXPIRATION_DELTA = timedelta(
            hours=self.env_manager.get_optional_env('JWT_EXPIRATION_HOURS', 48, int)  # Longer for dev
        )
        
        # Development JWT caching (shorter TTL for rapid development)
        self.JWT_CACHE_ENABLED = True
        self.JWT_CACHE_TTL = 60  # 1 minute for rapid development iteration
        
        # Development login settings
        self.LOGIN_DISABLED = self.env_manager.get_optional_env('LOGIN_DISABLED', False, bool)
        self.REMEMBER_COOKIE_DURATION = timedelta(days=30)  # Extended for development
        
        logger.debug("Development authentication settings configured")
    
    def _configure_development_monitoring(self) -> None:
        """Configure monitoring and observability for development environment."""
        # Enable development monitoring with debug features
        self.PROMETHEUS_METRICS_ENABLED = self.env_manager.get_optional_env(
            'PROMETHEUS_METRICS_ENABLED', True, bool
        )
        self.PROMETHEUS_METRICS_PORT = self.env_manager.get_optional_env(
            'PROMETHEUS_METRICS_PORT', 9090, int
        )
        
        # Development health check configuration
        self.HEALTH_CHECK_ENABLED = True
        
        # Development APM configuration (optional)
        self.APM_ENABLED = self.env_manager.get_optional_env('APM_ENABLED', False, bool)
        self.APM_SERVICE_NAME = self.env_manager.get_optional_env(
            'APM_SERVICE_NAME', 
            'flask-dev-app'
        )
        self.APM_ENVIRONMENT = 'development'
        
        # Development performance profiling
        self.ENABLE_PROFILING = self.env_manager.get_optional_env('ENABLE_PROFILING', True, bool)
        self.PROFILE_DIR = self.env_manager.get_optional_env('PROFILE_DIR', 'logs/profiles')
        
        logger.debug("Development monitoring settings configured")
    
    def _configure_development_external_services(self) -> None:
        """Configure external service connections for development environment."""
        # Development AWS configuration (can use localstack or dev account)
        self.AWS_ACCESS_KEY_ID = self.env_manager.get_optional_env('AWS_ACCESS_KEY_ID')
        self.AWS_SECRET_ACCESS_KEY = self.env_manager.get_optional_env('AWS_SECRET_ACCESS_KEY')
        self.AWS_DEFAULT_REGION = self.env_manager.get_optional_env('AWS_DEFAULT_REGION', 'us-east-1')
        
        # Development S3 configuration
        self.S3_BUCKET_NAME = self.env_manager.get_optional_env('S3_BUCKET_NAME', 'dev-flask-app-bucket')
        self.S3_ENDPOINT_URL = self.env_manager.get_optional_env('S3_ENDPOINT_URL')  # For localstack
        
        # Development HTTP client configuration with longer timeouts
        self.HTTP_TIMEOUT = self.env_manager.get_optional_env('HTTP_TIMEOUT', 60.0, float)
        self.HTTP_RETRIES = self.env_manager.get_optional_env('HTTP_RETRIES', 5, int)
        self.HTTP_BACKOFF_FACTOR = self.env_manager.get_optional_env('HTTP_BACKOFF_FACTOR', 2.0, float)
        
        # Disable circuit breaker for development to allow service debugging
        self.CIRCUIT_BREAKER_ENABLED = self.env_manager.get_optional_env(
            'CIRCUIT_BREAKER_ENABLED', False, bool
        )
        
        # Development email configuration (can use maildev or mailtrap)
        self.MAIL_SERVER = self.env_manager.get_optional_env('MAIL_SERVER', 'localhost')
        self.MAIL_PORT = self.env_manager.get_optional_env('MAIL_PORT', 1025, int)
        self.MAIL_USE_TLS = self.env_manager.get_optional_env('MAIL_USE_TLS', False, bool)
        self.MAIL_USERNAME = self.env_manager.get_optional_env('MAIL_USERNAME')
        self.MAIL_PASSWORD = self.env_manager.get_optional_env('MAIL_PASSWORD')
        
        logger.debug("Development external services configured")
    
    def _configure_development_logging(self) -> None:
        """Configure enhanced logging for development environment."""
        # Development logging level
        self.LOG_LEVEL = 'DEBUG'
        self.LOG_FORMAT = self.env_manager.get_optional_env('LOG_FORMAT', 'structured')
        
        # Development log file configuration
        self.LOG_FILE = self.env_manager.get_optional_env('LOG_FILE', 'logs/development.log')
        self.LOG_MAX_BYTES = self.env_manager.get_optional_env('LOG_MAX_BYTES', 10485760, int)  # 10MB
        self.LOG_BACKUP_COUNT = self.env_manager.get_optional_env('LOG_BACKUP_COUNT', 3, int)
        
        # Enable SQL query logging for development
        self.LOG_SQL_QUERIES = self.env_manager.get_optional_env('LOG_SQL_QUERIES', True, bool)
        
        # Enable request/response logging for development
        self.LOG_REQUESTS = self.env_manager.get_optional_env('LOG_REQUESTS', True, bool)
        self.LOG_RESPONSES = self.env_manager.get_optional_env('LOG_RESPONSES', True, bool)
        
        # Development security audit logging
        self.SECURITY_AUDIT_ENABLED = True
        self.SECURITY_LOG_LEVEL = 'DEBUG'
        
        # Enable performance logging for development optimization
        self.LOG_PERFORMANCE = self.env_manager.get_optional_env('LOG_PERFORMANCE', True, bool)
        
        logger.debug("Development logging configuration completed")
    
    def _configure_development_performance(self) -> None:
        """Configure performance settings optimized for development workflow."""
        # Development rate limiting (disabled or very permissive)
        self.RATELIMIT_ENABLED = self.env_manager.get_optional_env('RATELIMIT_ENABLED', False, bool)
        self.RATELIMIT_DEFAULT = '10000 per hour, 1000 per minute'  # Very permissive for dev
        
        # Development caching settings
        self.CACHE_DEFAULT_TIMEOUT = 60  # Short cache for development changes
        self.CACHE_THRESHOLD = 100  # Small cache for development
        
        # Development database query optimization
        self.OPTIMIZE_QUERIES = self.env_manager.get_optional_env('OPTIMIZE_QUERIES', False, bool)
        self.EXPLAIN_QUERIES = self.env_manager.get_optional_env('EXPLAIN_QUERIES', True, bool)
        
        # Development asset compilation
        self.ASSETS_DEBUG = True
        self.ASSETS_AUTO_BUILD = True
        
        logger.debug("Development performance settings configured")
    
    def _configure_development_flask_extensions(self) -> None:
        """Configure Flask extensions for development environment."""
        # Development Flask-CORS configuration
        self.CORS_SEND_WILDCARD = False
        self.CORS_VARY_HEADER = True
        self.CORS_AUTOMATIC_OPTIONS = True
        
        # Development Flask-Limiter configuration
        if self.RATELIMIT_ENABLED:
            self.RATELIMIT_STORAGE_URL = f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB + 2}"
            self.RATELIMIT_STRATEGY = "fixed-window"  # Simpler for development
        
        # Development Flask-RESTful configuration
        self.RESTFUL_JSON = {
            'sort_keys': True,
            'indent': 4,  # Pretty printing for development
            'separators': (',', ': ')
        }
        
        # Development Flask-DebugToolbar configuration
        self.DEBUG_TB_ENABLED = self.env_manager.get_optional_env('DEBUG_TB_ENABLED', True, bool)
        self.DEBUG_TB_INTERCEPT_REDIRECTS = False
        self.DEBUG_TB_HOSTS = ['127.0.0.1', 'localhost']
        
        logger.debug("Development Flask extensions configured")
    
    def _validate_development_config(self) -> None:
        """Validate development configuration for common issues and warnings."""
        validation_warnings = []
        
        # Check for insecure development settings
        if self.DEBUG and self.FLASK_ENV != 'development':
            validation_warnings.append("DEBUG is enabled but FLASK_ENV is not 'development'")
        
        if not self.FORCE_HTTPS:
            validation_warnings.append("HTTPS enforcement is disabled (acceptable for development)")
        
        if not self.SESSION_COOKIE_SECURE:
            validation_warnings.append("Session cookies are not secure (acceptable for development)")
        
        # Check for missing optional development services
        if not self.AUTH0_CLIENT_ID:
            validation_warnings.append("Auth0 client ID not configured (authentication may not work)")
        
        if not self.AWS_ACCESS_KEY_ID:
            validation_warnings.append("AWS credentials not configured (S3 features may not work)")
        
        # Check database connectivity
        if 'localhost' not in self.MONGODB_URI and '127.0.0.1' not in self.MONGODB_URI:
            validation_warnings.append("MongoDB URI does not appear to be local (check development setup)")
        
        if 'localhost' not in self.REDIS_HOST and '127.0.0.1' not in self.REDIS_HOST:
            validation_warnings.append("Redis host does not appear to be local (check development setup)")
        
        # Log warnings for developer awareness
        if validation_warnings:
            logger.warning("Development configuration validation warnings:")
            for warning in validation_warnings:
                logger.warning(f"  - {warning}")
        else:
            logger.info("Development configuration validation completed successfully")
    
    def get_development_info(self) -> Dict[str, Any]:
        """
        Get development-specific configuration information for debugging.
        
        Returns:
            Dictionary containing development configuration details
        """
        return {
            'environment': 'development',
            'debug_mode': self.DEBUG,
            'cors_origins_count': len(self.CORS_ORIGINS),
            'rate_limiting_enabled': self.RATELIMIT_ENABLED,
            'auth0_configured': bool(self.AUTH0_CLIENT_ID),
            'aws_configured': bool(self.AWS_ACCESS_KEY_ID),
            'database_uri': self.MONGODB_URI,
            'redis_host': f"{self.REDIS_HOST}:{self.REDIS_PORT}",
            'logging_level': self.LOG_LEVEL,
            'security_relaxed': not self.FORCE_HTTPS,
            'monitoring_enabled': self.PROMETHEUS_METRICS_ENABLED,
            'profiling_enabled': getattr(self, 'ENABLE_PROFILING', False),
            'circuit_breaker_disabled': not self.CIRCUIT_BREAKER_ENABLED
        }


# Development configuration factory
def create_development_config() -> DevelopmentConfig:
    """
    Factory function to create development configuration instance.
    
    This function provides a clean interface for creating development configuration
    with proper error handling and logging.
    
    Returns:
        DevelopmentConfig instance
        
    Raises:
        ConfigurationError: When development configuration creation fails
    """
    try:
        config = DevelopmentConfig()
        logger.info("Development configuration created successfully")
        return config
    except Exception as e:
        logger.error(f"Failed to create development configuration: {str(e)}")
        raise ConfigurationError(f"Development configuration creation failed: {str(e)}")


# Development utility functions
def validate_development_environment() -> bool:
    """
    Validate that the development environment is properly configured.
    
    Returns:
        True if development environment is valid, False otherwise
    """
    try:
        config = create_development_config()
        info = config.get_development_info()
        
        # Basic validation checks
        required_checks = [
            info['debug_mode'],  # Debug mode should be enabled
            info['cors_origins_count'] > 0,  # CORS origins should be configured
            info['security_relaxed']  # Security should be relaxed for development
        ]
        
        return all(required_checks)
    except Exception as e:
        logger.error(f"Development environment validation failed: {str(e)}")
        return False


def get_development_status() -> Dict[str, Any]:
    """
    Get comprehensive development environment status information.
    
    Returns:
        Dictionary containing development environment status
    """
    try:
        config = create_development_config()
        return {
            'status': 'configured',
            'environment_valid': validate_development_environment(),
            'configuration_info': config.get_development_info(),
            'warnings': [],  # Could be populated with configuration warnings
            'recommendations': [
                'Ensure MongoDB is running on localhost:27017',
                'Ensure Redis is running on localhost:6379',
                'Configure Auth0 development credentials if authentication is needed',
                'Consider using maildev for email testing',
                'Use browser developer tools with relaxed security settings'
            ]
        }
    except Exception as e:
        return {
            'status': 'error',
            'environment_valid': False,
            'error': str(e),
            'recommendations': [
                'Check environment variables in .env file',
                'Verify database services are running',
                'Review development configuration requirements'
            ]
        }


# Export development configuration
development_config = create_development_config()

# Configuration exports for application factory
__all__ = [
    'DevelopmentConfig',
    'create_development_config',
    'validate_development_environment',
    'get_development_status',
    'development_config'
]