"""
Development Environment Configuration Module

This module provides development-specific Flask application configuration that extends
base settings with development-friendly configurations, debug settings, local service
endpoints, and development-specific security relaxations while maintaining core
security principles.

Key Features:
- Development environment isolation per Section 8.1.2
- Flask development configuration patterns per Section 3.2.1
- Development-specific CORS and security settings per Section 6.4.2
- Local development support with python-dotenv per Section 8.1.2
- Debug configurations with structured logging
"""

import os
from typing import Dict, List, Any, Optional
from pathlib import Path

# Import for python-dotenv environment management
from dotenv import load_dotenv, find_dotenv

# Load development environment variables
load_dotenv(find_dotenv('.env.development', usecwd=True), override=True)


class DevelopmentConfig:
    """
    Development environment specific configuration class extending base Flask settings
    with development-friendly configurations, debug settings, and local service endpoints.
    
    This configuration implements:
    - Environment isolation with separate configurations per Section 8.1.2
    - Development environment management per Section 8.1.1
    - Flask development configuration patterns per Section 3.2.1
    - Development-specific CORS and security settings per Section 6.4.2
    - Local development support with python-dotenv per Section 8.1.2
    """
    
    # ==========================================
    # FLASK CORE DEVELOPMENT CONFIGURATION
    # ==========================================
    
    # Enable debug mode for development
    DEBUG = True
    TESTING = False
    DEVELOPMENT = True
    
    # Flask environment configuration
    ENV = 'development'
    
    # Secret key management for development
    SECRET_KEY = os.getenv('SECRET_KEY') or 'dev-secret-key-change-in-production-12345'
    
    # Enable Flask's development server auto-reload
    USE_RELOADER = True
    
    # Development server configuration
    HOST = os.getenv('FLASK_HOST', '0.0.0.0')
    PORT = int(os.getenv('FLASK_PORT', 5000))
    
    # Thread configuration for development debugging
    THREADED = True
    
    # ==========================================
    # DEVELOPMENT CORS CONFIGURATION
    # ==========================================
    
    # Development-specific CORS origins per Section 6.4.2
    CORS_ORIGINS: List[str] = [
        'http://localhost:3000',      # React development server
        'http://localhost:3001',      # Alternative React port
        'http://localhost:8080',      # Vue.js development server
        'http://localhost:8081',      # Alternative Vue port
        'http://127.0.0.1:3000',      # Localhost alternative
        'http://127.0.0.1:8080',      # Localhost alternative
        'https://localhost:3000',     # HTTPS development (if using SSL)
        'https://localhost:8080',     # HTTPS development (if using SSL)
        'http://dev.company.local',   # Local development domain
        'https://dev.company.local',  # Local development domain with SSL
    ]
    
    # CORS configuration for development flexibility
    CORS_ALLOW_HEADERS: List[str] = [
        'Accept',
        'Accept-Language',
        'Authorization',
        'Content-Language',
        'Content-Type',
        'X-Requested-With',
        'X-CSRF-Token',
        'X-Auth-Token',
        'X-API-Key',
        'Origin',
        'Cache-Control',
        'Pragma'
    ]
    
    CORS_METHODS: List[str] = [
        'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'
    ]
    
    # Enable credentials for development
    CORS_SUPPORTS_CREDENTIALS = True
    
    # Shorter preflight cache for development (5 minutes)
    CORS_MAX_AGE = 300
    
    # ==========================================
    # DEVELOPMENT DATABASE CONFIGURATION
    # ==========================================
    
    # MongoDB development configuration
    MONGODB_HOST = os.getenv('MONGODB_HOST', 'localhost')
    MONGODB_PORT = int(os.getenv('MONGODB_PORT', 27017))
    MONGODB_DB = os.getenv('MONGODB_DB', 'flask_app_dev')
    MONGODB_USERNAME = os.getenv('MONGODB_USERNAME', '')
    MONGODB_PASSWORD = os.getenv('MONGODB_PASSWORD', '')
    
    # Development MongoDB connection string
    if MONGODB_USERNAME and MONGODB_PASSWORD:
        MONGODB_URI = f"mongodb://{MONGODB_USERNAME}:{MONGODB_PASSWORD}@{MONGODB_HOST}:{MONGODB_PORT}/{MONGODB_DB}?authSource=admin"
    else:
        MONGODB_URI = f"mongodb://{MONGODB_HOST}:{MONGODB_PORT}/{MONGODB_DB}"
    
    # MongoDB development connection settings
    MONGODB_SETTINGS = {
        'host': MONGODB_URI,
        'connect': False,  # Lazy connection for development
        'maxPoolSize': 10,  # Smaller pool for development
        'minPoolSize': 1,
        'maxIdleTimeMS': 10000,  # 10 seconds
        'serverSelectionTimeoutMS': 5000,  # 5 seconds
        'socketTimeoutMS': 10000,  # 10 seconds
        'connectTimeoutMS': 5000,  # 5 seconds
        'retryWrites': True,
        'w': 'majority',
        # TLS disabled for local development (enable for staging/production)
        'tls': False,
        'tlsAllowInvalidCertificates': True,  # Only for development
    }
    
    # ==========================================
    # DEVELOPMENT REDIS CONFIGURATION
    # ==========================================
    
    # Redis development configuration
    REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
    REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
    REDIS_PASSWORD = os.getenv('REDIS_PASSWORD', '')
    REDIS_DB = int(os.getenv('REDIS_DB', 0))
    
    # Redis development connection settings
    REDIS_CONFIG = {
        'host': REDIS_HOST,
        'port': REDIS_PORT,
        'password': REDIS_PASSWORD if REDIS_PASSWORD else None,
        'db': REDIS_DB,
        'decode_responses': True,
        'max_connections': 20,  # Smaller pool for development
        'retry_on_timeout': True,
        'socket_timeout': 5.0,   # Shorter timeout for development
        'socket_connect_timeout': 3.0,
        'health_check_interval': 30
    }
    
    # Redis development URL
    if REDIS_PASSWORD:
        REDIS_URL = f"redis://:{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}"
    else:
        REDIS_URL = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}"
    
    # ==========================================
    # DEVELOPMENT SECURITY CONFIGURATION
    # ==========================================
    
    # Development-friendly security configurations while maintaining core security
    # per Section 6.4.2
    
    # Flask-Talisman development configuration
    TALISMAN_CONFIG = {
        'force_https': False,  # Allow HTTP for local development
        'force_https_permanent': False,
        'strict_transport_security': False,  # Disabled for local HTTP
        'strict_transport_security_max_age': 0,
        'strict_transport_security_include_subdomains': False,
        'content_security_policy': {
            'default-src': "'self'",
            'script-src': "'self' 'unsafe-inline' 'unsafe-eval' https://cdn.auth0.com",  # Allow inline for dev tools
            'style-src': "'self' 'unsafe-inline'",  # Allow inline styles for dev
            'img-src': "'self' data: https: http:",  # Allow HTTP images for dev
            'connect-src': "'self' http://localhost:* https://localhost:* https://*.auth0.com ws: wss:",
            'font-src': "'self' data:",
            'object-src': "'none'",
            'base-uri': "'self'",
            'frame-ancestors': "'self' http://localhost:*",  # Allow localhost frames
            'form-action': "'self' http://localhost:*"
        },
        'content_security_policy_nonce_in': [],  # Simplified for development
        'referrer_policy': 'strict-origin-when-cross-origin',
        'feature_policy': {
            'geolocation': "'none'",
            'microphone': "'none'",
            'camera': "'none'"
        },
        'session_cookie_secure': False,  # Allow non-HTTPS cookies for development
        'session_cookie_http_only': True,  # Maintain security
        'session_cookie_samesite': 'Lax'  # More flexible for development
    }
    
    # Rate limiting relaxed for development
    RATELIMIT_STORAGE_URL = REDIS_URL
    RATELIMIT_STRATEGY = 'moving-window'
    RATELIMIT_DEFAULT = '1000 per hour;100 per minute;20 per second'  # More permissive
    RATELIMIT_HEADERS_ENABLED = True
    
    # ==========================================
    # DEVELOPMENT AUTHENTICATION CONFIGURATION
    # ==========================================
    
    # Auth0 development configuration
    AUTH0_DOMAIN = os.getenv('AUTH0_DOMAIN', 'dev-company.auth0.com')
    AUTH0_CLIENT_ID = os.getenv('AUTH0_CLIENT_ID', '')
    AUTH0_CLIENT_SECRET = os.getenv('AUTH0_CLIENT_SECRET', '')
    AUTH0_AUDIENCE = os.getenv('AUTH0_AUDIENCE', 'https://api.dev.company.com')
    
    # JWT development configuration
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', SECRET_KEY)
    JWT_ALGORITHM = os.getenv('JWT_ALGORITHM', 'RS256')
    JWT_ACCESS_TOKEN_EXPIRES = int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', 3600))  # 1 hour
    JWT_REFRESH_TOKEN_EXPIRES = int(os.getenv('JWT_REFRESH_TOKEN_EXPIRES', 86400))  # 24 hours
    
    # Flask-Login development configuration
    REMEMBER_COOKIE_SECURE = False  # Allow non-HTTPS for development
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_DURATION = 86400  # 24 hours for development convenience
    SESSION_PROTECTION = 'basic'  # Less strict for development
    
    # ==========================================
    # DEVELOPMENT LOGGING CONFIGURATION
    # ==========================================
    
    # Development logging levels and settings
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'DEBUG')
    LOG_FORMAT = 'development'  # Human-readable format for development
    
    # Structured logging configuration for development
    LOGGING_CONFIG = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'development': {
                'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
                'datefmt': '%Y-%m-%d %H:%M:%S'
            },
            'json': {
                'class': 'pythonjsonlogger.jsonlogger.JsonFormatter',
                'format': '%(asctime)s %(name)s %(levelname)s %(message)s'
            }
        },
        'handlers': {
            'console': {
                'class': 'logging.StreamHandler',
                'level': LOG_LEVEL,
                'formatter': 'development',
                'stream': 'ext://sys.stdout'
            },
            'file': {
                'class': 'logging.handlers.RotatingFileHandler',
                'level': 'DEBUG',
                'formatter': 'json',
                'filename': 'logs/development.log',
                'maxBytes': 10485760,  # 10MB
                'backupCount': 5
            }
        },
        'loggers': {
            '': {  # Root logger
                'level': LOG_LEVEL,
                'handlers': ['console', 'file'],
                'propagate': False
            },
            'werkzeug': {
                'level': 'INFO',  # Reduce Werkzeug noise
                'handlers': ['console'],
                'propagate': False
            },
            'urllib3': {
                'level': 'WARNING',  # Reduce HTTP client noise
                'handlers': ['console'],
                'propagate': False
            }
        }
    }
    
    # ==========================================
    # DEVELOPMENT SERVICE ENDPOINTS
    # ==========================================
    
    # Local service endpoint configurations for development environment
    # per Section 8.1.2
    
    # Local development service URLs
    SERVICE_ENDPOINTS = {
        'auth_service': os.getenv('AUTH_SERVICE_URL', 'http://localhost:5001'),
        'user_service': os.getenv('USER_SERVICE_URL', 'http://localhost:5002'),
        'notification_service': os.getenv('NOTIFICATION_SERVICE_URL', 'http://localhost:5003'),
        'file_service': os.getenv('FILE_SERVICE_URL', 'http://localhost:5004'),
        'analytics_service': os.getenv('ANALYTICS_SERVICE_URL', 'http://localhost:5005'),
    }
    
    # External service configurations for development
    EXTERNAL_SERVICES = {
        'aws_s3_bucket': os.getenv('AWS_S3_BUCKET', 'dev-company-bucket'),
        'aws_region': os.getenv('AWS_REGION', 'us-east-1'),
        'sendgrid_api_key': os.getenv('SENDGRID_API_KEY', ''),
        'stripe_secret_key': os.getenv('STRIPE_SECRET_KEY', ''),
        'stripe_publishable_key': os.getenv('STRIPE_PUBLISHABLE_KEY', ''),
    }
    
    # ==========================================
    # DEVELOPMENT MONITORING CONFIGURATION
    # ==========================================
    
    # Development monitoring settings
    MONITORING_ENABLED = bool(os.getenv('MONITORING_ENABLED', False))
    
    # Prometheus metrics configuration for development
    PROMETHEUS_CONFIG = {
        'enabled': MONITORING_ENABLED,
        'port': int(os.getenv('PROMETHEUS_PORT', 8000)),
        'path': '/metrics',
        'namespace': 'flask_app_dev',
        'buckets': [0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0]
    }
    
    # Health check endpoints configuration
    HEALTH_CHECK_CONFIG = {
        'enabled': True,
        'endpoints': {
            'health': '/health',
            'ready': '/health/ready',
            'live': '/health/live'
        },
        'database_check': True,
        'redis_check': True,
        'external_service_check': False  # Disabled for development
    }
    
    # ==========================================
    # DEVELOPMENT TESTING CONFIGURATION
    # ==========================================
    
    # Testing configuration for development environment
    TESTING_CONFIG = {
        'enabled': True,
        'test_database': f"{MONGODB_DB}_test",
        'test_redis_db': 15,  # Use a different Redis DB for tests
        'preserve_context_on_exception': True,
        'trap_bad_request_errors': True,
        'trap_http_exceptions': True
    }
    
    # ==========================================
    # DEVELOPMENT FEATURE FLAGS
    # ==========================================
    
    # Feature flags for development environment
    FEATURE_FLAGS = {
        'enable_debug_toolbar': True,
        'enable_profiler': bool(os.getenv('ENABLE_PROFILER', False)),
        'enable_api_documentation': True,
        'enable_swagger_ui': True,
        'enable_admin_panel': True,
        'enable_debug_authentication': bool(os.getenv('ENABLE_DEBUG_AUTH', False)),
        'enable_mock_external_services': bool(os.getenv('ENABLE_MOCK_SERVICES', False)),
        'enable_sql_logging': bool(os.getenv('ENABLE_SQL_LOGGING', False)),
        'enable_request_logging': True,
    }
    
    # ==========================================
    # DEVELOPMENT SESSION CONFIGURATION
    # ==========================================
    
    # Flask-Session development configuration
    SESSION_TYPE = 'redis'
    SESSION_REDIS = None  # Will be set from REDIS_CONFIG
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    SESSION_KEY_PREFIX = 'dev_session:'
    SESSION_COOKIE_NAME = 'dev_session'
    SESSION_COOKIE_DOMAIN = None  # Allow for localhost
    SESSION_COOKIE_PATH = '/'
    SESSION_COOKIE_SECURE = False  # Allow HTTP for development
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # ==========================================
    # DEVELOPMENT CACHE CONFIGURATION
    # ==========================================
    
    # Cache configuration for development
    CACHE_CONFIG = {
        'CACHE_TYPE': 'RedisCache',
        'CACHE_REDIS_HOST': REDIS_HOST,
        'CACHE_REDIS_PORT': REDIS_PORT,
        'CACHE_REDIS_PASSWORD': REDIS_PASSWORD if REDIS_PASSWORD else None,
        'CACHE_REDIS_DB': 1,  # Different DB for cache
        'CACHE_DEFAULT_TIMEOUT': 300,  # 5 minutes
        'CACHE_KEY_PREFIX': 'dev_cache:',
        'CACHE_OPTIONS': {
            'max_connections': 10  # Smaller pool for development
        }
    }
    
    # ==========================================
    # DEVELOPMENT STATIC FILES CONFIGURATION
    # ==========================================
    
    # Static files configuration for development
    STATIC_FOLDER = 'static'
    STATIC_URL_PATH = '/static'
    TEMPLATES_AUTO_RELOAD = True
    EXPLAIN_TEMPLATE_LOADING = bool(os.getenv('EXPLAIN_TEMPLATE_LOADING', False))
    
    # ==========================================
    # DEVELOPMENT MAIL CONFIGURATION
    # ==========================================
    
    # Mail configuration for development (using console backend)
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'localhost')
    MAIL_PORT = int(os.getenv('MAIL_PORT', 1025))  # MailHog default port
    MAIL_USE_TLS = bool(os.getenv('MAIL_USE_TLS', False))
    MAIL_USE_SSL = bool(os.getenv('MAIL_USE_SSL', False))
    MAIL_USERNAME = os.getenv('MAIL_USERNAME', '')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD', '')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', 'noreply@dev.company.com')
    MAIL_SUPPRESS_SEND = bool(os.getenv('MAIL_SUPPRESS_SEND', True))  # Suppress for development
    
    # ==========================================
    # DEVELOPMENT UTILITIES
    # ==========================================
    
    @classmethod
    def validate_config(cls) -> Dict[str, Any]:
        """
        Validate development configuration settings and return validation results.
        
        Returns:
            Dictionary containing validation results and any configuration warnings.
        """
        warnings = []
        errors = []
        
        # Check for default secret key
        if cls.SECRET_KEY == 'dev-secret-key-change-in-production-12345':
            warnings.append("Using default SECRET_KEY in development. Set environment variable for security.")
        
        # Check Auth0 configuration
        if not cls.AUTH0_CLIENT_SECRET:
            warnings.append("AUTH0_CLIENT_SECRET not set. Authentication may not work properly.")
        
        # Check database connectivity requirements
        if not cls.MONGODB_URI:
            errors.append("MONGODB_URI is not properly configured.")
        
        # Check Redis configuration
        if not cls.REDIS_URL:
            errors.append("REDIS_URL is not properly configured.")
        
        # Validate CORS origins
        if not cls.CORS_ORIGINS:
            warnings.append("No CORS origins configured. Frontend may not be able to connect.")
        
        return {
            'valid': len(errors) == 0,
            'warnings': warnings,
            'errors': errors,
            'config_type': 'development'
        }
    
    @classmethod
    def get_environment_info(cls) -> Dict[str, Any]:
        """
        Get development environment information for debugging and monitoring.
        
        Returns:
            Dictionary containing environment configuration details.
        """
        return {
            'environment': 'development',
            'debug': cls.DEBUG,
            'testing': cls.TESTING,
            'flask_env': cls.ENV,
            'mongodb_host': cls.MONGODB_HOST,
            'redis_host': cls.REDIS_HOST,
            'cors_origins_count': len(cls.CORS_ORIGINS),
            'feature_flags': cls.FEATURE_FLAGS,
            'monitoring_enabled': cls.MONITORING_ENABLED,
            'log_level': cls.LOG_LEVEL
        }


# Export configuration for Flask application factory
config = DevelopmentConfig

# Export configuration validation utility
def validate_development_config() -> Dict[str, Any]:
    """
    Validate development configuration and log any issues.
    
    Returns:
        Configuration validation results.
    """
    return DevelopmentConfig.validate_config()


def setup_development_logging() -> None:
    """
    Set up development-specific logging configuration.
    This function configures logging for the development environment with
    console output and file logging for debugging purposes.
    """
    import logging.config
    import os
    from pathlib import Path
    
    # Ensure logs directory exists
    log_dir = Path('logs')
    log_dir.mkdir(exist_ok=True)
    
    # Apply logging configuration
    logging.config.dictConfig(DevelopmentConfig.LOGGING_CONFIG)
    
    # Log environment startup
    logger = logging.getLogger(__name__)
    logger.info("Development environment logging configured")
    logger.debug(f"Log level set to: {DevelopmentConfig.LOG_LEVEL}")
    logger.debug(f"Environment info: {DevelopmentConfig.get_environment_info()}")


# Auto-setup logging when module is imported
setup_development_logging()