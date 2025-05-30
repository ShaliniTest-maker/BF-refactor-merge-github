"""
Flask Application Configuration Settings Module

This module implements comprehensive Flask configuration classes for the Node.js to Python
migration project, providing environment-specific settings and centralized extension
configuration using the Flask application factory pattern.

Key Components:
- Environment-specific configuration classes (Development, Testing, Production)
- Flask application factory pattern with centralized extension initialization
- Flask-CORS 4.0+ cross-origin request handling configuration
- Flask-Limiter 3.5+ rate limiting configuration
- Flask-Talisman security headers configuration (helmet replacement)
- python-dotenv 1.0+ environment variable management
- Feature flag configuration for gradual traffic migration (5% → 25% → 50% → 100%)
- Performance monitoring integration for ≤10% variance compliance

Architecture Integration:
- Section 6.1.1: Flask application factory pattern with centralized extension initialization
- Section 0.2.5: Configuration file format migration from JSON to Python modules
- Section 0.2.4: Environment variable management using python-dotenv
- Section 3.2.1: Flask extensions configuration for CORS, rate limiting, and security headers

Author: Flask Migration Team
Version: 1.0.0
Dependencies: Flask 2.3+, python-dotenv 1.0+, Flask-CORS 4.0+, Flask-Limiter 3.5+, Flask-Talisman
"""

import os
import secrets
from datetime import timedelta
from typing import Dict, Any, List, Optional, Type, Union
from pathlib import Path

# Load environment variables from .env file
from dotenv import load_dotenv

# Import dependency configurations for integration
from .database import DatabaseConfig
from .auth import AuthConfig
from .monitoring import MonitoringConfig
from .feature_flags import (
    FeatureFlagConfig, 
    DeploymentStrategy, 
    MigrationPhase,
    PerformanceThresholds
)

# Load environment variables early in configuration initialization
load_dotenv()


class BaseConfig:
    """
    Base configuration class containing common settings shared across all environments.
    
    Implements core Flask application factory configuration patterns with centralized
    extension initialization and environment variable management using python-dotenv
    per Section 0.2.4 dependency decisions.
    """
    
    # Flask Core Configuration
    SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_urlsafe(32))
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    DEBUG = False
    TESTING = False
    
    # Application Metadata
    APP_NAME = os.getenv('APP_NAME', 'Flask Migration Application')
    APP_VERSION = os.getenv('APP_VERSION', '1.0.0')
    API_VERSION = os.getenv('API_VERSION', 'v1')
    
    # Request Configuration
    MAX_CONTENT_LENGTH = int(os.getenv('MAX_CONTENT_LENGTH', 16 * 1024 * 1024))  # 16MB
    SEND_FILE_MAX_AGE_DEFAULT = timedelta(hours=12)
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
    
    # JSON Configuration
    JSON_SORT_KEYS = True
    JSONIFY_PRETTYPRINT_REGULAR = False
    JSON_AS_ASCII = False
    
    # Security Configuration
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    REMEMBER_COOKIE_SECURE = True
    REMEMBER_COOKIE_HTTPONLY = True
    
    # Flask-CORS Configuration per Section 3.2.1 Core Web Framework
    CORS_ENABLED = os.getenv('CORS_ENABLED', 'true').lower() == 'true'
    CORS_ORIGINS = [
        origin.strip() 
        for origin in os.getenv('CORS_ORIGINS', 'http://localhost:3000').split(',')
        if origin.strip()
    ]
    CORS_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH']
    CORS_ALLOW_HEADERS = [
        'Authorization',
        'Content-Type',
        'X-Requested-With',
        'X-CSRF-Token',
        'X-Auth-Token',
        'Accept',
        'Origin',
        'Cache-Control',
        'X-File-Name'
    ]
    CORS_EXPOSE_HEADERS = [
        'X-RateLimit-Limit',
        'X-RateLimit-Remaining',
        'X-RateLimit-Reset',
        'X-Total-Count',
        'X-Pagination-Total-Pages'
    ]
    CORS_SUPPORTS_CREDENTIALS = True
    CORS_MAX_AGE = 600
    CORS_SEND_WILDCARD = False
    CORS_VARY_HEADER = True
    
    # Flask-Limiter Rate Limiting Configuration per Section 0.2.4 Dependency Decisions
    RATELIMIT_ENABLED = os.getenv('RATELIMIT_ENABLED', 'true').lower() == 'true'
    RATELIMIT_STORAGE_URL = os.getenv(
        'RATELIMIT_STORAGE_URL',
        f"redis://{os.getenv('REDIS_HOST', 'localhost')}:{os.getenv('REDIS_PORT', '6379')}/1"
    )
    RATELIMIT_STRATEGY = 'moving-window'
    RATELIMIT_DEFAULT = os.getenv('RATELIMIT_DEFAULT', '100 per hour')
    RATELIMIT_HEADERS_ENABLED = True
    RATELIMIT_HEADER_RESET = 'X-RateLimit-Reset'
    RATELIMIT_HEADER_REMAINING = 'X-RateLimit-Remaining'
    RATELIMIT_HEADER_LIMIT = 'X-RateLimit-Limit'
    RATELIMIT_HEADER_RETRY_AFTER = 'Retry-After'
    
    # Endpoint-specific rate limits
    RATELIMIT_PER_ENDPOINT = {
        'auth.login': '10 per minute',
        'auth.logout': '30 per minute',
        'auth.register': '5 per minute',
        'auth.reset_password': '3 per minute',
        'api.upload': '20 per minute',
        'api.bulk_operations': '5 per minute'
    }
    
    # Flask-Talisman Security Headers Configuration (helmet replacement) per Section 3.2.2
    TALISMAN_ENABLED = os.getenv('TALISMAN_ENABLED', 'true').lower() == 'true'
    TALISMAN_FORCE_HTTPS = os.getenv('TALISMAN_FORCE_HTTPS', 'true').lower() == 'true'
    TALISMAN_FORCE_HTTPS_PERMANENT = True
    TALISMAN_STRICT_TRANSPORT_SECURITY = True
    TALISMAN_STRICT_TRANSPORT_SECURITY_MAX_AGE = 31536000  # 1 year
    TALISMAN_STRICT_TRANSPORT_SECURITY_INCLUDE_SUBDOMAINS = True
    TALISMAN_STRICT_TRANSPORT_SECURITY_PRELOAD = True
    
    # Content Security Policy Configuration
    TALISMAN_CONTENT_SECURITY_POLICY = {
        'default-src': "'self'",
        'script-src': [
            "'self'",
            "'unsafe-inline'",  # Required for some enterprise apps
            'https://cdn.auth0.com',
            'https://js.stripe.com',
            'https://www.google-analytics.com'
        ],
        'style-src': [
            "'self'",
            "'unsafe-inline'",
            'https://fonts.googleapis.com'
        ],
        'font-src': [
            "'self'",
            'https://fonts.gstatic.com'
        ],
        'img-src': [
            "'self'",
            'data:',
            'https:',
            'blob:'
        ],
        'connect-src': [
            "'self'",
            'https://*.auth0.com',
            'https://*.amazonaws.com',
            'https://api.stripe.com',
            'wss:'  # WebSocket connections
        ],
        'object-src': "'none'",
        'base-uri': "'self'",
        'frame-ancestors': "'none'",
        'form-action': "'self'",
        'upgrade-insecure-requests': True
    }
    
    # Additional Security Headers
    TALISMAN_REFERRER_POLICY = 'strict-origin-when-cross-origin'
    TALISMAN_FEATURE_POLICY = {
        'geolocation': "'none'",
        'microphone': "'none'",
        'camera': "'none'",
        'accelerometer': "'none'",
        'gyroscope': "'none'",
        'magnetometer': "'none'",
        'payment': "'self'"
    }
    
    # Session Configuration  
    SESSION_TYPE = 'redis'
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    SESSION_KEY_PREFIX = 'flask_session:'
    SESSION_COOKIE_NAME = 'flask_session'
    
    # Feature Flags Configuration per Section 0.2.5 Infrastructure Updates
    FEATURE_FLAGS_ENABLED = os.getenv('FEATURE_FLAGS_ENABLED', 'true').lower() == 'true'
    FEATURE_FLAGS_REDIS_DB = int(os.getenv('FEATURE_FLAGS_REDIS_DB', '2'))
    
    # Migration Configuration for gradual traffic routing
    MIGRATION_ENABLED = os.getenv('MIGRATION_ENABLED', 'true').lower() == 'true'
    MIGRATION_PHASE = os.getenv('MIGRATION_PHASE', MigrationPhase.INITIALIZATION.name)
    DEPLOYMENT_STRATEGY = os.getenv('DEPLOYMENT_STRATEGY', DeploymentStrategy.BLUE_GREEN.value)
    
    # Performance Monitoring Configuration per Section 0.1.1 (≤10% variance requirement)
    PERFORMANCE_MONITORING_ENABLED = os.getenv('PERFORMANCE_MONITORING_ENABLED', 'true').lower() == 'true'
    PERFORMANCE_VARIANCE_THRESHOLD = float(os.getenv('PERFORMANCE_VARIANCE_THRESHOLD', '10.0'))
    NODEJS_BASELINE_MONITORING = os.getenv('NODEJS_BASELINE_MONITORING', 'true').lower() == 'true'
    
    # Health Check Configuration per Section 6.1.3
    HEALTH_CHECK_ENABLED = os.getenv('HEALTH_CHECK_ENABLED', 'true').lower() == 'true'
    HEALTH_CHECK_TIMEOUT = int(os.getenv('HEALTH_CHECK_TIMEOUT', '30'))
    HEALTH_CHECK_INCLUDE_EXTERNAL_SERVICES = True
    
    # Logging Configuration
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FORMAT = os.getenv('LOG_FORMAT', 'json')
    STRUCTURED_LOGGING_ENABLED = os.getenv('STRUCTURED_LOGGING_ENABLED', 'true').lower() == 'true'
    
    # Cache Configuration
    CACHE_TYPE = os.getenv('CACHE_TYPE', 'redis')
    CACHE_DEFAULT_TIMEOUT = int(os.getenv('CACHE_DEFAULT_TIMEOUT', '300'))
    CACHE_REDIS_URL = os.getenv(
        'CACHE_REDIS_URL',
        f"redis://{os.getenv('REDIS_HOST', 'localhost')}:{os.getenv('REDIS_PORT', '6379')}/0"
    )
    
    # File Upload Configuration
    UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', '/tmp/uploads')
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx'}
    MAX_FILE_SIZE = int(os.getenv('MAX_FILE_SIZE', 10 * 1024 * 1024))  # 10MB
    
    # API Configuration
    API_PAGINATION_DEFAULT_PAGE_SIZE = int(os.getenv('API_PAGINATION_DEFAULT_PAGE_SIZE', '20'))
    API_PAGINATION_MAX_PAGE_SIZE = int(os.getenv('API_PAGINATION_MAX_PAGE_SIZE', '100'))
    API_REQUEST_TIMEOUT = int(os.getenv('API_REQUEST_TIMEOUT', '30'))
    
    # Error Handling Configuration
    PROPAGATE_EXCEPTIONS = None
    TRAP_HTTP_EXCEPTIONS = False
    TRAP_BAD_REQUEST_ERRORS = None
    
    @classmethod
    def get_environment_name(cls) -> str:
        """Get the current environment name."""
        return cls.FLASK_ENV
    
    @classmethod
    def is_production(cls) -> bool:
        """Check if running in production environment."""
        return cls.FLASK_ENV == 'production'
    
    @classmethod
    def is_development(cls) -> bool:
        """Check if running in development environment."""
        return cls.FLASK_ENV == 'development'
    
    @classmethod
    def is_testing(cls) -> bool:
        """Check if running in testing environment."""
        return cls.FLASK_ENV == 'testing'
    
    @classmethod
    def get_cors_origins(cls) -> List[str]:
        """
        Get CORS origins based on environment configuration.
        
        Returns:
            List of allowed CORS origins for the current environment
        """
        return cls.CORS_ORIGINS
    
    @classmethod
    def get_feature_flag_config(cls) -> Dict[str, Any]:
        """
        Get feature flag configuration for gradual migration.
        
        Returns:
            Feature flag configuration dictionary
        """
        return {
            'enabled': cls.FEATURE_FLAGS_ENABLED,
            'redis_db': cls.FEATURE_FLAGS_REDIS_DB,
            'migration_phase': cls.MIGRATION_PHASE,
            'deployment_strategy': cls.DEPLOYMENT_STRATEGY,
            'performance_threshold': cls.PERFORMANCE_VARIANCE_THRESHOLD
        }
    
    @classmethod
    def get_security_config(cls) -> Dict[str, Any]:
        """
        Get comprehensive security configuration.
        
        Returns:
            Security configuration dictionary for Flask-Talisman and other security extensions
        """
        return {
            'talisman_enabled': cls.TALISMAN_ENABLED,
            'force_https': cls.TALISMAN_FORCE_HTTPS,
            'csp': cls.TALISMAN_CONTENT_SECURITY_POLICY,
            'csrf_enabled': cls.WTF_CSRF_ENABLED,
            'session_security': {
                'cookie_secure': cls.SESSION_COOKIE_SECURE,
                'cookie_httponly': cls.SESSION_COOKIE_HTTPONLY,
                'cookie_samesite': cls.SESSION_COOKIE_SAMESITE
            }
        }


class DevelopmentConfig(BaseConfig):
    """
    Development environment configuration with debugging enabled and relaxed security.
    
    Provides developer-friendly settings including debug mode, detailed logging,
    and permissive CORS policies while maintaining essential security practices.
    """
    
    # Flask Development Settings
    DEBUG = True
    FLASK_ENV = 'development'
    
    # Relaxed Security for Development
    TALISMAN_FORCE_HTTPS = False
    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_SECURE = False
    WTF_CSRF_ENABLED = False  # Disabled for API development
    
    # Development-specific CORS Origins
    CORS_ORIGINS = [
        'http://localhost:3000',
        'http://localhost:8080', 
        'http://localhost:5000',
        'http://127.0.0.1:3000',
        'http://127.0.0.1:8080',
        'http://127.0.0.1:5000',
        'https://dev.company.com',
        'https://localhost:3000'  # HTTPS for development testing
    ]
    
    # Development Rate Limiting (more permissive)
    RATELIMIT_DEFAULT = '1000 per hour'
    RATELIMIT_PER_ENDPOINT = {
        'auth.login': '100 per minute',
        'auth.logout': '100 per minute',
        'auth.register': '50 per minute',
        'auth.reset_password': '20 per minute',
        'api.upload': '100 per minute',
        'api.bulk_operations': '50 per minute'
    }
    
    # Development Logging
    LOG_LEVEL = 'DEBUG'
    STRUCTURED_LOGGING_ENABLED = False  # Console logging for development
    
    # Development Database Configuration
    SQLALCHEMY_ECHO = True  # Enable SQL query logging
    
    # Development Feature Flags
    MIGRATION_PHASE = MigrationPhase.INITIALIZATION.name
    PERFORMANCE_MONITORING_ENABLED = True
    NODEJS_BASELINE_MONITORING = False  # Not needed in development
    
    # Development CSP (more permissive)
    TALISMAN_CONTENT_SECURITY_POLICY = {
        'default-src': "'self'",
        'script-src': [
            "'self'",
            "'unsafe-inline'",
            "'unsafe-eval'",  # Allow eval for development tools
            'https://cdn.auth0.com',
            'http://localhost:*'
        ],
        'style-src': [
            "'self'",
            "'unsafe-inline'",
            'https://fonts.googleapis.com'
        ],
        'font-src': [
            "'self'",
            'https://fonts.gstatic.com'
        ],
        'img-src': [
            "'self'",
            'data:',
            'https:',
            'http:',
            'blob:'
        ],
        'connect-src': [
            "'self'",
            'https://*.auth0.com',
            'https://*.amazonaws.com',
            'http://localhost:*',
            'ws://localhost:*',
            'wss://localhost:*'
        ],
        'object-src': "'none'",
        'base-uri': "'self'",
        'frame-ancestors': "'self'",  # Allow framing for development tools
        'form-action': "'self'"
    }
    
    # Development Cache Configuration
    CACHE_TYPE = 'simple'  # In-memory cache for development
    CACHE_DEFAULT_TIMEOUT = 60  # Shorter timeout for development
    
    @classmethod
    def get_environment_name(cls) -> str:
        """Get development environment name."""
        return 'development'


class TestingConfig(BaseConfig):
    """
    Testing environment configuration optimized for automated testing and CI/CD.
    
    Provides isolated testing environment with in-memory databases, disabled
    external services, and fast execution optimizations for comprehensive test coverage.
    """
    
    # Flask Testing Settings
    TESTING = True
    FLASK_ENV = 'testing'
    DEBUG = False
    
    # Testing Security Settings
    WTF_CSRF_ENABLED = False  # Disabled for automated testing
    TALISMAN_ENABLED = False  # Disabled for testing
    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_SECURE = False
    
    # Testing CORS (restricted to test origins)
    CORS_ORIGINS = [
        'http://localhost:3000',
        'http://127.0.0.1:3000',
        'https://test.company.com'
    ]
    
    # Testing Rate Limiting (disabled for faster test execution)
    RATELIMIT_ENABLED = False
    
    # Testing Database Configuration
    MONGODB_URI = os.getenv('MONGODB_TEST_URI', 'mongodb://localhost:27017/test_database')
    REDIS_HOST = os.getenv('REDIS_TEST_HOST', 'localhost')
    REDIS_PORT = int(os.getenv('REDIS_TEST_PORT', '6379'))
    REDIS_DB = int(os.getenv('REDIS_TEST_DB', '15'))  # Use separate test DB
    
    # Testing Cache Configuration
    CACHE_TYPE = 'null'  # Disable caching for testing
    
    # Testing Logging
    LOG_LEVEL = 'WARNING'  # Reduce logging noise in tests
    STRUCTURED_LOGGING_ENABLED = False
    
    # Testing Feature Flags
    FEATURE_FLAGS_ENABLED = True
    MIGRATION_PHASE = MigrationPhase.INITIALIZATION.name
    PERFORMANCE_MONITORING_ENABLED = False  # Disabled for faster tests
    HEALTH_CHECK_ENABLED = False  # Disabled for unit tests
    
    # Testing File Upload
    UPLOAD_FOLDER = '/tmp/test_uploads'
    MAX_FILE_SIZE = 1 * 1024 * 1024  # 1MB for faster testing
    
    # Testing Session Configuration
    SESSION_TYPE = 'null'  # Disable persistent sessions for testing
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=5)  # Short session for tests
    
    # Testing Performance Thresholds (relaxed for testing)
    PERFORMANCE_VARIANCE_THRESHOLD = 50.0  # More lenient for testing environment
    
    @classmethod
    def get_environment_name(cls) -> str:
        """Get testing environment name."""
        return 'testing'


class ProductionConfig(BaseConfig):
    """
    Production environment configuration with enterprise-grade security and performance.
    
    Implements comprehensive security hardening, performance optimization, and enterprise
    integration requirements for production deployment with ≤10% performance variance
    compliance and full monitoring capabilities.
    """
    
    # Flask Production Settings
    DEBUG = False
    FLASK_ENV = 'production'
    
    # Production Security Settings (strict enforcement)
    TALISMAN_ENABLED = True
    TALISMAN_FORCE_HTTPS = True
    WTF_CSRF_ENABLED = True
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    
    # Production CORS Origins (whitelist only)
    CORS_ORIGINS = [
        'https://app.company.com',
        'https://admin.company.com',
        'https://api.company.com',
        'https://dashboard.company.com'
    ]
    
    # Production Rate Limiting (conservative limits)
    RATELIMIT_DEFAULT = '100 per hour'
    RATELIMIT_PER_ENDPOINT = {
        'auth.login': '10 per minute',
        'auth.logout': '30 per minute',
        'auth.register': '3 per minute',
        'auth.reset_password': '2 per minute',
        'api.upload': '10 per minute',
        'api.bulk_operations': '2 per minute'
    }
    
    # Production Logging
    LOG_LEVEL = 'INFO'
    STRUCTURED_LOGGING_ENABLED = True
    
    # Production Performance Monitoring (full monitoring enabled)
    PERFORMANCE_MONITORING_ENABLED = True
    NODEJS_BASELINE_MONITORING = True
    PERFORMANCE_VARIANCE_THRESHOLD = 10.0  # Strict ≤10% requirement
    
    # Production Feature Flags
    FEATURE_FLAGS_ENABLED = True
    MIGRATION_ENABLED = True
    
    # Production Health Checks
    HEALTH_CHECK_ENABLED = True
    HEALTH_CHECK_INCLUDE_EXTERNAL_SERVICES = True
    HEALTH_CHECK_TIMEOUT = 30
    
    # Production Session Configuration
    SESSION_TYPE = 'redis'
    SESSION_PERMANENT = False
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)  # 8-hour work session
    
    # Production Cache Configuration
    CACHE_TYPE = 'redis'
    CACHE_DEFAULT_TIMEOUT = 300  # 5 minutes
    
    # Production File Upload (stricter limits)
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB limit for production
    ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx', 'xls', 'xlsx'}
    
    # Production Content Security Policy (strict)
    TALISMAN_CONTENT_SECURITY_POLICY = {
        'default-src': "'self'",
        'script-src': [
            "'self'",
            'https://cdn.auth0.com',
            'https://js.stripe.com',
            'https://www.google-analytics.com',
            'https://www.googletagmanager.com'
        ],
        'style-src': [
            "'self'",
            "'unsafe-inline'",  # Required for some CSS frameworks
            'https://fonts.googleapis.com'
        ],
        'font-src': [
            "'self'",
            'https://fonts.gstatic.com'
        ],
        'img-src': [
            "'self'",
            'data:',
            'https:',
            'blob:'
        ],
        'connect-src': [
            "'self'",
            'https://*.auth0.com',
            'https://*.amazonaws.com',
            'https://api.stripe.com',
            'https://www.google-analytics.com',
            'wss://secure.company.com'
        ],
        'object-src': "'none'",
        'base-uri': "'self'",
        'frame-ancestors': "'none'",
        'form-action': "'self'",
        'upgrade-insecure-requests': True,
        'block-all-mixed-content': True
    }
    
    # Production Error Handling
    PROPAGATE_EXCEPTIONS = False
    TRAP_HTTP_EXCEPTIONS = True
    
    @classmethod
    def get_environment_name(cls) -> str:
        """Get production environment name."""
        return 'production'


class StagingConfig(ProductionConfig):
    """
    Staging environment configuration based on production with testing allowances.
    
    Inherits production security and performance settings while providing additional
    flexibility for UAT and pre-production validation activities.
    """
    
    # Staging Environment Settings
    FLASK_ENV = 'staging'
    
    # Staging CORS Origins (includes staging domains)
    CORS_ORIGINS = [
        'https://staging.company.com',
        'https://staging-admin.company.com',
        'https://staging-api.company.com',
        'https://uat.company.com'
    ]
    
    # Staging Rate Limiting (slightly more permissive for testing)
    RATELIMIT_DEFAULT = '200 per hour'
    RATELIMIT_PER_ENDPOINT = {
        'auth.login': '20 per minute',
        'auth.logout': '50 per minute',
        'auth.register': '10 per minute',
        'auth.reset_password': '5 per minute',
        'api.upload': '20 per minute',
        'api.bulk_operations': '5 per minute'
    }
    
    # Staging Performance Monitoring (includes baseline comparison)
    NODEJS_BASELINE_MONITORING = True
    PERFORMANCE_VARIANCE_THRESHOLD = 15.0  # Slightly more lenient for staging
    
    # Staging Logging (more detailed for debugging)
    LOG_LEVEL = 'DEBUG'
    
    # Staging Database Configuration
    MONGODB_URI = os.getenv('MONGODB_STAGING_URI', 'mongodb://localhost:27017/staging_database')
    REDIS_HOST = os.getenv('REDIS_STAGING_HOST', 'localhost')
    REDIS_DB = int(os.getenv('REDIS_STAGING_DB', '1'))
    
    @classmethod
    def get_environment_name(cls) -> str:
        """Get staging environment name."""
        return 'staging'


# Configuration Factory and Management
class ConfigFactory:
    """
    Configuration factory for Flask application factory pattern integration.
    
    Provides centralized configuration management with environment-specific
    settings and validation to ensure proper Flask application initialization.
    """
    
    _configs: Dict[str, Type[BaseConfig]] = {
        'development': DevelopmentConfig,
        'testing': TestingConfig,
        'staging': StagingConfig,
        'production': ProductionConfig
    }
    
    @classmethod
    def get_config(cls, environment: Optional[str] = None) -> Type[BaseConfig]:
        """
        Get configuration class for specified environment.
        
        Args:
            environment: Target environment name (defaults to FLASK_ENV)
            
        Returns:
            Configuration class for the specified environment
            
        Raises:
            ValueError: If environment is not supported
        """
        if environment is None:
            environment = os.getenv('FLASK_ENV', 'development')
        
        environment = environment.lower()
        
        if environment not in cls._configs:
            raise ValueError(
                f"Unsupported environment: {environment}. "
                f"Supported environments: {list(cls._configs.keys())}"
            )
        
        return cls._configs[environment]
    
    @classmethod
    def get_config_instance(cls, environment: Optional[str] = None) -> BaseConfig:
        """
        Get configuration instance for specified environment.
        
        Args:
            environment: Target environment name (defaults to FLASK_ENV)
            
        Returns:
            Configuration instance for the specified environment
        """
        config_class = cls.get_config(environment)
        return config_class()
    
    @classmethod
    def validate_config(cls, config: BaseConfig) -> bool:
        """
        Validate configuration settings for completeness and correctness.
        
        Args:
            config: Configuration instance to validate
            
        Returns:
            True if configuration is valid
            
        Raises:
            ValueError: If configuration validation fails
        """
        # Required settings validation
        required_settings = [
            'SECRET_KEY',
            'FLASK_ENV'
        ]
        
        for setting in required_settings:
            if not hasattr(config, setting) or not getattr(config, setting):
                raise ValueError(f"Required configuration setting missing: {setting}")
        
        # Security validation for production
        if config.is_production():
            if config.SECRET_KEY == 'dev-secret-key':
                raise ValueError("Production environment requires secure SECRET_KEY")
            
            if not config.TALISMAN_ENABLED:
                raise ValueError("Production environment requires Talisman security headers")
            
            if not config.SESSION_COOKIE_SECURE:
                raise ValueError("Production environment requires secure session cookies")
        
        # Performance threshold validation
        if hasattr(config, 'PERFORMANCE_VARIANCE_THRESHOLD'):
            if config.PERFORMANCE_VARIANCE_THRESHOLD <= 0:
                raise ValueError("Performance variance threshold must be positive")
        
        return True
    
    @classmethod
    def get_available_environments(cls) -> List[str]:
        """
        Get list of available configuration environments.
        
        Returns:
            List of supported environment names
        """
        return list(cls._configs.keys())


def create_config_for_environment(environment: Optional[str] = None) -> BaseConfig:
    """
    Create configuration instance for specified environment with validation.
    
    Args:
        environment: Target environment name (defaults to FLASK_ENV)
        
    Returns:
        Validated configuration instance
        
    Raises:
        ValueError: If environment is unsupported or configuration is invalid
    """
    config_instance = ConfigFactory.get_config_instance(environment)
    ConfigFactory.validate_config(config_instance)
    return config_instance


def get_database_config(environment: Optional[str] = None) -> DatabaseConfig:
    """
    Get database configuration for specified environment.
    
    Args:
        environment: Target environment name (defaults to FLASK_ENV)
        
    Returns:
        Database configuration instance
    """
    env = environment or os.getenv('FLASK_ENV', 'development')
    return DatabaseConfig(env)


def get_auth_config() -> AuthConfig:
    """
    Get authentication configuration instance.
    
    Returns:
        Authentication configuration instance
    """
    from .auth import get_auth_config
    return get_auth_config()


def get_monitoring_config() -> MonitoringConfig:
    """
    Get monitoring configuration instance.
    
    Returns:
        Monitoring configuration instance
    """
    return MonitoringConfig()


def get_feature_flag_config(environment: Optional[str] = None) -> FeatureFlagConfig:
    """
    Get feature flag configuration for gradual migration.
    
    Args:
        environment: Target environment name (defaults to FLASK_ENV)
        
    Returns:
        Feature flag configuration instance
    """
    env = environment or os.getenv('FLASK_ENV', 'development')
    return FeatureFlagConfig(env)


# Export configuration classes and factory for Flask application factory pattern
__all__ = [
    'BaseConfig',
    'DevelopmentConfig', 
    'TestingConfig',
    'StagingConfig',
    'ProductionConfig',
    'ConfigFactory',
    'create_config_for_environment',
    'get_database_config',
    'get_auth_config',
    'get_monitoring_config',
    'get_feature_flag_config'
]