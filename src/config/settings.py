"""
Main Flask Configuration Classes

This module implements environment-specific settings (Development, Testing, Production) 
using the Flask application factory pattern. Manages Flask extensions configuration, 
CORS settings, rate limiting, security headers, and environment variable loading via 
python-dotenv. Serves as the primary configuration entry point for the Flask application 
factory.

Key Components:
- Flask 2.3+ application factory configuration pattern per Section 0.2.3
- Environment-specific configuration classes (Development, Production, Testing) per Section 0.2.5
- Flask-CORS 4.0+ settings for cross-origin request handling per Section 3.2.1
- Flask-Limiter 3.5+ rate limiting configuration per dependency migration table Section 0.2.4
- Flask-Talisman security headers as helmet middleware replacement per Section 3.2.2
- python-dotenv 1.0+ for environment variable management per Section 0.2.4
- Feature flag configuration support for gradual traffic migration per Section 0.2.5

Architecture Integration:
- Section 6.1.1: Flask application factory pattern with centralized extension initialization
- Section 0.2.5: Configuration file format migration from JSON to Python modules
- Section 0.2.4: Environment variable management using python-dotenv
- Section 3.2.1: Flask extensions configuration for CORS, rate limiting, and security headers

Performance Requirements:
- Maintains ≤10% performance variance from Node.js baseline per Section 0.1.1
- Optimized configuration for production WSGI deployment per Section 6.1.3
- Connection pooling and resource optimization for enterprise deployment

Security Implementation:
- Flask-Talisman security headers enforcement replacing helmet middleware
- CORS policy preservation from Express.js configuration
- Rate limiting patterns equivalent to express-rate-limit functionality
- Secure session management with Redis backend integration

Author: Flask Migration Team
Version: 1.0.0
Dependencies: Flask 2.3+, Flask-CORS 4.0+, Flask-Limiter 3.5+, Flask-Talisman, python-dotenv 1.0+
"""

import os
import logging
from typing import Dict, Any, Optional, List, Union, Type
from datetime import timedelta
from pathlib import Path

# Flask core imports
from flask import Flask

# Environment management
from dotenv import load_dotenv

# Configuration module imports
from src.config.database import DatabaseConfig, create_database_config
from src.config.auth import AuthConfig, create_auth_config
from src.config.monitoring import (
    StructuredLoggingConfig, 
    PrometheusMetricsConfig, 
    HealthCheckConfig,
    create_monitoring_config
)
from src.config.feature_flags import (
    FeatureFlagConfig, 
    MigrationPhase,
    create_feature_flag_config
)

# Load environment variables early
load_dotenv()

# Configure module logger
logger = logging.getLogger(__name__)


class BaseConfig:
    """
    Base configuration class providing common settings for all environments.
    
    Implements core Flask application configuration including secret key management,
    security settings, and common extension configurations that are shared across
    all deployment environments.
    """
    
    # Flask Core Configuration
    SECRET_KEY = os.getenv('SECRET_KEY', os.urandom(32).hex())
    
    # Application Metadata
    APP_NAME = os.getenv('APP_NAME', 'Flask Migration App')
    APP_VERSION = os.getenv('APP_VERSION', '1.0.0')
    
    # Environment Configuration
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    
    # Security Configuration
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = int(os.getenv('CSRF_TIME_LIMIT', '3600'))  # 1 hour
    
    # Session Configuration
    PERMANENT_SESSION_LIFETIME = timedelta(
        hours=int(os.getenv('SESSION_LIFETIME_HOURS', '24'))
    )
    
    # Request Parsing Configuration
    MAX_CONTENT_LENGTH = int(os.getenv('MAX_CONTENT_LENGTH', '16777216'))  # 16MB default
    
    # JSON Configuration
    JSON_SORT_KEYS = False
    JSONIFY_PRETTYPRINT_REGULAR = False
    
    # Flask-CORS Configuration per Section 3.2.1
    CORS_CONFIG = {
        'origins': os.getenv('CORS_ORIGINS', '*').split(','),
        'methods': ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
        'allow_headers': [
            'Content-Type',
            'Authorization', 
            'X-Requested-With',
            'X-CSRF-Token',
            'X-Correlation-ID',
            'Cache-Control'
        ],
        'expose_headers': [
            'X-Total-Count',
            'X-Page-Count', 
            'X-Rate-Limit-Remaining',
            'X-Rate-Limit-Reset'
        ],
        'supports_credentials': True,
        'max_age': int(os.getenv('CORS_MAX_AGE', '86400'))  # 24 hours
    }
    
    # Flask-Limiter Configuration per Section 0.2.4 dependency decisions
    RATELIMIT_CONFIG = {
        'default': os.getenv('RATE_LIMIT_DEFAULT', '1000 per hour'),
        'key_func': lambda: 'global',  # Will be overridden for user-specific limits
        'storage_uri': None,  # Will be set from Redis configuration
        'strategy': 'fixed-window-elastic-expiry',
        'headers_enabled': True,
        'header_name_mapping': {
            'limit': 'X-Rate-Limit-Limit',
            'remaining': 'X-Rate-Limit-Remaining', 
            'reset': 'X-Rate-Limit-Reset',
            'retry_after': 'Retry-After'
        },
        'swallow_errors': True,  # Don't fail if rate limiter is unavailable
        'in_memory_fallback_enabled': True
    }
    
    # Flask-Talisman Security Headers Configuration per Section 3.2.2
    TALISMAN_CONFIG = {
        'force_https': os.getenv('FORCE_HTTPS', 'false').lower() == 'true',
        'strict_transport_security': True,
        'strict_transport_security_max_age': int(os.getenv('HSTS_MAX_AGE', '31536000')),  # 1 year
        'content_security_policy': {
            'default-src': "'self'",
            'script-src': "'self' 'unsafe-inline'",
            'style-src': "'self' 'unsafe-inline'",
            'img-src': "'self' data: https:",
            'connect-src': "'self'",
            'font-src': "'self'",
            'object-src': "'none'",
            'frame-ancestors': "'none'",
            'base-uri': "'self'"
        },
        'content_security_policy_nonce_in': ['script-src', 'style-src'],
        'referrer_policy': 'strict-origin-when-cross-origin',
        'feature_policy': {
            'geolocation': "'none'",
            'camera': "'none'",
            'microphone': "'none'",
            'payment': "'none'"
        },
        'permissions_policy': {
            'geolocation': [],
            'camera': [],
            'microphone': [],
            'payment': []
        }
    }
    
    # Health Check Configuration
    HEALTH_CHECK_CONFIG = {
        'enabled': True,
        'endpoint_path': '/health',
        'readiness_path': '/health/ready',
        'liveness_path': '/health/live',
        'include_version': True,
        'include_timestamp': True,
        'include_dependencies': True,
        'check_database': True,
        'check_redis': True,
        'check_external_services': False,  # Disabled by default to avoid cascading failures
        'timeout_seconds': int(os.getenv('HEALTH_CHECK_TIMEOUT', '5'))
    }
    
    # Logging Configuration
    LOGGING_CONFIG = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'default': {
                'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
            },
            'json': {
                'class': 'pythonjsonlogger.jsonlogger.JsonFormatter',
                'format': '%(asctime)s %(name)s %(levelname)s %(message)s'
            }
        },
        'handlers': {
            'console': {
                'class': 'logging.StreamHandler',
                'level': 'INFO',
                'formatter': 'default',
                'stream': 'ext://sys.stdout'
            }
        },
        'loggers': {
            '': {
                'level': 'INFO',
                'handlers': ['console']
            }
        }
    }
    
    @classmethod
    def init_app(cls, app: Flask) -> None:
        """
        Initialize Flask application with base configuration.
        
        Args:
            app: Flask application instance
        """
        # Set up logging
        app.logger.info(f"Initializing {cls.__name__} configuration")
        
        # Configure JSON encoder for consistent API responses
        app.json.sort_keys = cls.JSON_SORT_KEYS
        
        # Log configuration summary
        app.logger.info(
            "Base configuration initialized",
            extra={
                'app_name': cls.APP_NAME,
                'app_version': cls.APP_VERSION,
                'environment': cls.FLASK_ENV,
                'max_content_length': cls.MAX_CONTENT_LENGTH,
                'cors_enabled': bool(cls.CORS_CONFIG['origins']),
                'security_headers_enabled': bool(cls.TALISMAN_CONFIG),
                'rate_limiting_enabled': bool(cls.RATELIMIT_CONFIG['default'])
            }
        )


class DevelopmentConfig(BaseConfig):
    """
    Development environment configuration with debug features enabled.
    
    Provides developer-friendly settings including debug mode, detailed logging,
    relaxed security policies, and development-optimized database connections.
    Implements local development patterns while maintaining compatibility with
    production configuration structure.
    """
    
    # Debug Configuration
    DEBUG = True
    TESTING = False
    
    # Development Database Configuration
    DATABASE_CONFIG = None  # Will be initialized in init_app
    
    # Development Authentication Configuration
    AUTH_CONFIG = None  # Will be initialized in init_app
    
    # Development Monitoring Configuration
    MONITORING_CONFIG = None  # Will be initialized in init_app
    
    # Development Feature Flags Configuration
    FEATURE_FLAGS_CONFIG = None  # Will be initialized in init_app
    
    # Development-specific CORS (more permissive)
    CORS_CONFIG = {
        **BaseConfig.CORS_CONFIG,
        'origins': ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:8000'],
        'supports_credentials': True
    }
    
    # Development Rate Limiting (more permissive)
    RATELIMIT_CONFIG = {
        **BaseConfig.RATELIMIT_CONFIG,
        'default': '10000 per hour',  # Higher limits for development
        'swallow_errors': True
    }
    
    # Development Security Headers (relaxed CSP)
    TALISMAN_CONFIG = {
        **BaseConfig.TALISMAN_CONFIG,
        'force_https': False,
        'content_security_policy': {
            'default-src': "'self'",
            'script-src': "'self' 'unsafe-inline' 'unsafe-eval'",  # Allow eval for dev tools
            'style-src': "'self' 'unsafe-inline'",
            'img-src': "'self' data: blob: https: http:",  # Allow all image sources
            'connect-src': "'self' ws: wss:",  # Allow websockets for hot reload
            'font-src': "'self' data:",
            'object-src': "'none'",
            'frame-ancestors': "'self'",
            'base-uri': "'self'"
        }
    }
    
    # Development Logging (verbose)
    LOGGING_CONFIG = {
        **BaseConfig.LOGGING_CONFIG,
        'handlers': {
            **BaseConfig.LOGGING_CONFIG['handlers'],
            'console': {
                **BaseConfig.LOGGING_CONFIG['handlers']['console'],
                'level': 'DEBUG'
            }
        },
        'loggers': {
            '': {
                'level': 'DEBUG',
                'handlers': ['console']
            },
            'src': {
                'level': 'DEBUG',
                'handlers': ['console'],
                'propagate': False
            }
        }
    }
    
    @classmethod
    def init_app(cls, app: Flask) -> None:
        """
        Initialize Flask application with development configuration.
        
        Args:
            app: Flask application instance
        """
        # Initialize base configuration
        super().init_app(app)
        
        # Initialize development-specific configurations
        cls.DATABASE_CONFIG = create_database_config('development')
        cls.AUTH_CONFIG = create_auth_config('development')
        cls.MONITORING_CONFIG = create_monitoring_config('development')
        cls.FEATURE_FLAGS_CONFIG = create_feature_flag_config('development')
        
        # Set Redis URI for rate limiting from database config
        if cls.DATABASE_CONFIG and hasattr(cls.DATABASE_CONFIG, 'redis_config'):
            redis_config = cls.DATABASE_CONFIG.redis_config
            cls.RATELIMIT_CONFIG['storage_uri'] = (
                f"redis://:{redis_config.get('password', '')}@"
                f"{redis_config.get('host', 'localhost')}:"
                f"{redis_config.get('port', 6379)}/{redis_config.get('db', 0)}"
            )
        
        app.logger.info(
            "Development configuration initialized",
            extra={
                'debug_enabled': cls.DEBUG,
                'database_configured': cls.DATABASE_CONFIG is not None,
                'auth_configured': cls.AUTH_CONFIG is not None,
                'monitoring_configured': cls.MONITORING_CONFIG is not None,
                'feature_flags_configured': cls.FEATURE_FLAGS_CONFIG is not None
            }
        )


class TestingConfig(BaseConfig):
    """
    Testing environment configuration optimized for automated testing.
    
    Provides test-specific settings including isolated test database connections,
    disabled external service integrations, faster timeouts, and comprehensive
    test coverage support. Maintains security practices while enabling efficient
    test execution.
    """
    
    # Testing Configuration
    TESTING = True
    DEBUG = True
    WTF_CSRF_ENABLED = False  # Disable CSRF for easier testing
    
    # Testing Database Configuration
    DATABASE_CONFIG = None  # Will be initialized in init_app
    
    # Testing Authentication Configuration  
    AUTH_CONFIG = None  # Will be initialized in init_app
    
    # Testing Monitoring Configuration
    MONITORING_CONFIG = None  # Will be initialized in init_app
    
    # Testing Feature Flags Configuration
    FEATURE_FLAGS_CONFIG = None  # Will be initialized in init_app
    
    # Testing CORS (permissive for test clients)
    CORS_CONFIG = {
        **BaseConfig.CORS_CONFIG,
        'origins': '*',  # Allow all origins in testing
        'supports_credentials': False  # Simplified for testing
    }
    
    # Testing Rate Limiting (disabled for consistent test results)
    RATELIMIT_CONFIG = {
        **BaseConfig.RATELIMIT_CONFIG,
        'default': '100000 per hour',  # Very high limits to avoid interference
        'swallow_errors': True,
        'in_memory_fallback_enabled': True
    }
    
    # Testing Security Headers (minimal for testing)
    TALISMAN_CONFIG = {
        **BaseConfig.TALISMAN_CONFIG,
        'force_https': False,
        'strict_transport_security': False,
        'content_security_policy': None  # Disable CSP in testing
    }
    
    # Testing Health Checks (faster timeouts)
    HEALTH_CHECK_CONFIG = {
        **BaseConfig.HEALTH_CHECK_CONFIG,
        'timeout_seconds': 2,
        'check_external_services': False,  # Skip external services in testing
        'include_dependencies': True
    }
    
    # Testing Logging (capture everything)
    LOGGING_CONFIG = {
        **BaseConfig.LOGGING_CONFIG,
        'handlers': {
            **BaseConfig.LOGGING_CONFIG['handlers'],
            'console': {
                **BaseConfig.LOGGING_CONFIG['handlers']['console'],
                'level': 'DEBUG'
            }
        },
        'loggers': {
            '': {
                'level': 'DEBUG',
                'handlers': ['console']
            },
            'src': {
                'level': 'DEBUG', 
                'handlers': ['console'],
                'propagate': False
            }
        }
    }
    
    @classmethod
    def init_app(cls, app: Flask) -> None:
        """
        Initialize Flask application with testing configuration.
        
        Args:
            app: Flask application instance
        """
        # Initialize base configuration
        super().init_app(app)
        
        # Initialize testing-specific configurations
        cls.DATABASE_CONFIG = create_database_config('testing')
        cls.AUTH_CONFIG = create_auth_config('testing')
        cls.MONITORING_CONFIG = create_monitoring_config('testing')
        cls.FEATURE_FLAGS_CONFIG = create_feature_flag_config('testing')
        
        # Set Redis URI for rate limiting from database config
        if cls.DATABASE_CONFIG and hasattr(cls.DATABASE_CONFIG, 'redis_config'):
            redis_config = cls.DATABASE_CONFIG.redis_config
            cls.RATELIMIT_CONFIG['storage_uri'] = (
                f"redis://:{redis_config.get('password', '')}@"
                f"{redis_config.get('host', 'localhost')}:"
                f"{redis_config.get('port', 6379)}/{redis_config.get('db', 15)}"  # Use test DB
            )
        
        app.logger.info(
            "Testing configuration initialized",
            extra={
                'testing_enabled': cls.TESTING,
                'csrf_disabled': not cls.WTF_CSRF_ENABLED,
                'database_configured': cls.DATABASE_CONFIG is not None,
                'auth_configured': cls.AUTH_CONFIG is not None,
                'monitoring_configured': cls.MONITORING_CONFIG is not None,
                'feature_flags_configured': cls.FEATURE_FLAGS_CONFIG is not None
            }
        )


class StagingConfig(BaseConfig):
    """
    Staging environment configuration for pre-production validation.
    
    Provides production-like settings with enhanced monitoring and debugging
    capabilities for final validation before production deployment. Includes
    comprehensive performance monitoring and migration phase testing support.
    """
    
    # Staging Configuration
    DEBUG = False
    TESTING = False
    
    # Staging Database Configuration
    DATABASE_CONFIG = None  # Will be initialized in init_app
    
    # Staging Authentication Configuration
    AUTH_CONFIG = None  # Will be initialized in init_app
    
    # Staging Monitoring Configuration (enhanced)
    MONITORING_CONFIG = None  # Will be initialized in init_app
    
    # Staging Feature Flags Configuration (gradual migration testing)
    FEATURE_FLAGS_CONFIG = None  # Will be initialized in init_app
    
    # Staging CORS (production-like but with staging domains)
    CORS_CONFIG = {
        **BaseConfig.CORS_CONFIG,
        'origins': os.getenv('STAGING_CORS_ORIGINS', 'https://staging.example.com').split(','),
        'supports_credentials': True
    }
    
    # Staging Rate Limiting (production-like)
    RATELIMIT_CONFIG = {
        **BaseConfig.RATELIMIT_CONFIG,
        'default': '5000 per hour',  # Moderate limits for staging
        'swallow_errors': False  # Fail fast to catch rate limiting issues
    }
    
    # Staging Security Headers (production-like)
    TALISMAN_CONFIG = {
        **BaseConfig.TALISMAN_CONFIG,
        'force_https': True,
        'strict_transport_security': True,
        'content_security_policy': {
            **BaseConfig.TALISMAN_CONFIG['content_security_policy'],
            'connect-src': "'self' https://staging-api.example.com"
        }
    }
    
    # Staging Health Checks (comprehensive)
    HEALTH_CHECK_CONFIG = {
        **BaseConfig.HEALTH_CHECK_CONFIG,
        'include_dependencies': True,
        'check_external_services': True,  # Test external service connectivity
        'timeout_seconds': 10
    }
    
    # Staging Logging (production format with debug info)
    LOGGING_CONFIG = {
        **BaseConfig.LOGGING_CONFIG,
        'handlers': {
            **BaseConfig.LOGGING_CONFIG['handlers'],
            'console': {
                **BaseConfig.LOGGING_CONFIG['handlers']['console'],
                'level': 'INFO',
                'formatter': 'json'  # Use JSON formatting like production
            }
        },
        'loggers': {
            '': {
                'level': 'INFO',
                'handlers': ['console']
            },
            'src': {
                'level': 'DEBUG',  # More verbose for application code
                'handlers': ['console'],
                'propagate': False
            }
        }
    }
    
    @classmethod
    def init_app(cls, app: Flask) -> None:
        """
        Initialize Flask application with staging configuration.
        
        Args:
            app: Flask application instance
        """
        # Initialize base configuration
        super().init_app(app)
        
        # Initialize staging-specific configurations
        cls.DATABASE_CONFIG = create_database_config('staging')
        cls.AUTH_CONFIG = create_auth_config('staging') 
        cls.MONITORING_CONFIG = create_monitoring_config('staging')
        cls.FEATURE_FLAGS_CONFIG = create_feature_flag_config('staging')
        
        # Set Redis URI for rate limiting from database config
        if cls.DATABASE_CONFIG and hasattr(cls.DATABASE_CONFIG, 'redis_config'):
            redis_config = cls.DATABASE_CONFIG.redis_config
            cls.RATELIMIT_CONFIG['storage_uri'] = (
                f"redis://:{redis_config.get('password', '')}@"
                f"{redis_config.get('host', 'localhost')}:"
                f"{redis_config.get('port', 6379)}/{redis_config.get('db', 1)}"  # Use staging DB
            )
        
        app.logger.info(
            "Staging configuration initialized",
            extra={
                'debug_disabled': not cls.DEBUG,
                'https_enforced': cls.TALISMAN_CONFIG['force_https'],
                'database_configured': cls.DATABASE_CONFIG is not None,
                'auth_configured': cls.AUTH_CONFIG is not None,
                'monitoring_configured': cls.MONITORING_CONFIG is not None,
                'feature_flags_configured': cls.FEATURE_FLAGS_CONFIG is not None
            }
        )


class ProductionConfig(BaseConfig):
    """
    Production environment configuration optimized for enterprise deployment.
    
    Provides maximum security, performance optimization, comprehensive monitoring,
    and enterprise-grade reliability features. Implements all security headers,
    optimized connection pooling, and complete observability integration for
    production workloads.
    """
    
    # Production Configuration
    DEBUG = False
    TESTING = False
    
    # Production Database Configuration
    DATABASE_CONFIG = None  # Will be initialized in init_app
    
    # Production Authentication Configuration
    AUTH_CONFIG = None  # Will be initialized in init_app
    
    # Production Monitoring Configuration (comprehensive)
    MONITORING_CONFIG = None  # Will be initialized in init_app
    
    # Production Feature Flags Configuration
    FEATURE_FLAGS_CONFIG = None  # Will be initialized in init_app
    
    # Production CORS (restrictive)
    CORS_CONFIG = {
        **BaseConfig.CORS_CONFIG,
        'origins': os.getenv('PRODUCTION_CORS_ORIGINS', '').split(',') if os.getenv('PRODUCTION_CORS_ORIGINS') else [],
        'supports_credentials': True,
        'max_age': 86400  # 24 hours cache
    }
    
    # Production Rate Limiting (enterprise-grade)
    RATELIMIT_CONFIG = {
        **BaseConfig.RATELIMIT_CONFIG,
        'default': '1000 per hour',  # Production limits
        'swallow_errors': False,  # Strict error handling
        'strategy': 'fixed-window-elastic-expiry'
    }
    
    # Production Security Headers (maximum security)
    TALISMAN_CONFIG = {
        **BaseConfig.TALISMAN_CONFIG,
        'force_https': True,
        'strict_transport_security': True,
        'strict_transport_security_max_age': 31536000,  # 1 year
        'strict_transport_security_include_subdomains': True,
        'strict_transport_security_preload': True,
        'content_security_policy': {
            'default-src': "'self'",
            'script-src': "'self'",
            'style-src': "'self'",
            'img-src': "'self' data: https:",
            'connect-src': "'self' https:",
            'font-src': "'self'",
            'object-src': "'none'",
            'frame-ancestors': "'none'",
            'base-uri': "'self'",
            'form-action': "'self'"
        },
        'referrer_policy': 'strict-origin-when-cross-origin',
        'content_type_options': True,
        'x_frame_options': 'DENY'
    }
    
    # Production Health Checks (comprehensive monitoring)
    HEALTH_CHECK_CONFIG = {
        **BaseConfig.HEALTH_CHECK_CONFIG,
        'include_dependencies': True,
        'check_external_services': True,
        'timeout_seconds': 30,
        'include_version': True,
        'include_timestamp': True
    }
    
    # Production Logging (structured JSON with enterprise integration)
    LOGGING_CONFIG = {
        **BaseConfig.LOGGING_CONFIG,
        'handlers': {
            **BaseConfig.LOGGING_CONFIG['handlers'],
            'console': {
                **BaseConfig.LOGGING_CONFIG['handlers']['console'],
                'level': 'WARNING',  # Only warnings and errors to console
                'formatter': 'json'
            },
            'application': {
                'class': 'logging.StreamHandler',
                'level': 'INFO',
                'formatter': 'json',
                'stream': 'ext://sys.stdout'
            }
        },
        'loggers': {
            '': {
                'level': 'WARNING',
                'handlers': ['console']
            },
            'src': {
                'level': 'INFO',
                'handlers': ['application'],
                'propagate': False
            },
            'security': {
                'level': 'INFO',
                'handlers': ['application'],
                'propagate': False
            },
            'performance': {
                'level': 'INFO', 
                'handlers': ['application'],
                'propagate': False
            }
        }
    }
    
    @classmethod
    def init_app(cls, app: Flask) -> None:
        """
        Initialize Flask application with production configuration.
        
        Args:
            app: Flask application instance
        """
        # Initialize base configuration
        super().init_app(app)
        
        # Initialize production-specific configurations
        cls.DATABASE_CONFIG = create_database_config('production')
        cls.AUTH_CONFIG = create_auth_config('production')
        cls.MONITORING_CONFIG = create_monitoring_config('production')
        cls.FEATURE_FLAGS_CONFIG = create_feature_flag_config('production')
        
        # Set Redis URI for rate limiting from database config
        if cls.DATABASE_CONFIG and hasattr(cls.DATABASE_CONFIG, 'redis_config'):
            redis_config = cls.DATABASE_CONFIG.redis_config
            cls.RATELIMIT_CONFIG['storage_uri'] = (
                f"redis://:{redis_config.get('password', '')}@"
                f"{redis_config.get('host', 'localhost')}:"
                f"{redis_config.get('port', 6379)}/{redis_config.get('db', 0)}"  # Use production DB
            )
        
        # Production-specific validations
        if not os.getenv('SECRET_KEY'):
            raise ValueError("SECRET_KEY environment variable must be set in production")
        
        if not cls.CORS_CONFIG['origins']:
            app.logger.warning("No CORS origins configured for production")
        
        app.logger.info(
            "Production configuration initialized",
            extra={
                'security_headers_enabled': bool(cls.TALISMAN_CONFIG),
                'https_enforced': cls.TALISMAN_CONFIG['force_https'],
                'cors_origins_count': len(cls.CORS_CONFIG['origins']),
                'database_configured': cls.DATABASE_CONFIG is not None,
                'auth_configured': cls.AUTH_CONFIG is not None,
                'monitoring_configured': cls.MONITORING_CONFIG is not None,
                'feature_flags_configured': cls.FEATURE_FLAGS_CONFIG is not None
            }
        )


# Configuration mapping for environment-based selection
config_map: Dict[str, Type[BaseConfig]] = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'staging': StagingConfig,
    'production': ProductionConfig,
    
    # Aliases for convenience
    'dev': DevelopmentConfig,
    'test': TestingConfig,
    'stage': StagingConfig,
    'prod': ProductionConfig
}


def get_config(environment: Optional[str] = None) -> Type[BaseConfig]:
    """
    Get configuration class for the specified environment.
    
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
    
    if environment not in config_map:
        raise ValueError(
            f"Unsupported environment '{environment}'. "
            f"Supported environments: {list(config_map.keys())}"
        )
    
    config_class = config_map[environment]
    
    logger.info(
        "Configuration class selected",
        extra={
            'environment': environment,
            'config_class': config_class.__name__
        }
    )
    
    return config_class


def validate_configuration(config: BaseConfig) -> List[str]:
    """
    Validate configuration settings and return list of issues.
    
    Args:
        config: Configuration instance to validate
        
    Returns:
        List of validation error messages (empty if valid)
    """
    issues = []
    
    # Validate required settings
    if not config.SECRET_KEY:
        issues.append("SECRET_KEY is required")
    
    if len(config.SECRET_KEY) < 32:
        issues.append("SECRET_KEY should be at least 32 characters long")
    
    # Validate CORS configuration
    if config.CORS_CONFIG['origins'] == ['*'] and not config.DEBUG:
        issues.append("CORS origins should not use '*' in non-debug environments")
    
    # Validate security headers for production
    if not config.DEBUG:
        if not config.TALISMAN_CONFIG.get('force_https'):
            issues.append("HTTPS should be enforced in non-debug environments")
        
        if not config.TALISMAN_CONFIG.get('content_security_policy'):
            issues.append("Content Security Policy should be configured in non-debug environments")
    
    # Validate rate limiting
    if not config.RATELIMIT_CONFIG.get('storage_uri') and not config.DEBUG:
        issues.append("Rate limiting storage URI should be configured")
    
    logger.info(
        "Configuration validation completed",
        extra={
            'config_class': config.__class__.__name__,
            'issues_found': len(issues),
            'issues': issues
        }
    )
    
    return issues


def create_app_config(environment: Optional[str] = None) -> Type[BaseConfig]:
    """
    Factory function to create and validate application configuration.
    
    Args:
        environment: Target environment name
        
    Returns:
        Validated configuration class instance
        
    Raises:
        ValueError: If configuration validation fails
    """
    config_class = get_config(environment)
    
    # Create a temporary instance for validation
    config_instance = config_class()
    
    # Validate configuration
    issues = validate_configuration(config_instance)
    
    if issues and not config_instance.DEBUG:
        raise ValueError(f"Configuration validation failed: {'; '.join(issues)}")
    elif issues:
        logger.warning(
            "Configuration validation warnings (ignored in debug mode)",
            extra={'issues': issues}
        )
    
    return config_class


# Export main configuration classes and factory functions
__all__ = [
    'BaseConfig',
    'DevelopmentConfig', 
    'TestingConfig',
    'StagingConfig',
    'ProductionConfig',
    'get_config',
    'validate_configuration',
    'create_app_config',
    'config_map'
]