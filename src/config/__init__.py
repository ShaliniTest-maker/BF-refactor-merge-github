"""
Flask Configuration Package

This package provides centralized Flask configuration management for the Node.js to Python
migration project, implementing environment-specific settings and modular configuration
organization according to Flask application factory patterns.

Package Architecture:
- Environment-specific configuration classes (Development, Testing, Staging, Production)
- Flask application factory pattern with centralized extension initialization
- Comprehensive security, performance, and monitoring configuration
- Feature flag management for gradual traffic migration (5% → 25% → 50% → 100%)
- Performance monitoring integration ensuring ≤10% variance compliance

Key Components:
- settings.py: Core Flask configuration classes and factory implementation
- database.py: MongoDB and Redis database configuration management
- auth.py: Authentication and authorization configuration (JWT, Auth0, security headers)
- monitoring.py: Application performance monitoring and observability configuration  
- feature_flags.py: Feature flag and deployment strategy configuration

Usage Examples:
    # Basic configuration loading
    from src.config import create_config_for_environment, ConfigFactory
    
    config = create_config_for_environment('production')
    app.config.from_object(config)
    
    # Environment-specific configuration
    from src.config import DevelopmentConfig, ProductionConfig
    
    if app.config['DEBUG']:
        app.config.from_object(DevelopmentConfig)
    else:
        app.config.from_object(ProductionConfig)
    
    # Specialized configuration access
    from src.config import get_database_config, get_auth_config
    
    db_config = get_database_config('production')
    auth_config = get_auth_config()

Architecture Integration:
- Section 0.2.5: Configuration file format migration from JSON to Python modules
- Section 3.2.1: Flask application factory pattern with centralized extension initialization
- Section 6.1.1: Flask configuration supporting enterprise-grade security and performance
- Section 8.5.1: Environment-specific configuration for CI/CD pipeline integration

Author: Flask Migration Team
Version: 1.0.0
Dependencies: Flask 2.3+, python-dotenv 1.0+, comprehensive configuration dependencies
"""

import os
from typing import Type, Optional, Dict, Any, List

# Core configuration classes and factory
from .settings import (
    BaseConfig,
    DevelopmentConfig,
    TestingConfig,
    StagingConfig,
    ProductionConfig,
    ConfigFactory,
    create_config_for_environment
)

# Configuration helper functions
from .settings import (
    get_database_config,
    get_auth_config,
    get_monitoring_config,
    get_feature_flag_config
)

# Specialized configuration modules  
try:
    from .database import DatabaseConfig
except ImportError:
    # Handle optional database configuration module
    DatabaseConfig = None

try:
    from .auth import AuthConfig
except ImportError:
    # Handle optional auth configuration module  
    AuthConfig = None

try:
    from .monitoring import MonitoringConfig
except ImportError:
    # Handle optional monitoring configuration module
    MonitoringConfig = None

try:
    from .feature_flags import (
        FeatureFlagConfig,
        DeploymentStrategy,
        MigrationPhase,
        PerformanceThresholds
    )
except ImportError:
    # Handle optional feature flags configuration module
    FeatureFlagConfig = None
    DeploymentStrategy = None
    MigrationPhase = None
    PerformanceThresholds = None


def get_config_for_flask_app(environment: Optional[str] = None) -> Type[BaseConfig]:
    """
    Get configuration class optimized for Flask application factory pattern.
    
    This function provides the recommended approach for Flask application configuration
    loading with comprehensive validation and environment-specific optimization.
    
    Args:
        environment: Target environment name (defaults to FLASK_ENV)
                    Supported: 'development', 'testing', 'staging', 'production'
    
    Returns:
        Configuration class ready for Flask app.config.from_object()
        
    Raises:
        ValueError: If environment is unsupported or configuration is invalid
        
    Example:
        >>> from flask import Flask
        >>> from src.config import get_config_for_flask_app
        >>> 
        >>> app = Flask(__name__)
        >>> config_class = get_config_for_flask_app('production')
        >>> app.config.from_object(config_class)
    """
    return ConfigFactory.get_config(environment)


def get_validated_config_instance(environment: Optional[str] = None) -> BaseConfig:
    """
    Get validated configuration instance with comprehensive validation.
    
    Provides configuration instance with full validation including security settings,
    performance thresholds, and environment-specific requirements compliance.
    
    Args:
        environment: Target environment name (defaults to FLASK_ENV)
        
    Returns:
        Validated configuration instance
        
    Raises:
        ValueError: If configuration validation fails or environment is unsupported
        
    Example:
        >>> config = get_validated_config_instance('staging')
        >>> print(f"Environment: {config.get_environment_name()}")
        >>> print(f"Performance threshold: {config.PERFORMANCE_VARIANCE_THRESHOLD}%")
    """
    return create_config_for_environment(environment)


def get_environment_configs() -> Dict[str, Type[BaseConfig]]:
    """
    Get all available environment configuration classes.
    
    Returns dictionary mapping environment names to their configuration classes
    for programmatic configuration management and testing scenarios.
    
    Returns:
        Dictionary of environment name to configuration class mappings
        
    Example:
        >>> configs = get_environment_configs()
        >>> dev_config = configs['development']
        >>> prod_config = configs['production']
    """
    return {
        'development': DevelopmentConfig,
        'testing': TestingConfig,
        'staging': StagingConfig,
        'production': ProductionConfig
    }


def get_current_environment() -> str:
    """
    Get the current environment name from environment variables.
    
    Returns the active environment configuration name with fallback
    to development for safe default behavior.
    
    Returns:
        Current environment name string
        
    Example:
        >>> env = get_current_environment()
        >>> print(f"Running in {env} environment")
    """
    return os.getenv('FLASK_ENV', 'development').lower()


def is_production_environment() -> bool:
    """
    Check if running in production environment.
    
    Utility function for environment-specific logic and security
    enforcement in application code.
    
    Returns:
        True if production environment, False otherwise
        
    Example:
        >>> if is_production_environment():
        ...     enable_strict_security()
    """
    return get_current_environment() == 'production'


def is_development_environment() -> bool:
    """
    Check if running in development environment.
    
    Utility function for development-specific features and
    debugging capabilities.
    
    Returns:
        True if development environment, False otherwise
        
    Example:
        >>> if is_development_environment():
        ...     enable_debug_logging()
    """
    return get_current_environment() == 'development'


def is_testing_environment() -> bool:
    """
    Check if running in testing environment.
    
    Utility function for test-specific configuration and
    isolated testing capabilities.
    
    Returns:
        True if testing environment, False otherwise
        
    Example:
        >>> if is_testing_environment():
        ...     use_test_database()
    """
    return get_current_environment() == 'testing'


def get_security_config(environment: Optional[str] = None) -> Dict[str, Any]:
    """
    Get comprehensive security configuration for specified environment.
    
    Provides security settings including Flask-Talisman configuration,
    CORS policies, session security, and CSP policies.
    
    Args:
        environment: Target environment name (defaults to current environment)
        
    Returns:
        Security configuration dictionary
        
    Example:
        >>> security_config = get_security_config('production')
        >>> csp_policy = security_config['csp']
        >>> force_https = security_config['force_https']
    """
    config_class = ConfigFactory.get_config(environment)
    return config_class.get_security_config()


def get_performance_config(environment: Optional[str] = None) -> Dict[str, Any]:
    """
    Get performance monitoring configuration for specified environment.
    
    Provides performance thresholds, monitoring settings, and baseline
    comparison configuration for ≤10% variance compliance.
    
    Args:
        environment: Target environment name (defaults to current environment)
        
    Returns:
        Performance configuration dictionary
        
    Example:
        >>> perf_config = get_performance_config('production')
        >>> variance_threshold = perf_config['variance_threshold']
        >>> monitoring_enabled = perf_config['monitoring_enabled']
    """
    config_class = ConfigFactory.get_config(environment)
    return {
        'monitoring_enabled': config_class.PERFORMANCE_MONITORING_ENABLED,
        'variance_threshold': config_class.PERFORMANCE_VARIANCE_THRESHOLD,
        'nodejs_baseline': config_class.NODEJS_BASELINE_MONITORING,
        'health_check_enabled': config_class.HEALTH_CHECK_ENABLED,
        'health_check_timeout': config_class.HEALTH_CHECK_TIMEOUT
    }


def get_cors_config(environment: Optional[str] = None) -> Dict[str, Any]:
    """
    Get CORS configuration for specified environment.
    
    Provides environment-specific CORS origins, headers, and policies
    for cross-origin request handling.
    
    Args:
        environment: Target environment name (defaults to current environment)
        
    Returns:
        CORS configuration dictionary
        
    Example:
        >>> cors_config = get_cors_config('development')
        >>> allowed_origins = cors_config['origins']
        >>> allowed_methods = cors_config['methods']
    """
    config_class = ConfigFactory.get_config(environment)
    return {
        'enabled': config_class.CORS_ENABLED,
        'origins': config_class.CORS_ORIGINS,
        'methods': config_class.CORS_METHODS,
        'allow_headers': config_class.CORS_ALLOW_HEADERS,
        'expose_headers': config_class.CORS_EXPOSE_HEADERS,
        'supports_credentials': config_class.CORS_SUPPORTS_CREDENTIALS,
        'max_age': config_class.CORS_MAX_AGE
    }


def get_rate_limiting_config(environment: Optional[str] = None) -> Dict[str, Any]:
    """
    Get rate limiting configuration for specified environment.
    
    Provides rate limiting settings, endpoint-specific limits, and
    storage configuration for request throttling.
    
    Args:
        environment: Target environment name (defaults to current environment)
        
    Returns:
        Rate limiting configuration dictionary
        
    Example:
        >>> rate_config = get_rate_limiting_config('production')
        >>> default_limit = rate_config['default_limit']
        >>> endpoint_limits = rate_config['per_endpoint']
    """
    config_class = ConfigFactory.get_config(environment)
    return {
        'enabled': config_class.RATELIMIT_ENABLED,
        'storage_url': config_class.RATELIMIT_STORAGE_URL,
        'strategy': config_class.RATELIMIT_STRATEGY,
        'default_limit': config_class.RATELIMIT_DEFAULT,
        'per_endpoint': config_class.RATELIMIT_PER_ENDPOINT,
        'headers_enabled': config_class.RATELIMIT_HEADERS_ENABLED
    }


def validate_configuration_completeness(environment: Optional[str] = None) -> bool:
    """
    Validate configuration completeness for specified environment.
    
    Performs comprehensive validation of configuration settings including
    required parameters, security settings, and environment-specific requirements.
    
    Args:
        environment: Target environment name (defaults to current environment)
        
    Returns:
        True if configuration is complete and valid
        
    Raises:
        ValueError: If configuration validation fails
        
    Example:
        >>> try:
        ...     validate_configuration_completeness('production')
        ...     print("Configuration is valid")
        ... except ValueError as e:
        ...     print(f"Configuration error: {e}")
    """
    config_instance = create_config_for_environment(environment)
    return ConfigFactory.validate_config(config_instance)


def get_configuration_summary(environment: Optional[str] = None) -> Dict[str, Any]:
    """
    Get comprehensive configuration summary for specified environment.
    
    Provides overview of all configuration settings for debugging,
    documentation, and environment validation purposes.
    
    Args:
        environment: Target environment name (defaults to current environment)
        
    Returns:
        Configuration summary dictionary with non-sensitive settings
        
    Example:
        >>> summary = get_configuration_summary('staging')
        >>> print(f"Environment: {summary['environment']}")
        >>> print(f"Debug mode: {summary['debug']}")
        >>> print(f"Security enabled: {summary['security']['talisman_enabled']}")
    """
    config_class = ConfigFactory.get_config(environment)
    
    return {
        'environment': config_class.get_environment_name(),
        'debug': config_class.DEBUG,
        'testing': config_class.TESTING,
        'security': {
            'talisman_enabled': config_class.TALISMAN_ENABLED,
            'csrf_enabled': config_class.WTF_CSRF_ENABLED,
            'session_secure': config_class.SESSION_COOKIE_SECURE
        },
        'performance': {
            'monitoring_enabled': config_class.PERFORMANCE_MONITORING_ENABLED,
            'variance_threshold': config_class.PERFORMANCE_VARIANCE_THRESHOLD,
            'nodejs_baseline': config_class.NODEJS_BASELINE_MONITORING
        },
        'features': {
            'cors_enabled': config_class.CORS_ENABLED,
            'rate_limiting': config_class.RATELIMIT_ENABLED,
            'feature_flags': config_class.FEATURE_FLAGS_ENABLED,
            'migration_enabled': getattr(config_class, 'MIGRATION_ENABLED', False)
        },
        'cors_origins_count': len(config_class.CORS_ORIGINS),
        'available_environments': ConfigFactory.get_available_environments()
    }


# Package-level exports for clean imports and modular organization
__all__ = [
    # Core configuration classes
    'BaseConfig',
    'DevelopmentConfig', 
    'TestingConfig',
    'StagingConfig',
    'ProductionConfig',
    
    # Configuration factory and creation
    'ConfigFactory',
    'create_config_for_environment',
    'get_config_for_flask_app',
    'get_validated_config_instance',
    
    # Specialized configuration modules (when available)
    'DatabaseConfig',
    'AuthConfig', 
    'MonitoringConfig',
    'FeatureFlagConfig',
    'DeploymentStrategy',
    'MigrationPhase',
    'PerformanceThresholds',
    
    # Configuration helper functions
    'get_database_config',
    'get_auth_config',
    'get_monitoring_config',
    'get_feature_flag_config',
    
    # Environment utilities
    'get_environment_configs',
    'get_current_environment',
    'is_production_environment',
    'is_development_environment', 
    'is_testing_environment',
    
    # Configuration access utilities
    'get_security_config',
    'get_performance_config',
    'get_cors_config',
    'get_rate_limiting_config',
    
    # Validation and summary utilities
    'validate_configuration_completeness',
    'get_configuration_summary'
]


# Package-level configuration initialization and validation
def _initialize_package():
    """
    Initialize configuration package with validation and environment detection.
    
    Performs package-level initialization including environment validation,
    dependency checking, and configuration consistency verification.
    """
    current_env = get_current_environment()
    
    # Validate current environment is supported
    available_envs = ConfigFactory.get_available_environments()
    if current_env not in available_envs:
        import warnings
        warnings.warn(
            f"Current environment '{current_env}' not in supported environments: {available_envs}. "
            f"Falling back to 'development' environment.",
            UserWarning
        )
    
    # Validate configuration completeness for current environment
    try:
        validate_configuration_completeness(current_env)
    except ValueError as e:
        import warnings
        warnings.warn(
            f"Configuration validation failed for environment '{current_env}': {e}",
            UserWarning
        )


# Initialize package when imported
_initialize_package()