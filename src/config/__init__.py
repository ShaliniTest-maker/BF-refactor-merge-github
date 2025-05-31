"""
Flask Configuration Package

This package provides centralized access to Flask configuration classes and environment-specific 
settings for the Flask application factory pattern. Implements modular configuration organization 
following Python packaging standards and supports dynamic environment configuration loading for 
development, testing, staging, and production deployments.

Package Structure:
- settings.py: Main configuration classes with environment-specific implementations
- database.py: Database connection and MongoDB/Redis configuration
- auth.py: Authentication and JWT configuration settings
- monitoring.py: Logging, metrics, and observability configuration
- feature_flags.py: Migration phase and feature flag management

Architecture Integration:
- Section 0.2.5: Configuration file format migration from JSON to Python modules
- Section 0.2.3: Flask application factory pattern with centralized extension initialization
- Section 6.1.1: Flask application factory pattern implementation
- Section 3.2.1: Flask extensions configuration for CORS, rate limiting, and security headers

Key Features:
- Environment-specific configuration classes (Development, Testing, Staging, Production)
- Flask application factory pattern compatibility with modular extension initialization
- Centralized configuration validation and error handling
- Enterprise-grade security and monitoring configuration
- Redis and MongoDB connection management
- Feature flag support for gradual migration deployment per Section 0.2.5

Usage Examples:
    Basic configuration loading:
        >>> from src.config import get_config
        >>> config_class = get_config('production')
        >>> app.config.from_object(config_class)
    
    Application factory pattern:
        >>> from src.config import create_app_config
        >>> config_class = create_app_config()
        >>> app = create_app(config_class)
    
    Environment-specific configuration:
        >>> from src.config import DevelopmentConfig, ProductionConfig
        >>> if app.debug:
        ...     app.config.from_object(DevelopmentConfig)

Author: Flask Migration Team
Version: 1.0.0
License: Enterprise Internal Use
Dependencies: Flask 2.3+, PyMongo 4.5+, redis-py 5.0+, python-dotenv 1.0+
"""

import os
import logging
from typing import Dict, Type, Optional, List, Any, Union

# Import environment configuration early to ensure proper initialization
from dotenv import load_dotenv

# Load environment variables at package import time
load_dotenv()

# Configure package logger
logger = logging.getLogger(__name__)

# Package metadata
__version__ = "1.0.0"
__author__ = "Flask Migration Team"
__license__ = "Enterprise Internal Use"

# Import core configuration classes from settings module
from .settings import (
    BaseConfig,
    DevelopmentConfig,
    TestingConfig,
    StagingConfig,
    ProductionConfig,
    get_config,
    validate_configuration,
    create_app_config,
    config_map
)

# Import specialized configuration modules
try:
    from .database import (
        DatabaseConfig,
        create_database_config
    )
except ImportError as e:
    logger.warning(f"Database configuration module not available: {e}")
    DatabaseConfig = None
    create_database_config = None

try:
    from .auth import (
        AuthConfig,
        create_auth_config
    )
except ImportError as e:
    logger.warning(f"Authentication configuration module not available: {e}")
    AuthConfig = None
    create_auth_config = None

try:
    from .monitoring import (
        StructuredLoggingConfig,
        PrometheusMetricsConfig,
        HealthCheckConfig,
        create_monitoring_config
    )
except ImportError as e:
    logger.warning(f"Monitoring configuration module not available: {e}")
    StructuredLoggingConfig = None
    PrometheusMetricsConfig = None
    HealthCheckConfig = None
    create_monitoring_config = None

try:
    from .feature_flags import (
        FeatureFlagConfig,
        MigrationPhase,
        create_feature_flag_config
    )
except ImportError as e:
    logger.warning(f"Feature flags configuration module not available: {e}")
    FeatureFlagConfig = None
    MigrationPhase = None
    create_feature_flag_config = None


def get_environment() -> str:
    """
    Get the current application environment from environment variables.
    
    Returns:
        str: Current environment name (development, testing, staging, production)
        
    Environment Variables:
        FLASK_ENV: Primary environment setting
        ENVIRONMENT: Alternative environment setting
        ENV: Fallback environment setting
    """
    # Check multiple environment variable names for flexibility
    environment = (
        os.getenv('FLASK_ENV') or 
        os.getenv('ENVIRONMENT') or 
        os.getenv('ENV') or 
        'development'
    )
    
    # Normalize environment name
    environment = environment.lower().strip()
    
    # Map common aliases to standard names
    env_aliases = {
        'dev': 'development',
        'devel': 'development',
        'develop': 'development',
        'test': 'testing',
        'tests': 'testing',
        'stage': 'staging',
        'staging': 'staging',
        'prod': 'production',
        'production': 'production'
    }
    
    environment = env_aliases.get(environment, environment)
    
    logger.info(
        "Environment detected",
        extra={
            'environment': environment,
            'flask_env': os.getenv('FLASK_ENV'),
            'environment_var': os.getenv('ENVIRONMENT'),
            'env_var': os.getenv('ENV')
        }
    )
    
    return environment


def get_current_config() -> Type[BaseConfig]:
    """
    Get the configuration class for the current environment.
    
    Returns:
        Type[BaseConfig]: Configuration class appropriate for current environment
        
    Raises:
        ValueError: If the current environment is not supported
    """
    environment = get_environment()
    return get_config(environment)


def get_config_info() -> Dict[str, Any]:
    """
    Get comprehensive information about the current configuration.
    
    Returns:
        Dict[str, Any]: Configuration metadata and status information
    """
    environment = get_environment()
    config_class = get_config(environment)
    
    # Get configuration validation results
    config_instance = config_class()
    validation_issues = validate_configuration(config_instance)
    
    info = {
        'environment': environment,
        'config_class': config_class.__name__,
        'debug_mode': getattr(config_instance, 'DEBUG', False),
        'testing_mode': getattr(config_instance, 'TESTING', False),
        'validation_issues': validation_issues,
        'validation_passed': len(validation_issues) == 0,
        'package_version': __version__,
        'available_environments': list(config_map.keys()),
        'modules_available': {
            'database': DatabaseConfig is not None,
            'auth': AuthConfig is not None,
            'monitoring': StructuredLoggingConfig is not None,
            'feature_flags': FeatureFlagConfig is not None
        }
    }
    
    # Add Flask-specific configuration details if available
    if hasattr(config_instance, 'CORS_CONFIG'):
        info['cors_enabled'] = bool(config_instance.CORS_CONFIG.get('origins'))
    
    if hasattr(config_instance, 'RATELIMIT_CONFIG'):
        info['rate_limiting_enabled'] = bool(config_instance.RATELIMIT_CONFIG.get('default'))
    
    if hasattr(config_instance, 'TALISMAN_CONFIG'):
        info['security_headers_enabled'] = bool(config_instance.TALISMAN_CONFIG)
    
    logger.info(
        "Configuration information retrieved",
        extra=info
    )
    
    return info


def initialize_configuration(environment: Optional[str] = None, validate: bool = True) -> Type[BaseConfig]:
    """
    Initialize and validate configuration for the specified environment.
    
    Args:
        environment: Target environment (defaults to current environment)
        validate: Whether to perform configuration validation
        
    Returns:
        Type[BaseConfig]: Validated configuration class
        
    Raises:
        ValueError: If configuration validation fails in non-debug mode
    """
    if environment is None:
        environment = get_environment()
    
    logger.info(
        "Initializing configuration",
        extra={
            'environment': environment,
            'validation_enabled': validate
        }
    )
    
    if validate:
        config_class = create_app_config(environment)
    else:
        config_class = get_config(environment)
    
    logger.info(
        "Configuration initialized successfully",
        extra={
            'environment': environment,
            'config_class': config_class.__name__
        }
    )
    
    return config_class


def list_available_environments() -> List[str]:
    """
    Get list of all supported environment names.
    
    Returns:
        List[str]: List of supported environment names
    """
    return list(config_map.keys())


def is_environment_supported(environment: str) -> bool:
    """
    Check if the specified environment is supported.
    
    Args:
        environment: Environment name to check
        
    Returns:
        bool: True if environment is supported, False otherwise
    """
    return environment.lower() in config_map


def export_config_for_flask(environment: Optional[str] = None) -> Dict[str, Any]:
    """
    Export configuration dictionary suitable for Flask app.config.update().
    
    Args:
        environment: Target environment (defaults to current environment)
        
    Returns:
        Dict[str, Any]: Configuration dictionary for Flask application
    """
    config_class = initialize_configuration(environment)
    config_instance = config_class()
    
    # Extract all uppercase attributes (Flask convention)
    config_dict = {}
    for attr_name in dir(config_instance):
        if attr_name.isupper() and not attr_name.startswith('_'):
            config_dict[attr_name] = getattr(config_instance, attr_name)
    
    logger.info(
        "Configuration exported for Flask",
        extra={
            'environment': environment or get_environment(),
            'config_keys': list(config_dict.keys()),
            'total_settings': len(config_dict)
        }
    )
    
    return config_dict


# Configuration class registry for backward compatibility and debugging
CONFIG_REGISTRY = {
    'base': BaseConfig,
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'staging': StagingConfig,
    'production': ProductionConfig
}

# Convenience aliases for common configurations
DevConfig = DevelopmentConfig
TestConfig = TestingConfig
StageConfig = StagingConfig
ProdConfig = ProductionConfig

# Package-level public API exports
__all__ = [
    # Version and metadata
    '__version__',
    '__author__',
    '__license__',
    
    # Core configuration classes
    'BaseConfig',
    'DevelopmentConfig',
    'TestingConfig', 
    'StagingConfig',
    'ProductionConfig',
    
    # Convenience aliases
    'DevConfig',
    'TestConfig',
    'StageConfig',
    'ProdConfig',
    
    # Configuration factory functions
    'get_config',
    'get_current_config',
    'create_app_config',
    'initialize_configuration',
    
    # Environment utilities
    'get_environment',
    'list_available_environments',
    'is_environment_supported',
    
    # Configuration information and validation
    'get_config_info',
    'validate_configuration',
    'export_config_for_flask',
    
    # Configuration registry
    'config_map',
    'CONFIG_REGISTRY',
    
    # Specialized configuration classes (if available)
    'DatabaseConfig',
    'AuthConfig',
    'StructuredLoggingConfig',
    'PrometheusMetricsConfig',
    'HealthCheckConfig',
    'FeatureFlagConfig',
    'MigrationPhase',
    
    # Specialized configuration factories (if available)
    'create_database_config',
    'create_auth_config',
    'create_monitoring_config',
    'create_feature_flag_config'
]

# Log package initialization
logger.info(
    "Flask configuration package initialized",
    extra={
        'package_version': __version__,
        'current_environment': get_environment(),
        'available_environments': list_available_environments(),
        'modules_loaded': {
            'settings': True,
            'database': DatabaseConfig is not None,
            'auth': AuthConfig is not None,
            'monitoring': StructuredLoggingConfig is not None,
            'feature_flags': FeatureFlagConfig is not None
        }
    }
)