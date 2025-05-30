"""
Configuration Package Initialization Module

This module provides centralized access to all Flask application configuration settings,
environment management, and configuration validation for the Node.js to Python/Flask migration project.
Implements enterprise-grade configuration management with comprehensive security controls and validation.

Key Features:
- Flask 2.3+ application factory pattern configuration (Section 3.2.1)
- Environment variable management using python-dotenv 1.0+ (Section 0.2.4)
- Environment isolation with separate configurations (Section 8.1.2)
- Configuration validation and error handling for production deployments
- Centralized configuration exports for Flask application integration
- Enterprise security settings and compliance controls (Section 6.4.3)
- MongoDB and Redis connection management (Section 3.4.1, 3.4.2)
- Auth0 and JWT authentication configuration (Section 6.4.1)
- Monitoring and observability integration (Section 3.6.1)
- External service integration settings (Section 3.2.3)

This replaces the Node.js JSON-based configuration structure with Python configuration modules
providing type safety, validation, and enhanced security controls as specified in Section 0.1.2.

Exports:
- Configuration classes for all environments (Development, Staging, Production, Testing)
- Database and caching configuration utilities
- Authentication and security configuration
- Monitoring and logging configuration
- External service integration settings
- Configuration factory functions and validation utilities

Usage:
    from config import get_config, config, DatabaseConfig, AuthConfig
    
    # Get environment-specific configuration
    app_config = get_config('production')
    
    # Use default configuration based on FLASK_ENV
    default_config = config
    
    # Access specific configuration components
    db_config = DatabaseConfig(app_config)
    auth_config = AuthConfig(app_config)

Author: Flask Migration Team
Version: 1.0.0
Migration Phase: Node.js to Python/Flask Migration (Section 0.1.1)
Compliance: Enterprise security standards, SOC 2, ISO 27001
"""

import os
import sys
import logging
from typing import Dict, Any, Optional, Type, Union, List
from pathlib import Path

# Configure package-level logging
logger = logging.getLogger(__name__)

# Version information
__version__ = "1.0.0"
__author__ = "Flask Migration Team"
__description__ = "Enterprise Flask configuration package for Node.js migration"

try:
    # Core configuration imports from settings module
    from .settings import (
        BaseConfig,
        DevelopmentConfig,
        StagingConfig,
        ProductionConfig,
        TestingConfig,
        get_config,
        config,
        EnvironmentManager,
        ConfigurationError
    )
    
    # Database and caching configuration imports
    from .database import (
        DatabaseConfig,
        MongoDBConfig,
        RedisConfig,
        SessionConfig,
        EncryptionManager,
        DatabaseError,
        RedisError,
        EncryptionError
    )
    
    # Authentication and security configuration imports
    from .auth import (
        AuthConfig,
        Auth0Config,
        JWTConfig,
        FlaskLoginConfig,
        PermissionManager,
        TokenValidator,
        AuthenticationError,
        AuthorizationError
    )
    
    # Security configuration imports
    from .security import (
        SecurityConfig,
        TalismanConfig,
        CSPConfig,
        CORSConfig,
        RateLimitConfig,
        SecurityError,
        SecurityValidator
    )
    
    # Logging configuration imports
    from .logging import (
        LoggingConfig,
        StructlogConfig,
        FlaskLoggingConfig,
        LoggingError,
        get_logger,
        configure_logging
    )
    
    # Monitoring configuration imports
    from .monitoring import (
        MonitoringConfig,
        PrometheusConfig,
        APMConfig,
        HealthCheckConfig,
        MetricsCollector,
        MonitoringError
    )
    
    # External services configuration imports
    from .external_services import (
        ExternalServicesConfig,
        AWSConfig,
        S3Config,
        HTTPClientConfig,
        CircuitBreakerConfig,
        ExternalServiceError
    )
    
    # Environment-specific configuration imports
    from .development import (
        DevelopmentOverrides,
        DevelopmentDatabaseConfig,
        DevelopmentSecurityConfig
    )
    
    from .production import (
        ProductionOverrides,
        ProductionDatabaseConfig,
        ProductionSecurityConfig,
        ProductionMonitoringConfig
    )

except ImportError as e:
    logger.error(f"Failed to import configuration modules: {str(e)}")
    # Create minimal fallback configuration for graceful degradation
    class ConfigurationError(Exception):
        """Fallback configuration error class."""
        pass
    
    class BaseConfig:
        """Minimal fallback configuration class."""
        def __init__(self):
            self.SECRET_KEY = os.getenv('SECRET_KEY', 'fallback-secret-key')
            self.DEBUG = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
            self.FLASK_ENV = os.getenv('FLASK_ENV', 'production')
    
    def get_config(config_name: Optional[str] = None) -> BaseConfig:
        """Fallback configuration factory."""
        logger.warning("Using fallback configuration due to import failure")
        return BaseConfig()
    
    config = get_config()


class ConfigurationManager:
    """
    Centralized configuration manager providing unified access to all application
    configuration components with validation and environment management.
    
    This class implements the configuration management pattern for Flask applications
    as specified in Section 3.2.1, providing centralized access to all configuration
    components with comprehensive validation and error handling.
    """
    
    def __init__(self, config_name: Optional[str] = None):
        """
        Initialize configuration manager with environment-specific settings.
        
        Args:
            config_name: Optional configuration environment name
            
        Raises:
            ConfigurationError: When configuration initialization fails
        """
        self.config_name = config_name or os.getenv('FLASK_ENV', 'production')
        self.logger = logging.getLogger(f"{__name__}.ConfigurationManager")
        
        try:
            # Load base configuration
            self.base_config = get_config(self.config_name)
            
            # Initialize component configurations
            self._initialize_component_configs()
            
            # Validate complete configuration
            self._validate_configuration()
            
            self.logger.info(f"Configuration manager initialized for environment: {self.config_name}")
            
        except Exception as e:
            error_msg = f"Configuration manager initialization failed: {str(e)}"
            self.logger.error(error_msg)
            raise ConfigurationError(error_msg)
    
    def _initialize_component_configs(self) -> None:
        """Initialize all component-specific configurations."""
        try:
            # Database and caching configuration
            self.database = DatabaseConfig(self.base_config)
            self.mongodb = MongoDBConfig(self.base_config)
            self.redis = RedisConfig(self.base_config)
            self.session = SessionConfig(self.base_config)
            
            # Authentication and security configuration
            self.auth = AuthConfig(self.base_config)
            self.auth0 = Auth0Config(self.base_config)
            self.jwt = JWTConfig(self.base_config)
            self.security = SecurityConfig(self.base_config)
            
            # Monitoring and logging configuration
            self.logging = LoggingConfig(self.base_config)
            self.monitoring = MonitoringConfig(self.base_config)
            self.prometheus = PrometheusConfig(self.base_config)
            
            # External services configuration
            self.external_services = ExternalServicesConfig(self.base_config)
            self.aws = AWSConfig(self.base_config)
            self.s3 = S3Config(self.base_config)
            
        except Exception as e:
            raise ConfigurationError(f"Component configuration initialization failed: {str(e)}")
    
    def _validate_configuration(self) -> None:
        """
        Validate complete configuration for consistency and security compliance.
        
        Performs comprehensive validation across all configuration components
        to ensure enterprise security and compliance requirements are met.
        
        Raises:
            ConfigurationError: When configuration validation fails
        """
        validation_errors = []
        
        try:
            # Validate base configuration
            if hasattr(self.base_config, '_validate_configuration'):
                self.base_config._validate_configuration()
            
            # Validate component configurations
            component_configs = [
                ('database', self.database),
                ('auth', self.auth),
                ('security', self.security),
                ('monitoring', self.monitoring),
                ('external_services', self.external_services)
            ]
            
            for component_name, component_config in component_configs:
                if hasattr(component_config, 'validate'):
                    try:
                        component_config.validate()
                    except Exception as e:
                        validation_errors.append(f"{component_name}: {str(e)}")
            
            # Cross-component validation
            self._validate_cross_component_dependencies()
            
        except Exception as e:
            validation_errors.append(f"Configuration validation error: {str(e)}")
        
        if validation_errors:
            error_message = "Configuration validation failed:\n" + "\n".join(
                f"- {error}" for error in validation_errors
            )
            raise ConfigurationError(error_message)
        
        self.logger.info("Complete configuration validation passed successfully")
    
    def _validate_cross_component_dependencies(self) -> None:
        """
        Validate dependencies between configuration components.
        
        Ensures that configuration components are compatible and properly
        integrated with each other.
        """
        # Validate Redis session configuration consistency
        if (hasattr(self.session, 'session_type') and 
            self.session.session_type == 'redis' and
            not self.redis.is_configured()):
            raise ConfigurationError(
                "Redis configuration required when SESSION_TYPE is 'redis'"
            )
        
        # Validate Auth0 and JWT configuration consistency
        if (hasattr(self.auth0, 'is_configured') and 
            self.auth0.is_configured() and
            not hasattr(self.jwt, 'secret_key')):
            raise ConfigurationError(
                "JWT configuration required when Auth0 is configured"
            )
        
        # Validate MongoDB and database configuration consistency
        if (hasattr(self.database, 'database_type') and
            self.database.database_type == 'mongodb' and
            not self.mongodb.is_configured()):
            raise ConfigurationError(
                "MongoDB configuration required for database operations"
            )
        
        # Validate monitoring and logging configuration
        if (hasattr(self.monitoring, 'prometheus_enabled') and
            self.monitoring.prometheus_enabled and
            not hasattr(self.prometheus, 'metrics_port')):
            raise ConfigurationError(
                "Prometheus configuration required when metrics are enabled"
            )
    
    def get_flask_config(self) -> Dict[str, Any]:
        """
        Get Flask-compatible configuration dictionary.
        
        Returns:
            Dictionary containing all Flask configuration settings
        """
        flask_config = {}
        
        # Add base configuration
        if hasattr(self.base_config, 'to_dict'):
            flask_config.update(self.base_config.to_dict())
        else:
            # Fallback for basic configuration attributes
            for attr in dir(self.base_config):
                if not attr.startswith('_') and not callable(getattr(self.base_config, attr)):
                    flask_config[attr] = getattr(self.base_config, attr)
        
        return flask_config
    
    def configure_flask_app(self, app) -> None:
        """
        Configure Flask application instance with all settings.
        
        Args:
            app: Flask application instance to configure
            
        Raises:
            ConfigurationError: When Flask app configuration fails
        """
        try:
            # Apply base configuration
            app.config.from_object(self.base_config)
            
            # Configure Flask extensions
            self._configure_flask_extensions(app)
            
            # Register configuration-dependent services
            self._register_configuration_services(app)
            
            self.logger.info("Flask application configuration completed successfully")
            
        except Exception as e:
            error_msg = f"Flask application configuration failed: {str(e)}"
            self.logger.error(error_msg)
            raise ConfigurationError(error_msg)
    
    def _configure_flask_extensions(self, app) -> None:
        """Configure Flask extensions with component-specific settings."""
        # Configure database extensions
        if hasattr(self.database, 'configure_flask_app'):
            self.database.configure_flask_app(app)
        
        # Configure authentication extensions
        if hasattr(self.auth, 'configure_flask_app'):
            self.auth.configure_flask_app(app)
        
        # Configure security extensions
        if hasattr(self.security, 'configure_flask_app'):
            self.security.configure_flask_app(app)
        
        # Configure monitoring extensions
        if hasattr(self.monitoring, 'configure_flask_app'):
            self.monitoring.configure_flask_app(app)
    
    def _register_configuration_services(self, app) -> None:
        """Register configuration-dependent services with Flask app."""
        # Register configuration manager with app context
        app.config_manager = self
        
        # Store component configurations in app context for easy access
        app.config.database_config = self.database
        app.config.auth_config = self.auth
        app.config.security_config = self.security
        app.config.monitoring_config = self.monitoring
        app.config.external_services_config = self.external_services


def create_config_manager(config_name: Optional[str] = None) -> ConfigurationManager:
    """
    Factory function to create ConfigurationManager instance.
    
    This function provides a convenient way to create a fully configured
    ConfigurationManager instance for Flask application integration.
    
    Args:
        config_name: Optional configuration environment name
        
    Returns:
        Configured ConfigurationManager instance
        
    Raises:
        ConfigurationError: When configuration manager creation fails
    """
    try:
        return ConfigurationManager(config_name)
    except Exception as e:
        logger.error(f"Failed to create configuration manager: {str(e)}")
        raise ConfigurationError(f"Configuration manager creation failed: {str(e)}")


def validate_environment() -> bool:
    """
    Validate that the current environment has all required configuration settings.
    
    This function performs a comprehensive check of environment variables and
    configuration files to ensure the application can start successfully.
    
    Returns:
        True if environment is valid, False otherwise
    """
    try:
        # Create temporary configuration manager for validation
        config_manager = create_config_manager()
        logger.info("Environment validation passed successfully")
        return True
        
    except ConfigurationError as e:
        logger.error(f"Environment validation failed: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during environment validation: {str(e)}")
        return False


def get_configuration_info() -> Dict[str, Any]:
    """
    Get comprehensive information about the current configuration.
    
    Returns:
        Dictionary containing configuration metadata and status
    """
    try:
        config_manager = create_config_manager()
        
        info = {
            'environment': config_manager.config_name,
            'version': __version__,
            'author': __author__,
            'description': __description__,
            'components': {
                'database': hasattr(config_manager, 'database'),
                'auth': hasattr(config_manager, 'auth'),
                'security': hasattr(config_manager, 'security'),
                'monitoring': hasattr(config_manager, 'monitoring'),
                'external_services': hasattr(config_manager, 'external_services')
            },
            'validation_status': 'passed',
            'flask_config_keys': len(config_manager.get_flask_config())
        }
        
        return info
        
    except Exception as e:
        return {
            'environment': os.getenv('FLASK_ENV', 'unknown'),
            'version': __version__,
            'error': str(e),
            'validation_status': 'failed'
        }


# Default configuration manager instance
try:
    default_config_manager = create_config_manager()
except Exception as e:
    logger.warning(f"Failed to create default configuration manager: {str(e)}")
    default_config_manager = None


# Package exports for Flask application factory pattern
__all__ = [
    # Version information
    '__version__',
    '__author__',
    '__description__',
    
    # Core configuration classes
    'BaseConfig',
    'DevelopmentConfig',
    'StagingConfig', 
    'ProductionConfig',
    'TestingConfig',
    
    # Configuration factory functions
    'get_config',
    'config',
    'create_config_manager',
    'default_config_manager',
    
    # Configuration manager
    'ConfigurationManager',
    
    # Component configuration classes
    'DatabaseConfig',
    'MongoDBConfig',
    'RedisConfig',
    'SessionConfig',
    'AuthConfig',
    'Auth0Config',
    'JWTConfig',
    'SecurityConfig',
    'LoggingConfig',
    'MonitoringConfig',
    'ExternalServicesConfig',
    'AWSConfig',
    'S3Config',
    
    # Utility classes and functions
    'EnvironmentManager',
    'EncryptionManager',
    'TokenValidator',
    'SecurityValidator',
    'MetricsCollector',
    'get_logger',
    'configure_logging',
    
    # Environment-specific configurations
    'DevelopmentOverrides',
    'ProductionOverrides',
    
    # Validation and utility functions
    'validate_environment',
    'get_configuration_info',
    
    # Exception classes
    'ConfigurationError',
    'DatabaseError',
    'RedisError',
    'EncryptionError',
    'AuthenticationError',
    'AuthorizationError',
    'SecurityError',
    'LoggingError',
    'MonitoringError',
    'ExternalServiceError'
]


# Initialize package logging
logger.info(f"Configuration package initialized (version {__version__})")
logger.info(f"Environment: {os.getenv('FLASK_ENV', 'production')}")

# Validate environment on import if not in testing mode
if os.getenv('FLASK_ENV') != 'testing' and os.getenv('SKIP_CONFIG_VALIDATION') != 'true':
    try:
        if not validate_environment():
            logger.warning(
                "Environment validation failed. "
                "Application may not start correctly. "
                "Check configuration settings and environment variables."
            )
    except Exception as e:
        logger.warning(f"Could not perform environment validation: {str(e)}")