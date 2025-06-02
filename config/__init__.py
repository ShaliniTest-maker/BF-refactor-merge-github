"""
Configuration Package Initialization Module

This module provides centralized access to all Flask application configuration settings,
environment management, and configuration validation for the Node.js to Python/Flask
migration project. It implements the Flask application factory pattern and exposes
configuration classes and utilities for the entire application.

This replaces JSON-based Node.js configuration files with Python-based configuration
modules using python-dotenv 1.0+ for environment variable management as specified
in Section 0.2.4 and implements Flask 2.3+ configuration requirements per Section 3.2.1.

Key Features:
- Flask application factory pattern support (Section 3.2.1)
- Environment-specific configuration loading and validation (Section 8.1.2)
- Centralized configuration access for all application components
- Configuration validation and error handling for production deployments
- python-dotenv 1.0+ environment variable management (Section 0.2.4)
- Enterprise security configuration and compliance (Section 6.4.3)
- Database and caching configuration management (Section 3.4)
- Authentication and authorization configuration (Section 6.4.1)
- Monitoring and observability configuration (Section 3.6.1)
- External service integration configuration (Section 3.2.3)

Migration Features:
- Replaces Node.js JSON configuration structure with Python modules
- Maintains equivalent configuration patterns while adding enterprise features
- Supports blue-green deployment and feature flag configurations
- Enterprise environment isolation with separate configurations per Section 8.1.2

Dependencies:
- python-dotenv 1.0+ for secure environment variable management
- Flask 2.3+ for application factory pattern configuration
- All configuration submodules for comprehensive application setup

Usage Example:
    ```python
    from config import get_config, init_app_config, ConfigurationError
    
    # Get environment-specific configuration
    config = get_config('production')
    
    # Initialize Flask app with configuration
    app = Flask(__name__)
    init_app_config(app, config)
    ```

Author: Flask Migration Team
Version: 1.0.0
Migration Phase: Node.js to Python/Flask Migration (Section 0.1.1)
"""

import os
import sys
import logging
from typing import Dict, Any, Optional, Union, Type, Tuple
from pathlib import Path

# Import Flask for type hints and application factory support
from flask import Flask

# Core configuration imports
try:
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
except ImportError as e:
    logging.error(f"Failed to import core configuration settings: {str(e)}")
    raise ImportError(f"Core configuration import failed: {str(e)}")

# Database and caching configuration imports
try:
    from .database import (
        DatabaseManager,
        MongoDBManager,
        RedisManager,
        FlaskSessionManager,
        AWSKMSManager,
        EncryptedSessionInterface,
        init_database,
        get_database_manager,
        create_health_check_response,
        DatabaseConfigurationError
    )
except ImportError as e:
    logging.warning(f"Database configuration import failed: {str(e)}")
    # Set fallback values for optional database components
    DatabaseManager = None
    init_database = None
    get_database_manager = None
    create_health_check_response = None
    DatabaseConfigurationError = Exception

# Authentication and authorization configuration imports
try:
    from .auth import (
        AuthenticationManager,
        JWTTokenManager,
        Auth0Integration,
        FlaskLoginManager,
        AuthorizationDecorators,
        UserContextManager,
        AuthenticationError
    )
except ImportError as e:
    logging.warning(f"Authentication configuration import failed: {str(e)}")
    # Set fallback values for optional auth components
    AuthenticationManager = None
    AuthenticationError = Exception

# Security configuration imports
try:
    from .security import (
        SecurityManager,
        ContentSecurityPolicyManager,
        CORSManager,
        RateLimitManager,
        InputValidationManager,
        SecurityValidationError,
        SecurityConfigurationError
    )
except ImportError as e:
    logging.warning(f"Security configuration import failed: {str(e)}")
    # Set fallback values for optional security components
    SecurityManager = None
    SecurityConfigurationError = Exception

# Logging configuration imports
try:
    from .logging import (
        StructuredLoggingManager,
        EnterpriseLogFormatter,
        SecurityAuditLogger,
        PerformanceLogger,
        configure_structured_logging,
        get_logger
    )
except ImportError as e:
    logging.warning(f"Logging configuration import failed: {str(e)}")
    # Set fallback values for optional logging components
    configure_structured_logging = None
    get_logger = logging.getLogger

# Monitoring configuration imports
try:
    from .monitoring import (
        MonitoringManager,
        PrometheusMetricsManager,
        HealthCheckManager,
        PerformanceTracker,
        APMIntegration,
        configure_monitoring,
        MonitoringError
    )
except ImportError as e:
    logging.warning(f"Monitoring configuration import failed: {str(e)}")
    # Set fallback values for optional monitoring components
    configure_monitoring = None
    MonitoringError = Exception

# External services configuration imports
try:
    from .external_services import (
        ExternalServicesManager,
        AWSServiceManager,
        HTTPClientManager,
        Auth0ServiceManager,
        CircuitBreakerManager,
        ExternalServiceError
    )
except ImportError as e:
    logging.warning(f"External services configuration import failed: {str(e)}")
    # Set fallback values for optional external service components
    ExternalServicesManager = None
    ExternalServiceError = Exception

# Environment-specific configuration imports
try:
    from .development import DevelopmentEnvironmentConfig
except ImportError as e:
    logging.warning(f"Development configuration import failed: {str(e)}")
    DevelopmentEnvironmentConfig = None

try:
    from .production import ProductionEnvironmentConfig
except ImportError as e:
    logging.warning(f"Production configuration import failed: {str(e)}")
    ProductionEnvironmentConfig = None

# Configure module logger
logger = logging.getLogger(__name__)


class ConfigurationPackageError(Exception):
    """Custom exception for configuration package initialization errors."""
    pass


class ConfigurationValidationError(Exception):
    """Custom exception for configuration validation failures."""
    pass


class FlaskConfigurationManager:
    """
    Flask Configuration Manager for comprehensive application setup.
    
    This class implements the Flask application factory pattern with comprehensive
    configuration management, validation, and initialization for all application
    components as specified in Section 3.2.1.
    """
    
    def __init__(self, config_name: Optional[str] = None):
        """
        Initialize Flask configuration manager.
        
        Args:
            config_name: Optional configuration environment name
        """
        self.config_name = config_name or os.getenv('FLASK_ENV', 'production')
        self.config = get_config(self.config_name)
        self.logger = logging.getLogger(f"{__name__}.FlaskConfigurationManager")
        
        # Component managers
        self.database_manager: Optional[DatabaseManager] = None
        self.security_manager: Optional[Any] = None
        self.monitoring_manager: Optional[Any] = None
        self.auth_manager: Optional[Any] = None
        self.external_services_manager: Optional[Any] = None
        
        # Initialization status
        self._initialized = False
        self._component_status = {
            'core_config': False,
            'database': False,
            'security': False,
            'authentication': False,
            'monitoring': False,
            'logging': False,
            'external_services': False
        }
    
    def init_app(self, app: Flask, validate_config: bool = True) -> None:
        """
        Initialize Flask application with comprehensive configuration.
        
        This method implements the Flask application factory pattern with complete
        configuration setup for all application components.
        
        Args:
            app: Flask application instance to configure
            validate_config: Whether to perform configuration validation
            
        Raises:
            ConfigurationPackageError: When initialization fails
        """
        try:
            self.logger.info(f"Initializing Flask application with {self.config_name} configuration")
            
            # Apply core Flask configuration
            self._apply_core_configuration(app)
            
            # Initialize database and caching
            self._initialize_database(app)
            
            # Initialize security components
            self._initialize_security(app)
            
            # Initialize authentication
            self._initialize_authentication(app)
            
            # Initialize monitoring and logging
            self._initialize_monitoring(app)
            
            # Initialize external services
            self._initialize_external_services(app)
            
            # Perform configuration validation
            if validate_config:
                self._validate_configuration()
            
            # Store configuration manager in app extensions
            app.extensions = getattr(app, 'extensions', {})
            app.extensions['config_manager'] = self
            
            self._initialized = True
            self.logger.info("Flask application configuration completed successfully")
            
        except Exception as e:
            self.logger.error(f"Flask configuration initialization failed: {str(e)}")
            raise ConfigurationPackageError(f"Configuration initialization failed: {str(e)}")
    
    def _apply_core_configuration(self, app: Flask) -> None:
        """Apply core Flask configuration settings."""
        try:
            # Apply all configuration settings from config object
            for key, value in self.config.__dict__.items():
                if not key.startswith('_') and hasattr(self.config, key):
                    app.config[key] = value
            
            # Ensure Flask-specific configurations are properly set
            app.config['ENV'] = self.config.FLASK_ENV
            app.config['DEBUG'] = self.config.DEBUG
            app.config['TESTING'] = self.config.TESTING
            app.config['SECRET_KEY'] = self.config.SECRET_KEY
            
            self._component_status['core_config'] = True
            self.logger.debug("Core Flask configuration applied successfully")
            
        except Exception as e:
            self.logger.error(f"Core configuration setup failed: {str(e)}")
            raise ConfigurationPackageError(f"Core configuration failed: {str(e)}")
    
    def _initialize_database(self, app: Flask) -> None:
        """Initialize database and caching components."""
        if init_database and DatabaseManager:
            try:
                self.database_manager = init_database(app, self.config)
                self._component_status['database'] = True
                self.logger.info("Database and caching initialization completed")
            except Exception as e:
                self.logger.error(f"Database initialization failed: {str(e)}")
                # Don't fail the entire app if database init fails
                self.logger.warning("Continuing without database components")
        else:
            self.logger.warning("Database components not available - skipping database initialization")
    
    def _initialize_security(self, app: Flask) -> None:
        """Initialize security components."""
        if SecurityManager:
            try:
                self.security_manager = SecurityManager(app, self.config)
                self._component_status['security'] = True
                self.logger.info("Security components initialization completed")
            except Exception as e:
                self.logger.error(f"Security initialization failed: {str(e)}")
                # Security is critical - consider this a warning but continue
                self.logger.warning("Continuing with basic security settings")
        else:
            self.logger.warning("Security components not available - using basic Flask security")
    
    def _initialize_authentication(self, app: Flask) -> None:
        """Initialize authentication components."""
        if AuthenticationManager:
            try:
                self.auth_manager = AuthenticationManager(app, self.config)
                self._component_status['authentication'] = True
                self.logger.info("Authentication components initialization completed")
            except Exception as e:
                self.logger.error(f"Authentication initialization failed: {str(e)}")
                # Auth failure is significant but not app-breaking in dev
                if self.config.FLASK_ENV == 'production':
                    raise ConfigurationPackageError(f"Authentication required for production: {str(e)}")
                self.logger.warning("Continuing without authentication in development mode")
        else:
            self.logger.warning("Authentication components not available")
    
    def _initialize_monitoring(self, app: Flask) -> None:
        """Initialize monitoring and logging components."""
        # Initialize structured logging
        if configure_structured_logging:
            try:
                configure_structured_logging(self.config)
                self._component_status['logging'] = True
                self.logger.info("Structured logging initialization completed")
            except Exception as e:
                self.logger.error(f"Logging initialization failed: {str(e)}")
        
        # Initialize monitoring
        if configure_monitoring:
            try:
                self.monitoring_manager = configure_monitoring(app, self.config)
                self._component_status['monitoring'] = True
                self.logger.info("Monitoring components initialization completed")
            except Exception as e:
                self.logger.error(f"Monitoring initialization failed: {str(e)}")
                self.logger.warning("Continuing without advanced monitoring")
    
    def _initialize_external_services(self, app: Flask) -> None:
        """Initialize external service integrations."""
        if ExternalServicesManager:
            try:
                self.external_services_manager = ExternalServicesManager(app, self.config)
                self._component_status['external_services'] = True
                self.logger.info("External services initialization completed")
            except Exception as e:
                self.logger.error(f"External services initialization failed: {str(e)}")
                self.logger.warning("Continuing without external service integrations")
    
    def _validate_configuration(self) -> None:
        """Perform comprehensive configuration validation."""
        try:
            validation_errors = []
            
            # Validate required configuration
            required_attrs = ['SECRET_KEY', 'FLASK_ENV']
            for attr in required_attrs:
                if not hasattr(self.config, attr) or not getattr(self.config, attr):
                    validation_errors.append(f"Required configuration missing: {attr}")
            
            # Validate production requirements
            if self.config.FLASK_ENV == 'production':
                production_requirements = ['MONGODB_URI', 'REDIS_HOST']
                for req in production_requirements:
                    if not hasattr(self.config, req) or not getattr(self.config, req):
                        validation_errors.append(f"Production requires: {req}")
            
            # Check component initialization status
            failed_critical_components = []
            critical_components = ['core_config']
            
            for component in critical_components:
                if not self._component_status[component]:
                    failed_critical_components.append(component)
            
            if failed_critical_components:
                validation_errors.append(f"Critical components failed: {', '.join(failed_critical_components)}")
            
            if validation_errors:
                error_message = "Configuration validation failed:\n" + "\n".join(
                    f"- {error}" for error in validation_errors
                )
                raise ConfigurationValidationError(error_message)
            
            self.logger.info("Configuration validation completed successfully")
            
        except Exception as e:
            self.logger.error(f"Configuration validation failed: {str(e)}")
            raise ConfigurationValidationError(f"Validation failed: {str(e)}")
    
    def get_component_status(self) -> Dict[str, Any]:
        """
        Get comprehensive component initialization status.
        
        Returns:
            Dictionary containing component status and configuration information
        """
        return {
            'initialized': self._initialized,
            'configuration_name': self.config_name,
            'component_status': dict(self._component_status),
            'flask_env': self.config.FLASK_ENV,
            'debug_mode': self.config.DEBUG,
            'testing_mode': self.config.TESTING,
            'available_managers': {
                'database': self.database_manager is not None,
                'security': self.security_manager is not None,
                'authentication': self.auth_manager is not None,
                'monitoring': self.monitoring_manager is not None,
                'external_services': self.external_services_manager is not None
            }
        }
    
    def get_health_status(self) -> Dict[str, Any]:
        """
        Get comprehensive health status for all configured components.
        
        Returns:
            Dictionary containing health status of all components
        """
        health_status = {
            'overall_healthy': self._initialized,
            'configuration_manager': self.get_component_status(),
            'timestamp': os.environ.get('HEALTH_CHECK_TIMESTAMP', 'unknown')
        }
        
        # Add database health if available
        if self.database_manager and hasattr(self.database_manager, 'get_health_status'):
            health_status['database'] = self.database_manager.get_health_status()
        
        # Add monitoring health if available
        if self.monitoring_manager and hasattr(self.monitoring_manager, 'get_health_status'):
            health_status['monitoring'] = self.monitoring_manager.get_health_status()
        
        return health_status


def init_app_config(app: Flask, config_name: Optional[str] = None, 
                   validate_config: bool = True) -> FlaskConfigurationManager:
    """
    Initialize Flask application with comprehensive configuration management.
    
    This function provides the main entry point for Flask application factory
    pattern configuration setup with all required components.
    
    Args:
        app: Flask application instance to configure
        config_name: Optional environment configuration name
        validate_config: Whether to perform configuration validation
        
    Returns:
        Initialized FlaskConfigurationManager instance
        
    Raises:
        ConfigurationPackageError: When configuration initialization fails
    """
    try:
        config_manager = FlaskConfigurationManager(config_name)
        config_manager.init_app(app, validate_config)
        
        logger.info(f"Flask application configured successfully with {config_name or 'default'} settings")
        return config_manager
        
    except Exception as e:
        logger.error(f"Flask configuration initialization failed: {str(e)}")
        raise ConfigurationPackageError(f"Flask app configuration failed: {str(e)}")


def create_app_with_config(config_name: Optional[str] = None, 
                          **flask_kwargs) -> Tuple[Flask, FlaskConfigurationManager]:
    """
    Create Flask application with comprehensive configuration setup.
    
    This function implements the Flask application factory pattern with
    complete configuration management for rapid application setup.
    
    Args:
        config_name: Optional environment configuration name
        **flask_kwargs: Additional Flask application arguments
        
    Returns:
        Tuple of (Flask app instance, configuration manager)
        
    Raises:
        ConfigurationPackageError: When application creation fails
    """
    try:
        # Create Flask application
        app = Flask(__name__, **flask_kwargs)
        
        # Initialize configuration
        config_manager = init_app_config(app, config_name)
        
        logger.info("Flask application created successfully with configuration management")
        return app, config_manager
        
    except Exception as e:
        logger.error(f"Flask application creation failed: {str(e)}")
        raise ConfigurationPackageError(f"App creation failed: {str(e)}")


def get_configuration_status() -> Dict[str, Any]:
    """
    Get comprehensive configuration package status information.
    
    This function provides detailed information about the configuration
    package initialization status and available components.
    
    Returns:
        Dictionary containing package status and component availability
    """
    return {
        'package_version': '1.0.0',
        'migration_phase': 'Node.js to Python/Flask Migration',
        'available_components': {
            'core_config': BaseConfig is not None,
            'database_manager': DatabaseManager is not None,
            'authentication_manager': AuthenticationManager is not None,
            'security_manager': SecurityManager is not None,
            'monitoring_manager': configure_monitoring is not None,
            'logging_manager': configure_structured_logging is not None,
            'external_services_manager': ExternalServicesManager is not None
        },
        'configuration_classes': {
            'base': BaseConfig.__name__ if BaseConfig else None,
            'development': DevelopmentConfig.__name__ if DevelopmentConfig else None,
            'staging': StagingConfig.__name__ if StagingConfig else None,
            'production': ProductionConfig.__name__ if ProductionConfig else None,
            'testing': TestingConfig.__name__ if TestingConfig else None
        },
        'environment_support': {
            'dotenv_integration': True,
            'flask_factory_pattern': True,
            'environment_validation': True,
            'security_compliance': SecurityManager is not None,
            'enterprise_features': all([
                DatabaseManager is not None,
                configure_monitoring is not None,
                configure_structured_logging is not None
            ])
        }
    }


# Package exports for application usage
__all__ = [
    # Core configuration classes
    'BaseConfig',
    'DevelopmentConfig',
    'StagingConfig', 
    'ProductionConfig',
    'TestingConfig',
    
    # Configuration factory functions
    'get_config',
    'config',
    
    # Flask application factory support
    'FlaskConfigurationManager',
    'init_app_config',
    'create_app_with_config',
    
    # Environment and utility classes
    'EnvironmentManager',
    
    # Database and caching components (if available)
    'DatabaseManager',
    'MongoDBManager',
    'RedisManager',
    'FlaskSessionManager',
    'init_database',
    'get_database_manager',
    'create_health_check_response',
    
    # Authentication components (if available)
    'AuthenticationManager',
    'JWTTokenManager',
    'Auth0Integration',
    
    # Security components (if available)
    'SecurityManager',
    'ContentSecurityPolicyManager',
    'CORSManager',
    'RateLimitManager',
    
    # Monitoring components (if available)
    'configure_monitoring',
    'configure_structured_logging',
    'get_logger',
    
    # External services components (if available)
    'ExternalServicesManager',
    'AWSServiceManager',
    'HTTPClientManager',
    
    # Environment-specific configurations (if available)
    'DevelopmentEnvironmentConfig',
    'ProductionEnvironmentConfig',
    
    # Status and utility functions
    'get_configuration_status',
    
    # Exception classes
    'ConfigurationError',
    'ConfigurationPackageError',
    'ConfigurationValidationError',
    'DatabaseConfigurationError',
    'AuthenticationError',
    'SecurityConfigurationError',
    'MonitoringError',
    'ExternalServiceError'
]

# Module metadata
__version__ = '1.0.0'
__author__ = 'Flask Migration Team'
__description__ = 'Configuration package for Node.js to Python/Flask migration'
__migration_phase__ = 'Node.js to Python/Flask Migration (Section 0.1.1)'

# Log package initialization
logger.info(f"Configuration package initialized - version {__version__}")
logger.info(f"Migration phase: {__migration_phase__}")

# Validate package consistency on import
try:
    status = get_configuration_status()
    available_components = sum(1 for available in status['available_components'].values() if available)
    total_components = len(status['available_components'])
    
    logger.info(f"Configuration package status: {available_components}/{total_components} components available")
    
    if available_components == 0:
        logger.error("No configuration components available - check module imports")
    elif available_components < total_components:
        logger.warning(f"Some configuration components unavailable: {total_components - available_components} missing")
    else:
        logger.info("All configuration components successfully loaded")
        
except Exception as e:
    logger.error(f"Configuration package validation failed: {str(e)}")