"""
Main Source Package Initialization
==================================

Python package initialization file for the main src module, establishing the Flask application
as a proper Python package and providing centralized imports for the application factory and
core components.

This module serves as the primary entry point for the Flask application package, implementing
Python packaging standards and supporting Blueprint-based modular architecture as specified
in the technical requirements for the Node.js to Python/Flask migration project.

Architecture:
- Establishes proper Python package namespace for modular organization
- Provides centralized imports for Flask application factory accessibility
- Supports Blueprint-based architecture per Section 5.1.2 of technical specifications
- Implements package-level metadata and version management
- Enables seamless integration with enterprise Python infrastructure

Package Structure:
- Application factory pattern with centralized extension initialization
- Blueprint-based modular architecture for maintainable code organization
- Enterprise-grade configuration and environment management
- Comprehensive logging and monitoring integration capabilities
"""

import os
import sys
from typing import Optional, Any, Dict

# Package metadata and version information
__version__ = "1.0.0"
__title__ = "Flask Migration Application"
__description__ = "Enterprise Flask application migrated from Node.js/Express.js"
__author__ = "Migration Team"
__email__ = "migration@company.com"
__license__ = "Proprietary"

# Package-level constants for Flask application configuration
PACKAGE_NAME = "src"
APPLICATION_NAME = "flask-migration-app"
DEFAULT_CONFIG_ENV = "development"

# Environment and configuration management
SUPPORTED_ENVIRONMENTS = ["development", "testing", "staging", "production"]
REQUIRED_ENV_VARS = [
    "SECRET_KEY",
    "JWT_SECRET_KEY", 
    "MONGODB_URI",
    "REDIS_URL"
]

# Import core application components for package-level accessibility
try:
    # Import Flask application factory - primary entry point
    from src.app import create_app, create_wsgi_app
    
    # Import application configuration components
    from src.app import application as wsgi_application
    
    # Import key Flask extensions for external access if needed
    from src.app import (
        mongo_client,
        motor_client, 
        redis_client,
        logger
    )
    
    # Core application initialization successful
    _CORE_IMPORTS_AVAILABLE = True
    
except ImportError as e:
    # Handle graceful import failure during package development
    _CORE_IMPORTS_AVAILABLE = False
    
    # Define fallback functions for development scenarios
    def create_app(config_name: Optional[str] = None):
        """Fallback application factory when core imports fail"""
        raise ImportError(f"Core application components not available: {e}")
    
    def create_wsgi_app():
        """Fallback WSGI application factory"""
        raise ImportError(f"WSGI application not available: {e}")
    
    # Fallback application instance
    wsgi_application = None
    
    # Fallback client instances
    mongo_client = None
    motor_client = None
    redis_client = None
    logger = None


# Blueprint module imports for modular architecture support
try:
    # Import Blueprint registration functionality when available
    from src.blueprints import register_all_blueprints
    
    _BLUEPRINT_IMPORTS_AVAILABLE = True
    
except ImportError:
    # Blueprints not yet implemented - graceful degradation
    _BLUEPRINT_IMPORTS_AVAILABLE = False
    
    def register_all_blueprints(app):
        """Fallback blueprint registration function"""
        pass


# Configuration and utilities imports
try:
    # Import configuration management when available
    from src.config.settings import Config, get_config
    
    _CONFIG_IMPORTS_AVAILABLE = True
    
except ImportError:
    # Configuration not yet implemented - provide fallback
    _CONFIG_IMPORTS_AVAILABLE = False
    
    class Config:
        """Fallback configuration class"""
        pass
    
    def get_config():
        """Fallback configuration getter"""
        return Config()


def get_package_info() -> Dict[str, Any]:
    """
    Get comprehensive package information and metadata.
    
    Returns comprehensive information about the package including version,
    component availability, environment configuration, and system status.
    
    Returns:
        Dict containing package metadata, version info, and component status
    """
    return {
        "name": PACKAGE_NAME,
        "version": __version__,
        "title": __title__,
        "description": __description__,
        "author": __author__,
        "email": __email__,
        "license": __license__,
        "application_name": APPLICATION_NAME,
        "supported_environments": SUPPORTED_ENVIRONMENTS,
        "component_status": {
            "core_imports": _CORE_IMPORTS_AVAILABLE,
            "blueprint_imports": _BLUEPRINT_IMPORTS_AVAILABLE,
            "config_imports": _CONFIG_IMPORTS_AVAILABLE
        },
        "python_version": sys.version,
        "package_path": os.path.dirname(__file__)
    }


def validate_environment() -> Dict[str, Any]:
    """
    Validate required environment variables and system dependencies.
    
    Performs comprehensive validation of the runtime environment including
    required environment variables, Python version compatibility, and
    critical dependency availability.
    
    Returns:
        Dict containing environment validation results and status
    """
    validation_result = {
        "valid": True,
        "python_version_compatible": True,
        "required_env_vars": {},
        "missing_env_vars": [],
        "warnings": [],
        "errors": []
    }
    
    # Validate Python version compatibility (3.8+)
    python_version = sys.version_info
    if python_version < (3, 8):
        validation_result["valid"] = False
        validation_result["python_version_compatible"] = False
        validation_result["errors"].append(
            f"Python 3.8+ required, found {python_version.major}.{python_version.minor}"
        )
    
    # Validate required environment variables
    for env_var in REQUIRED_ENV_VARS:
        value = os.getenv(env_var)
        validation_result["required_env_vars"][env_var] = bool(value)
        
        if not value:
            validation_result["missing_env_vars"].append(env_var)
            validation_result["warnings"].append(f"Environment variable {env_var} not set")
    
    # Check for missing environment variables
    if validation_result["missing_env_vars"]:
        validation_result["warnings"].append(
            "Some environment variables are missing - application may not function correctly"
        )
    
    # Validate component import status
    if not _CORE_IMPORTS_AVAILABLE:
        validation_result["warnings"].append("Core application components not available")
    
    if not _BLUEPRINT_IMPORTS_AVAILABLE:
        validation_result["warnings"].append("Blueprint components not available")
    
    if not _CONFIG_IMPORTS_AVAILABLE:
        validation_result["warnings"].append("Configuration components not available")
    
    return validation_result


def get_application_factory():
    """
    Get the Flask application factory function.
    
    Returns the primary Flask application factory function for programmatic
    application creation with proper error handling and validation.
    
    Returns:
        Flask application factory function
        
    Raises:
        ImportError: If core application components are not available
        RuntimeError: If environment validation fails
    """
    if not _CORE_IMPORTS_AVAILABLE:
        raise ImportError("Core application components not available - check imports")
    
    # Validate environment before returning factory
    env_validation = validate_environment()
    if not env_validation["python_version_compatible"]:
        raise RuntimeError("Python version incompatible - upgrade to Python 3.8+")
    
    return create_app


def get_wsgi_application():
    """
    Get the WSGI application instance for production deployment.
    
    Returns the configured WSGI application instance suitable for deployment
    with Gunicorn, uWSGI, or other WSGI servers.
    
    Returns:
        Configured Flask WSGI application instance
        
    Raises:
        ImportError: If core application components are not available
        RuntimeError: If application instance is not properly configured
    """
    if not _CORE_IMPORTS_AVAILABLE:
        raise ImportError("Core application components not available - check imports")
    
    if wsgi_application is None:
        raise RuntimeError("WSGI application not properly initialized")
    
    return wsgi_application


def initialize_package_logging():
    """
    Initialize package-level logging configuration.
    
    Sets up basic logging for the package initialization and import processes,
    providing visibility into package loading and component availability.
    """
    import logging
    
    # Configure basic logging for package initialization
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    package_logger = logging.getLogger(PACKAGE_NAME)
    
    # Log package initialization status
    package_logger.info(f"Package {PACKAGE_NAME} v{__version__} initializing")
    package_logger.info(f"Core imports available: {_CORE_IMPORTS_AVAILABLE}")
    package_logger.info(f"Blueprint imports available: {_BLUEPRINT_IMPORTS_AVAILABLE}")
    package_logger.info(f"Config imports available: {_CONFIG_IMPORTS_AVAILABLE}")
    
    # Log environment validation results
    env_validation = validate_environment()
    if env_validation["warnings"]:
        for warning in env_validation["warnings"]:
            package_logger.warning(warning)
    
    if env_validation["errors"]:
        for error in env_validation["errors"]:
            package_logger.error(error)
    
    package_logger.info("Package initialization completed")


# Package-level exports for public API
__all__ = [
    # Package metadata
    "__version__",
    "__title__", 
    "__description__",
    "__author__",
    "__email__",
    "__license__",
    
    # Core application factory functions
    "create_app",
    "create_wsgi_app",
    "wsgi_application",
    
    # Database and cache clients
    "mongo_client",
    "motor_client", 
    "redis_client",
    
    # Configuration components
    "Config",
    "get_config",
    
    # Blueprint registration
    "register_all_blueprints",
    
    # Package utility functions
    "get_package_info",
    "validate_environment",
    "get_application_factory",
    "get_wsgi_application",
    "initialize_package_logging",
    
    # Package constants
    "PACKAGE_NAME",
    "APPLICATION_NAME",
    "SUPPORTED_ENVIRONMENTS",
    "REQUIRED_ENV_VARS"
]


# Initialize package logging on import
if __name__ != "__main__":
    # Only initialize logging when imported as a package
    try:
        initialize_package_logging()
    except Exception:
        # Graceful handling of logging initialization failures
        pass


# Package initialization completed - ready for use
# The src package is now properly initialized with Flask application factory
# accessibility and Blueprint-based modular architecture support