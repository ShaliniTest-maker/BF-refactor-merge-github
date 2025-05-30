"""
Flask Application Package Initialization

This module establishes the src package as the main Flask application package,
implementing a modular Blueprint-based architecture for enterprise-grade scalability.
Provides centralized imports for the Flask application factory and core components,
supporting the strategic migration from Node.js to Python 3.8+ with Flask 2.3+.

Key Features:
- Flask application factory pattern support
- Blueprint-based modular architecture
- Enterprise integration components
- Type-safe imports with Python 3.8+ compatibility
- Centralized configuration and dependency management

Architecture Alignment:
- Section 5.1.2: Core Components Table - Flask Blueprint organization
- Section 6.1.1: Flask Application Factory Pattern Implementation
- Section 0.1.2: Affected Components - Modular component architecture
- Section 3.1.1: Python 3.8+ runtime environment requirements

Performance Requirements:
- ≤10% variance from Node.js baseline per Section 0.1.1
- Horizontal scaling through WSGI server deployment per Section 6.1.3
- Connection pooling optimization per Section 6.1.3

Author: Enterprise Migration Team
Version: 1.0.0
Python: 3.8+
Flask: 2.3+
"""

from typing import Optional, Any, Dict
import sys

# Package metadata following Python packaging standards
__version__ = "1.0.0"
__author__ = "Enterprise Migration Team"
__description__ = "Flask Application Package - Node.js to Python Migration"
__python_requires__ = ">=3.8"

# Ensure Python version compatibility
if sys.version_info < (3, 8):
    raise RuntimeError(
        f"Python 3.8+ is required for this application. "
        f"Current version: {sys.version_info.major}.{sys.version_info.minor}"
    )

# Lazy import pattern for application factory to prevent circular imports
# This allows the package to be imported without immediately initializing Flask
_app_factory = None

def get_app_factory():
    """
    Lazy-load the Flask application factory.
    
    This pattern prevents circular imports and allows the package
    to be imported without immediately creating Flask instances.
    
    Returns:
        Callable: The Flask application factory function
        
    Raises:
        ImportError: If the app module cannot be imported
        AttributeError: If create_app function is not found
    """
    global _app_factory
    if _app_factory is None:
        try:
            from .app import create_app
            _app_factory = create_app
        except ImportError as e:
            raise ImportError(
                f"Failed to import Flask application factory: {e}. "
                "Ensure src/app.py exists and contains create_app function."
            ) from e
    return _app_factory

def create_app(*args, **kwargs) -> Any:
    """
    Create and configure the Flask application instance.
    
    This function delegates to the actual application factory in app.py,
    providing a convenient entry point for application creation while
    maintaining the factory pattern requirements.
    
    Args:
        *args: Positional arguments to pass to the application factory
        **kwargs: Keyword arguments to pass to the application factory
        
    Returns:
        Flask: Configured Flask application instance
        
    Example:
        >>> from src import create_app
        >>> app = create_app()
        >>> app.run(debug=True)
    """
    factory = get_app_factory()
    return factory(*args, **kwargs)

# Core module namespace organization for Blueprint architecture
# These imports are structured to support the modular Flask Blueprint pattern

# Authentication and authorization components
def get_auth_module():
    """Lazy import for authentication module."""
    try:
        from . import auth
        return auth
    except ImportError:
        return None

# Blueprint organization and registration
def get_blueprints_module():
    """Lazy import for blueprints module."""
    try:
        from . import blueprints
        return blueprints
    except ImportError:
        return None

# Data access layer with PyMongo and Motor
def get_data_module():
    """Lazy import for data access module."""
    try:
        from . import data
        return data
    except ImportError:
        return None

# Business logic processing engine
def get_business_module():
    """Lazy import for business logic module."""
    try:
        from . import business
        return business
    except ImportError:
        return None

# External service integrations
def get_integrations_module():
    """Lazy import for integrations module."""
    try:
        from . import integrations
        return integrations
    except ImportError:
        return None

# Caching layer with Redis
def get_cache_module():
    """Lazy import for cache module."""
    try:
        from . import cache
        return cache
    except ImportError:
        return None

# Monitoring and observability
def get_monitoring_module():
    """Lazy import for monitoring module."""
    try:
        from . import monitoring
        return monitoring
    except ImportError:
        return None

# Configuration management
def get_config_module():
    """Lazy import for configuration module."""
    try:
        from . import config
        return config
    except ImportError:
        return None

# Utility functions
def get_utils_module():
    """Lazy import for utilities module."""
    try:
        from . import utils
        return utils
    except ImportError:
        return None

# Package health check for dependency validation
def validate_package_dependencies() -> Dict[str, bool]:
    """
    Validate the availability of core package dependencies.
    
    This function checks that all required modules can be imported
    successfully, providing diagnostic information for troubleshooting.
    
    Returns:
        Dict[str, bool]: Dictionary mapping module names to availability status
        
    Example:
        >>> from src import validate_package_dependencies
        >>> status = validate_package_dependencies()
        >>> print("Auth module available:", status.get('auth', False))
    """
    modules = {
        'auth': get_auth_module(),
        'blueprints': get_blueprints_module(),
        'data': get_data_module(),
        'business': get_business_module(),
        'integrations': get_integrations_module(),
        'cache': get_cache_module(),
        'monitoring': get_monitoring_module(),
        'config': get_config_module(),
        'utils': get_utils_module(),
    }
    
    return {name: module is not None for name, module in modules.items()}

# Public API following Python packaging conventions
__all__ = [
    # Core application factory
    'create_app',
    'get_app_factory',
    
    # Module accessors
    'get_auth_module',
    'get_blueprints_module',
    'get_data_module',
    'get_business_module',
    'get_integrations_module',
    'get_cache_module',
    'get_monitoring_module',
    'get_config_module',
    'get_utils_module',
    
    # Package utilities
    'validate_package_dependencies',
    
    # Metadata
    '__version__',
    '__author__',
    '__description__',
    '__python_requires__',
]

# Package-level configuration for development and debugging
# This allows easy access to package information during development
def get_package_info() -> Dict[str, Any]:
    """
    Get comprehensive package information for debugging and monitoring.
    
    Returns:
        Dict[str, Any]: Package metadata and status information
        
    Example:
        >>> from src import get_package_info
        >>> info = get_package_info()
        >>> print(f"Package version: {info['version']}")
    """
    return {
        'version': __version__,
        'author': __author__,
        'description': __description__,
        'python_requires': __python_requires__,
        'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        'dependencies_status': validate_package_dependencies(),
    }

# Add package info to public API
__all__.append('get_package_info')