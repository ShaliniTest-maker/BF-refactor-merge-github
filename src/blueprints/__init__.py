"""
Flask Blueprint Package Initialization

Centralized blueprint registration and management for the Flask application factory,
providing modular route organization equivalent to Express.js routing patterns.
Implements enterprise-grade Flask Blueprint architecture supporting comprehensive
API endpoints, health monitoring, public access, and administrative functionality.

This module orchestrates the registration of all application blueprints including:
- API Blueprint: Authenticated REST endpoints with business logic integration  
- Health Blueprint: Kubernetes-native monitoring and health check endpoints
- Public Blueprint: Unauthenticated endpoints for registration and public content
- Admin Blueprint: Administrative endpoints with elevated security and permissions

Architecture Features:
- Flask application factory pattern integration per Section 6.1.1
- Modular routing architecture for maintainable code organization per Section 3.2.1
- RESTful API patterns and resource management per Flask-RESTful requirements
- Blueprint URL prefix and subdomain routing for scalable API organization
- Comprehensive error handling and logging integration
- Rate limiting and security header management across all blueprints

Blueprint Organization:
┌─────────────────────┬──────────────────┬─────────────────────────────────────┐
│ Blueprint           │ URL Prefix       │ Functionality                       │
├─────────────────────┼──────────────────┼─────────────────────────────────────┤
│ API Blueprint       │ /api/v1          │ Authenticated REST endpoints        │
│ Health Blueprint    │ /health          │ Health checks and monitoring        │
│ Public Blueprint    │ /public          │ Unauthenticated public endpoints    │
│ Admin Blueprint     │ /admin           │ Administrative management interface  │
└─────────────────────┴──────────────────┴─────────────────────────────────────┘

Integration Points:
- Flask application factory (app.py): Blueprint registration during app creation
- Authentication system: Decorator integration across protected blueprints
- Rate limiting: Flask-Limiter configuration for blueprint-specific limits
- CORS configuration: Cross-origin request handling per blueprint requirements
- Error handling: Centralized error response formatting and logging

Compliance:
- F-002 requirement: Flask Blueprints for modular routing architecture
- Section 3.2.1: Flask-Blueprints for maintainable code organization
- Section 6.1.1: Flask application factory pattern support
- Section 5.2.2: Blueprint URL prefixes and RESTful API organization
- Section 4.2.1: Seamless Blueprint registration in application factory

Dependencies:
- src.blueprints.api: Core authenticated API endpoints
- src.blueprints.health: Health monitoring and system status endpoints
- src.blueprints.public: Public access endpoints and registration flows
- src.blueprints.admin: Administrative management and elevated permissions

Usage Example:
    from src.blueprints import register_all_blueprints
    
    app = Flask(__name__)
    register_all_blueprints(app)

Author: Flask Migration System
Created: 2024
Version: 1.0.0
"""

import logging
from typing import Dict, Any, List, Optional, Callable
from flask import Flask, Blueprint, current_app

# Import all blueprint modules with error handling
try:
    from .api import api_blueprint, register_api_blueprint
    API_BLUEPRINT_AVAILABLE = True
except ImportError as e:
    logging.error(f"Failed to import API blueprint: {e}")
    api_blueprint = None
    register_api_blueprint = None
    API_BLUEPRINT_AVAILABLE = False

try:
    from .health import health_blueprint, register_health_blueprint
    HEALTH_BLUEPRINT_AVAILABLE = True
except ImportError as e:
    logging.error(f"Failed to import Health blueprint: {e}")
    health_blueprint = None
    register_health_blueprint = None
    HEALTH_BLUEPRINT_AVAILABLE = False

try:
    from .public import public_blueprint, register_public_blueprint
    PUBLIC_BLUEPRINT_AVAILABLE = True
except ImportError as e:
    logging.error(f"Failed to import Public blueprint: {e}")
    public_blueprint = None
    register_public_blueprint = None
    PUBLIC_BLUEPRINT_AVAILABLE = False

try:
    from .admin import admin_blueprint, register_admin_blueprint
    ADMIN_BLUEPRINT_AVAILABLE = True
except ImportError as e:
    logging.error(f"Failed to import Admin blueprint: {e}")
    admin_blueprint = None
    register_admin_blueprint = None
    ADMIN_BLUEPRINT_AVAILABLE = False


# Configure module logger
logger = logging.getLogger(__name__)


# =============================================================================
# BLUEPRINT REGISTRY AND METADATA
# =============================================================================

class BlueprintInfo:
    """Blueprint metadata and registration information"""
    
    def __init__(self, name: str, blueprint: Blueprint, register_func: Optional[Callable],
                 url_prefix: str, description: str, required: bool = True,
                 dependencies: Optional[List[str]] = None):
        self.name = name
        self.blueprint = blueprint
        self.register_func = register_func
        self.url_prefix = url_prefix
        self.description = description
        self.required = required
        self.dependencies = dependencies or []
        self.registered = False
        self.registration_error = None


# Blueprint registry with comprehensive metadata
BLUEPRINT_REGISTRY: Dict[str, BlueprintInfo] = {
    'api': BlueprintInfo(
        name='api',
        blueprint=api_blueprint,
        register_func=register_api_blueprint,
        url_prefix='/api/v1',
        description='Core authenticated API endpoints with business logic integration',
        required=True,
        dependencies=['auth', 'business', 'data', 'integrations']
    ),
    'health': BlueprintInfo(
        name='health',
        blueprint=health_blueprint,
        register_func=register_health_blueprint,
        url_prefix='/health',
        description='Health monitoring and system status endpoints for load balancers',
        required=True,
        dependencies=['monitoring', 'data', 'cache']
    ),
    'public': BlueprintInfo(
        name='public',
        blueprint=public_blueprint,
        register_func=register_public_blueprint,
        url_prefix='/public',
        description='Unauthenticated public endpoints for registration and content',
        required=False,
        dependencies=['auth']
    ),
    'admin': BlueprintInfo(
        name='admin',
        blueprint=admin_blueprint,
        register_func=register_admin_blueprint,
        url_prefix='/admin',
        description='Administrative management interface with elevated permissions',
        required=False,
        dependencies=['auth', 'data', 'monitoring']
    )
}


# =============================================================================
# BLUEPRINT VALIDATION AND AVAILABILITY CHECKING
# =============================================================================

def validate_blueprint_availability() -> Dict[str, Dict[str, Any]]:
    """
    Validate which blueprints are available and properly configured
    
    Returns:
        Dictionary containing availability status for each blueprint
    """
    availability_status = {}
    
    # Check API Blueprint
    availability_status['api'] = {
        'available': API_BLUEPRINT_AVAILABLE and api_blueprint is not None,
        'blueprint_object': api_blueprint is not None,
        'register_function': register_api_blueprint is not None,
        'required': True
    }
    
    # Check Health Blueprint
    availability_status['health'] = {
        'available': HEALTH_BLUEPRINT_AVAILABLE and health_blueprint is not None,
        'blueprint_object': health_blueprint is not None,
        'register_function': register_health_blueprint is not None,
        'required': True
    }
    
    # Check Public Blueprint
    availability_status['public'] = {
        'available': PUBLIC_BLUEPRINT_AVAILABLE and public_blueprint is not None,
        'blueprint_object': public_blueprint is not None,
        'register_function': register_public_blueprint is not None,
        'required': False
    }
    
    # Check Admin Blueprint
    availability_status['admin'] = {
        'available': ADMIN_BLUEPRINT_AVAILABLE and admin_blueprint is not None,
        'blueprint_object': admin_blueprint is not None,
        'register_function': register_admin_blueprint is not None,
        'required': False
    }
    
    return availability_status


def check_required_blueprints() -> Dict[str, bool]:
    """
    Check if all required blueprints are available
    
    Returns:
        Dictionary indicating which required blueprints are missing
    """
    availability = validate_blueprint_availability()
    missing_required = {}
    
    for blueprint_name, status in availability.items():
        if status['required'] and not status['available']:
            missing_required[blueprint_name] = False
            logger.error(f"Required blueprint '{blueprint_name}' is not available")
        else:
            missing_required[blueprint_name] = True
    
    return missing_required


# =============================================================================
# BLUEPRINT REGISTRATION FUNCTIONS
# =============================================================================

def register_api_blueprint_safe(app: Flask) -> bool:
    """
    Safely register API blueprint with comprehensive error handling
    
    Args:
        app: Flask application instance
        
    Returns:
        Boolean indicating successful registration
    """
    try:
        if not API_BLUEPRINT_AVAILABLE or api_blueprint is None:
            logger.error("API blueprint is not available for registration")
            return False
        
        # Use custom registration function if available
        if register_api_blueprint is not None:
            register_api_blueprint(app)
            logger.info("API blueprint registered using custom registration function")
        else:
            # Fallback to direct blueprint registration
            app.register_blueprint(api_blueprint, url_prefix='/api/v1')
            logger.info("API blueprint registered using direct registration")
        
        BLUEPRINT_REGISTRY['api'].registered = True
        return True
        
    except Exception as e:
        error_msg = f"Failed to register API blueprint: {str(e)}"
        logger.error(error_msg)
        BLUEPRINT_REGISTRY['api'].registration_error = error_msg
        return False


def register_health_blueprint_safe(app: Flask) -> bool:
    """
    Safely register Health blueprint with comprehensive error handling
    
    Args:
        app: Flask application instance
        
    Returns:
        Boolean indicating successful registration
    """
    try:
        if not HEALTH_BLUEPRINT_AVAILABLE or health_blueprint is None:
            logger.error("Health blueprint is not available for registration")
            return False
        
        # Use custom registration function if available
        if register_health_blueprint is not None:
            register_health_blueprint(app)
            logger.info("Health blueprint registered using custom registration function")
        else:
            # Fallback to direct blueprint registration
            app.register_blueprint(health_blueprint, url_prefix='/health')
            logger.info("Health blueprint registered using direct registration")
        
        BLUEPRINT_REGISTRY['health'].registered = True
        return True
        
    except Exception as e:
        error_msg = f"Failed to register Health blueprint: {str(e)}"
        logger.error(error_msg)
        BLUEPRINT_REGISTRY['health'].registration_error = error_msg
        return False


def register_public_blueprint_safe(app: Flask) -> bool:
    """
    Safely register Public blueprint with comprehensive error handling
    
    Args:
        app: Flask application instance
        
    Returns:
        Boolean indicating successful registration
    """
    try:
        if not PUBLIC_BLUEPRINT_AVAILABLE or public_blueprint is None:
            logger.warning("Public blueprint is not available for registration (non-critical)")
            return False
        
        # Use custom registration function if available
        if register_public_blueprint is not None:
            register_public_blueprint(app)
            logger.info("Public blueprint registered using custom registration function")
        else:
            # Fallback to direct blueprint registration
            app.register_blueprint(public_blueprint, url_prefix='/public')
            logger.info("Public blueprint registered using direct registration")
        
        BLUEPRINT_REGISTRY['public'].registered = True
        return True
        
    except Exception as e:
        error_msg = f"Failed to register Public blueprint: {str(e)}"
        logger.warning(error_msg)  # Warning for optional blueprint
        BLUEPRINT_REGISTRY['public'].registration_error = error_msg
        return False


def register_admin_blueprint_safe(app: Flask) -> bool:
    """
    Safely register Admin blueprint with comprehensive error handling
    
    Args:
        app: Flask application instance
        
    Returns:
        Boolean indicating successful registration
    """
    try:
        if not ADMIN_BLUEPRINT_AVAILABLE or admin_blueprint is None:
            logger.warning("Admin blueprint is not available for registration (non-critical)")
            return False
        
        # Use custom registration function if available
        if register_admin_blueprint is not None:
            register_admin_blueprint(app)
            logger.info("Admin blueprint registered using custom registration function")
        else:
            # Fallback to direct blueprint registration
            app.register_blueprint(admin_blueprint, url_prefix='/admin')
            logger.info("Admin blueprint registered using direct registration")
        
        BLUEPRINT_REGISTRY['admin'].registered = True
        return True
        
    except Exception as e:
        error_msg = f"Failed to register Admin blueprint: {str(e)}"
        logger.warning(error_msg)  # Warning for optional blueprint
        BLUEPRINT_REGISTRY['admin'].registration_error = error_msg
        return False


# =============================================================================
# COMPREHENSIVE BLUEPRINT REGISTRATION
# =============================================================================

def register_all_blueprints(app: Flask, 
                           include_optional: bool = True,
                           fail_on_missing_required: bool = True) -> Dict[str, bool]:
    """
    Register all available blueprints with the Flask application factory
    
    This function implements centralized blueprint registration for modular route
    organization per F-002 requirement and Flask application factory pattern
    per Section 6.1.1. It provides comprehensive error handling, dependency
    validation, and registration status tracking.
    
    Args:
        app: Flask application instance from application factory
        include_optional: Whether to register optional blueprints (default: True)
        fail_on_missing_required: Whether to raise exception if required blueprints are missing
        
    Returns:
        Dictionary mapping blueprint names to registration success status
        
    Raises:
        RuntimeError: If required blueprints are missing and fail_on_missing_required is True
    """
    logger.info("Starting blueprint registration process")
    
    # Validate blueprint availability
    availability = validate_blueprint_availability()
    required_status = check_required_blueprints()
    
    registration_results = {}
    
    # Check for missing required blueprints
    missing_required = [name for name, available in required_status.items() 
                       if not available]
    
    if missing_required and fail_on_missing_required:
        error_msg = f"Required blueprints are missing: {', '.join(missing_required)}"
        logger.error(error_msg)
        raise RuntimeError(error_msg)
    elif missing_required:
        logger.warning(f"Required blueprints are missing but continuing: {', '.join(missing_required)}")
    
    # Register API Blueprint (critical for application functionality)
    api_success = register_api_blueprint_safe(app)
    registration_results['api'] = api_success
    
    if not api_success and fail_on_missing_required:
        error_msg = "Failed to register critical API blueprint"
        logger.error(error_msg)
        raise RuntimeError(error_msg)
    
    # Register Health Blueprint (critical for monitoring and load balancing)
    health_success = register_health_blueprint_safe(app)
    registration_results['health'] = health_success
    
    if not health_success and fail_on_missing_required:
        error_msg = "Failed to register critical Health blueprint"
        logger.error(error_msg)
        raise RuntimeError(error_msg)
    
    # Register optional blueprints if requested
    if include_optional:
        # Register Public Blueprint (optional but recommended)
        public_success = register_public_blueprint_safe(app)
        registration_results['public'] = public_success
        
        # Register Admin Blueprint (optional)
        admin_success = register_admin_blueprint_safe(app)
        registration_results['admin'] = admin_success
    else:
        logger.info("Skipping optional blueprint registration as requested")
        registration_results['public'] = False
        registration_results['admin'] = False
    
    # Log registration summary
    successful_registrations = [name for name, success in registration_results.items() if success]
    failed_registrations = [name for name, success in registration_results.items() if not success]
    
    logger.info(f"Blueprint registration completed:")
    logger.info(f"  Successful: {', '.join(successful_registrations) if successful_registrations else 'None'}")
    
    if failed_registrations:
        logger.warning(f"  Failed: {', '.join(failed_registrations)}")
    
    # Configure Flask application with registered blueprints
    _configure_blueprint_integration(app, registration_results)
    
    return registration_results


def register_blueprint_by_name(app: Flask, blueprint_name: str) -> bool:
    """
    Register a specific blueprint by name with error handling
    
    Args:
        app: Flask application instance
        blueprint_name: Name of blueprint to register
        
    Returns:
        Boolean indicating successful registration
    """
    if blueprint_name not in BLUEPRINT_REGISTRY:
        logger.error(f"Unknown blueprint name: {blueprint_name}")
        return False
    
    blueprint_info = BLUEPRINT_REGISTRY[blueprint_name]
    
    if blueprint_info.registered:
        logger.warning(f"Blueprint '{blueprint_name}' is already registered")
        return True
    
    # Call appropriate registration function
    registration_functions = {
        'api': register_api_blueprint_safe,
        'health': register_health_blueprint_safe,
        'public': register_public_blueprint_safe,
        'admin': register_admin_blueprint_safe
    }
    
    register_func = registration_functions.get(blueprint_name)
    if register_func:
        return register_func(app)
    else:
        logger.error(f"No registration function found for blueprint: {blueprint_name}")
        return False


# =============================================================================
# BLUEPRINT INTEGRATION AND CONFIGURATION
# =============================================================================

def _configure_blueprint_integration(app: Flask, registration_results: Dict[str, bool]) -> None:
    """
    Configure Flask application settings for registered blueprints
    
    Args:
        app: Flask application instance
        registration_results: Results from blueprint registration process
    """
    logger.info("Configuring blueprint integration settings")
    
    # Configure CORS for registered blueprints
    registered_blueprints = [name for name, success in registration_results.items() if success]
    
    # Configure rate limiting for registered blueprints
    if 'api' in registered_blueprints:
        # API blueprint specific configuration
        logger.info("Configuring API blueprint integration")
    
    if 'health' in registered_blueprints:
        # Health blueprint specific configuration
        logger.info("Configuring Health blueprint integration")
        # Health endpoints should be excluded from rate limiting
        app.config.setdefault('RATELIMIT_EXEMPT_ENDPOINTS', []).extend([
            'health.health_check',
            'health.liveness_probe',
            'health.readiness_probe'
        ])
    
    if 'public' in registered_blueprints:
        # Public blueprint specific configuration
        logger.info("Configuring Public blueprint integration")
    
    if 'admin' in registered_blueprints:
        # Admin blueprint specific configuration
        logger.info("Configuring Admin blueprint integration")
    
    # Store blueprint registration status in app config for runtime access
    app.config['REGISTERED_BLUEPRINTS'] = registered_blueprints
    app.config['BLUEPRINT_REGISTRATION_RESULTS'] = registration_results
    
    logger.info("Blueprint integration configuration completed")


def get_blueprint_status(app: Flask = None) -> Dict[str, Any]:
    """
    Get comprehensive status of all blueprints
    
    Args:
        app: Optional Flask application instance (uses current_app if not provided)
        
    Returns:
        Dictionary containing detailed blueprint status information
    """
    if app is None:
        app = current_app
    
    status_info = {
        'availability': validate_blueprint_availability(),
        'registration_status': {},
        'registered_blueprints': app.config.get('REGISTERED_BLUEPRINTS', []),
        'registration_results': app.config.get('BLUEPRINT_REGISTRATION_RESULTS', {}),
        'blueprint_registry': {}
    }
    
    # Collect registration status from registry
    for name, blueprint_info in BLUEPRINT_REGISTRY.items():
        status_info['registration_status'][name] = {
            'registered': blueprint_info.registered,
            'registration_error': blueprint_info.registration_error,
            'required': blueprint_info.required,
            'url_prefix': blueprint_info.url_prefix,
            'description': blueprint_info.description,
            'dependencies': blueprint_info.dependencies
        }
        
        status_info['blueprint_registry'][name] = {
            'name': blueprint_info.name,
            'url_prefix': blueprint_info.url_prefix,
            'description': blueprint_info.description,
            'required': blueprint_info.required,
            'dependencies': blueprint_info.dependencies
        }
    
    return status_info


def get_registered_blueprint_urls(app: Flask = None) -> Dict[str, str]:
    """
    Get URL prefixes for all registered blueprints
    
    Args:
        app: Optional Flask application instance
        
    Returns:
        Dictionary mapping blueprint names to their URL prefixes
    """
    if app is None:
        app = current_app
    
    registered_blueprints = app.config.get('REGISTERED_BLUEPRINTS', [])
    blueprint_urls = {}
    
    for blueprint_name in registered_blueprints:
        if blueprint_name in BLUEPRINT_REGISTRY:
            blueprint_info = BLUEPRINT_REGISTRY[blueprint_name]
            blueprint_urls[blueprint_name] = blueprint_info.url_prefix
    
    return blueprint_urls


# =============================================================================
# BLUEPRINT HEALTH CHECK AND DIAGNOSTICS
# =============================================================================

def validate_blueprint_dependencies(app: Flask) -> Dict[str, List[str]]:
    """
    Validate that all blueprint dependencies are satisfied
    
    Args:
        app: Flask application instance
        
    Returns:
        Dictionary mapping blueprint names to lists of missing dependencies
    """
    missing_dependencies = {}
    
    for blueprint_name, blueprint_info in BLUEPRINT_REGISTRY.items():
        if not blueprint_info.registered:
            continue
        
        blueprint_missing = []
        for dependency in blueprint_info.dependencies:
            # Check if dependency modules are available
            try:
                __import__(f"src.{dependency}")
            except ImportError:
                blueprint_missing.append(dependency)
        
        if blueprint_missing:
            missing_dependencies[blueprint_name] = blueprint_missing
    
    return missing_dependencies


def blueprint_health_check() -> Dict[str, Any]:
    """
    Perform comprehensive health check of blueprint system
    
    Returns:
        Dictionary containing health check results
    """
    health_status = {
        'overall_status': 'healthy',
        'timestamp': str(datetime.now()),
        'blueprint_count': len(BLUEPRINT_REGISTRY),
        'registered_count': sum(1 for info in BLUEPRINT_REGISTRY.values() if info.registered),
        'required_blueprints_registered': True,
        'issues': []
    }
    
    # Check required blueprints
    required_missing = []
    for name, blueprint_info in BLUEPRINT_REGISTRY.items():
        if blueprint_info.required and not blueprint_info.registered:
            required_missing.append(name)
    
    if required_missing:
        health_status['overall_status'] = 'unhealthy'
        health_status['required_blueprints_registered'] = False
        health_status['issues'].append(f"Required blueprints not registered: {', '.join(required_missing)}")
    
    # Check for registration errors
    registration_errors = []
    for name, blueprint_info in BLUEPRINT_REGISTRY.items():
        if blueprint_info.registration_error:
            registration_errors.append(f"{name}: {blueprint_info.registration_error}")
    
    if registration_errors:
        if health_status['overall_status'] == 'healthy':
            health_status['overall_status'] = 'degraded'
        health_status['issues'].extend(registration_errors)
    
    return health_status


# =============================================================================
# EXPORT INTERFACE
# =============================================================================

# Export primary registration function and utility functions
__all__ = [
    # Main registration functions
    'register_all_blueprints',
    'register_blueprint_by_name',
    
    # Blueprint objects (if available)
    'api_blueprint',
    'health_blueprint', 
    'public_blueprint',
    'admin_blueprint',
    
    # Status and validation functions
    'get_blueprint_status',
    'get_registered_blueprint_urls',
    'validate_blueprint_availability',
    'check_required_blueprints',
    'validate_blueprint_dependencies',
    'blueprint_health_check',
    
    # Constants
    'BLUEPRINT_REGISTRY',
    'API_BLUEPRINT_AVAILABLE',
    'HEALTH_BLUEPRINT_AVAILABLE',
    'PUBLIC_BLUEPRINT_AVAILABLE',
    'ADMIN_BLUEPRINT_AVAILABLE'
]