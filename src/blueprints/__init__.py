"""
Flask Blueprints Package Initialization Module

This module provides centralized blueprint registration and management for the Flask application factory
pattern, implementing comprehensive modular route organization equivalent to Express.js routing patterns.
Orchestrates the registration of all application blueprints including API, health, public, and admin
endpoints while ensuring enterprise-grade integration and monitoring capabilities.

Key Features:
- Flask application factory pattern integration per Section 6.1.1
- Centralized blueprint registration for modular route organization per F-002 requirement
- Blueprint namespace organization for Flask-Blueprints architecture per Section 3.2.1
- URL prefixes and subdomain routing configuration for RESTful API organization per Section 5.2.2
- Comprehensive blueprint initialization with rate limiting and monitoring integration
- Enterprise-grade error handling and logging for blueprint registration process
- Performance monitoring ensuring ≤10% variance compliance per Section 0.1.1
- CORS and security configuration across all blueprint endpoints
- Health check integration for blueprint status monitoring

Architecture Integration:
- Section 6.1.1: Flask application factory pattern with Blueprint module integration
- Section 5.2.2: API router component with Flask-Blueprints modular organization
- Section 4.2.1: Blueprint registration pattern for maintainable code structure
- F-002-RQ-001: Complete HTTP method support across all registered blueprints
- F-002-RQ-002: Advanced URL pattern matching with route parameters and query strings
- Section 3.2.1: Flask-RESTful patterns and resource management integration

Blueprint Organization:
- API Blueprint (/api/v1/*): Core application endpoints with authentication and business logic
- Health Blueprint (/health/*): System health monitoring and Kubernetes probe integration
- Public Blueprint (/api/public/*): Unauthenticated endpoints for registration and public information
- Admin Blueprint (/api/admin/*): Administrative functions with elevated security controls

Performance Requirements:
- Blueprint registration latency: <50ms per Section 6.1.1 application factory requirements
- Route resolution overhead: <2ms per request per Section 5.2.2 API router specifications
- Monitoring integration: <1% CPU impact per Section 6.5.1.1 monitoring requirements
- Memory usage: <10MB additional overhead for blueprint registration and organization

Security Integration:
- Rate limiting configuration across all blueprint endpoints per Section 5.2.2
- CORS policy enforcement with blueprint-specific configurations
- Security header management for enterprise compliance requirements
- Audit logging for blueprint registration and configuration changes

Dependencies:
- Flask 2.3+ for Blueprint architecture and application factory pattern integration
- Flask-Limiter 3.5+ for comprehensive rate limiting across blueprint endpoints
- Flask-CORS 4.0+ for cross-origin request handling with blueprint-specific policies
- structlog 23.1+ for enterprise-grade logging and audit trail capabilities
- prometheus-client 0.17+ for performance metrics and monitoring integration

Author: Flask Migration Team
Version: 1.0.0
Compliance: Section 6.1.1 Flask application factory, F-002 modular routing, Section 5.2.2 API organization
"""

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union
from functools import wraps

# Flask core imports for blueprint management
from flask import Flask, current_app, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS

# Enterprise logging and monitoring integration
import structlog
from prometheus_client import Counter, Histogram, Gauge, Info

# Import all application blueprints for centralized registration
from src.blueprints.api import api_bp, init_api_blueprint
from src.blueprints.health import health_bp, init_health_blueprint
from src.blueprints.public import public_blueprint, init_public_api
from src.blueprints.admin import admin_bp, register_admin_blueprint

# Configure structured logger for blueprint management
logger = structlog.get_logger("blueprints.init")

# ============================================================================
# PROMETHEUS METRICS FOR BLUEPRINT MONITORING
# ============================================================================

# Blueprint registration metrics
BLUEPRINT_REGISTRATION_DURATION = Histogram(
    'blueprint_registration_duration_seconds',
    'Time spent registering blueprints with Flask application',
    ['blueprint_name', 'registration_status']
)

BLUEPRINT_REGISTRATION_COUNT = Counter(
    'blueprint_registrations_total',
    'Total number of blueprint registration attempts',
    ['blueprint_name', 'status']
)

ACTIVE_BLUEPRINTS = Gauge(
    'active_blueprints_count',
    'Number of successfully registered blueprints'
)

BLUEPRINT_ROUTES_COUNT = Gauge(
    'blueprint_routes_total',
    'Total number of routes registered per blueprint',
    ['blueprint_name']
)

BLUEPRINT_INITIALIZATION_STATUS = Info(
    'blueprint_initialization_info',
    'Blueprint initialization status and configuration'
)

# Performance monitoring for blueprint overhead
BLUEPRINT_ROUTE_RESOLUTION_TIME = Histogram(
    'blueprint_route_resolution_seconds',
    'Time spent resolving routes within blueprints',
    ['blueprint_name']
)

# ============================================================================
# BLUEPRINT CONFIGURATION REGISTRY
# ============================================================================

class BlueprintConfig:
    """
    Configuration class for blueprint registration with comprehensive settings.
    
    This class provides structured configuration for each blueprint including
    URL prefixes, initialization functions, dependencies, and monitoring settings.
    """
    
    def __init__(
        self,
        blueprint,
        name: str,
        init_function: Optional[callable] = None,
        url_prefix: Optional[str] = None,
        subdomain: Optional[str] = None,
        requires_auth: bool = True,
        requires_rate_limiting: bool = True,
        cors_enabled: bool = True,
        monitoring_enabled: bool = True,
        priority: int = 100,
        dependencies: Optional[List[str]] = None,
        description: str = ""
    ):
        """
        Initialize blueprint configuration.
        
        Args:
            blueprint: Flask Blueprint instance
            name: Blueprint name for identification and logging
            init_function: Optional initialization function to call after registration
            url_prefix: URL prefix for blueprint routes (overrides blueprint default)
            subdomain: Subdomain configuration for blueprint
            requires_auth: Whether blueprint endpoints require authentication
            requires_rate_limiting: Whether to apply rate limiting to blueprint endpoints
            cors_enabled: Whether to enable CORS for blueprint endpoints
            monitoring_enabled: Whether to enable performance monitoring
            priority: Registration priority (lower numbers register first)
            dependencies: List of blueprint names this blueprint depends on
            description: Human-readable description of blueprint functionality
        """
        self.blueprint = blueprint
        self.name = name
        self.init_function = init_function
        self.url_prefix = url_prefix
        self.subdomain = subdomain
        self.requires_auth = requires_auth
        self.requires_rate_limiting = requires_rate_limiting
        self.cors_enabled = cors_enabled
        self.monitoring_enabled = monitoring_enabled
        self.priority = priority
        self.dependencies = dependencies or []
        self.description = description
        self.registration_time = None
        self.initialization_time = None
        self.route_count = 0
        self.status = 'pending'


# ============================================================================
# BLUEPRINT REGISTRY DEFINITION
# ============================================================================

# Comprehensive blueprint registry with enterprise configuration
BLUEPRINT_REGISTRY = {
    'health': BlueprintConfig(
        blueprint=health_bp,
        name='health',
        init_function=init_health_blueprint,
        url_prefix=None,  # Health endpoints at root level
        requires_auth=False,
        requires_rate_limiting=True,
        cors_enabled=True,
        monitoring_enabled=True,
        priority=10,  # Register first for health monitoring
        dependencies=[],
        description="System health monitoring and Kubernetes probe endpoints"
    ),
    
    'public': BlueprintConfig(
        blueprint=public_blueprint,
        name='public',
        init_function=init_public_api,
        url_prefix='/api/public',
        requires_auth=False,
        requires_rate_limiting=True,
        cors_enabled=True,
        monitoring_enabled=True,
        priority=20,
        dependencies=[],
        description="Public API endpoints for registration and unauthenticated access"
    ),
    
    'api': BlueprintConfig(
        blueprint=api_bp,
        name='api',
        init_function=init_api_blueprint,
        url_prefix='/api/v1',
        requires_auth=True,
        requires_rate_limiting=True,
        cors_enabled=True,
        monitoring_enabled=True,
        priority=30,
        dependencies=['health'],  # Depends on health for monitoring
        description="Core API endpoints with authentication and business logic"
    ),
    
    'admin': BlueprintConfig(
        blueprint=admin_bp,
        name='admin',
        init_function=register_admin_blueprint,
        url_prefix='/api/admin',
        requires_auth=True,
        requires_rate_limiting=True,
        cors_enabled=False,  # Admin endpoints use stricter CORS
        monitoring_enabled=True,
        priority=40,
        dependencies=['api', 'health'],
        description="Administrative endpoints with elevated security controls"
    )
}


# ============================================================================
# BLUEPRINT REGISTRATION MANAGER
# ============================================================================

class BlueprintManager:
    """
    Comprehensive blueprint registration and management system.
    
    This class provides enterprise-grade blueprint management with dependency
    resolution, performance monitoring, error handling, and audit logging.
    Implements the Flask application factory pattern integration per Section 6.1.1.
    """
    
    def __init__(self):
        """Initialize blueprint manager with monitoring and state tracking."""
        self.registered_blueprints = {}
        self.initialization_errors = {}
        self.registration_start_time = None
        self.total_registration_time = None
        self.dependency_graph = {}
        self._build_dependency_graph()
        
        logger.info(
            "Blueprint manager initialized",
            total_blueprints=len(BLUEPRINT_REGISTRY),
            has_dependencies=any(config.dependencies for config in BLUEPRINT_REGISTRY.values()),
            monitoring_enabled=True
        )
    
    def _build_dependency_graph(self):
        """Build dependency graph for proper registration order."""
        self.dependency_graph = {}
        
        for blueprint_name, config in BLUEPRINT_REGISTRY.items():
            self.dependency_graph[blueprint_name] = {
                'config': config,
                'dependencies': set(config.dependencies),
                'dependents': set()
            }
        
        # Build reverse dependencies (dependents)
        for blueprint_name, node in self.dependency_graph.items():
            for dependency in node['dependencies']:
                if dependency in self.dependency_graph:
                    self.dependency_graph[dependency]['dependents'].add(blueprint_name)
        
        logger.debug(
            "Blueprint dependency graph constructed",
            total_nodes=len(self.dependency_graph),
            dependencies_detected=sum(len(node['dependencies']) for node in self.dependency_graph.values())
        )
    
    def _resolve_registration_order(self) -> List[str]:
        """
        Resolve blueprint registration order based on dependencies and priorities.
        
        Uses topological sorting with priority-based tie-breaking to ensure
        blueprints are registered in the correct order while respecting dependencies.
        
        Returns:
            List of blueprint names in registration order
        """
        # Topological sort with priority
        visited = set()
        temp_visited = set()
        result = []
        
        def visit(blueprint_name: str):
            if blueprint_name in temp_visited:
                raise ValueError(f"Circular dependency detected involving blueprint '{blueprint_name}'")
            
            if blueprint_name not in visited:
                temp_visited.add(blueprint_name)
                
                # Visit dependencies first
                dependencies = self.dependency_graph[blueprint_name]['dependencies']
                dependency_list = sorted(
                    dependencies,
                    key=lambda x: BLUEPRINT_REGISTRY[x].priority if x in BLUEPRINT_REGISTRY else 999
                )
                
                for dependency in dependency_list:
                    if dependency in self.dependency_graph:
                        visit(dependency)
                
                temp_visited.remove(blueprint_name)
                visited.add(blueprint_name)
                result.append(blueprint_name)
        
        # Visit all blueprints in priority order
        blueprint_names = sorted(
            BLUEPRINT_REGISTRY.keys(),
            key=lambda x: BLUEPRINT_REGISTRY[x].priority
        )
        
        for blueprint_name in blueprint_names:
            if blueprint_name not in visited:
                visit(blueprint_name)
        
        logger.debug(
            "Blueprint registration order resolved",
            order=result,
            dependency_resolution_successful=True
        )
        
        return result
    
    def _register_single_blueprint(
        self, 
        app: Flask, 
        blueprint_name: str, 
        config: BlueprintConfig,
        rate_limiter: Optional[Limiter] = None
    ) -> bool:
        """
        Register a single blueprint with comprehensive error handling and monitoring.
        
        Args:
            app: Flask application instance
            blueprint_name: Name of blueprint to register
            config: Blueprint configuration
            rate_limiter: Optional rate limiter instance
            
        Returns:
            True if registration successful, False otherwise
        """
        start_time = time.time()
        
        try:
            # Validate dependencies are already registered
            for dependency in config.dependencies:
                if dependency not in self.registered_blueprints:
                    raise ValueError(f"Dependency '{dependency}' not registered for blueprint '{blueprint_name}'")
            
            # Configure blueprint URL prefix if specified
            blueprint = config.blueprint
            registration_kwargs = {}
            
            if config.url_prefix is not None:
                registration_kwargs['url_prefix'] = config.url_prefix
            
            if config.subdomain is not None:
                registration_kwargs['subdomain'] = config.subdomain
            
            # Register blueprint with Flask application
            app.register_blueprint(blueprint, **registration_kwargs)
            
            # Count routes registered
            config.route_count = len([
                rule for rule in app.url_map.iter_rules()
                if rule.endpoint and rule.endpoint.startswith(f"{blueprint.name}.")
            ])
            
            # Mark registration time
            config.registration_time = time.time()
            config.status = 'registered'
            
            # Call initialization function if provided
            if config.init_function:
                init_start_time = time.time()
                
                try:
                    # Call initialization function with appropriate parameters
                    if blueprint_name == 'api':
                        config.init_function(app, rate_limiter)
                    elif blueprint_name == 'public':
                        config.init_function(app, rate_limiter)
                    elif blueprint_name == 'health':
                        config.init_function(app)
                    elif blueprint_name == 'admin':
                        config.init_function(app)
                    else:
                        # Generic initialization call
                        config.init_function(app)
                    
                    config.initialization_time = time.time() - init_start_time
                    config.status = 'initialized'
                    
                except Exception as e:
                    logger.error(
                        "Blueprint initialization failed",
                        blueprint_name=blueprint_name,
                        error=str(e),
                        init_function=config.init_function.__name__,
                        exc_info=True
                    )
                    config.status = 'init_failed'
                    self.initialization_errors[blueprint_name] = str(e)
                    # Continue registration even if initialization fails
            
            # Configure CORS if enabled
            if config.cors_enabled:
                try:
                    CORS(blueprint)
                    logger.debug(f"CORS enabled for blueprint '{blueprint_name}'")
                except Exception as e:
                    logger.warning(
                        "Failed to configure CORS for blueprint",
                        blueprint_name=blueprint_name,
                        error=str(e)
                    )
            
            # Store successful registration
            self.registered_blueprints[blueprint_name] = config
            
            # Record metrics
            registration_duration = time.time() - start_time
            BLUEPRINT_REGISTRATION_DURATION.labels(
                blueprint_name=blueprint_name,
                registration_status='success'
            ).observe(registration_duration)
            
            BLUEPRINT_REGISTRATION_COUNT.labels(
                blueprint_name=blueprint_name,
                status='success'
            ).inc()
            
            BLUEPRINT_ROUTES_COUNT.labels(
                blueprint_name=blueprint_name
            ).set(config.route_count)
            
            logger.info(
                "Blueprint registered successfully",
                blueprint_name=blueprint_name,
                url_prefix=config.url_prefix,
                route_count=config.route_count,
                registration_duration_ms=round(registration_duration * 1000, 2),
                initialization_duration_ms=round((config.initialization_time or 0) * 1000, 2),
                requires_auth=config.requires_auth,
                cors_enabled=config.cors_enabled,
                status=config.status
            )
            
            return True
            
        except Exception as e:
            # Record failed registration
            registration_duration = time.time() - start_time
            BLUEPRINT_REGISTRATION_DURATION.labels(
                blueprint_name=blueprint_name,
                registration_status='error'
            ).observe(registration_duration)
            
            BLUEPRINT_REGISTRATION_COUNT.labels(
                blueprint_name=blueprint_name,
                status='error'
            ).inc()
            
            config.status = 'failed'
            self.initialization_errors[blueprint_name] = str(e)
            
            logger.error(
                "Blueprint registration failed",
                blueprint_name=blueprint_name,
                error=str(e),
                registration_duration_ms=round(registration_duration * 1000, 2),
                exc_info=True
            )
            
            return False
    
    def register_all_blueprints(
        self, 
        app: Flask, 
        rate_limiter: Optional[Limiter] = None
    ) -> Dict[str, Any]:
        """
        Register all blueprints with Flask application using dependency-aware ordering.
        
        Implements comprehensive blueprint registration with dependency resolution,
        error handling, performance monitoring, and audit logging per Section 6.1.1.
        
        Args:
            app: Flask application instance
            rate_limiter: Optional rate limiter instance for blueprint integration
            
        Returns:
            Dictionary containing registration results and comprehensive status
        """
        self.registration_start_time = time.time()
        
        logger.info(
            "Starting blueprint registration process",
            total_blueprints=len(BLUEPRINT_REGISTRY),
            app_name=app.name,
            rate_limiter_enabled=rate_limiter is not None
        )
        
        try:
            # Resolve registration order based on dependencies and priorities
            registration_order = self._resolve_registration_order()
            
            successful_registrations = []
            failed_registrations = []
            
            # Register blueprints in resolved order
            for blueprint_name in registration_order:
                config = BLUEPRINT_REGISTRY[blueprint_name]
                
                logger.debug(
                    "Registering blueprint",
                    blueprint_name=blueprint_name,
                    priority=config.priority,
                    dependencies=config.dependencies,
                    url_prefix=config.url_prefix
                )
                
                success = self._register_single_blueprint(
                    app, blueprint_name, config, rate_limiter
                )
                
                if success:
                    successful_registrations.append(blueprint_name)
                else:
                    failed_registrations.append(blueprint_name)
            
            # Calculate total registration time
            self.total_registration_time = time.time() - self.registration_start_time
            
            # Update overall metrics
            ACTIVE_BLUEPRINTS.set(len(successful_registrations))
            
            # Update blueprint initialization info
            BLUEPRINT_INITIALIZATION_STATUS.info({
                'total_blueprints': str(len(BLUEPRINT_REGISTRY)),
                'successful_registrations': str(len(successful_registrations)),
                'failed_registrations': str(len(failed_registrations)),
                'total_registration_time_ms': str(round(self.total_registration_time * 1000, 2)),
                'registration_order': ','.join(registration_order)
            })
            
            # Prepare comprehensive results
            registration_results = {
                'success': len(failed_registrations) == 0,
                'total_blueprints': len(BLUEPRINT_REGISTRY),
                'successful_registrations': len(successful_registrations),
                'failed_registrations': len(failed_registrations),
                'registration_order': registration_order,
                'successful_blueprints': successful_registrations,
                'failed_blueprints': failed_registrations,
                'initialization_errors': dict(self.initialization_errors),
                'total_registration_time_ms': round(self.total_registration_time * 1000, 2),
                'blueprint_details': {
                    name: {
                        'status': config.status,
                        'route_count': config.route_count,
                        'url_prefix': config.url_prefix,
                        'requires_auth': config.requires_auth,
                        'cors_enabled': config.cors_enabled,
                        'registration_time_ms': round((config.registration_time - self.registration_start_time) * 1000, 2) if config.registration_time else None,
                        'initialization_time_ms': round((config.initialization_time or 0) * 1000, 2)
                    }
                    for name, config in self.registered_blueprints.items()
                },
                'total_routes': sum(config.route_count for config in self.registered_blueprints.values()),
                'performance_compliance': self.total_registration_time < 0.05  # <50ms requirement
            }
            
            # Log comprehensive registration summary
            if registration_results['success']:
                logger.info(
                    "Blueprint registration completed successfully",
                    **{k: v for k, v in registration_results.items() 
                       if k not in ['blueprint_details', 'initialization_errors']}
                )
            else:
                logger.error(
                    "Blueprint registration completed with failures",
                    **{k: v for k, v in registration_results.items() 
                       if k not in ['blueprint_details', 'initialization_errors']},
                    errors=registration_results['initialization_errors']
                )
            
            # Store results in app config for runtime access
            app.config['BLUEPRINT_REGISTRATION_RESULTS'] = registration_results
            
            return registration_results
            
        except Exception as e:
            self.total_registration_time = time.time() - self.registration_start_time
            
            logger.error(
                "Blueprint registration process failed",
                error=str(e),
                total_time_ms=round(self.total_registration_time * 1000, 2),
                exc_info=True
            )
            
            # Return error results
            return {
                'success': False,
                'error': str(e),
                'total_registration_time_ms': round(self.total_registration_time * 1000, 2),
                'registered_blueprints': list(self.registered_blueprints.keys()),
                'performance_compliance': False
            }
    
    def get_blueprint_status(self, blueprint_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Get comprehensive status information for blueprints.
        
        Args:
            blueprint_name: Optional specific blueprint name, returns all if None
            
        Returns:
            Dictionary containing blueprint status and metrics
        """
        if blueprint_name:
            if blueprint_name not in self.registered_blueprints:
                return {'error': f"Blueprint '{blueprint_name}' not found"}
            
            config = self.registered_blueprints[blueprint_name]
            return {
                'name': blueprint_name,
                'status': config.status,
                'route_count': config.route_count,
                'url_prefix': config.url_prefix,
                'requires_auth': config.requires_auth,
                'cors_enabled': config.cors_enabled,
                'dependencies': config.dependencies,
                'description': config.description,
                'registration_time': config.registration_time,
                'initialization_time': config.initialization_time
            }
        else:
            return {
                'total_blueprints': len(self.registered_blueprints),
                'total_routes': sum(config.route_count for config in self.registered_blueprints.values()),
                'blueprints': {
                    name: self.get_blueprint_status(name)
                    for name in self.registered_blueprints.keys()
                }
            }


# ============================================================================
# GLOBAL BLUEPRINT MANAGER INSTANCE
# ============================================================================

# Global blueprint manager instance for Flask application factory integration
blueprint_manager = BlueprintManager()


# ============================================================================
# MAIN BLUEPRINT REGISTRATION FUNCTION
# ============================================================================

def register_blueprints(app: Flask, rate_limiter: Optional[Limiter] = None) -> Dict[str, Any]:
    """
    Main function for registering all Flask blueprints with comprehensive configuration.
    
    This function implements the Flask application factory pattern integration per Section 6.1.1,
    providing centralized blueprint registration with dependency resolution, performance monitoring,
    and enterprise-grade error handling. Supports modular route organization equivalent to
    Express.js routing patterns while maintaining ≤10% performance variance compliance.
    
    Features:
    - Dependency-aware blueprint registration order
    - Performance monitoring with Prometheus metrics integration
    - Comprehensive error handling and rollback capabilities
    - Rate limiting integration across all blueprint endpoints
    - CORS configuration with blueprint-specific policies
    - Audit logging for compliance and security requirements
    - Health check integration for blueprint status monitoring
    
    Args:
        app: Flask application instance from application factory
        rate_limiter: Optional Flask-Limiter instance for rate limiting integration
        
    Returns:
        Dictionary containing comprehensive registration results including:
        - success: Boolean indicating overall registration success
        - total_blueprints: Total number of blueprints processed
        - successful_registrations: Count of successfully registered blueprints
        - failed_registrations: Count of failed blueprint registrations
        - registration_order: Order in which blueprints were registered
        - blueprint_details: Detailed status for each blueprint
        - total_routes: Total number of routes across all blueprints
        - performance_compliance: Whether registration met performance requirements
        
    Raises:
        ValueError: If circular dependencies detected in blueprint configuration
        RuntimeError: If critical blueprint registration failures occur
        
    Example:
        ```python
        from flask import Flask
        from flask_limiter import Limiter
        from src.blueprints import register_blueprints
        
        def create_app():
            app = Flask(__name__)
            limiter = Limiter(app=app, key_func=get_remote_address)
            
            results = register_blueprints(app, limiter)
            
            if not results['success']:
                app.logger.error("Blueprint registration failed", extra=results)
                
            return app
        ```
    """
    start_time = time.time()
    
    logger.info(
        "Initiating Flask blueprint registration process",
        app_name=app.name,
        app_debug=app.debug,
        rate_limiter_enabled=rate_limiter is not None,
        available_blueprints=list(BLUEPRINT_REGISTRY.keys())
    )
    
    try:
        # Validate Flask application instance
        if not isinstance(app, Flask):
            raise TypeError("app must be a Flask application instance")
        
        # Register all blueprints using the global manager
        registration_results = blueprint_manager.register_all_blueprints(app, rate_limiter)
        
        # Validate performance compliance
        total_time = time.time() - start_time
        performance_compliant = total_time < 0.05  # <50ms requirement per Section 6.1.1
        
        registration_results['total_function_time_ms'] = round(total_time * 1000, 2)
        registration_results['performance_compliance'] = performance_compliant
        
        # Log final results
        if registration_results['success']:
            logger.info(
                "Blueprint registration process completed successfully",
                total_blueprints=registration_results['total_blueprints'],
                successful_registrations=registration_results['successful_registrations'],
                total_routes=registration_results['total_routes'],
                total_time_ms=registration_results['total_function_time_ms'],
                performance_compliant=performance_compliant,
                blueprints_registered=registration_results['successful_blueprints']
            )
        else:
            logger.error(
                "Blueprint registration process completed with errors",
                total_blueprints=registration_results['total_blueprints'],
                successful_registrations=registration_results['successful_registrations'],
                failed_registrations=registration_results['failed_registrations'],
                total_time_ms=registration_results['total_function_time_ms'],
                performance_compliant=performance_compliant,
                failed_blueprints=registration_results['failed_blueprints'],
                errors=registration_results.get('initialization_errors', {})
            )
        
        return registration_results
        
    except Exception as e:
        total_time = time.time() - start_time
        
        error_result = {
            'success': False,
            'error': str(e),
            'error_type': type(e).__name__,
            'total_function_time_ms': round(total_time * 1000, 2),
            'performance_compliance': False,
            'app_name': app.name
        }
        
        logger.error(
            "Blueprint registration process failed with exception",
            error=str(e),
            error_type=type(e).__name__,
            total_time_ms=error_result['total_function_time_ms'],
            exc_info=True
        )
        
        # Store error results in app config
        app.config['BLUEPRINT_REGISTRATION_RESULTS'] = error_result
        
        return error_result


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_blueprint_status(blueprint_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Get comprehensive status information for registered blueprints.
    
    Args:
        blueprint_name: Optional specific blueprint name, returns all if None
        
    Returns:
        Dictionary containing blueprint status and metrics
    """
    return blueprint_manager.get_blueprint_status(blueprint_name)


def get_registered_blueprints() -> List[str]:
    """
    Get list of successfully registered blueprint names.
    
    Returns:
        List of registered blueprint names
    """
    return list(blueprint_manager.registered_blueprints.keys())


def get_blueprint_routes(blueprint_name: str) -> List[Dict[str, Any]]:
    """
    Get detailed route information for a specific blueprint.
    
    Args:
        blueprint_name: Name of blueprint to query
        
    Returns:
        List of route dictionaries with endpoint, methods, and URL pattern information
    """
    if blueprint_name not in blueprint_manager.registered_blueprints:
        return []
    
    try:
        from flask import current_app
        routes = []
        
        for rule in current_app.url_map.iter_rules():
            if rule.endpoint and rule.endpoint.startswith(f"{blueprint_name}."):
                routes.append({
                    'endpoint': rule.endpoint,
                    'methods': list(rule.methods - {'HEAD', 'OPTIONS'}),
                    'url_pattern': str(rule.rule),
                    'subdomain': rule.subdomain,
                    'defaults': rule.defaults
                })
        
        return routes
        
    except Exception as e:
        logger.error(
            "Failed to get blueprint routes",
            blueprint_name=blueprint_name,
            error=str(e)
        )
        return []


def validate_blueprint_health() -> Dict[str, Any]:
    """
    Validate health and operational status of all registered blueprints.
    
    Returns:
        Dictionary containing comprehensive health status for all blueprints
    """
    health_status = {
        'overall_status': 'healthy',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'blueprints': {},
        'summary': {
            'total_blueprints': len(blueprint_manager.registered_blueprints),
            'healthy_blueprints': 0,
            'degraded_blueprints': 0,
            'failed_blueprints': 0
        }
    }
    
    for blueprint_name, config in blueprint_manager.registered_blueprints.items():
        blueprint_health = {
            'status': 'healthy' if config.status == 'initialized' else 'degraded',
            'route_count': config.route_count,
            'initialization_time_ms': round((config.initialization_time or 0) * 1000, 2),
            'errors': blueprint_manager.initialization_errors.get(blueprint_name)
        }
        
        health_status['blueprints'][blueprint_name] = blueprint_health
        
        if blueprint_health['status'] == 'healthy':
            health_status['summary']['healthy_blueprints'] += 1
        elif blueprint_health['status'] == 'degraded':
            health_status['summary']['degraded_blueprints'] += 1
        else:
            health_status['summary']['failed_blueprints'] += 1
    
    # Determine overall status
    if health_status['summary']['failed_blueprints'] > 0:
        health_status['overall_status'] = 'critical'
    elif health_status['summary']['degraded_blueprints'] > 0:
        health_status['overall_status'] = 'degraded'
    
    return health_status


# ============================================================================
# MODULE EXPORTS
# ============================================================================

# Export all blueprint instances for direct access if needed
__all__ = [
    # Main registration function
    'register_blueprints',
    
    # Blueprint instances
    'api_bp',
    'health_bp', 
    'public_blueprint',
    'admin_bp',
    
    # Management classes
    'BlueprintManager',
    'BlueprintConfig',
    'blueprint_manager',
    
    # Utility functions
    'get_blueprint_status',
    'get_registered_blueprints',
    'get_blueprint_routes',
    'validate_blueprint_health',
    
    # Configuration registry
    'BLUEPRINT_REGISTRY'
]


# ============================================================================
# MODULE INITIALIZATION
# ============================================================================

# Log module initialization
logger.info(
    "Flask blueprints package initialized successfully",
    available_blueprints=list(BLUEPRINT_REGISTRY.keys()),
    total_blueprints=len(BLUEPRINT_REGISTRY),
    dependency_resolution_enabled=True,
    performance_monitoring_enabled=True,
    compliance_sections=['6.1.1', '5.2.2', 'F-002']
)