"""
Flask Application Factory Implementation

Central WSGI application entry point implementing comprehensive enterprise initialization
with Flask 2.3+ application factory pattern per Section 6.1.1. Orchestrates Blueprint
registration, middleware stack configuration, database connections (PyMongo/Motor),
Redis caching, authentication setup, and monitoring integration for production-grade
Flask application deployment.

This module serves as the primary orchestration point implementing:
- Flask application factory pattern with centralized extension initialization
- Blueprint registration for modular route organization per Section 5.2.2
- PyMongo 4.5+ and Motor 3.3+ dual database connection architecture
- redis-py 5.0+ connection pooling for distributed caching and sessions
- PyJWT 2.8+ and Flask-JWT-Extended authentication with Auth0 integration
- Flask-CORS 4.0+ cross-origin request handling per Section 3.2.1
- Flask-Limiter 3.5+ rate limiting protection per Section 5.2.2
- Flask-Talisman security headers as helmet middleware replacement
- structlog 23.1+ enterprise structured logging per Section 6.1.1
- prometheus-client 0.17+ metrics collection and APM integration
- Comprehensive error handlers per Section 4.2.3 error handling flows

Performance Requirements:
- System must support ≤10% performance variance from Node.js baseline per Section 0.1.1
- WSGI server deployment support for horizontal scaling per Section 6.1.3
- Enterprise APM and monitoring systems integration per Section 0.1.4

Architecture Integration:
- Flask Blueprint modular organization equivalent to Express.js patterns
- Comprehensive middleware pipeline using Flask decorators and extensions
- Database connection pooling with PyMongo/Motor dual architecture
- Redis-backed session management and application caching
- Circuit breaker patterns for external service resilience
- Health check endpoints for Kubernetes and load balancer integration

Usage:
    # Development server
    export FLASK_ENV=development
    python -m flask run
    
    # Production WSGI deployment
    gunicorn --config gunicorn.conf.py "src.app:create_app()"
    
    # Application factory usage
    from src.app import create_app
    app = create_app()

Author: Flask Migration Team
Version: 1.0.0
Compliance: SOC 2, ISO 27001, OWASP Top 10
Dependencies: Flask 2.3+, PyMongo 4.5+, Motor 3.3+, redis-py 5.0+, structlog 23.1+
"""

import os
import sys
import time
import logging
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timedelta
from pathlib import Path

# Flask core imports
from flask import Flask, request, jsonify, g, current_app
from flask.logging import default_handler
from werkzeug.exceptions import HTTPException, InternalServerError
from werkzeug.middleware.proxy_fix import ProxyFix

# Import configuration management
from src.config.settings import (
    ConfigFactory,
    create_config_for_environment,
    BaseConfig,
    DevelopmentConfig,
    TestingConfig,
    StagingConfig,
    ProductionConfig
)

# Import component initialization functions
from src.auth import init_auth_module, get_auth_health_status, cleanup_auth_module
from src.blueprints import register_all_blueprints, get_blueprint_status
from src.data import init_database_app, get_database_manager
from src.cache import init_cache, get_cache_manager, is_cache_available
from src.monitoring import init_monitoring, get_monitoring_stack

# Import specific Flask extensions for comprehensive initialization
try:
    from flask_cors import CORS
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    from flask_talisman import Talisman
    import structlog
    from prometheus_client import generate_latest, CONTENT_TYPE_LATEST, CollectorRegistry
    
    # Additional enterprise libraries
    import redis
    from pymongo.errors import PyMongoError
    from redis.exceptions import RedisError
    
except ImportError as e:
    print(f"Critical dependency import failed: {e}")
    print("Please ensure all required packages are installed:")
    print("pip install flask flask-cors flask-limiter flask-talisman")
    print("pip install structlog prometheus-client redis pymongo motor")
    sys.exit(1)

# Configure structured logging for application factory
logger = structlog.get_logger(__name__)

# Application factory metadata
__version__ = "1.0.0"
__author__ = "Flask Migration Team"


class FlaskApplicationFactory:
    """
    Enterprise Flask application factory implementing comprehensive initialization
    with centralized extension management, monitoring integration, and production
    deployment patterns per Section 6.1.1 Flask application factory pattern.
    
    This factory orchestrates the creation and configuration of production-ready
    Flask applications with complete observability, security, and scalability
    features required for enterprise deployment environments.
    """
    
    def __init__(self):
        """Initialize application factory with default settings."""
        self.instance_created = False
        self.creation_timestamp = None
        self.initialization_metrics = {
            'config_load_time': 0.0,
            'auth_init_time': 0.0,
            'database_init_time': 0.0,
            'cache_init_time': 0.0,
            'monitoring_init_time': 0.0,
            'blueprint_registration_time': 0.0,
            'extension_init_time': 0.0,
            'total_creation_time': 0.0
        }
        
    def create_application(
        self,
        config_name: Optional[str] = None,
        instance_relative_config: bool = False,
        **config_overrides
    ) -> Flask:
        """
        Create and configure Flask application with comprehensive enterprise features.
        
        Implements Section 6.1.1 Flask application factory pattern with centralized
        extension initialization, Section 6.5.1 comprehensive observability capabilities,
        and Section 3.2.1 core web framework integration.
        
        Args:
            config_name: Configuration environment name (development, testing, staging, production)
            instance_relative_config: Enable instance-relative configuration loading
            **config_overrides: Additional configuration parameter overrides
            
        Returns:
            Flask: Fully configured Flask application instance
            
        Raises:
            RuntimeError: If application creation fails
            ImportError: If required dependencies are missing
        """
        creation_start_time = time.time()
        
        try:
            # Create base Flask application instance
            app = Flask(
                __name__.split('.')[0],  # src
                instance_relative_config=instance_relative_config,
                static_folder='static',
                template_folder='templates'
            )
            
            logger.info(
                "Flask application instance created",
                app_name=app.name,
                config_name=config_name,
                instance_relative=instance_relative_config,
                python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
            )
            
            # Initialize comprehensive application configuration
            self._configure_application(app, config_name, **config_overrides)
            
            # Configure reverse proxy integration for production deployment
            self._configure_reverse_proxy(app)
            
            # Initialize Flask extensions with enterprise features
            self._initialize_flask_extensions(app)
            
            # Initialize authentication and security systems
            self._initialize_authentication(app)
            
            # Initialize database connectivity (PyMongo and Motor)
            self._initialize_database_layer(app)
            
            # Initialize caching and session management
            self._initialize_caching_layer(app)
            
            # Initialize comprehensive monitoring and observability
            self._initialize_monitoring_stack(app)
            
            # Register all application blueprints
            self._register_application_blueprints(app)
            
            # Configure comprehensive error handlers
            self._configure_error_handlers(app)
            
            # Configure application middleware pipeline
            self._configure_middleware_pipeline(app)
            
            # Configure health check and metrics endpoints
            self._configure_health_and_metrics(app)
            
            # Perform final application validation
            self._validate_application_configuration(app)
            
            # Record creation metrics
            self.initialization_metrics['total_creation_time'] = time.time() - creation_start_time
            self.instance_created = True
            self.creation_timestamp = datetime.utcnow()
            
            # Log comprehensive application creation summary
            self._log_application_creation_summary(app)
            
            return app
            
        except Exception as e:
            logger.error(
                "Flask application creation failed",
                error=str(e),
                error_type=type(e).__name__,
                config_name=config_name,
                creation_time_ms=round((time.time() - creation_start_time) * 1000, 2)
            )
            raise RuntimeError(f"Flask application factory failed: {str(e)}") from e
    
    def _configure_application(
        self,
        app: Flask,
        config_name: Optional[str],
        **config_overrides
    ) -> None:
        """
        Configure Flask application with environment-specific settings.
        
        Args:
            app: Flask application instance
            config_name: Environment configuration name
            **config_overrides: Configuration overrides
        """
        config_start_time = time.time()
        
        try:
            # Determine configuration environment
            environment = config_name or os.getenv('FLASK_ENV', 'development')
            
            # Load comprehensive configuration
            config_instance = create_config_for_environment(environment)
            app.config.from_object(config_instance)
            
            # Apply configuration overrides
            if config_overrides:
                app.config.update(config_overrides)
                logger.info(
                    "Configuration overrides applied",
                    overrides=list(config_overrides.keys()),
                    environment=environment
                )
            
            # Store configuration metadata in app context
            app.config.update({
                'APP_CREATION_TIMESTAMP': self.creation_timestamp or datetime.utcnow(),
                'APP_FACTORY_VERSION': __version__,
                'ENVIRONMENT': environment,
                'CONFIG_CLASS': config_instance.__class__.__name__
            })
            
            self.initialization_metrics['config_load_time'] = time.time() - config_start_time
            
            logger.info(
                "Application configuration loaded",
                environment=environment,
                config_class=config_instance.__class__.__name__,
                debug_mode=app.config.get('DEBUG', False),
                testing_mode=app.config.get('TESTING', False),
                load_time_ms=round(self.initialization_metrics['config_load_time'] * 1000, 2)
            )
            
        except Exception as e:
            logger.error(
                "Application configuration failed",
                error=str(e),
                config_name=config_name
            )
            raise
    
    def _configure_reverse_proxy(self, app: Flask) -> None:
        """
        Configure reverse proxy support for production deployment.
        
        Args:
            app: Flask application instance
        """
        try:
            # Configure ProxyFix for production deployment behind reverse proxy
            if app.config.get('FLASK_ENV') == 'production' or app.config.get('PROXY_FIX_ENABLED', False):
                app.wsgi_app = ProxyFix(
                    app.wsgi_app,
                    x_for=int(app.config.get('PROXY_FIX_X_FOR', 1)),
                    x_proto=int(app.config.get('PROXY_FIX_X_PROTO', 1)),
                    x_host=int(app.config.get('PROXY_FIX_X_HOST', 1)),
                    x_prefix=int(app.config.get('PROXY_FIX_X_PREFIX', 1))
                )
                
                logger.info("Reverse proxy configuration applied")
            
        except Exception as e:
            logger.warning(
                "Reverse proxy configuration failed",
                error=str(e)
            )
    
    def _initialize_flask_extensions(self, app: Flask) -> None:
        """
        Initialize Flask extensions with enterprise configuration.
        
        Args:
            app: Flask application instance
        """
        extension_start_time = time.time()
        
        try:
            # Initialize Flask-CORS for cross-origin request handling
            if app.config.get('CORS_ENABLED', True):
                CORS(
                    app,
                    origins=app.config.get('CORS_ORIGINS', ['*']),
                    methods=app.config.get('CORS_METHODS', ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']),
                    allow_headers=app.config.get('CORS_ALLOW_HEADERS', ['*']),
                    expose_headers=app.config.get('CORS_EXPOSE_HEADERS', []),
                    supports_credentials=app.config.get('CORS_SUPPORTS_CREDENTIALS', True),
                    max_age=app.config.get('CORS_MAX_AGE', 600),
                    send_wildcard=app.config.get('CORS_SEND_WILDCARD', False),
                    vary_header=app.config.get('CORS_VARY_HEADER', True)
                )
                logger.info("Flask-CORS initialized successfully")
            
            # Initialize Flask-Limiter for rate limiting protection
            if app.config.get('RATELIMIT_ENABLED', True):
                Limiter(
                    app=app,
                    key_func=get_remote_address,
                    storage_uri=app.config.get('RATELIMIT_STORAGE_URL'),
                    strategy=app.config.get('RATELIMIT_STRATEGY', 'moving-window'),
                    default_limits=[app.config.get('RATELIMIT_DEFAULT', '100 per hour')],
                    headers_enabled=app.config.get('RATELIMIT_HEADERS_ENABLED', True),
                    header_name_mapping={
                        'X-RateLimit-Reset': app.config.get('RATELIMIT_HEADER_RESET', 'X-RateLimit-Reset'),
                        'X-RateLimit-Remaining': app.config.get('RATELIMIT_HEADER_REMAINING', 'X-RateLimit-Remaining'),
                        'X-RateLimit-Limit': app.config.get('RATELIMIT_HEADER_LIMIT', 'X-RateLimit-Limit'),
                        'Retry-After': app.config.get('RATELIMIT_HEADER_RETRY_AFTER', 'Retry-After')
                    }
                )
                logger.info("Flask-Limiter rate limiting initialized successfully")
            
            # Initialize Flask-Talisman for security headers (helmet replacement)
            if app.config.get('TALISMAN_ENABLED', True):
                Talisman(
                    app,
                    force_https=app.config.get('TALISMAN_FORCE_HTTPS', True),
                    force_https_permanent=app.config.get('TALISMAN_FORCE_HTTPS_PERMANENT', True),
                    strict_transport_security=app.config.get('TALISMAN_STRICT_TRANSPORT_SECURITY', True),
                    strict_transport_security_max_age=app.config.get('TALISMAN_STRICT_TRANSPORT_SECURITY_MAX_AGE', 31536000),
                    strict_transport_security_include_subdomains=app.config.get('TALISMAN_STRICT_TRANSPORT_SECURITY_INCLUDE_SUBDOMAINS', True),
                    strict_transport_security_preload=app.config.get('TALISMAN_STRICT_TRANSPORT_SECURITY_PRELOAD', True),
                    content_security_policy=app.config.get('TALISMAN_CONTENT_SECURITY_POLICY', {}),
                    referrer_policy=app.config.get('TALISMAN_REFERRER_POLICY', 'strict-origin-when-cross-origin'),
                    feature_policy=app.config.get('TALISMAN_FEATURE_POLICY', {}),
                    session_cookie_secure=app.config.get('SESSION_COOKIE_SECURE', True),
                    session_cookie_http_only=app.config.get('SESSION_COOKIE_HTTPONLY', True),
                    session_cookie_samesite=app.config.get('SESSION_COOKIE_SAMESITE', 'Lax')
                )
                logger.info("Flask-Talisman security headers initialized successfully")
            
            self.initialization_metrics['extension_init_time'] = time.time() - extension_start_time
            
            logger.info(
                "Flask extensions initialized",
                cors_enabled=app.config.get('CORS_ENABLED', True),
                rate_limiting_enabled=app.config.get('RATELIMIT_ENABLED', True),
                security_headers_enabled=app.config.get('TALISMAN_ENABLED', True),
                init_time_ms=round(self.initialization_metrics['extension_init_time'] * 1000, 2)
            )
            
        except Exception as e:
            logger.error(
                "Flask extension initialization failed",
                error=str(e),
                error_type=type(e).__name__
            )
            raise
    
    def _initialize_authentication(self, app: Flask) -> None:
        """
        Initialize authentication and security systems.
        
        Args:
            app: Flask application instance
        """
        auth_start_time = time.time()
        
        try:
            # Initialize comprehensive authentication module
            auth_result = init_auth_module(app)
            
            # Store authentication initialization result
            app.config['AUTH_INITIALIZATION_RESULT'] = auth_result
            
            self.initialization_metrics['auth_init_time'] = time.time() - auth_start_time
            
            logger.info(
                "Authentication system initialized",
                status=auth_result.get('status', 'unknown'),
                components=auth_result.get('components', {}),
                init_time_ms=round(self.initialization_metrics['auth_init_time'] * 1000, 2)
            )
            
        except Exception as e:
            logger.error(
                "Authentication initialization failed",
                error=str(e),
                error_type=type(e).__name__
            )
            raise
    
    def _initialize_database_layer(self, app: Flask) -> None:
        """
        Initialize database connectivity with PyMongo and Motor.
        
        Args:
            app: Flask application instance
        """
        database_start_time = time.time()
        
        try:
            # Initialize comprehensive database layer
            database_manager = init_database_app(app)
            
            # Store database manager reference
            app.config['DATABASE_MANAGER'] = database_manager
            
            self.initialization_metrics['database_init_time'] = time.time() - database_start_time
            
            logger.info(
                "Database layer initialized",
                mongodb_client=database_manager.mongodb_client is not None,
                motor_client=database_manager.motor_client is not None,
                monitoring_enabled=database_manager.config.enable_monitoring,
                database_name=database_manager.config.database_name,
                init_time_ms=round(self.initialization_metrics['database_init_time'] * 1000, 2)
            )
            
        except Exception as e:
            logger.error(
                "Database initialization failed",
                error=str(e),
                error_type=type(e).__name__
            )
            raise
    
    def _initialize_caching_layer(self, app: Flask) -> None:
        """
        Initialize Redis caching and session management.
        
        Args:
            app: Flask application instance
        """
        cache_start_time = time.time()
        
        try:
            # Initialize comprehensive caching system
            cache_manager = init_cache(app)
            
            # Store cache manager reference
            app.config['CACHE_MANAGER'] = cache_manager
            
            self.initialization_metrics['cache_init_time'] = time.time() - cache_start_time
            
            logger.info(
                "Caching layer initialized",
                redis_client=cache_manager.redis_client is not None,
                response_cache=cache_manager.response_cache is not None,
                cache_available=is_cache_available(),
                init_time_ms=round(self.initialization_metrics['cache_init_time'] * 1000, 2)
            )
            
        except Exception as e:
            logger.error(
                "Cache initialization failed",
                error=str(e),
                error_type=type(e).__name__
            )
            # Cache failure is not critical - continue without caching
            app.config['CACHE_MANAGER'] = None
            logger.warning("Continuing without caching functionality")
    
    def _initialize_monitoring_stack(self, app: Flask) -> None:
        """
        Initialize comprehensive monitoring and observability stack.
        
        Args:
            app: Flask application instance
        """
        monitoring_start_time = time.time()
        
        try:
            # Initialize comprehensive monitoring stack
            monitoring_stack = init_monitoring(app)
            
            # Store monitoring stack reference
            app.config['MONITORING_STACK'] = monitoring_stack
            
            self.initialization_metrics['monitoring_init_time'] = time.time() - monitoring_start_time
            
            logger.info(
                "Monitoring stack initialized",
                logging_enabled=monitoring_stack.config.enable_logging,
                metrics_enabled=monitoring_stack.config.enable_metrics,
                health_checks_enabled=monitoring_stack.config.enable_health_checks,
                apm_enabled=monitoring_stack.config.enable_apm,
                service_name=monitoring_stack.config.service_name,
                environment=monitoring_stack.config.environment,
                init_time_ms=round(self.initialization_metrics['monitoring_init_time'] * 1000, 2)
            )
            
        except Exception as e:
            logger.error(
                "Monitoring initialization failed",
                error=str(e),
                error_type=type(e).__name__
            )
            # Monitoring failure is not critical - continue without full monitoring
            app.config['MONITORING_STACK'] = None
            logger.warning("Continuing with limited monitoring functionality")
    
    def _register_application_blueprints(self, app: Flask) -> None:
        """
        Register all application blueprints for modular route organization.
        
        Args:
            app: Flask application instance
        """
        blueprint_start_time = time.time()
        
        try:
            # Register all available blueprints
            registration_results = register_all_blueprints(
                app,
                include_optional=True,
                fail_on_missing_required=False  # Continue with partial functionality
            )
            
            # Store blueprint registration results
            app.config['BLUEPRINT_REGISTRATION_RESULTS'] = registration_results
            
            self.initialization_metrics['blueprint_registration_time'] = time.time() - blueprint_start_time
            
            # Get comprehensive blueprint status
            blueprint_status = get_blueprint_status(app)
            
            logger.info(
                "Application blueprints registered",
                registration_results=registration_results,
                registered_blueprints=blueprint_status.get('registered_blueprints', []),
                registration_time_ms=round(self.initialization_metrics['blueprint_registration_time'] * 1000, 2)
            )
            
        except Exception as e:
            logger.error(
                "Blueprint registration failed",
                error=str(e),
                error_type=type(e).__name__
            )
            # Continue with limited functionality if blueprint registration fails
            app.config['BLUEPRINT_REGISTRATION_RESULTS'] = {}
            logger.warning("Continuing with limited blueprint functionality")
    
    def _configure_error_handlers(self, app: Flask) -> None:
        """
        Configure comprehensive error handlers per Section 4.2.3.
        
        Args:
            app: Flask application instance
        """
        try:
            @app.errorhandler(400)
            def handle_bad_request(error):
                """Handle 400 Bad Request errors with structured logging."""
                logger.warning(
                    "Bad request error",
                    error_code=400,
                    error_message=str(error),
                    endpoint=request.endpoint,
                    method=request.method,
                    url=request.url,
                    remote_addr=request.remote_addr
                )
                return jsonify({
                    'error': 'Bad Request',
                    'message': 'The request was invalid or malformed',
                    'status_code': 400,
                    'timestamp': datetime.utcnow().isoformat()
                }), 400
            
            @app.errorhandler(401)
            def handle_unauthorized(error):
                """Handle 401 Unauthorized errors with security logging."""
                logger.warning(
                    "Unauthorized access attempt",
                    error_code=401,
                    error_message=str(error),
                    endpoint=request.endpoint,
                    method=request.method,
                    url=request.url,
                    remote_addr=request.remote_addr,
                    user_agent=request.headers.get('User-Agent')
                )
                return jsonify({
                    'error': 'Unauthorized',
                    'message': 'Authentication required to access this resource',
                    'status_code': 401,
                    'timestamp': datetime.utcnow().isoformat()
                }), 401
            
            @app.errorhandler(403)
            def handle_forbidden(error):
                """Handle 403 Forbidden errors with security logging."""
                logger.warning(
                    "Forbidden access attempt",
                    error_code=403,
                    error_message=str(error),
                    endpoint=request.endpoint,
                    method=request.method,
                    url=request.url,
                    remote_addr=request.remote_addr,
                    user_agent=request.headers.get('User-Agent')
                )
                return jsonify({
                    'error': 'Forbidden',
                    'message': 'Insufficient permissions to access this resource',
                    'status_code': 403,
                    'timestamp': datetime.utcnow().isoformat()
                }), 403
            
            @app.errorhandler(404)
            def handle_not_found(error):
                """Handle 404 Not Found errors."""
                logger.info(
                    "Resource not found",
                    error_code=404,
                    error_message=str(error),
                    endpoint=request.endpoint,
                    method=request.method,
                    url=request.url,
                    remote_addr=request.remote_addr
                )
                return jsonify({
                    'error': 'Not Found',
                    'message': 'The requested resource was not found',
                    'status_code': 404,
                    'timestamp': datetime.utcnow().isoformat()
                }), 404
            
            @app.errorhandler(405)
            def handle_method_not_allowed(error):
                """Handle 405 Method Not Allowed errors."""
                logger.info(
                    "Method not allowed",
                    error_code=405,
                    error_message=str(error),
                    endpoint=request.endpoint,
                    method=request.method,
                    url=request.url,
                    allowed_methods=error.valid_methods if hasattr(error, 'valid_methods') else None
                )
                return jsonify({
                    'error': 'Method Not Allowed',
                    'message': f'The {request.method} method is not allowed for this resource',
                    'status_code': 405,
                    'timestamp': datetime.utcnow().isoformat()
                }), 405
            
            @app.errorhandler(429)
            def handle_rate_limit_exceeded(error):
                """Handle 429 Too Many Requests errors from Flask-Limiter."""
                logger.warning(
                    "Rate limit exceeded",
                    error_code=429,
                    error_message=str(error),
                    endpoint=request.endpoint,
                    method=request.method,
                    url=request.url,
                    remote_addr=request.remote_addr,
                    user_agent=request.headers.get('User-Agent')
                )
                return jsonify({
                    'error': 'Too Many Requests',
                    'message': 'Rate limit exceeded. Please try again later.',
                    'status_code': 429,
                    'timestamp': datetime.utcnow().isoformat(),
                    'retry_after': getattr(error, 'retry_after', None)
                }), 429
            
            @app.errorhandler(500)
            def handle_internal_server_error(error):
                """Handle 500 Internal Server Error with comprehensive logging."""
                logger.error(
                    "Internal server error",
                    error_code=500,
                    error_message=str(error),
                    error_type=type(error).__name__,
                    endpoint=request.endpoint,
                    method=request.method,
                    url=request.url,
                    remote_addr=request.remote_addr
                )
                return jsonify({
                    'error': 'Internal Server Error',
                    'message': 'An unexpected error occurred. Please try again later.',
                    'status_code': 500,
                    'timestamp': datetime.utcnow().isoformat()
                }), 500
            
            @app.errorhandler(503)
            def handle_service_unavailable(error):
                """Handle 503 Service Unavailable errors."""
                logger.error(
                    "Service unavailable",
                    error_code=503,
                    error_message=str(error),
                    endpoint=request.endpoint,
                    method=request.method,
                    url=request.url
                )
                return jsonify({
                    'error': 'Service Unavailable',
                    'message': 'The service is temporarily unavailable. Please try again later.',
                    'status_code': 503,
                    'timestamp': datetime.utcnow().isoformat()
                }), 503
            
            # Database-specific error handlers
            @app.errorhandler(PyMongoError)
            def handle_database_error(error):
                """Handle database connection and operation errors."""
                logger.error(
                    "Database error",
                    error_message=str(error),
                    error_type=type(error).__name__,
                    endpoint=request.endpoint,
                    method=request.method
                )
                return jsonify({
                    'error': 'Database Error',
                    'message': 'A database error occurred. Please try again later.',
                    'status_code': 503,
                    'timestamp': datetime.utcnow().isoformat()
                }), 503
            
            # Cache-specific error handlers
            @app.errorhandler(RedisError)
            def handle_cache_error(error):
                """Handle Redis cache connection and operation errors."""
                logger.warning(
                    "Cache error",
                    error_message=str(error),
                    error_type=type(error).__name__,
                    endpoint=request.endpoint,
                    method=request.method
                )
                # Cache errors should not prevent application functionality
                # Continue processing without caching
                return None
            
            # Generic exception handler for unexpected errors
            @app.errorhandler(Exception)
            def handle_unexpected_error(error):
                """Handle unexpected exceptions with comprehensive logging."""
                logger.error(
                    "Unexpected error",
                    error_message=str(error),
                    error_type=type(error).__name__,
                    endpoint=request.endpoint,
                    method=request.method,
                    url=request.url,
                    remote_addr=request.remote_addr,
                    exc_info=True
                )
                return jsonify({
                    'error': 'Internal Server Error',
                    'message': 'An unexpected error occurred. Please try again later.',
                    'status_code': 500,
                    'timestamp': datetime.utcnow().isoformat()
                }), 500
            
            logger.info("Comprehensive error handlers configured successfully")
            
        except Exception as e:
            logger.error(
                "Error handler configuration failed",
                error=str(e),
                error_type=type(e).__name__
            )
            raise
    
    def _configure_middleware_pipeline(self, app: Flask) -> None:
        """
        Configure application middleware pipeline.
        
        Args:
            app: Flask application instance
        """
        try:
            @app.before_request
            def before_request_logging():
                """Log request start and set up request context."""
                g.request_start_time = time.time()
                g.request_id = request.headers.get('X-Request-ID', f'req-{int(time.time() * 1000)}')
                
                logger.info(
                    "Request started",
                    request_id=g.request_id,
                    method=request.method,
                    url=request.url,
                    remote_addr=request.remote_addr,
                    user_agent=request.headers.get('User-Agent')
                )
            
            @app.after_request
            def after_request_logging(response):
                """Log request completion and performance metrics."""
                if hasattr(g, 'request_start_time'):
                    request_duration = time.time() - g.request_start_time
                    
                    logger.info(
                        "Request completed",
                        request_id=getattr(g, 'request_id', 'unknown'),
                        method=request.method,
                        url=request.url,
                        status_code=response.status_code,
                        response_size=len(response.get_data()),
                        duration_ms=round(request_duration * 1000, 2),
                        endpoint=request.endpoint
                    )
                
                # Add standard response headers
                response.headers['X-Request-ID'] = getattr(g, 'request_id', 'unknown')
                response.headers['X-Response-Time'] = str(round(
                    (time.time() - getattr(g, 'request_start_time', time.time())) * 1000, 2
                ))
                
                return response
            
            @app.teardown_request
            def teardown_request_cleanup(exception=None):
                """Clean up request context and resources."""
                if exception:
                    logger.error(
                        "Request teardown with exception",
                        request_id=getattr(g, 'request_id', 'unknown'),
                        exception=str(exception),
                        exception_type=type(exception).__name__
                    )
                
                # Clear request-specific data
                for attr in ['request_start_time', 'request_id', 'current_user', 'auth_token']:
                    if hasattr(g, attr):
                        delattr(g, attr)
            
            logger.info("Middleware pipeline configured successfully")
            
        except Exception as e:
            logger.error(
                "Middleware pipeline configuration failed",
                error=str(e),
                error_type=type(e).__name__
            )
            raise
    
    def _configure_health_and_metrics(self, app: Flask) -> None:
        """
        Configure health check and metrics endpoints.
        
        Args:
            app: Flask application instance
        """
        try:
            @app.route('/health')
            def health_check():
                """Comprehensive application health check endpoint."""
                try:
                    health_status = {
                        'status': 'healthy',
                        'timestamp': datetime.utcnow().isoformat(),
                        'service': app.config.get('MONITORING_SERVICE_NAME', 'flask-migration-app'),
                        'version': __version__,
                        'environment': app.config.get('ENVIRONMENT', 'unknown'),
                        'uptime_seconds': time.time() - app.config.get('APP_CREATION_TIMESTAMP', time.time()).timestamp(),
                        'components': {}
                    }
                    
                    # Check authentication system health
                    try:
                        auth_health = get_auth_health_status()
                        health_status['components']['authentication'] = auth_health
                        if auth_health.get('status') != 'healthy':
                            health_status['status'] = 'degraded'
                    except Exception as e:
                        health_status['components']['authentication'] = {
                            'status': 'unhealthy',
                            'error': str(e)
                        }
                        health_status['status'] = 'degraded'
                    
                    # Check database health
                    try:
                        db_manager = get_database_manager()
                        if db_manager:
                            db_health = db_manager.get_health_status()
                            health_status['components']['database'] = db_health
                            if db_health.get('overall_status') != 'healthy':
                                health_status['status'] = 'degraded'
                        else:
                            health_status['components']['database'] = {'status': 'not_initialized'}
                    except Exception as e:
                        health_status['components']['database'] = {
                            'status': 'unhealthy',
                            'error': str(e)
                        }
                        health_status['status'] = 'degraded'
                    
                    # Check cache health
                    try:
                        cache_manager = get_cache_manager()
                        if cache_manager:
                            cache_health = cache_manager.get_health_status()
                            health_status['components']['cache'] = cache_health
                            if cache_health.get('status') != 'healthy':
                                health_status['status'] = 'degraded'
                        else:
                            health_status['components']['cache'] = {'status': 'not_initialized'}
                    except Exception as e:
                        health_status['components']['cache'] = {
                            'status': 'unhealthy',
                            'error': str(e)
                        }
                        # Cache failure is not critical
                    
                    # Check monitoring stack health
                    try:
                        monitoring_stack = get_monitoring_stack()
                        if monitoring_stack:
                            monitoring_health = monitoring_stack.get_monitoring_status()
                            health_status['components']['monitoring'] = monitoring_health
                        else:
                            health_status['components']['monitoring'] = {'status': 'not_initialized'}
                    except Exception as e:
                        health_status['components']['monitoring'] = {
                            'status': 'unhealthy',
                            'error': str(e)
                        }
                        # Monitoring failure is not critical
                    
                    status_code = 200 if health_status['status'] == 'healthy' else 503
                    return jsonify(health_status), status_code
                    
                except Exception as e:
                    logger.error("Health check endpoint error", error=str(e))
                    return jsonify({
                        'status': 'unhealthy',
                        'error': str(e),
                        'timestamp': datetime.utcnow().isoformat()
                    }), 503
            
            @app.route('/health/live')
            def liveness_probe():
                """Kubernetes liveness probe endpoint."""
                return jsonify({
                    'status': 'alive',
                    'timestamp': datetime.utcnow().isoformat()
                }), 200
            
            @app.route('/health/ready')
            def readiness_probe():
                """Kubernetes readiness probe endpoint."""
                try:
                    # Check critical dependencies
                    ready = True
                    components = {}
                    
                    # Check database connectivity
                    try:
                        db_manager = get_database_manager()
                        if db_manager and db_manager.mongodb_client:
                            # Test database connection
                            db_manager.mongodb_client.client.admin.command('ping')
                            components['database'] = 'ready'
                        else:
                            components['database'] = 'not_ready'
                            ready = False
                    except Exception:
                        components['database'] = 'not_ready'
                        ready = False
                    
                    # Check authentication system
                    try:
                        auth_health = get_auth_health_status()
                        if auth_health.get('status') == 'healthy':
                            components['authentication'] = 'ready'
                        else:
                            components['authentication'] = 'not_ready'
                            ready = False
                    except Exception:
                        components['authentication'] = 'not_ready'
                        ready = False
                    
                    status_code = 200 if ready else 503
                    return jsonify({
                        'status': 'ready' if ready else 'not_ready',
                        'components': components,
                        'timestamp': datetime.utcnow().isoformat()
                    }), status_code
                    
                except Exception as e:
                    logger.error("Readiness probe error", error=str(e))
                    return jsonify({
                        'status': 'not_ready',
                        'error': str(e),
                        'timestamp': datetime.utcnow().isoformat()
                    }), 503
            
            @app.route('/metrics')
            def metrics_endpoint():
                """Prometheus metrics endpoint."""
                try:
                    # Get Prometheus metrics
                    metrics_data = generate_latest()
                    return metrics_data, 200, {'Content-Type': CONTENT_TYPE_LATEST}
                except Exception as e:
                    logger.error("Metrics endpoint error", error=str(e))
                    return f"# Error generating metrics: {str(e)}", 500
            
            @app.route('/info')
            def application_info():
                """Application information endpoint."""
                try:
                    info = {
                        'application': app.name,
                        'version': __version__,
                        'environment': app.config.get('ENVIRONMENT', 'unknown'),
                        'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
                        'flask_version': getattr(app, '__version__', 'unknown'),
                        'creation_timestamp': app.config.get('APP_CREATION_TIMESTAMP', datetime.utcnow()).isoformat(),
                        'config_class': app.config.get('CONFIG_CLASS', 'unknown'),
                        'debug_mode': app.config.get('DEBUG', False),
                        'testing_mode': app.config.get('TESTING', False),
                        'blueprint_count': len(app.blueprints),
                        'registered_blueprints': list(app.blueprints.keys()),
                        'initialization_metrics': self.initialization_metrics
                    }
                    
                    return jsonify(info), 200
                    
                except Exception as e:
                    logger.error("Application info endpoint error", error=str(e))
                    return jsonify({
                        'error': str(e),
                        'timestamp': datetime.utcnow().isoformat()
                    }), 500
            
            logger.info("Health check and metrics endpoints configured")
            
        except Exception as e:
            logger.error(
                "Health and metrics endpoint configuration failed",
                error=str(e),
                error_type=type(e).__name__
            )
            raise
    
    def _validate_application_configuration(self, app: Flask) -> None:
        """
        Perform final application configuration validation.
        
        Args:
            app: Flask application instance
        """
        try:
            validation_results = {
                'config_validation': True,
                'extension_validation': True,
                'blueprint_validation': True,
                'security_validation': True,
                'performance_validation': True
            }
            
            # Validate critical configuration
            required_config = ['SECRET_KEY', 'FLASK_ENV']
            for config_key in required_config:
                if not app.config.get(config_key):
                    validation_results['config_validation'] = False
                    logger.error(f"Missing required configuration: {config_key}")
            
            # Validate security configuration for production
            if app.config.get('FLASK_ENV') == 'production':
                if app.config.get('SECRET_KEY') == 'dev-secret-key':
                    validation_results['security_validation'] = False
                    logger.error("Production environment requires secure SECRET_KEY")
                
                if not app.config.get('TALISMAN_ENABLED', True):
                    validation_results['security_validation'] = False
                    logger.error("Production environment requires Talisman security headers")
            
            # Validate blueprint registration
            blueprint_results = app.config.get('BLUEPRINT_REGISTRATION_RESULTS', {})
            if not blueprint_results.get('api', False) or not blueprint_results.get('health', False):
                validation_results['blueprint_validation'] = False
                logger.error("Critical blueprints not registered")
            
            # Log validation summary
            validation_passed = all(validation_results.values())
            
            logger.info(
                "Application validation completed",
                validation_passed=validation_passed,
                validation_results=validation_results
            )
            
            if not validation_passed:
                logger.warning("Application validation failed - some features may not work correctly")
            
        except Exception as e:
            logger.error(
                "Application validation failed",
                error=str(e),
                error_type=type(e).__name__
            )
    
    def _log_application_creation_summary(self, app: Flask) -> None:
        """
        Log comprehensive application creation summary.
        
        Args:
            app: Flask application instance
        """
        try:
            summary = {
                'application_name': app.name,
                'version': __version__,
                'environment': app.config.get('ENVIRONMENT', 'unknown'),
                'config_class': app.config.get('CONFIG_CLASS', 'unknown'),
                'creation_timestamp': self.creation_timestamp.isoformat() if self.creation_timestamp else 'unknown',
                'total_creation_time_ms': round(self.initialization_metrics['total_creation_time'] * 1000, 2),
                'initialization_metrics': {
                    k: round(v * 1000, 2) if isinstance(v, float) else v
                    for k, v in self.initialization_metrics.items()
                },
                'components_initialized': {
                    'authentication': bool(app.config.get('AUTH_INITIALIZATION_RESULT')),
                    'database': bool(app.config.get('DATABASE_MANAGER')),
                    'cache': bool(app.config.get('CACHE_MANAGER')),
                    'monitoring': bool(app.config.get('MONITORING_STACK')),
                    'blueprints': bool(app.config.get('BLUEPRINT_REGISTRATION_RESULTS'))
                },
                'registered_blueprints': list(app.blueprints.keys()),
                'endpoints': {
                    'health_check': '/health',
                    'liveness_probe': '/health/live',
                    'readiness_probe': '/health/ready',
                    'metrics': '/metrics',
                    'application_info': '/info'
                },
                'security_features': {
                    'cors_enabled': app.config.get('CORS_ENABLED', False),
                    'rate_limiting_enabled': app.config.get('RATELIMIT_ENABLED', False),
                    'security_headers_enabled': app.config.get('TALISMAN_ENABLED', False),
                    'csrf_protection': app.config.get('WTF_CSRF_ENABLED', False)
                },
                'performance_features': {
                    'response_caching': is_cache_available(),
                    'connection_pooling': True,
                    'async_database_support': bool(app.config.get('DATABASE_MANAGER')),
                    'monitoring_enabled': bool(app.config.get('MONITORING_STACK'))
                }
            }
            
            logger.info(
                "Flask application factory creation completed successfully",
                summary=summary
            )
            
        except Exception as e:
            logger.error(
                "Failed to log application creation summary",
                error=str(e),
                error_type=type(e).__name__
            )


# Global application factory instance
_application_factory = FlaskApplicationFactory()


def create_app(
    config_name: Optional[str] = None,
    instance_relative_config: bool = False,
    **config_overrides
) -> Flask:
    """
    Create Flask application using enterprise application factory pattern.
    
    Primary entry point for Flask application creation implementing Section 6.1.1
    Flask application factory pattern with centralized extension initialization,
    comprehensive observability capabilities, and production deployment support.
    
    This function orchestrates the complete application initialization including:
    - Environment-specific configuration loading and validation
    - Flask extension initialization (CORS, Limiter, Talisman)
    - Authentication and security system setup (PyJWT, Auth0 integration)
    - Database connectivity (PyMongo 4.5+ and Motor 3.3+ dual architecture)
    - Redis caching and session management (redis-py 5.0+)
    - Comprehensive monitoring stack (structlog, Prometheus, APM)
    - Blueprint registration for modular route organization
    - Error handling and middleware pipeline configuration
    - Health check and metrics endpoint setup
    
    Args:
        config_name: Environment configuration name (development, testing, staging, production)
        instance_relative_config: Enable instance-relative configuration loading
        **config_overrides: Additional configuration parameter overrides
        
    Returns:
        Flask: Fully configured Flask application instance ready for WSGI deployment
        
    Raises:
        RuntimeError: If application creation fails
        ImportError: If required dependencies are missing
        
    Examples:
        # Development application
        app = create_app('development')
        
        # Production application with overrides
        app = create_app('production', MONGODB_URI='mongodb://prod-server:27017/app')
        
        # Auto-detect environment from FLASK_ENV
        app = create_app()
        
        # WSGI deployment
        application = create_app('production')
    """
    global _application_factory
    
    logger.info(
        "Creating Flask application",
        config_name=config_name,
        instance_relative_config=instance_relative_config,
        config_overrides=list(config_overrides.keys()) if config_overrides else []
    )
    
    try:
        # Create application using factory
        app = _application_factory.create_application(
            config_name=config_name,
            instance_relative_config=instance_relative_config,
            **config_overrides
        )
        
        return app
        
    except Exception as e:
        logger.error(
            "Flask application creation failed",
            error=str(e),
            error_type=type(e).__name__,
            config_name=config_name
        )
        raise


def create_wsgi_application() -> Flask:
    """
    Create Flask application for WSGI server deployment.
    
    Convenience function for production WSGI deployment that auto-detects
    environment and applies production-optimized configuration.
    
    Returns:
        Flask: Production-ready Flask application for WSGI deployment
        
    Examples:
        # Gunicorn deployment
        gunicorn --config gunicorn.conf.py "src.app:create_wsgi_application()"
        
        # uWSGI deployment
        uwsgi --module src.app:create_wsgi_application() --callable app
    """
    environment = os.getenv('FLASK_ENV', 'production')
    
    logger.info(
        "Creating WSGI application",
        environment=environment,
        python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    )
    
    return create_app(config_name=environment)


def get_application_factory() -> FlaskApplicationFactory:
    """
    Get the global application factory instance.
    
    Returns:
        FlaskApplicationFactory: Global application factory instance
    """
    return _application_factory


def cleanup_application(app: Flask) -> None:
    """
    Cleanup application resources for graceful shutdown.
    
    Args:
        app: Flask application instance to cleanup
    """
    try:
        logger.info("Starting application cleanup")
        
        # Cleanup authentication module
        try:
            cleanup_auth_module()
        except Exception as e:
            logger.warning(f"Auth cleanup error: {e}")
        
        # Cleanup database connections
        try:
            db_manager = get_database_manager()
            if db_manager:
                db_manager.close()
        except Exception as e:
            logger.warning(f"Database cleanup error: {e}")
        
        # Cleanup cache connections
        try:
            cache_manager = get_cache_manager()
            if cache_manager:
                cache_manager.close()
        except Exception as e:
            logger.warning(f"Cache cleanup error: {e}")
        
        logger.info("Application cleanup completed")
        
    except Exception as e:
        logger.error(
            "Application cleanup failed",
            error=str(e),
            error_type=type(e).__name__
        )


# Export public interface for WSGI deployment and testing
__all__ = [
    'create_app',
    'create_wsgi_application',
    'FlaskApplicationFactory',
    'get_application_factory',
    'cleanup_application',
    '__version__'
]


# WSGI application instance for deployment
application = create_wsgi_application()


# Development server entry point
if __name__ == '__main__':
    # Create development application
    dev_app = create_app('development')
    
    # Run development server
    dev_app.run(
        host=dev_app.config.get('HOST', '0.0.0.0'),
        port=dev_app.config.get('PORT', 5000),
        debug=dev_app.config.get('DEBUG', True),
        threaded=True
    )