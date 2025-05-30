"""
Flask Application Factory Entry Point

This module serves as the main WSGI application entry point for the Flask application,
implementing a comprehensive application factory pattern that replaces the Node.js
Express.js server with equivalent functionality and enterprise-grade features.

This implementation provides:
- Flask 2.3+ application factory pattern with WSGI compatibility (Section 5.2.1)
- Comprehensive Flask extension integration (Section 3.2.1)
- Enterprise authentication and security (Section 6.4.1)
- MongoDB/Redis database integration (Section 3.4.1, 3.4.2)
- Structured logging and monitoring (Section 3.6.1)
- Health check endpoints for orchestration (Section 6.1.3)
- Blueprint-based modular architecture (Section 5.2.2)

Key Features:
- Production-ready WSGI deployment with Gunicorn compatibility
- Environment-specific configuration management
- Comprehensive error handling and security
- Performance monitoring with ≤10% variance tracking
- Zero-downtime deployment support
- Enterprise APM and observability integration

Dependencies:
- Flask 2.3+ for core web framework functionality
- Flask-CORS 4.0+ for cross-origin request handling
- Flask-Limiter 3.5+ for rate limiting protection
- Flask-Talisman 1.1.0+ for security headers
- PyMongo 4.5+ and Motor 3.3+ for MongoDB integration
- redis-py 5.0+ for caching and session management
- structlog 23.1+ for enterprise structured logging
- prometheus-client 0.17+ for metrics collection

Author: Flask Migration Team
Version: 1.0.0
Migration Phase: Node.js to Python/Flask Migration (Section 0.1.1)
"""

import os
import sys
import logging
import traceback
from typing import Dict, Any, Optional, Callable, Tuple
from datetime import datetime, timedelta
from urllib.parse import urlparse

# Flask core imports
from flask import Flask, request, jsonify, g
from flask.logging import default_handler
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

# Flask extensions
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_login import LoginManager
from flask_session import Session

# Database and caching
import pymongo
from pymongo import MongoClient
import motor.motor_asyncio
import redis
from redis import ConnectionPool

# Authentication and security
import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets

# Monitoring and observability
import structlog
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
import time

# Configuration and utilities
from config.settings import get_config, ConfigurationError
from dotenv import load_dotenv

# Application modules (will be imported after Flask app creation to avoid circular imports)
# These imports are deferred to prevent circular dependency issues


class FlaskApplicationFactory:
    """
    Flask Application Factory implementing enterprise-grade application initialization
    with comprehensive extension configuration, database connections, and monitoring
    integration as specified in Section 6.1.1.
    
    This factory provides centralized application creation with environment-specific
    configuration, ensuring consistent deployment across development, staging, and
    production environments while maintaining ≤10% performance variance requirements.
    """
    
    def __init__(self):
        """Initialize the Flask application factory."""
        self.logger = None
        self._app = None
        self._config = None
        self._extensions = {}
        self._metrics = {}
        
    def create_app(self, config_name: Optional[str] = None) -> Flask:
        """
        Create and configure Flask application with enterprise-grade setup.
        
        This method implements the complete application factory pattern with:
        - Environment-specific configuration loading
        - Flask extension initialization and configuration
        - Database connection establishment (MongoDB, Redis)
        - Authentication and security setup
        - Monitoring and observability integration
        - Blueprint registration for modular architecture
        - Error handling and health check configuration
        
        Args:
            config_name: Optional configuration environment override
            
        Returns:
            Fully configured Flask application instance
            
        Raises:
            ConfigurationError: When application configuration fails
            RuntimeError: When critical application initialization fails
        """
        try:
            # Initialize Flask application
            app = Flask(__name__)
            self._app = app
            
            # Load environment variables early
            load_dotenv()
            
            # Configure application
            self._configure_application(app, config_name)
            
            # Setup structured logging first (required for all other components)
            self._setup_logging(app)
            
            # Initialize Flask extensions
            self._initialize_extensions(app)
            
            # Configure security and authentication
            self._configure_security(app)
            
            # Setup database connections
            self._setup_database_connections(app)
            
            # Configure monitoring and metrics
            self._setup_monitoring(app)
            
            # Register blueprints
            self._register_blueprints(app)
            
            # Configure error handlers
            self._configure_error_handlers(app)
            
            # Setup health check endpoints
            self._setup_health_checks(app)
            
            # Configure request/response hooks
            self._configure_request_hooks(app)
            
            # Validate application configuration
            self._validate_application(app)
            
            self.logger.info(
                "Flask application created successfully",
                extra={
                    "config_name": app.config.get('FLASK_ENV', 'unknown'),
                    "debug": app.debug,
                    "testing": app.testing
                }
            )
            
            return app
            
        except Exception as e:
            error_msg = f"Failed to create Flask application: {str(e)}"
            if self.logger:
                self.logger.error(error_msg, extra={"error": str(e), "traceback": traceback.format_exc()})
            else:
                print(f"ERROR: {error_msg}", file=sys.stderr)
            raise RuntimeError(error_msg) from e
    
    def _configure_application(self, app: Flask, config_name: Optional[str]) -> None:
        """
        Configure Flask application with environment-specific settings.
        
        This method loads configuration from config/settings.py using the
        configuration factory pattern as specified in Section 3.2.1.
        
        Args:
            app: Flask application instance
            config_name: Optional configuration environment override
        """
        try:
            # Load configuration
            config = get_config(config_name)
            self._config = config
            
            # Apply configuration to Flask app
            for key, value in config.to_dict().items():
                if not key.startswith('_'):
                    app.config[key] = value
            
            # Configure WSGI middleware for production deployment
            if not app.debug:
                # Configure proxy fix for load balancer/reverse proxy integration
                app.wsgi_app = ProxyFix(
                    app.wsgi_app, 
                    x_for=1, 
                    x_proto=1, 
                    x_host=1, 
                    x_prefix=1
                )
            
            # Set JSON configuration for consistent API responses
            app.json.sort_keys = app.config.get('JSON_SORT_KEYS', True)
            
        except ConfigurationError as e:
            raise ConfigurationError(f"Application configuration failed: {str(e)}") from e
    
    def _setup_logging(self, app: Flask) -> None:
        """
        Configure structured logging using structlog 23.1+ for enterprise integration.
        
        This method implements JSON-formatted logging equivalent to Node.js winston
        patterns as specified in Section 3.6.1, providing compatibility with
        enterprise log aggregation systems.
        
        Args:
            app: Flask application instance
        """
        # Remove default Flask handler to prevent duplicate logs
        app.logger.removeHandler(default_handler)
        
        # Configure structlog for enterprise logging
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.UnicodeDecoder(),
                structlog.processors.JSONRenderer()
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
        
        # Create structured logger
        self.logger = structlog.get_logger("flask_app")
        
        # Configure Python logging integration
        logging.basicConfig(
            format="%(message)s",
            stream=sys.stdout,
            level=getattr(logging, app.config.get('LOG_LEVEL', 'INFO'))
        )
        
        # Configure Flask logger
        app.logger.setLevel(getattr(logging, app.config.get('LOG_LEVEL', 'INFO')))
        
        self.logger.info("Structured logging configured successfully")
    
    def _initialize_extensions(self, app: Flask) -> None:
        """
        Initialize Flask extensions with enterprise configuration.
        
        This method configures all Flask extensions including CORS, rate limiting,
        session management, and security headers as specified in Section 3.2.1.
        
        Args:
            app: Flask application instance
        """
        # Flask-CORS 4.0+ for cross-origin request handling
        cors = CORS(
            app,
            origins=app.config.get('CORS_ORIGINS', []),
            methods=app.config.get('CORS_METHODS', ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']),
            allow_headers=app.config.get('CORS_ALLOW_HEADERS', []),
            expose_headers=app.config.get('CORS_EXPOSE_HEADERS', []),
            supports_credentials=app.config.get('CORS_SUPPORTS_CREDENTIALS', True),
            max_age=app.config.get('CORS_MAX_AGE', 600)
        )
        self._extensions['cors'] = cors
        
        # Flask-Limiter 3.5+ for rate limiting protection
        if app.config.get('RATELIMIT_ENABLED', True):
            limiter = Limiter(
                key_func=get_remote_address,
                app=app,
                storage_uri=app.config.get('RATELIMIT_STORAGE_URL'),
                default_limits=[app.config.get('RATELIMIT_DEFAULT', '1000 per hour')],
                headers_enabled=app.config.get('RATELIMIT_HEADERS_ENABLED', True)
            )
            self._extensions['limiter'] = limiter
        
        # Flask-Login for session management
        login_manager = LoginManager()
        login_manager.init_app(app)
        login_manager.login_view = 'auth.login'
        login_manager.login_message = 'Authentication required to access this resource.'
        login_manager.login_message_category = 'info'
        self._extensions['login_manager'] = login_manager
        
        # Flask-Session for distributed session management
        Session(app)
        
        self.logger.info("Flask extensions initialized successfully")
    
    def _configure_security(self, app: Flask) -> None:
        """
        Configure Flask-Talisman security headers and authentication.
        
        This method implements comprehensive HTTP security header enforcement
        as specified in Section 6.4.1, replacing Node.js helmet middleware.
        
        Args:
            app: Flask application instance
        """
        # Flask-Talisman 1.1.0+ for security headers
        talisman = Talisman(
            app,
            force_https=app.config.get('FORCE_HTTPS', True),
            strict_transport_security=app.config.get('HSTS_MAX_AGE', 31536000),
            strict_transport_security_include_subdomains=app.config.get('HSTS_INCLUDE_SUBDOMAINS', True),
            strict_transport_security_preload=app.config.get('HSTS_PRELOAD', True),
            content_security_policy=app.config.get('CSP_POLICY', {}),
            feature_policy=app.config.get('FEATURE_POLICY', {}),
            referrer_policy=app.config.get('REFERRER_POLICY', 'strict-origin-when-cross-origin'),
            x_frame_options=app.config.get('X_FRAME_OPTIONS', 'DENY'),
            x_content_type_options=app.config.get('X_CONTENT_TYPE_OPTIONS', 'nosniff'),
            x_xss_protection=app.config.get('X_XSS_PROTECTION', '1; mode=block')
        )
        self._extensions['talisman'] = talisman
        
        # Configure user loader for Flask-Login
        @app.login_manager.user_loader
        def load_user(user_id: str):
            """Load user for Flask-Login session management."""
            # This will be implemented by the auth module
            # Import deferred to avoid circular imports
            try:
                from src.auth import load_user_by_id
                return load_user_by_id(user_id)
            except ImportError:
                # Fallback for initial deployment
                return None
        
        self.logger.info("Security configuration completed successfully")
    
    def _setup_database_connections(self, app: Flask) -> None:
        """
        Setup MongoDB and Redis database connections.
        
        This method configures PyMongo 4.5+ and Motor 3.3+ for MongoDB operations
        and redis-py 5.0+ for caching as specified in Section 3.4.1 and 3.4.2.
        
        Args:
            app: Flask application instance
        """
        # MongoDB connection setup
        try:
            mongodb_uri = app.config.get('MONGODB_URI')
            if mongodb_uri:
                # Synchronous MongoDB client (PyMongo)
                mongo_client = MongoClient(
                    mongodb_uri,
                    **app.config.get('MONGODB_SETTINGS', {})
                )
                
                # Test connection
                mongo_client.admin.command('ping')
                app.mongo_client = mongo_client
                app.mongodb = mongo_client[app.config.get('MONGODB_DATABASE', 'flask_app')]
                
                # Asynchronous MongoDB client (Motor)
                motor_client = motor.motor_asyncio.AsyncIOMotorClient(
                    mongodb_uri,
                    **app.config.get('MONGODB_SETTINGS', {})
                )
                app.motor_client = motor_client
                app.motor_db = motor_client[app.config.get('MONGODB_DATABASE', 'flask_app')]
                
                self.logger.info("MongoDB connections established successfully")
            else:
                self.logger.warning("MongoDB URI not configured - database operations disabled")
                
        except Exception as e:
            error_msg = f"MongoDB connection failed: {str(e)}"
            self.logger.error(error_msg)
            if not app.testing:
                raise RuntimeError(error_msg) from e
        
        # Redis connection setup
        try:
            redis_config = app.config.get('REDIS_CONNECTION_POOL_KWARGS', {})
            if redis_config.get('host'):
                # Create Redis connection pool
                redis_pool = ConnectionPool(**redis_config)
                redis_client = redis.Redis(connection_pool=redis_pool)
                
                # Test connection
                redis_client.ping()
                app.redis_client = redis_client
                app.redis_pool = redis_pool
                
                # Configure session Redis instance
                session_redis = redis.Redis(
                    host=redis_config.get('host'),
                    port=redis_config.get('port'),
                    password=redis_config.get('password'),
                    db=redis_config.get('db', 0)
                )
                app.session_interface.redis = session_redis
                
                self.logger.info("Redis connections established successfully")
            else:
                self.logger.warning("Redis configuration not found - caching disabled")
                
        except Exception as e:
            error_msg = f"Redis connection failed: {str(e)}"
            self.logger.error(error_msg)
            if not app.testing:
                raise RuntimeError(error_msg) from e
    
    def _setup_monitoring(self, app: Flask) -> None:
        """
        Configure Prometheus metrics and monitoring integration.
        
        This method sets up metrics collection for performance monitoring
        and ≤10% variance tracking as specified in Section 3.6.1.
        
        Args:
            app: Flask application instance
        """
        # Initialize Prometheus metrics
        self._metrics = {
            'request_count': Counter(
                'flask_requests_total',
                'Total number of requests',
                ['method', 'endpoint', 'status_code']
            ),
            'request_duration': Histogram(
                'flask_request_duration_seconds',
                'Request duration in seconds',
                ['method', 'endpoint']
            ),
            'active_requests': Gauge(
                'flask_active_requests',
                'Number of active requests'
            ),
            'performance_variance': Gauge(
                'flask_performance_variance_percent',
                'Performance variance from Node.js baseline',
                ['metric_type']
            ),
            'database_operations': Counter(
                'flask_database_operations_total',
                'Total database operations',
                ['operation', 'collection']
            ),
            'cache_operations': Counter(
                'flask_cache_operations_total',
                'Total cache operations',
                ['operation', 'result']
            )
        }
        
        # Store metrics in app context for global access
        app.prometheus_metrics = self._metrics
        
        # Configure APM integration if enabled
        if app.config.get('APM_ENABLED', False):
            try:
                # This will be implemented by the monitoring module
                from src.monitoring import initialize_apm
                initialize_apm(app)
                self.logger.info("APM integration initialized successfully")
            except ImportError:
                self.logger.warning("APM module not available - monitoring limited")
        
        self.logger.info("Monitoring and metrics configured successfully")
    
    def _register_blueprints(self, app: Flask) -> None:
        """
        Register Flask Blueprints for modular route organization.
        
        This method implements Blueprint-based architecture equivalent to
        Express.js routing patterns as specified in Section 5.2.2.
        
        Args:
            app: Flask application instance
        """
        try:
            # Import blueprints (deferred to avoid circular imports)
            from src.blueprints import register_blueprints
            
            # Register all application blueprints
            register_blueprints(app)
            
            self.logger.info("Application blueprints registered successfully")
            
        except ImportError as e:
            self.logger.warning(f"Blueprint registration failed: {str(e)} - using fallback routes")
            
            # Fallback basic routes for initial deployment
            @app.route('/health')
            def health_check():
                """Basic health check endpoint."""
                return jsonify({
                    'status': 'healthy',
                    'timestamp': datetime.utcnow().isoformat(),
                    'version': app.config.get('APP_VERSION', '1.0.0')
                })
            
            @app.route('/metrics')
            def metrics():
                """Prometheus metrics endpoint."""
                return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}
    
    def _configure_error_handlers(self, app: Flask) -> None:
        """
        Configure comprehensive error handlers for consistent error responses.
        
        This method implements enterprise-grade error handling with structured
        logging and monitoring integration as specified in Section 4.2.3.
        
        Args:
            app: Flask application instance
        """
        @app.errorhandler(HTTPException)
        def handle_http_exception(error: HTTPException) -> Tuple[Dict[str, Any], int]:
            """Handle HTTP exceptions with structured error responses."""
            self.logger.warning(
                "HTTP exception occurred",
                extra={
                    "status_code": error.code,
                    "error": error.description,
                    "endpoint": request.endpoint,
                    "method": request.method,
                    "user_agent": request.headers.get('User-Agent'),
                    "remote_addr": request.remote_addr
                }
            )
            
            # Update metrics
            if hasattr(app, 'prometheus_metrics'):
                app.prometheus_metrics['request_count'].labels(
                    method=request.method,
                    endpoint=request.endpoint or 'unknown',
                    status_code=error.code
                ).inc()
            
            return {
                'error': {
                    'code': error.code,
                    'message': error.description,
                    'timestamp': datetime.utcnow().isoformat()
                }
            }, error.code
        
        @app.errorhandler(500)
        def handle_internal_error(error: Exception) -> Tuple[Dict[str, Any], int]:
            """Handle internal server errors with logging and monitoring."""
            self.logger.error(
                "Internal server error occurred",
                extra={
                    "error": str(error),
                    "traceback": traceback.format_exc(),
                    "endpoint": request.endpoint,
                    "method": request.method,
                    "user_agent": request.headers.get('User-Agent'),
                    "remote_addr": request.remote_addr
                }
            )
            
            # Update metrics
            if hasattr(app, 'prometheus_metrics'):
                app.prometheus_metrics['request_count'].labels(
                    method=request.method,
                    endpoint=request.endpoint or 'unknown',
                    status_code=500
                ).inc()
            
            return {
                'error': {
                    'code': 500,
                    'message': 'Internal server error' if not app.debug else str(error),
                    'timestamp': datetime.utcnow().isoformat()
                }
            }, 500
        
        @app.errorhandler(404)
        def handle_not_found(error: Exception) -> Tuple[Dict[str, Any], int]:
            """Handle 404 errors with consistent response format."""
            return {
                'error': {
                    'code': 404,
                    'message': 'Resource not found',
                    'timestamp': datetime.utcnow().isoformat()
                }
            }, 404
        
        self.logger.info("Error handlers configured successfully")
    
    def _setup_health_checks(self, app: Flask) -> None:
        """
        Setup health check endpoints for Kubernetes and load balancer integration.
        
        This method implements health endpoints as specified in Section 6.1.3
        for enterprise container orchestration.
        
        Args:
            app: Flask application instance
        """
        @app.route('/health')
        def health_check() -> Dict[str, Any]:
            """Basic application health check."""
            return {
                'status': 'healthy',
                'timestamp': datetime.utcnow().isoformat(),
                'version': app.config.get('APP_VERSION', '1.0.0'),
                'environment': app.config.get('FLASK_ENV', 'unknown')
            }
        
        @app.route('/health/ready')
        def readiness_check() -> Tuple[Dict[str, Any], int]:
            """Kubernetes readiness probe endpoint."""
            checks = {
                'database': False,
                'cache': False,
                'overall': False
            }
            
            # Check MongoDB connection
            try:
                if hasattr(app, 'mongo_client'):
                    app.mongo_client.admin.command('ping')
                    checks['database'] = True
            except Exception as e:
                self.logger.warning(f"Database health check failed: {str(e)}")
            
            # Check Redis connection
            try:
                if hasattr(app, 'redis_client'):
                    app.redis_client.ping()
                    checks['cache'] = True
            except Exception as e:
                self.logger.warning(f"Cache health check failed: {str(e)}")
            
            # Overall health assessment
            checks['overall'] = checks['database'] and checks['cache']
            status_code = 200 if checks['overall'] else 503
            
            return {
                'status': 'ready' if checks['overall'] else 'not_ready',
                'checks': checks,
                'timestamp': datetime.utcnow().isoformat()
            }, status_code
        
        @app.route('/health/live')
        def liveness_check() -> Dict[str, Any]:
            """Kubernetes liveness probe endpoint."""
            return {
                'status': 'alive',
                'timestamp': datetime.utcnow().isoformat(),
                'uptime_seconds': time.time() - app.start_time
            }
        
        # Store application start time for uptime calculation
        app.start_time = time.time()
        
        self.logger.info("Health check endpoints configured successfully")
    
    def _configure_request_hooks(self, app: Flask) -> None:
        """
        Configure request/response hooks for monitoring and correlation tracking.
        
        This method implements request lifecycle hooks for metrics collection
        and correlation ID tracking as specified in Section 4.5.1.
        
        Args:
            app: Flask application instance
        """
        @app.before_request
        def before_request() -> None:
            """Pre-request processing for monitoring and correlation."""
            # Generate correlation ID for request tracking
            g.correlation_id = request.headers.get('X-Correlation-ID', secrets.token_hex(16))
            g.request_start_time = time.time()
            
            # Update active requests metric
            if hasattr(app, 'prometheus_metrics'):
                app.prometheus_metrics['active_requests'].inc()
        
        @app.after_request
        def after_request(response) -> object:
            """Post-request processing for metrics and correlation."""
            # Calculate request duration
            if hasattr(g, 'request_start_time'):
                duration = time.time() - g.request_start_time
                
                # Update metrics
                if hasattr(app, 'prometheus_metrics'):
                    app.prometheus_metrics['active_requests'].dec()
                    app.prometheus_metrics['request_count'].labels(
                        method=request.method,
                        endpoint=request.endpoint or 'unknown',
                        status_code=response.status_code
                    ).inc()
                    app.prometheus_metrics['request_duration'].labels(
                        method=request.method,
                        endpoint=request.endpoint or 'unknown'
                    ).observe(duration)
            
            # Add correlation ID to response headers
            if hasattr(g, 'correlation_id'):
                response.headers['X-Correlation-ID'] = g.correlation_id
            
            # Add security headers
            response.headers['X-Request-ID'] = getattr(g, 'correlation_id', 'unknown')
            
            return response
        
        @app.teardown_appcontext
        def teardown_request(exception=None) -> None:
            """Cleanup request context and log request completion."""
            if exception:
                self.logger.error(
                    "Request completed with exception",
                    extra={
                        "correlation_id": getattr(g, 'correlation_id', 'unknown'),
                        "exception": str(exception),
                        "endpoint": request.endpoint,
                        "method": request.method
                    }
                )
        
        self.logger.info("Request hooks configured successfully")
    
    def _validate_application(self, app: Flask) -> None:
        """
        Validate application configuration and dependencies.
        
        This method performs final validation to ensure the application
        is properly configured for deployment.
        
        Args:
            app: Flask application instance
            
        Raises:
            RuntimeError: When critical validation fails
        """
        validation_errors = []
        
        # Validate required configuration
        required_config = ['SECRET_KEY', 'FLASK_ENV']
        for config_key in required_config:
            if not app.config.get(config_key):
                validation_errors.append(f"Missing required configuration: {config_key}")
        
        # Validate database connections in production
        if app.config.get('FLASK_ENV') == 'production':
            if not hasattr(app, 'mongo_client'):
                validation_errors.append("MongoDB connection required for production")
            if not hasattr(app, 'redis_client'):
                validation_errors.append("Redis connection required for production")
        
        # Validate security configuration
        if app.config.get('FLASK_ENV') == 'production':
            if app.debug:
                validation_errors.append("Debug mode must be disabled in production")
            if not app.config.get('FORCE_HTTPS', True):
                validation_errors.append("HTTPS must be enforced in production")
        
        if validation_errors:
            error_message = "Application validation failed:\n" + "\n".join(
                f"- {error}" for error in validation_errors
            )
            raise RuntimeError(error_message)
        
        self.logger.info("Application validation completed successfully")


# Global application factory instance
factory = FlaskApplicationFactory()

def create_app(config_name: Optional[str] = None) -> Flask:
    """
    Application factory function for creating Flask application instances.
    
    This function provides the main entry point for creating Flask applications
    with comprehensive enterprise configuration as specified in Section 6.1.1.
    
    Args:
        config_name: Optional configuration environment override
        
    Returns:
        Fully configured Flask application instance
        
    Raises:
        RuntimeError: When application creation fails
    """
    return factory.create_app(config_name)

# Create application instance for WSGI deployment
app = create_app()

# WSGI entry point for production deployment
application = app

if __name__ == '__main__':
    """
    Development server entry point.
    
    This section provides local development server startup with hot reloading
    and debug capabilities. Production deployment should use Gunicorn WSGI server.
    """
    # Load environment for development
    load_dotenv()
    
    # Get configuration for development server
    host = os.getenv('FLASK_HOST', '0.0.0.0')
    port = int(os.getenv('FLASK_PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    
    print(f"Starting Flask development server on {host}:{port}")
    print(f"Environment: {os.getenv('FLASK_ENV', 'development')}")
    print(f"Debug mode: {debug}")
    print("For production deployment, use Gunicorn WSGI server")
    
    # Start development server
    app.run(
        host=host,
        port=port,
        debug=debug,
        threaded=True,
        use_reloader=debug
    )