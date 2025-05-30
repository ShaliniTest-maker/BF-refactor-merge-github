"""
Flask Application Factory
=========================

Main WSGI application entry point implementing comprehensive enterprise initialization
including Blueprint registration, middleware stack configuration, database connections
(PyMongo/Motor), Redis caching, authentication setup, and monitoring integration.

This module serves as the central orchestration point for the entire Flask application,
implementing the migration from Node.js/Express.js to Python/Flask while maintaining
≤10% performance variance and full API compatibility.

Architecture:
- Flask 2.3+ application factory pattern with centralized extension initialization
- Blueprint-based modular architecture for maintainable code organization
- Dual database driver architecture (PyMongo sync + Motor async)
- Enterprise-grade security, monitoring, and error handling
- Horizontal scaling support through WSGI server deployment
"""

import os
import logging
from typing import Optional, Dict, Any
from datetime import timedelta

# Core Flask and extensions
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_jwt_extended import JWTManager
from flask_talisman import Talisman

# Database and caching
import pymongo
from motor.motor_asyncio import AsyncIOMotorClient
import redis
from redis.connection import ConnectionPool

# Monitoring and logging
import structlog
from prometheus_client import Counter, Histogram, Gauge, make_wsgi_app
from werkzeug.middleware.dispatcher import DispatcherMiddleware

# Validation and security
from marshmallow import ValidationError
import jwt
from cryptography.fernet import InvalidToken

# Error handling and resilience
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from circuit_breaker import CircuitBreaker, CircuitBreakerOpenException

# HTTP client for health checks
import requests
from requests.exceptions import RequestException

# Configuration and environment
from dotenv import load_dotenv

# Application modules (will be created by other agents)
try:
    from src.config.settings import Config, get_config
except ImportError:
    # Fallback configuration for initialization
    class Config:
        """Fallback configuration class for application initialization"""
        SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
        JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'jwt-secret-key-change-in-production')
        JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
        JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
        
        # Database configuration
        MONGODB_URI = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/flask_app')
        MONGODB_DATABASE = os.getenv('MONGODB_DATABASE', 'flask_app')
        
        # Redis configuration
        REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
        
        # Security configuration
        CORS_ORIGINS = os.getenv('CORS_ORIGINS', '*').split(',')
        RATE_LIMIT_DEFAULT = os.getenv('RATE_LIMIT_DEFAULT', '1000 per hour')
        
        # Monitoring configuration
        ENABLE_METRICS = os.getenv('ENABLE_METRICS', 'true').lower() == 'true'
        LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
        
        # Feature flags
        ENABLE_CIRCUIT_BREAKER = os.getenv('ENABLE_CIRCUIT_BREAKER', 'true').lower() == 'true'
        ENABLE_HEALTH_CHECKS = os.getenv('ENABLE_HEALTH_CHECKS', 'true').lower() == 'true'
    
    def get_config():
        """Fallback configuration getter"""
        return Config()


# Global extension instances
cors = CORS()
limiter = Limiter(key_func=get_remote_address)
jwt_manager = JWTManager()
talisman = Talisman()

# Database connection instances
mongo_client: Optional[pymongo.MongoClient] = None
motor_client: Optional[AsyncIOMotorClient] = None
redis_client: Optional[redis.Redis] = None

# Monitoring instances
logger = structlog.get_logger()

# Prometheus metrics
REQUEST_COUNT = Counter(
    'flask_requests_total',
    'Total number of requests',
    ['method', 'endpoint', 'status']
)

REQUEST_DURATION = Histogram(
    'flask_request_duration_seconds',
    'Request duration in seconds',
    ['method', 'endpoint']
)

ACTIVE_CONNECTIONS = Gauge(
    'flask_active_connections',
    'Number of active connections',
    ['connection_type']
)

ERROR_COUNT = Counter(
    'flask_errors_total',
    'Total number of errors',
    ['error_type', 'endpoint']
)

DATABASE_OPERATIONS = Counter(
    'flask_database_operations_total',
    'Total database operations',
    ['operation', 'collection', 'status']
)

EXTERNAL_SERVICE_CALLS = Counter(
    'flask_external_service_calls_total',
    'Total external service calls',
    ['service', 'status']
)

# Circuit breakers for external services
auth0_circuit_breaker: Optional[CircuitBreaker] = None
aws_circuit_breaker: Optional[CircuitBreaker] = None
redis_circuit_breaker: Optional[CircuitBreaker] = None


def configure_logging(app: Flask) -> None:
    """
    Configure enterprise-grade structured logging with structlog.
    
    Implements JSON-formatted logging compatible with enterprise log aggregation
    systems, replacing Node.js winston/morgan logging patterns.
    
    Args:
        app: Flask application instance
    """
    config = get_config()
    
    # Configure structlog for JSON output
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
    
    # Set log level
    log_level = getattr(logging, config.LOG_LEVEL.upper(), logging.INFO)
    logging.basicConfig(level=log_level, format='%(message)s')
    
    # Configure Flask app logger
    app.logger.handlers.clear()
    app.logger.addHandler(logging.StreamHandler())
    app.logger.setLevel(log_level)
    
    logger.info("Structured logging configured", log_level=config.LOG_LEVEL)


def configure_security(app: Flask) -> None:
    """
    Configure comprehensive security middleware stack.
    
    Implements Flask-Talisman as direct replacement for Node.js helmet middleware,
    providing Content Security Policy, HSTS, X-Frame-Options, and comprehensive
    web application security header management.
    
    Args:
        app: Flask application instance
    """
    config = get_config()
    
    # Configure Flask-Talisman (helmet replacement)
    talisman.init_app(
        app,
        force_https=app.config.get('FORCE_HTTPS', False),
        strict_transport_security=True,
        strict_transport_security_max_age=31536000,  # 1 year
        content_security_policy={
            'default-src': "'self'",
            'script-src': "'self' 'unsafe-inline'",
            'style-src': "'self' 'unsafe-inline'",
            'img-src': "'self' data: https:",
            'connect-src': "'self'",
            'font-src': "'self'",
            'object-src': "'none'",
            'media-src': "'self'",
            'frame-src': "'none'",
        },
        referrer_policy='strict-origin-when-cross-origin',
        feature_policy={
            'camera': "'none'",
            'microphone': "'none'",
            'geolocation': "'none'"
        }
    )
    
    # Configure CORS
    cors.init_app(
        app,
        origins=config.CORS_ORIGINS,
        methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
        allow_headers=['Content-Type', 'Authorization', 'X-Requested-With'],
        supports_credentials=True,
        max_age=86400  # 24 hours
    )
    
    # Configure rate limiting
    limiter.init_app(
        app,
        default_limits=[config.RATE_LIMIT_DEFAULT],
        storage_uri=config.REDIS_URL,
        strategy="fixed-window"
    )
    
    logger.info("Security middleware configured", 
                cors_origins=config.CORS_ORIGINS,
                rate_limit=config.RATE_LIMIT_DEFAULT)


def configure_jwt(app: Flask) -> None:
    """
    Configure JWT authentication using Flask-JWT-Extended.
    
    Implements PyJWT 2.8+ token processing equivalent to Node.js jsonwebtoken,
    with enterprise-grade token validation and refresh capabilities.
    
    Args:
        app: Flask application instance
    """
    config = get_config()
    
    # Configure JWT settings
    app.config['JWT_SECRET_KEY'] = config.JWT_SECRET_KEY
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = config.JWT_ACCESS_TOKEN_EXPIRES
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = config.JWT_REFRESH_TOKEN_EXPIRES
    app.config['JWT_ALGORITHM'] = 'HS256'
    app.config['JWT_TOKEN_LOCATION'] = ['headers', 'query_string']
    app.config['JWT_HEADER_NAME'] = 'Authorization'
    app.config['JWT_HEADER_TYPE'] = 'Bearer'
    
    # Initialize JWT manager
    jwt_manager.init_app(app)
    
    @jwt_manager.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        """Handle expired token scenarios"""
        ERROR_COUNT.labels(error_type='expired_token', endpoint=request.endpoint).inc()
        logger.warning("JWT token expired", user_id=jwt_payload.get('sub'))
        return jsonify({'error': 'Token has expired'}), 401
    
    @jwt_manager.invalid_token_loader
    def invalid_token_callback(error_string):
        """Handle invalid token scenarios"""
        ERROR_COUNT.labels(error_type='invalid_token', endpoint=request.endpoint).inc()
        logger.warning("Invalid JWT token", error=error_string)
        return jsonify({'error': 'Invalid token'}), 401
    
    @jwt_manager.unauthorized_loader
    def missing_token_callback(error_string):
        """Handle missing token scenarios"""
        ERROR_COUNT.labels(error_type='missing_token', endpoint=request.endpoint).inc()
        logger.warning("Missing JWT token", error=error_string)
        return jsonify({'error': 'Authorization token required'}), 401
    
    logger.info("JWT authentication configured", 
                access_token_expires=config.JWT_ACCESS_TOKEN_EXPIRES,
                refresh_token_expires=config.JWT_REFRESH_TOKEN_EXPIRES)


def configure_database(app: Flask) -> None:
    """
    Configure dual database driver architecture (PyMongo + Motor).
    
    Implements PyMongo 4.5+ for synchronous operations and Motor 3.3+ for
    async operations, with optimized connection pooling and enterprise-grade
    connection management.
    
    Args:
        app: Flask application instance
    """
    global mongo_client, motor_client
    config = get_config()
    
    try:
        # Configure PyMongo (synchronous) connection pool
        mongo_client = pymongo.MongoClient(
            config.MONGODB_URI,
            maxPoolSize=50,
            waitQueueTimeoutMS=30000,
            serverSelectionTimeoutMS=10000,
            connectTimeoutMS=10000,
            socketTimeoutMS=60000,
            retryWrites=True,
            retryReads=True
        )
        
        # Test connection
        mongo_client.admin.command('ping')
        app.config['MONGO_CLIENT'] = mongo_client
        app.config['MONGO_DB'] = mongo_client[config.MONGODB_DATABASE]
        
        ACTIVE_CONNECTIONS.labels(connection_type='mongodb_sync').set(1)
        logger.info("PyMongo connection established", 
                   database=config.MONGODB_DATABASE,
                   max_pool_size=50)
        
        # Configure Motor (asynchronous) connection pool
        motor_client = AsyncIOMotorClient(
            config.MONGODB_URI,
            maxPoolSize=100,
            waitQueueMultiple=2,
            waitQueueTimeoutMS=30000,
            serverSelectionTimeoutMS=10000,
            connectTimeoutMS=10000,
            socketTimeoutMS=60000
        )
        
        app.config['MOTOR_CLIENT'] = motor_client
        app.config['MOTOR_DB'] = motor_client[config.MONGODB_DATABASE]
        
        ACTIVE_CONNECTIONS.labels(connection_type='mongodb_async').set(1)
        logger.info("Motor async connection established",
                   database=config.MONGODB_DATABASE,
                   max_pool_size=100)
        
    except Exception as e:
        ERROR_COUNT.labels(error_type='database_init', endpoint='startup').inc()
        logger.error("Database connection failed", error=str(e))
        raise RuntimeError(f"Failed to connect to MongoDB: {e}")


def configure_cache(app: Flask) -> None:
    """
    Configure Redis caching with connection pooling.
    
    Implements redis-py 5.0+ with enterprise-grade connection pooling,
    distributed session management, and circuit breaker protection.
    
    Args:
        app: Flask application instance
    """
    global redis_client, redis_circuit_breaker
    config = get_config()
    
    try:
        # Configure Redis connection pool
        pool = ConnectionPool.from_url(
            config.REDIS_URL,
            max_connections=50,
            retry_on_timeout=True,
            socket_timeout=30.0,
            socket_connect_timeout=10.0,
            health_check_interval=30
        )
        
        redis_client = redis.Redis(
            connection_pool=pool,
            decode_responses=True,
            protocol=3
        )
        
        # Test connection
        redis_client.ping()
        app.config['REDIS_CLIENT'] = redis_client
        
        # Configure circuit breaker for Redis
        if config.ENABLE_CIRCUIT_BREAKER:
            redis_circuit_breaker = CircuitBreaker(
                fail_max=5,
                reset_timeout=60,
                expected_exception=redis.RedisError
            )
            app.config['REDIS_CIRCUIT_BREAKER'] = redis_circuit_breaker
        
        ACTIVE_CONNECTIONS.labels(connection_type='redis').set(1)
        logger.info("Redis connection established",
                   max_connections=50,
                   circuit_breaker_enabled=config.ENABLE_CIRCUIT_BREAKER)
        
    except Exception as e:
        ERROR_COUNT.labels(error_type='cache_init', endpoint='startup').inc()
        logger.warning("Redis connection failed, continuing without cache", error=str(e))
        # Continue without cache - graceful degradation
        app.config['REDIS_CLIENT'] = None


def configure_circuit_breakers(app: Flask) -> None:
    """
    Configure circuit breakers for external service resilience.
    
    Implements circuit breaker pattern for Auth0 authentication and AWS service
    calls to prevent cascade failures and enable rapid recovery.
    
    Args:
        app: Flask application instance
    """
    global auth0_circuit_breaker, aws_circuit_breaker
    config = get_config()
    
    if config.ENABLE_CIRCUIT_BREAKER:
        # Auth0 circuit breaker
        auth0_circuit_breaker = CircuitBreaker(
            fail_max=5,
            reset_timeout=60,
            expected_exception=RequestException
        )
        
        # AWS circuit breaker
        aws_circuit_breaker = CircuitBreaker(
            fail_max=5,
            reset_timeout=60,
            expected_exception=Exception  # Boto3 exceptions
        )
        
        app.config['AUTH0_CIRCUIT_BREAKER'] = auth0_circuit_breaker
        app.config['AWS_CIRCUIT_BREAKER'] = aws_circuit_breaker
        
        logger.info("Circuit breakers configured",
                   auth0_enabled=True,
                   aws_enabled=True)


def configure_monitoring(app: Flask) -> None:
    """
    Configure comprehensive monitoring and metrics collection.
    
    Implements prometheus-client 0.17+ metrics collection with custom metrics
    for database operations, external service calls, and application performance.
    
    Args:
        app: Flask application instance
    """
    config = get_config()
    
    if config.ENABLE_METRICS:
        # Add Prometheus metrics endpoint
        app.wsgi_app = DispatcherMiddleware(
            app.wsgi_app,
            {'/metrics': make_wsgi_app()}
        )
        
        @app.before_request
        def before_request():
            """Record request start time and increment request counter"""
            g.start_time = REQUEST_DURATION.labels(
                method=request.method,
                endpoint=request.endpoint or 'unknown'
            ).time()
            
            REQUEST_COUNT.labels(
                method=request.method,
                endpoint=request.endpoint or 'unknown',
                status='processing'
            ).inc()
        
        @app.after_request
        def after_request(response):
            """Record request completion metrics"""
            if hasattr(g, 'start_time'):
                g.start_time.observe()
            
            REQUEST_COUNT.labels(
                method=request.method,
                endpoint=request.endpoint or 'unknown',
                status=response.status_code
            ).inc()
            
            return response
        
        logger.info("Prometheus metrics configured", metrics_endpoint="/metrics")


def configure_error_handlers(app: Flask) -> None:
    """
    Configure comprehensive error handlers with Flask @errorhandler decorators.
    
    Implements enterprise-grade exception management with specific handling for
    validation errors, JWT errors, database errors, and external service errors.
    
    Args:
        app: Flask application instance
    """
    
    @app.errorhandler(ValidationError)
    def handle_validation_error(error):
        """Handle marshmallow validation errors"""
        ERROR_COUNT.labels(error_type='validation_error', endpoint=request.endpoint).inc()
        logger.warning("Validation error", 
                      endpoint=request.endpoint,
                      errors=error.messages)
        return jsonify({
            'error': 'Validation failed',
            'details': error.messages
        }), 400
    
    @app.errorhandler(jwt.PyJWTError)
    def handle_jwt_error(error):
        """Handle PyJWT authentication errors"""
        ERROR_COUNT.labels(error_type='jwt_error', endpoint=request.endpoint).inc()
        logger.warning("JWT error", 
                      endpoint=request.endpoint,
                      error=str(error))
        return jsonify({
            'error': 'Authentication failed',
            'message': 'Invalid or expired token'
        }), 401
    
    @app.errorhandler(PermissionError)
    def handle_permission_error(error):
        """Handle authorization errors"""
        ERROR_COUNT.labels(error_type='permission_error', endpoint=request.endpoint).inc()
        logger.warning("Permission denied", 
                      endpoint=request.endpoint,
                      error=str(error))
        return jsonify({
            'error': 'Permission denied',
            'message': 'Insufficient privileges'
        }), 403
    
    @app.errorhandler(pymongo.errors.PyMongoError)
    def handle_database_error(error):
        """Handle database errors with retry logic"""
        ERROR_COUNT.labels(error_type='database_error', endpoint=request.endpoint).inc()
        logger.error("Database error", 
                    endpoint=request.endpoint,
                    error=str(error))
        return jsonify({
            'error': 'Database operation failed',
            'message': 'Please try again later'
        }), 500
    
    @app.errorhandler(redis.RedisError)
    def handle_cache_error(error):
        """Handle Redis cache errors"""
        ERROR_COUNT.labels(error_type='cache_error', endpoint=request.endpoint).inc()
        logger.warning("Cache error", 
                      endpoint=request.endpoint,
                      error=str(error))
        # Continue without cache - graceful degradation
        return None
    
    @app.errorhandler(CircuitBreakerOpenException)
    def handle_circuit_breaker_error(error):
        """Handle circuit breaker open state"""
        ERROR_COUNT.labels(error_type='circuit_breaker_open', endpoint=request.endpoint).inc()
        logger.warning("Circuit breaker open", 
                      endpoint=request.endpoint,
                      service=str(error))
        return jsonify({
            'error': 'Service temporarily unavailable',
            'message': 'Please try again later'
        }), 503
    
    @app.errorhandler(RequestException)
    def handle_external_service_error(error):
        """Handle external service communication errors"""
        ERROR_COUNT.labels(error_type='external_service_error', endpoint=request.endpoint).inc()
        logger.error("External service error", 
                    endpoint=request.endpoint,
                    error=str(error))
        return jsonify({
            'error': 'External service error',
            'message': 'Please try again later'
        }), 502
    
    @app.errorhandler(404)
    def handle_not_found(error):
        """Handle 404 errors"""
        ERROR_COUNT.labels(error_type='not_found', endpoint=request.endpoint).inc()
        logger.info("Resource not found", 
                   endpoint=request.endpoint,
                   path=request.path)
        return jsonify({
            'error': 'Resource not found',
            'message': 'The requested resource does not exist'
        }), 404
    
    @app.errorhandler(500)
    def handle_internal_error(error):
        """Handle internal server errors"""
        ERROR_COUNT.labels(error_type='internal_error', endpoint=request.endpoint).inc()
        logger.error("Internal server error", 
                    endpoint=request.endpoint,
                    error=str(error))
        return jsonify({
            'error': 'Internal server error',
            'message': 'An unexpected error occurred'
        }), 500
    
    logger.info("Error handlers configured")


def configure_health_checks(app: Flask) -> None:
    """
    Configure enterprise health check endpoints.
    
    Implements Kubernetes-compatible health endpoints for readiness and liveness
    probes, with comprehensive service dependency validation.
    
    Args:
        app: Flask application instance
    """
    config = get_config()
    
    if config.ENABLE_HEALTH_CHECKS:
        
        @app.route('/health', methods=['GET'])
        def health_check():
            """Basic application health check"""
            return jsonify({
                'status': 'healthy',
                'timestamp': REQUEST_DURATION.labels(method='GET', endpoint='health')._value.get(),
                'version': app.config.get('VERSION', '1.0.0')
            })
        
        @app.route('/health/ready', methods=['GET'])
        def readiness_check():
            """Kubernetes readiness probe - check if ready to receive traffic"""
            health_status = {
                'status': 'ready',
                'timestamp': REQUEST_DURATION.labels(method='GET', endpoint='readiness')._value.get(),
                'checks': {}
            }
            
            # Check database connectivity
            try:
                if mongo_client:
                    mongo_client.admin.command('ping')
                    health_status['checks']['mongodb'] = 'healthy'
                else:
                    health_status['checks']['mongodb'] = 'unavailable'
            except Exception as e:
                health_status['checks']['mongodb'] = f'error: {str(e)}'
                health_status['status'] = 'not_ready'
            
            # Check Redis connectivity
            try:
                if redis_client:
                    redis_client.ping()
                    health_status['checks']['redis'] = 'healthy'
                else:
                    health_status['checks']['redis'] = 'unavailable'
            except Exception as e:
                health_status['checks']['redis'] = f'error: {str(e)}'
                # Redis is optional, don't fail readiness
            
            status_code = 200 if health_status['status'] == 'ready' else 503
            return jsonify(health_status), status_code
        
        @app.route('/health/live', methods=['GET'])
        def liveness_check():
            """Kubernetes liveness probe - check if application is alive"""
            return jsonify({
                'status': 'alive',
                'timestamp': REQUEST_DURATION.labels(method='GET', endpoint='liveness')._value.get(),
                'uptime': app.config.get('START_TIME', 0)
            })
        
        logger.info("Health check endpoints configured",
                   endpoints=['/health', '/health/ready', '/health/live'])


def register_blueprints(app: Flask) -> None:
    """
    Register Flask Blueprints for modular architecture.
    
    Implements Blueprint-based modular organization equivalent to Express.js
    routing patterns, enabling maintainable code structure.
    
    Args:
        app: Flask application instance
    """
    try:
        # Import and register blueprints when they become available
        from src.blueprints import register_all_blueprints
        register_all_blueprints(app)
        logger.info("All blueprints registered successfully")
        
    except ImportError:
        # Blueprints not yet created - will be registered when available
        logger.warning("Blueprint modules not found, skipping registration")
        
        # Create a basic root endpoint for testing
        @app.route('/', methods=['GET'])
        def root():
            """Basic root endpoint for application verification"""
            return jsonify({
                'message': 'Flask application is running',
                'status': 'ok',
                'version': app.config.get('VERSION', '1.0.0')
            })


def create_app(config_name: Optional[str] = None) -> Flask:
    """
    Flask application factory implementing comprehensive enterprise initialization.
    
    Creates and configures a Flask application instance with all necessary
    extensions, middleware, database connections, and monitoring capabilities.
    
    This factory pattern enables:
    - Environment-specific configuration
    - Comprehensive testing capabilities
    - Horizontal scaling through WSGI server deployment
    - Modular component initialization
    
    Args:
        config_name: Optional configuration name for environment-specific settings
        
    Returns:
        Configured Flask application instance
        
    Raises:
        RuntimeError: If critical components fail to initialize
    """
    # Load environment variables
    load_dotenv()
    
    # Create Flask application instance
    app = Flask(__name__)
    
    # Load configuration
    config = get_config()
    app.config.from_object(config)
    
    # Store application start time for health checks
    import time
    app.config['START_TIME'] = time.time()
    app.config['VERSION'] = os.getenv('APP_VERSION', '1.0.0')
    
    # Configure structured logging first
    configure_logging(app)
    logger.info("Flask application factory started", version=app.config['VERSION'])
    
    try:
        # Configure core components in dependency order
        configure_security(app)
        configure_jwt(app)
        configure_database(app)
        configure_cache(app)
        configure_circuit_breakers(app)
        configure_monitoring(app)
        configure_error_handlers(app)
        configure_health_checks(app)
        
        # Register application blueprints
        register_blueprints(app)
        
        logger.info("Flask application factory completed successfully",
                   components=['security', 'jwt', 'database', 'cache', 'monitoring', 'blueprints'])
        
        return app
        
    except Exception as e:
        logger.error("Flask application factory failed", error=str(e))
        raise RuntimeError(f"Failed to create Flask application: {e}")


def create_wsgi_app() -> Flask:
    """
    Create WSGI application for production deployment.
    
    This function provides the WSGI entry point for Gunicorn and other
    WSGI servers, enabling production deployment with proper configuration.
    
    Returns:
        Configured Flask application instance for WSGI deployment
    """
    return create_app()


# WSGI application instance for deployment
application = create_wsgi_app()


if __name__ == '__main__':
    """
    Development server entry point.
    
    This section runs the Flask development server when the module is executed
    directly. In production, use a WSGI server like Gunicorn instead.
    """
    app = create_app()
    
    # Development server configuration
    debug_mode = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    host = os.getenv('FLASK_HOST', '127.0.0.1')
    port = int(os.getenv('FLASK_PORT', 5000))
    
    logger.info("Starting Flask development server",
               host=host,
               port=port,
               debug=debug_mode)
    
    app.run(
        host=host,
        port=port,
        debug=debug_mode,
        threaded=True
    )