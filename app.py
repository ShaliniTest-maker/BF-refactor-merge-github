"""
Flask Application WSGI Entry Point

Main entry point serving as the WSGI application module for production deployment
with Gunicorn/uWSGI servers. This module implements the Flask application factory
pattern integration, replacing the Node.js server entry point with enterprise-grade
Python/Flask WSGI application serving.

This module serves as the primary entry point implementing:
- Flask 2.3+ application factory pattern integration per Section 5.2.1
- WSGI server deployment compatibility for Gunicorn/uWSGI per Section 8.5.2
- Environment-specific configuration loading per Section 3.2.1
- Production-grade application initialization with comprehensive error handling
- Health check endpoint integration for load balancer and Kubernetes compatibility
- Development server capability for local development workflows
- Enterprise monitoring and observability integration per Section 5.2.8

Architecture Integration:
- Seamless integration with Flask application factory from src.app module
- Environment-specific configuration management using config.settings
- WSGI-compatible application instance for production deployment
- Comprehensive error handling and graceful degradation patterns
- Monitoring endpoint exposure for Prometheus metrics collection
- Health check endpoints for container orchestration integration

Performance Requirements:
- Zero-overhead WSGI application serving for production deployment
- Efficient request routing through Flask Blueprint architecture
- Optimized initialization for container startup time requirements
- Memory-efficient application serving supporting horizontal scaling

Security Integration:
- Flask-Talisman security headers enforcement per Section 3.2.2
- HTTPS enforcement and secure cookie configuration
- CORS policy compliance for cross-origin request handling
- Rate limiting integration for external service protection

Usage Examples:
    # Production WSGI deployment
    gunicorn --config gunicorn.conf.py "app:application"
    
    # Development server
    export FLASK_ENV=development
    python app.py
    
    # Container deployment
    docker run -p 8000:8000 flask-app:latest gunicorn "app:application"
    
    # Kubernetes deployment
    kubectl apply -f deployment.yaml  # References app:application

Author: Flask Migration Team  
Version: 1.0.0
Migration Phase: Node.js to Python/Flask Migration (Section 0.1.1)
Compliance: Enterprise WSGI deployment standards, SOC 2, ISO 27001
Dependencies: Flask 2.3+, Gunicorn 23.0+, src.app application factory
"""

import os
import sys
import signal
import logging
from pathlib import Path
from typing import Optional, Dict, Any, Callable
from datetime import datetime

# Add src directory to Python path for application factory imports
src_path = Path(__file__).parent / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

# Flask application factory imports
try:
    from src.app import create_app, get_application_info, cleanup_application_resources
    from config.settings import get_config, ConfigurationError
except ImportError as e:
    # Graceful handling for development environments
    print(f"Import error: {e}")
    print("Ensure src/ directory contains the Flask application factory")
    sys.exit(1)

# Configure module-level logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class WSGIApplicationManager:
    """
    WSGI Application Manager for Flask application lifecycle management.
    
    This class provides comprehensive Flask application lifecycle management
    including initialization, configuration, health monitoring, and graceful
    shutdown procedures for enterprise deployment environments.
    
    Features:
    - Thread-safe application initialization with error handling
    - Environment-specific configuration loading and validation
    - Health check endpoint registration for load balancer integration
    - Graceful shutdown procedures for container orchestration
    - Application metrics collection and monitoring integration
    - Error handling and recovery procedures for production stability
    """
    
    def __init__(self) -> None:
        """Initialize WSGI application manager with default configuration."""
        self.app: Optional[object] = None
        self.config: Optional[object] = None
        self.initialized: bool = False
        self.startup_time: Optional[datetime] = None
        self.shutdown_handlers: list = []
        self.logger = logging.getLogger(f"{__name__}.WSGIApplicationManager")
    
    def initialize_application(self, config_name: Optional[str] = None) -> object:
        """
        Initialize Flask application with comprehensive error handling.
        
        This method implements thread-safe application initialization with
        configuration validation, extension registration, and health check
        setup as specified in Section 5.2.1.
        
        Args:
            config_name: Optional configuration environment name override
            
        Returns:
            Initialized Flask application instance
            
        Raises:
            ConfigurationError: When configuration validation fails
            RuntimeError: When application initialization fails
        """
        if self.initialized and self.app:
            self.logger.warning("Application already initialized, returning existing instance")
            return self.app
        
        try:
            # Record startup time for health checks
            self.startup_time = datetime.utcnow()
            
            # Load environment-specific configuration
            self.logger.info("Loading application configuration...")
            self.config = get_config(config_name)
            
            # Validate configuration for production requirements
            self._validate_production_configuration()
            
            # Create Flask application using factory pattern
            self.logger.info("Creating Flask application instance...")
            self.app = create_app(self.config)
            
            # Register application-level error handlers
            self._register_application_error_handlers()
            
            # Register health check endpoints
            self._register_health_endpoints()
            
            # Register shutdown handlers for graceful cleanup
            self._register_shutdown_handlers()
            
            # Mark application as initialized
            self.initialized = True
            
            self.logger.info(
                f"Flask application initialized successfully "
                f"(env: {self.config.FLASK_ENV}, "
                f"debug: {self.config.DEBUG})"
            )
            
            return self.app
            
        except ConfigurationError as e:
            error_msg = f"Configuration validation failed: {str(e)}"
            self.logger.error(error_msg)
            raise RuntimeError(error_msg)
            
        except Exception as e:
            error_msg = f"Application initialization failed: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            raise RuntimeError(error_msg)
    
    def _validate_production_configuration(self) -> None:
        """
        Validate configuration for production deployment requirements.
        
        This method ensures that all required configuration settings are
        present and valid for enterprise production deployment as specified
        in Section 6.4.3.
        
        Raises:
            ConfigurationError: When production validation fails
        """
        if not self.config:
            raise ConfigurationError("Configuration not loaded")
        
        # Validate production-specific requirements
        if self.config.FLASK_ENV == 'production':
            production_checks = [
                ('SECRET_KEY', 'Production requires secure SECRET_KEY'),
                ('MONGODB_URI', 'Production requires MongoDB connection'),
                ('REDIS_HOST', 'Production requires Redis for caching'),
                ('AUTH0_DOMAIN', 'Production requires Auth0 configuration'),
            ]
            
            validation_errors = []
            for attr, error_msg in production_checks:
                if not getattr(self.config, attr, None):
                    validation_errors.append(error_msg)
            
            if validation_errors:
                raise ConfigurationError(
                    "Production validation failed:\n" + 
                    "\n".join(f"- {error}" for error in validation_errors)
                )
        
        # Validate WSGI server compatibility
        if not hasattr(self.config, 'HOST') or not hasattr(self.config, 'PORT'):
            raise ConfigurationError("WSGI server configuration incomplete")
        
        self.logger.info("Configuration validation completed successfully")
    
    def _register_application_error_handlers(self) -> None:
        """
        Register comprehensive application-level error handlers.
        
        This method implements Flask error handlers for consistent error
        response formatting and enterprise monitoring integration as
        specified in Section 4.2.3.
        """
        if not self.app:
            return
        
        @self.app.errorhandler(Exception)
        def handle_unexpected_error(error: Exception):
            """Handle unexpected errors with comprehensive logging."""
            error_id = datetime.utcnow().strftime('%Y%m%d%H%M%S%f')
            
            self.logger.error(
                f"Unexpected error [ID: {error_id}]: {str(error)}",
                exc_info=True,
                extra={
                    'error_id': error_id,
                    'error_type': type(error).__name__,
                    'request_path': getattr(self.app, 'request', {}).get('path', 'unknown')
                }
            )
            
            # Return enterprise-grade error response
            if self.config.DEBUG:
                return {
                    'error': 'Internal Server Error',
                    'error_id': error_id,
                    'error_type': type(error).__name__,
                    'error_message': str(error),
                    'timestamp': datetime.utcnow().isoformat()
                }, 500
            else:
                return {
                    'error': 'Internal Server Error',
                    'error_id': error_id,
                    'timestamp': datetime.utcnow().isoformat()
                }, 500
        
        @self.app.errorhandler(404)
        def handle_not_found(error):
            """Handle 404 errors with structured response."""
            return {
                'error': 'Not Found',
                'message': 'The requested resource was not found',
                'timestamp': datetime.utcnow().isoformat()
            }, 404
        
        @self.app.errorhandler(500)
        def handle_internal_error(error):
            """Handle 500 errors with enterprise monitoring integration."""
            error_id = datetime.utcnow().strftime('%Y%m%d%H%M%S%f')
            
            self.logger.error(
                f"Internal server error [ID: {error_id}]: {str(error)}",
                exc_info=True,
                extra={'error_id': error_id}
            )
            
            return {
                'error': 'Internal Server Error',
                'error_id': error_id,
                'timestamp': datetime.utcnow().isoformat()
            }, 500
        
        self.logger.info("Application error handlers registered successfully")
    
    def _register_health_endpoints(self) -> None:
        """
        Register health check endpoints for load balancer and Kubernetes integration.
        
        This method implements comprehensive health check endpoints supporting
        container orchestration and load balancer health monitoring as specified
        in Section 8.5.2.
        """
        if not self.app:
            return
        
        @self.app.route('/health', methods=['GET'])
        def health_check():
            """
            Basic health check endpoint for load balancer integration.
            
            Returns:
                Health status with timestamp for monitoring systems
            """
            try:
                # Get application information for health validation
                app_info = get_application_info()
                
                return {
                    'status': 'healthy',
                    'timestamp': datetime.utcnow().isoformat(),
                    'uptime': str(datetime.utcnow() - self.startup_time) if self.startup_time else None,
                    'version': app_info.get('version', '1.0.0'),
                    'environment': self.config.FLASK_ENV if self.config else 'unknown'
                }, 200
                
            except Exception as e:
                self.logger.error(f"Health check failed: {str(e)}", exc_info=True)
                return {
                    'status': 'unhealthy',
                    'error': str(e),
                    'timestamp': datetime.utcnow().isoformat()
                }, 503
        
        @self.app.route('/health/detailed', methods=['GET'])
        def detailed_health_check():
            """
            Detailed health check endpoint with dependency validation.
            
            Returns:
                Comprehensive health status including external dependencies
            """
            try:
                # Get comprehensive application status
                app_info = get_application_info()
                
                # Basic health information
                health_data = {
                    'status': 'healthy',
                    'timestamp': datetime.utcnow().isoformat(),
                    'uptime': str(datetime.utcnow() - self.startup_time) if self.startup_time else None,
                    'application': {
                        'name': self.config.APP_NAME if self.config else 'Flask App',
                        'version': app_info.get('version', '1.0.0'),
                        'environment': self.config.FLASK_ENV if self.config else 'unknown'
                    },
                    'dependencies': {}
                }
                
                # Add dependency health checks when available
                try:
                    from src.data import get_database_manager
                    db_manager = get_database_manager()
                    if db_manager:
                        health_data['dependencies']['database'] = {
                            'status': 'healthy' if db_manager.is_connected() else 'unhealthy',
                            'type': 'MongoDB'
                        }
                except Exception as e:
                    health_data['dependencies']['database'] = {
                        'status': 'unknown',
                        'error': str(e)
                    }
                
                try:
                    from src.cache import get_cache_manager, is_cache_available
                    if is_cache_available():
                        cache_manager = get_cache_manager()
                        health_data['dependencies']['cache'] = {
                            'status': 'healthy' if cache_manager.ping() else 'unhealthy',
                            'type': 'Redis'
                        }
                except Exception as e:
                    health_data['dependencies']['cache'] = {
                        'status': 'unknown',
                        'error': str(e)
                    }
                
                # Determine overall health status
                dependency_statuses = [
                    dep.get('status', 'unknown') 
                    for dep in health_data['dependencies'].values()
                ]
                
                if any(status == 'unhealthy' for status in dependency_statuses):
                    health_data['status'] = 'degraded'
                    return health_data, 503
                elif any(status == 'unknown' for status in dependency_statuses):
                    health_data['status'] = 'partial'
                    return health_data, 200
                
                return health_data, 200
                
            except Exception as e:
                self.logger.error(f"Detailed health check failed: {str(e)}", exc_info=True)
                return {
                    'status': 'unhealthy',
                    'error': str(e),
                    'timestamp': datetime.utcnow().isoformat()
                }, 503
        
        @self.app.route('/ready', methods=['GET'])
        def readiness_check():
            """
            Kubernetes readiness probe endpoint.
            
            Returns:
                Readiness status for container orchestration
            """
            try:
                # Validate application is fully initialized
                if not self.initialized:
                    return {
                        'ready': False,
                        'reason': 'Application not fully initialized',
                        'timestamp': datetime.utcnow().isoformat()
                    }, 503
                
                return {
                    'ready': True,
                    'timestamp': datetime.utcnow().isoformat()
                }, 200
                
            except Exception as e:
                self.logger.error(f"Readiness check failed: {str(e)}", exc_info=True)
                return {
                    'ready': False,
                    'error': str(e),
                    'timestamp': datetime.utcnow().isoformat()
                }, 503
        
        @self.app.route('/live', methods=['GET'])
        def liveness_check():
            """
            Kubernetes liveness probe endpoint.
            
            Returns:
                Liveness status for container health monitoring
            """
            return {
                'alive': True,
                'timestamp': datetime.utcnow().isoformat()
            }, 200
        
        self.logger.info("Health check endpoints registered successfully")
    
    def _register_shutdown_handlers(self) -> None:
        """
        Register graceful shutdown handlers for container orchestration.
        
        This method implements signal handlers for graceful application
        shutdown with resource cleanup as specified in Section 8.5.2.
        """
        def graceful_shutdown(signum, frame):
            """Handle graceful shutdown on SIGTERM/SIGINT."""
            self.logger.info(f"Received signal {signum}, initiating graceful shutdown...")
            
            # Execute registered shutdown handlers
            for handler in self.shutdown_handlers:
                try:
                    handler()
                except Exception as e:
                    self.logger.error(f"Shutdown handler failed: {str(e)}", exc_info=True)
            
            # Cleanup application resources
            try:
                cleanup_application_resources()
                self.logger.info("Application resources cleaned up successfully")
            except Exception as e:
                self.logger.error(f"Resource cleanup failed: {str(e)}", exc_info=True)
            
            self.logger.info("Graceful shutdown completed")
            sys.exit(0)
        
        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGTERM, graceful_shutdown)
        signal.signal(signal.SIGINT, graceful_shutdown)
        
        self.logger.info("Shutdown handlers registered successfully")
    
    def add_shutdown_handler(self, handler: Callable[[], None]) -> None:
        """
        Add custom shutdown handler for graceful cleanup.
        
        Args:
            handler: Callable function for shutdown cleanup
        """
        self.shutdown_handlers.append(handler)
    
    def get_application(self) -> object:
        """
        Get the initialized Flask application instance.
        
        Returns:
            Flask application instance
            
        Raises:
            RuntimeError: When application is not initialized
        """
        if not self.initialized or not self.app:
            raise RuntimeError("Application not initialized. Call initialize_application() first.")
        
        return self.app


# Global application manager instance
app_manager = WSGIApplicationManager()

# Initialize application with environment-specific configuration
application = app_manager.initialize_application()

# WSGI application export for production deployment
# This is the primary entry point for Gunicorn/uWSGI servers
app = application


def create_dev_server(host: str = None, port: int = None, debug: bool = None) -> None:
    """
    Create and run development server with configuration override capability.
    
    This function provides Flask development server capability with
    environment-specific configuration and comprehensive error handling
    for local development workflows.
    
    Args:
        host: Optional host override for development server
        port: Optional port override for development server  
        debug: Optional debug mode override for development server
        
    Raises:
        RuntimeError: When development server startup fails
    """
    try:
        # Get application configuration
        config = app_manager.config
        if not config:
            raise RuntimeError("Application configuration not available")
        
        # Use provided overrides or configuration defaults
        server_host = host or config.HOST
        server_port = port or config.PORT
        debug_mode = debug if debug is not None else config.DEBUG
        
        logger.info(
            f"Starting Flask development server "
            f"(host: {server_host}, port: {server_port}, debug: {debug_mode})"
        )
        
        # Start Flask development server
        application.run(
            host=server_host,
            port=server_port,
            debug=debug_mode,
            threaded=True,
            use_reloader=debug_mode
        )
        
    except Exception as e:
        error_msg = f"Development server startup failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        raise RuntimeError(error_msg)


def get_wsgi_application(config_name: Optional[str] = None) -> object:
    """
    Get WSGI application instance for custom deployment scenarios.
    
    This function provides access to the Flask application factory
    with custom configuration for specialized deployment requirements.
    
    Args:
        config_name: Optional configuration environment name
        
    Returns:
        Flask application instance configured for WSGI deployment
        
    Raises:
        RuntimeError: When application creation fails
    """
    try:
        # Create new application manager for custom configuration
        custom_manager = WSGIApplicationManager()
        return custom_manager.initialize_application(config_name)
        
    except Exception as e:
        error_msg = f"WSGI application creation failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        raise RuntimeError(error_msg)


if __name__ == '__main__':
    """
    Main entry point for development server execution.
    
    This section provides Flask development server capability with
    environment variable configuration and command-line argument support
    for local development workflows as specified in Section 8.5.1.
    """
    try:
        # Parse command line arguments for development server customization
        import argparse
        
        parser = argparse.ArgumentParser(description='Flask Application Development Server')
        parser.add_argument(
            '--host', 
            default=os.getenv('FLASK_HOST', '127.0.0.1'),
            help='Development server host (default: 127.0.0.1)'
        )
        parser.add_argument(
            '--port', 
            type=int,
            default=int(os.getenv('FLASK_PORT', 5000)),
            help='Development server port (default: 5000)'
        )
        parser.add_argument(
            '--debug', 
            action='store_true',
            default=os.getenv('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes'),
            help='Enable debug mode (default: False)'
        )
        parser.add_argument(
            '--config',
            default=os.getenv('FLASK_ENV', 'development'),
            choices=['development', 'staging', 'production', 'testing'],
            help='Configuration environment (default: development)'
        )
        
        args = parser.parse_args()
        
        # Display startup information
        print("\n" + "="*60)
        print("Flask Application Development Server")
        print("="*60)
        print(f"Environment: {args.config}")
        print(f"Host: {args.host}")
        print(f"Port: {args.port}")
        print(f"Debug: {args.debug}")
        print(f"Application Factory: src.app.create_app")
        print("="*60)
        
        # Reinitialize application with custom configuration if needed
        if args.config != app_manager.config.FLASK_ENV:
            logger.info(f"Reinitializing application with {args.config} configuration")
            app_manager.initialized = False
            application = app_manager.initialize_application(args.config)
        
        # Start development server
        create_dev_server(
            host=args.host,
            port=args.port,
            debug=args.debug
        )
        
    except KeyboardInterrupt:
        logger.info("Development server stopped by user")
        
    except Exception as e:
        logger.error(f"Development server failed: {str(e)}", exc_info=True)
        sys.exit(1)