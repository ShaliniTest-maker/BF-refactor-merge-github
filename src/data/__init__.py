"""
Database Access Layer Package Initialization

This module provides centralized PyMongo and Motor client setup, connection pool configuration,
and Flask application integration for the Node.js to Python migration. Exposes database clients
and core data access functionality to the Flask application factory for seamless database
connectivity with performance monitoring compliance.

Key Features:
- PyMongo 4.5+ synchronous database client setup with optimized connection pooling
- Motor 3.3+ asynchronous database client configuration for high-performance operations
- Flask application factory pattern integration with database service registration
- Centralized database configuration management with environment-specific settings
- Performance monitoring integration ensuring ≤10% variance from Node.js baseline
- Database health check functionality for monitoring and observability
- Comprehensive error handling with circuit breaker patterns and retry logic
- Prometheus metrics collection for enterprise monitoring infrastructure

Architecture Integration:
- Integrates with Flask application factory via init_app() pattern
- Provides database client instances accessible throughout Flask application context
- Supports environment-specific configuration (development, testing, production)
- Enables structured logging for database operations and performance events
- Facilitates seamless integration with business logic and API endpoints

Technical Requirements Compliance:
- Section 0.1.2: PyMongo 4.5+ and Motor 3.3+ driver implementation per data access components
- Section 0.1.2: Connection pool management with equivalent Node.js patterns
- Section 6.1.1: Flask application factory pattern integration per core services architecture
- Section 0.1.1: Performance monitoring to ensure ≤10% variance from Node.js baseline
- Section 5.2.5: Database access layer with comprehensive CRUD operations and monitoring
- Section 6.2.4: Performance optimization with connection pooling and health monitoring
- Section 6.2.2: Prometheus metrics collection for data management compliance monitoring

Usage Examples:
    # Basic initialization in Flask application factory
    from src.data import init_database_services, get_mongodb_manager
    
    def create_app():
        app = Flask(__name__)
        
        # Initialize database services
        init_database_services(app, environment='production')
        
        # Access database manager in routes
        @app.route('/api/data')
        def get_data():
            db_manager = get_mongodb_manager()
            return db_manager.find_many('collection_name', {})
    
    # Async operations with Motor
    from src.data import get_async_mongodb_manager
    
    async def async_data_operation():
        async_manager = get_async_mongodb_manager()
        result = await async_manager.find_one('collection', {'_id': object_id})
        return result
    
    # Health monitoring integration
    from src.data import get_database_health_status
    
    @app.route('/health/database')
    def database_health():
        return get_database_health_status()

References:
- Section 0.1.2 DATA ACCESS COMPONENTS: MongoDB driver migration and connection pooling
- Section 6.1.1 FLASK APPLICATION FACTORY: Database service integration patterns  
- Section 5.2.5 DATABASE ACCESS LAYER: Comprehensive database operations and monitoring
- Section 6.2.4 PERFORMANCE OPTIMIZATION: Connection pool configuration and monitoring
- Section 0.1.1 PRIMARY OBJECTIVE: ≤10% performance variance compliance requirements
"""

import asyncio
import logging
import sys
import warnings
from typing import Any, Dict, List, Optional, Union, Callable
from datetime import datetime, timezone
from contextlib import contextmanager

# Flask integration
try:
    from flask import Flask, current_app, g
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    Flask = None

# Database drivers and core functionality
import pymongo
from pymongo import MongoClient
from pymongo.database import Database
from pymongo.collection import Collection

try:
    from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase, AsyncIOMotorCollection
    MOTOR_AVAILABLE = True
except ImportError:
    MOTOR_AVAILABLE = False

# Core database components
from src.config.database import (
    DatabaseConfig, 
    DatabaseConnectionError,
    init_database_config,
    get_database_config,
    get_mongodb_client,
    get_motor_client,
    get_redis_client,
    get_database,
    get_async_database
)

from src.data.mongodb import (
    MongoDBManager,
    AsyncMongoDBManager,
    create_mongodb_manager,
    create_async_mongodb_manager,
    init_mongodb_manager,
    init_async_mongodb_manager,
    get_mongodb_manager,
    get_async_mongodb_manager,
    validate_object_id
)

from src.data.monitoring import (
    DatabaseMonitoringManager,
    DatabaseMetricsCollector,
    monitor_database_operation,
    monitor_async_database_operation,
    monitor_database_transaction
)

from src.data.exceptions import (
    DatabaseException,
    ConnectionException,
    TimeoutException,
    TransactionException,
    QueryException,
    ResourceException,
    DatabaseErrorSeverity,
    DatabaseOperationType,
    DatabaseErrorCategory,
    with_database_retry,
    handle_database_error,
    mongodb_circuit_breaker
)

# Configure module logger
logger = logging.getLogger(__name__)


class DatabaseServices:
    """
    Centralized database services container providing comprehensive database functionality
    for Flask application integration with performance monitoring compliance.
    
    This class manages the lifecycle of database services including:
    - PyMongo 4.5+ synchronous database operations with connection pooling
    - Motor 3.3+ asynchronous database operations for high-performance scenarios
    - Database configuration management with environment-specific settings
    - Performance monitoring and metrics collection for baseline compliance
    - Health checking and observability for enterprise monitoring integration
    - Circuit breaker patterns and error handling for system resilience
    
    Features:
    - Flask application factory pattern support via init_app()
    - Environment-specific database configuration (development, testing, production)
    - Connection pool optimization per Section 6.1.3 resource optimization patterns
    - Performance monitoring ensuring ≤10% variance compliance per Section 0.1.1
    - Comprehensive error handling with circuit breaker integration per Section 4.2.3
    - Prometheus metrics collection for enterprise monitoring per Section 6.2.2
    """
    
    def __init__(self, environment: str = 'development', monitoring_enabled: bool = True):
        """
        Initialize database services with comprehensive configuration.
        
        Args:
            environment: Target environment ('development', 'testing', 'production')
            monitoring_enabled: Enable performance monitoring and metrics collection
        """
        self.environment = environment
        self.monitoring_enabled = monitoring_enabled
        self._initialized = False
        self._app = None
        
        # Core database components
        self._database_config: Optional[DatabaseConfig] = None
        self._mongodb_manager: Optional[MongoDBManager] = None
        self._async_mongodb_manager: Optional[AsyncMongoDBManager] = None
        self._monitoring_manager: Optional[DatabaseMonitoringManager] = None
        
        # Flask integration state
        self._flask_integrated = False
        
        logger.info(
            "Database services initialized",
            environment=environment,
            monitoring_enabled=monitoring_enabled,
            pymongo_available=True,
            motor_available=MOTOR_AVAILABLE,
            flask_available=FLASK_AVAILABLE
        )
    
    def init_app(self, app: Flask) -> None:
        """
        Initialize database services with Flask application using factory pattern.
        
        Implements Flask application factory integration per Section 6.1.1 core services
        architecture, providing database client registration and configuration management.
        
        Args:
            app: Flask application instance
            
        Raises:
            RuntimeError: If Flask is not available or initialization fails
        """
        if not FLASK_AVAILABLE:
            raise RuntimeError("Flask is not available for database services integration")
        
        if self._flask_integrated:
            logger.warning("Database services already integrated with Flask application")
            return
        
        try:
            self._app = app
            
            # Store database services instance in Flask app config
            if not hasattr(app, 'extensions'):
                app.extensions = {}
            app.extensions['database_services'] = self
            
            # Initialize database configuration
            self._initialize_database_config()
            
            # Initialize MongoDB managers
            self._initialize_mongodb_managers()
            
            # Initialize monitoring if enabled
            if self.monitoring_enabled:
                self._initialize_monitoring()
            
            # Register Flask teardown handlers
            self._register_teardown_handlers(app)
            
            # Register health check endpoints
            self._register_health_endpoints(app)
            
            self._flask_integrated = True
            self._initialized = True
            
            logger.info(
                "Database services integrated with Flask application",
                app_name=app.name,
                environment=self.environment,
                monitoring_enabled=self.monitoring_enabled
            )
            
        except Exception as e:
            error_msg = f"Failed to initialize database services with Flask: {str(e)}"
            logger.error(error_msg, error=str(e), error_type=type(e).__name__)
            raise RuntimeError(error_msg) from e
    
    def _initialize_database_config(self) -> None:
        """Initialize database configuration with environment-specific settings."""
        try:
            self._database_config = init_database_config(environment=self.environment)
            
            logger.info(
                "Database configuration initialized",
                environment=self.environment,
                mongodb_database=self._database_config.mongodb_database
            )
            
        except Exception as e:
            error_msg = f"Failed to initialize database configuration: {str(e)}"
            logger.error(error_msg)
            raise DatabaseConnectionError(error_msg) from e
    
    def _initialize_mongodb_managers(self) -> None:
        """Initialize PyMongo and Motor database managers with optimized configuration."""
        try:
            # Initialize synchronous MongoDB manager
            database_name = self._database_config.mongodb_database if self._database_config else None
            self._mongodb_manager = init_mongodb_manager(
                database_name=database_name,
                monitoring_enabled=self.monitoring_enabled
            )
            
            logger.info(
                "PyMongo synchronous manager initialized",
                database=database_name,
                monitoring_enabled=self.monitoring_enabled
            )
            
            # Initialize asynchronous MongoDB manager if Motor is available
            if MOTOR_AVAILABLE:
                # Note: Async manager initialization requires asyncio context
                # This will be handled by the get_async_mongodb_manager() function
                # when first accessed in an async context
                logger.info("Motor async manager setup prepared (requires async context for initialization)")
            else:
                logger.warning("Motor async driver not available - async operations disabled")
            
        except Exception as e:
            error_msg = f"Failed to initialize MongoDB managers: {str(e)}"
            logger.error(error_msg)
            raise DatabaseConnectionError(error_msg) from e
    
    def _initialize_monitoring(self) -> None:
        """Initialize database monitoring and metrics collection."""
        try:
            self._monitoring_manager = DatabaseMonitoringManager()
            
            # Register MongoDB clients for monitoring
            if self._mongodb_manager:
                self._monitoring_manager.register_pymongo_client(self._mongodb_manager.client)
            
            # Motor client registration handled when async manager is initialized
            
            logger.info("Database monitoring initialized successfully")
            
        except Exception as e:
            logger.warning(f"Failed to initialize database monitoring: {str(e)}")
            self._monitoring_manager = None
    
    def _register_teardown_handlers(self, app: Flask) -> None:
        """Register Flask teardown handlers for database cleanup."""
        @app.teardown_appcontext
        def close_database_connections(error):
            """Close database connections on application context teardown."""
            try:
                # Close database config connections
                if self._database_config:
                    self._database_config.close_connections()
                
                logger.debug("Database connections closed on teardown")
                
            except Exception as e:
                logger.error(f"Error closing database connections: {str(e)}")
        
        logger.debug("Flask teardown handlers registered")
    
    def _register_health_endpoints(self, app: Flask) -> None:
        """Register database health check endpoints for monitoring integration."""
        @app.route('/health/database')
        def database_health_check():
            """Database health check endpoint for monitoring integration."""
            try:
                health_status = self.get_health_status()
                
                # Determine overall status
                overall_status = 'healthy'
                if any(
                    service.get('status') == 'unhealthy' 
                    for service in health_status.get('services', {}).values()
                ):
                    overall_status = 'unhealthy'
                
                return {
                    'status': overall_status,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'details': health_status
                }, 200 if overall_status == 'healthy' else 503
                
            except Exception as e:
                logger.error(f"Health check failed: {str(e)}")
                return {
                    'status': 'unhealthy',
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'error': str(e)
                }, 503
        
        @app.route('/health/database/detailed')
        def detailed_database_health():
            """Detailed database health check with performance metrics."""
            try:
                health_status = self.get_health_status()
                performance_metrics = self.get_performance_metrics()
                
                return {
                    'health': health_status,
                    'performance': performance_metrics,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
                
            except Exception as e:
                logger.error(f"Detailed health check failed: {str(e)}")
                return {'error': str(e)}, 500
        
        logger.debug("Database health check endpoints registered")
    
    @property
    def database_config(self) -> Optional[DatabaseConfig]:
        """Get database configuration instance."""
        return self._database_config
    
    @property
    def mongodb_manager(self) -> Optional[MongoDBManager]:
        """Get PyMongo synchronous database manager."""
        return self._mongodb_manager
    
    @property
    def async_mongodb_manager(self) -> Optional[AsyncMongoDBManager]:
        """Get Motor asynchronous database manager."""
        return self._async_mongodb_manager
    
    @property
    def monitoring_manager(self) -> Optional[DatabaseMonitoringManager]:
        """Get database monitoring manager."""
        return self._monitoring_manager
    
    @property
    def is_initialized(self) -> bool:
        """Check if database services are fully initialized."""
        return self._initialized
    
    @property
    def flask_integrated(self) -> bool:
        """Check if database services are integrated with Flask."""
        return self._flask_integrated
    
    def get_health_status(self) -> Dict[str, Any]:
        """
        Get comprehensive database health status for monitoring integration.
        
        Returns:
            Dict[str, Any]: Complete health status including all database services
        """
        health_status = {
            'environment': self.environment,
            'initialized': self._initialized,
            'flask_integrated': self._flask_integrated,
            'monitoring_enabled': self.monitoring_enabled,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'services': {}
        }
        
        try:
            # Database configuration health
            if self._database_config:
                health_status['services']['database_config'] = self._database_config.health_check()
            
            # MongoDB manager health
            if self._mongodb_manager:
                health_status['services']['mongodb_sync'] = self._mongodb_manager.health_check()
            
            # Async MongoDB manager health (if available)
            if self._async_mongodb_manager:
                # Note: Async health check would require asyncio context
                health_status['services']['mongodb_async'] = {
                    'status': 'available',
                    'note': 'async health check requires asyncio context'
                }
            
            # Monitoring manager health
            if self._monitoring_manager:
                health_status['services']['monitoring'] = {
                    'status': 'healthy',
                    'enabled': True
                }
            else:
                health_status['services']['monitoring'] = {
                    'status': 'disabled',
                    'enabled': False
                }
            
        except Exception as e:
            logger.error(f"Error getting health status: {str(e)}")
            health_status['error'] = str(e)
        
        return health_status
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """
        Get database performance metrics for baseline compliance monitoring.
        
        Returns:
            Dict[str, Any]: Performance metrics and statistics
        """
        metrics = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'environment': self.environment,
            'monitoring_enabled': self.monitoring_enabled,
            'mongodb_sync': {},
            'mongodb_async': {},
            'connection_pools': {}
        }
        
        try:
            # PyMongo synchronous metrics
            if self._mongodb_manager:
                metrics['mongodb_sync'] = self._mongodb_manager.get_performance_metrics()
            
            # Connection pool metrics
            if self._database_config:
                metrics['connection_pools'] = self._database_config.get_connection_info()
            
            # Note: Async metrics would require asyncio context
            
        except Exception as e:
            logger.error(f"Error getting performance metrics: {str(e)}")
            metrics['error'] = str(e)
        
        return metrics


# Global database services instance for application use
_database_services: Optional[DatabaseServices] = None


def init_database_services(app: Optional[Flask] = None, environment: str = 'development', 
                          monitoring_enabled: bool = True) -> DatabaseServices:
    """
    Initialize global database services instance with Flask application integration.
    
    Implements centralized database services initialization supporting Flask application
    factory pattern per Section 6.1.1 core services architecture.
    
    Args:
        app: Flask application instance (optional)
        environment: Target environment ('development', 'testing', 'production')
        monitoring_enabled: Enable performance monitoring and metrics collection
        
    Returns:
        DatabaseServices: Global database services instance
        
    Raises:
        RuntimeError: If initialization fails or Flask integration errors occur
    """
    global _database_services
    
    try:
        # Initialize database services
        _database_services = DatabaseServices(
            environment=environment,
            monitoring_enabled=monitoring_enabled
        )
        
        # Integrate with Flask application if provided
        if app is not None:
            _database_services.init_app(app)
        
        logger.info(
            "Global database services initialized",
            environment=environment,
            monitoring_enabled=monitoring_enabled,
            flask_integrated=app is not None
        )
        
        return _database_services
        
    except Exception as e:
        error_msg = f"Failed to initialize database services: {str(e)}"
        logger.error(error_msg)
        raise RuntimeError(error_msg) from e


def get_database_services() -> DatabaseServices:
    """
    Get global database services instance.
    
    Returns:
        DatabaseServices: Global database services instance
        
    Raises:
        RuntimeError: If database services not initialized
    """
    if _database_services is None:
        raise RuntimeError(
            "Database services not initialized. "
            "Call init_database_services() first."
        )
    return _database_services


def get_current_database_services() -> DatabaseServices:
    """
    Get database services from current Flask application context.
    
    Returns:
        DatabaseServices: Database services from Flask application extensions
        
    Raises:
        RuntimeError: If not in Flask context or services not initialized
    """
    if not FLASK_AVAILABLE:
        raise RuntimeError("Flask not available for context access")
    
    try:
        app = current_app
        if 'database_services' not in app.extensions:
            raise RuntimeError("Database services not initialized in Flask application")
        
        return app.extensions['database_services']
        
    except Exception as e:
        raise RuntimeError(f"Failed to get database services from Flask context: {str(e)}")


# Convenience functions for direct database access

def get_mongodb_client() -> MongoClient:
    """
    Get PyMongo synchronous client from global database services.
    
    Returns:
        MongoClient: Configured PyMongo client instance
    """
    services = get_database_services()
    if services.mongodb_manager:
        return services.mongodb_manager.client
    else:
        # Fallback to direct config access
        return get_mongodb_client()


def get_motor_client() -> Optional['AsyncIOMotorClient']:
    """
    Get Motor asynchronous client from global database services.
    
    Returns:
        Optional[AsyncIOMotorClient]: Configured Motor async client instance or None
    """
    if not MOTOR_AVAILABLE:
        return None
    
    services = get_database_services()
    if services.async_mongodb_manager:
        return services.async_mongodb_manager.motor_client
    else:
        # Fallback to direct config access
        return get_motor_client()


def get_database(database_name: Optional[str] = None) -> Database:
    """
    Get MongoDB database instance from global database services.
    
    Args:
        database_name: Database name (defaults to configured database)
        
    Returns:
        Database: PyMongo database instance
    """
    services = get_database_services()
    if services.mongodb_manager:
        return services.mongodb_manager.database if database_name is None else services.mongodb_manager.client[database_name]
    else:
        # Fallback to direct config access
        return get_database(database_name)


def get_async_database(database_name: Optional[str] = None) -> Optional['AsyncIOMotorDatabase']:
    """
    Get async MongoDB database instance from global database services.
    
    Args:
        database_name: Database name (defaults to configured database)
        
    Returns:
        Optional[AsyncIOMotorDatabase]: Motor async database instance or None
    """
    if not MOTOR_AVAILABLE:
        return None
    
    services = get_database_services()
    if services.async_mongodb_manager:
        return services.async_mongodb_manager.database if database_name is None else services.async_mongodb_manager.motor_client[database_name]
    else:
        # Fallback to direct config access
        return get_async_database(database_name)


def get_collection(collection_name: str, database_name: Optional[str] = None) -> Collection:
    """
    Get MongoDB collection instance from global database services.
    
    Args:
        collection_name: Collection name
        database_name: Database name (defaults to configured database)
        
    Returns:
        Collection: PyMongo collection instance
    """
    services = get_database_services()
    if services.mongodb_manager:
        return services.mongodb_manager.get_collection(collection_name)
    else:
        # Fallback to direct access
        db = get_database(database_name)
        return db[collection_name]


def get_async_collection(collection_name: str, database_name: Optional[str] = None) -> Optional['AsyncIOMotorCollection']:
    """
    Get async MongoDB collection instance from global database services.
    
    Args:
        collection_name: Collection name
        database_name: Database name (defaults to configured database)
        
    Returns:
        Optional[AsyncIOMotorCollection]: Motor async collection instance or None
    """
    if not MOTOR_AVAILABLE:
        return None
    
    services = get_database_services()
    if services.async_mongodb_manager:
        return services.async_mongodb_manager.get_collection(collection_name)
    else:
        # Fallback to direct access
        db = get_async_database(database_name)
        return db[collection_name] if db else None


# Health monitoring functions

def get_database_health_status() -> Dict[str, Any]:
    """
    Get comprehensive database health status for monitoring integration.
    
    Returns:
        Dict[str, Any]: Complete health status including all database services
    """
    try:
        services = get_database_services()
        return services.get_health_status()
    except Exception as e:
        return {
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }


def get_database_performance_metrics() -> Dict[str, Any]:
    """
    Get database performance metrics for baseline compliance monitoring.
    
    Returns:
        Dict[str, Any]: Performance metrics and statistics
    """
    try:
        services = get_database_services()
        return services.get_performance_metrics()
    except Exception as e:
        return {
            'error': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }


# Transaction management convenience functions

@contextmanager
def database_transaction(read_concern=None, write_concern=None, read_preference=None):
    """
    Context manager for database transactions using global services.
    
    Args:
        read_concern: Read concern for transaction
        write_concern: Write concern for transaction
        read_preference: Read preference for transaction
        
    Yields:
        session: MongoDB session for transaction operations
        
    Example:
        with database_transaction() as session:
            # Perform database operations within transaction
            pass
    """
    services = get_database_services()
    if not services.mongodb_manager:
        raise RuntimeError("MongoDB manager not available for transactions")
    
    with services.mongodb_manager.transaction(
        read_concern=read_concern,
        write_concern=write_concern,
        read_preference=read_preference
    ) as session:
        yield session


# Package public interface
__all__ = [
    # Core classes
    'DatabaseServices',
    
    # Initialization functions
    'init_database_services',
    'get_database_services',
    'get_current_database_services',
    
    # Database client access
    'get_mongodb_client',
    'get_motor_client',
    'get_database',
    'get_async_database',
    'get_collection',
    'get_async_collection',
    
    # Manager access
    'get_mongodb_manager',
    'get_async_mongodb_manager',
    
    # Health monitoring
    'get_database_health_status',
    'get_database_performance_metrics',
    
    # Transaction management
    'database_transaction',
    
    # Utilities
    'validate_object_id',
    
    # Exception classes
    'DatabaseException',
    'ConnectionException',
    'TimeoutException',
    'TransactionException',
    'QueryException',
    'ResourceException',
    'DatabaseConnectionError',
    
    # Enums
    'DatabaseErrorSeverity',
    'DatabaseOperationType',
    'DatabaseErrorCategory',
    
    # Decorators and utilities
    'with_database_retry',
    'handle_database_error',
    'mongodb_circuit_breaker',
    'monitor_database_operation',
    'monitor_async_database_operation',
    'monitor_database_transaction',
    
    # Availability flags
    'MOTOR_AVAILABLE',
    'FLASK_AVAILABLE'
]


# Package version and metadata
__version__ = '1.0.0'
__author__ = 'Database Migration Team'
__description__ = 'Database access layer for Node.js to Python Flask migration'


# Initialize warnings for missing dependencies
if not MOTOR_AVAILABLE:
    warnings.warn(
        "Motor async driver not available. Async database operations disabled.",
        ImportWarning,
        stacklevel=2
    )

if not FLASK_AVAILABLE:
    warnings.warn(
        "Flask not available. Flask integration features disabled.",
        ImportWarning,
        stacklevel=2
    )


# Module-level initialization logging
logger.info(
    "Database access layer package initialized",
    pymongo_available=True,
    motor_available=MOTOR_AVAILABLE,
    flask_available=FLASK_AVAILABLE,
    version=__version__
)