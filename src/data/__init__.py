"""
Database access layer package initialization providing centralized PyMongo and Motor client setup.

This package initializes and configures the complete database access infrastructure for the Flask application,
implementing PyMongo 4.5+ and Motor 3.3+ drivers with connection pooling, monitoring integration, and health
checks. Provides seamless Flask application factory integration for comprehensive database connectivity.

Key Components:
- PyMongo 4.5+ synchronous client with connection pooling and monitoring
- Motor 3.3+ async client for high-performance concurrent operations  
- Prometheus metrics collection and performance monitoring integration
- Database health checking and circuit breaker patterns
- Flask application factory registration and configuration
- Connection pool optimization for ≤10% variance from Node.js baseline

Implements requirements from:
- Section 0.1.2: Database access layer must implement PyMongo 4.5+ and Motor 3.3+ drivers
- Section 0.1.2: Connection pool management with equivalent patterns for data access components
- Section 6.1.1: Database layer must integrate with Flask application factory pattern
- Section 0.1.1: Performance monitoring to ensure ≤10% variance from Node.js baseline
- Section 6.2.4: Performance optimization with connection pooling and monitoring
- Section 6.2.2: Data management with PyMongo event monitoring for Prometheus metrics
"""

import logging
import os
import time
from typing import Optional, Dict, Any, Union, List, Tuple
from threading import Lock
from dataclasses import dataclass, field
from contextlib import contextmanager

import structlog
from flask import Flask, g, current_app
from motor.motor_asyncio import AsyncIOMotorClient

# Import core database modules
from .mongodb import (
    MongoDBClient,
    MongoDBConfig,
    QueryResult,
    create_mongodb_client,
    get_object_id,
    serialize_for_json,
    DEFAULT_CONNECTION_TIMEOUT_MS,
    DEFAULT_SERVER_SELECTION_TIMEOUT_MS,
    DEFAULT_SOCKET_TIMEOUT_MS,
    DEFAULT_MAX_POOL_SIZE,
    DEFAULT_MIN_POOL_SIZE,
    DEFAULT_MAX_IDLE_TIME_MS,
    DEFAULT_WAIT_QUEUE_TIMEOUT_MS,
    DEFAULT_TRANSACTION_TIMEOUT_SECONDS,
    MAX_TRANSACTION_RETRY_ATTEMPTS,
    DEFAULT_BATCH_SIZE,
    MAX_BATCH_SIZE
)

from .motor_async import (
    MotorAsyncDatabase,
    initialize_motor_client,
    get_motor_database,
    close_motor_client,
    DocumentType,
    FilterType,
    UpdateType,
    ProjectionType
)

from .monitoring import (
    DatabaseMetrics,
    DatabaseMonitoringListener,
    ConnectionPoolMonitoringListener,
    ServerMonitoringListener,
    MotorMonitoringIntegration,
    DatabaseHealthChecker,
    initialize_database_monitoring,
    get_database_monitoring_components,
    get_database_metrics_exposition,
    get_database_metrics_content_type,
    monitor_transaction,
    database_registry,
    PERFORMANCE_VARIANCE_THRESHOLD,
    NODEJS_BASELINE_PERCENTILES
)

# Configure structured logger
logger = structlog.get_logger(__name__)

# Global database client instances for Flask integration
_mongodb_client: Optional[MongoDBClient] = None
_motor_client: Optional[AsyncIOMotorClient] = None
_monitoring_components: Optional[Dict[str, Any]] = None
_database_lock = Lock()


@dataclass
class DatabasePackageConfig:
    """
    Database package configuration container for comprehensive database initialization.
    
    Centralizes all database configuration parameters including MongoDB connection settings,
    Motor async client configuration, monitoring integration options, and Flask application
    factory integration parameters.
    """
    
    # MongoDB connection configuration
    mongodb_uri: str = field(default_factory=lambda: os.getenv('MONGODB_URI', 'mongodb://localhost:27017'))
    database_name: str = field(default_factory=lambda: os.getenv('DATABASE_NAME', 'flask_app'))
    
    # Connection pool configuration
    max_pool_size: int = field(default=DEFAULT_MAX_POOL_SIZE)
    min_pool_size: int = field(default=DEFAULT_MIN_POOL_SIZE)
    max_idle_time_ms: int = field(default=DEFAULT_MAX_IDLE_TIME_MS)
    wait_queue_timeout_ms: int = field(default=DEFAULT_WAIT_QUEUE_TIMEOUT_MS)
    
    # Timeout configuration
    connection_timeout_ms: int = field(default=DEFAULT_CONNECTION_TIMEOUT_MS)
    server_selection_timeout_ms: int = field(default=DEFAULT_SERVER_SELECTION_TIMEOUT_MS)
    socket_timeout_ms: int = field(default=DEFAULT_SOCKET_TIMEOUT_MS)
    
    # Performance and monitoring configuration
    enable_monitoring: bool = field(default=True)
    enable_health_checks: bool = field(default=True)
    performance_variance_threshold: float = field(default=PERFORMANCE_VARIANCE_THRESHOLD)
    
    # Motor async configuration
    enable_motor_async: bool = field(default=True)
    motor_max_pool_size: int = field(default=100)
    motor_min_pool_size: int = field(default=10)
    
    # Flask integration configuration
    flask_config_key: str = field(default='DATABASE_CONFIG')
    health_check_endpoint: str = field(default='/health/database')
    metrics_endpoint: str = field(default='/metrics')
    
    def to_mongodb_config(self) -> MongoDBConfig:
        """Convert to MongoDBConfig for PyMongo client initialization."""
        return MongoDBConfig(
            uri=self.mongodb_uri,
            database_name=self.database_name,
            max_pool_size=self.max_pool_size,
            min_pool_size=self.min_pool_size,
            max_idle_time_ms=self.max_idle_time_ms,
            wait_queue_timeout_ms=self.wait_queue_timeout_ms,
            connection_timeout_ms=self.connection_timeout_ms,
            server_selection_timeout_ms=self.server_selection_timeout_ms,
            socket_timeout_ms=self.socket_timeout_ms,
            enable_monitoring=self.enable_monitoring
        )
    
    def get_motor_client_options(self) -> Dict[str, Any]:
        """Get Motor async client configuration options."""
        return {
            'maxPoolSize': self.motor_max_pool_size,
            'minPoolSize': self.motor_min_pool_size,
            'maxIdleTimeMS': self.max_idle_time_ms,
            'waitQueueTimeoutMS': self.wait_queue_timeout_ms,
            'serverSelectionTimeoutMS': self.server_selection_timeout_ms,
            'socketTimeoutMS': self.socket_timeout_ms,
            'connectTimeoutMS': self.connection_timeout_ms,
            'retryWrites': True,
            'retryReads': True,
            'appName': 'Flask-Migration-App-Async'
        }


class DatabaseManager:
    """
    Centralized database management for Flask application integration.
    
    Provides comprehensive database client lifecycle management, monitoring integration,
    health checking, and Flask application factory pattern support. Manages both PyMongo
    synchronous and Motor async clients with connection pooling optimization.
    """
    
    def __init__(self, config: Optional[DatabasePackageConfig] = None):
        """
        Initialize database manager with configuration and monitoring setup.
        
        Args:
            config: Database package configuration (creates default if not provided)
        """
        self.config = config or DatabasePackageConfig()
        self._mongodb_client: Optional[MongoDBClient] = None
        self._motor_client: Optional[AsyncIOMotorClient] = None
        self._motor_database: Optional[MotorAsyncDatabase] = None
        self._monitoring_components: Optional[Dict[str, Any]] = None
        self._health_checker: Optional[DatabaseHealthChecker] = None
        self._initialized = False
        self._flask_app: Optional[Flask] = None
        
        logger.info(
            "Database manager initialized",
            database_name=self.config.database_name,
            mongodb_uri=self.config.mongodb_uri.split('@')[-1] if '@' in self.config.mongodb_uri else self.config.mongodb_uri,
            max_pool_size=self.config.max_pool_size,
            enable_monitoring=self.config.enable_monitoring
        )
    
    def initialize(self) -> None:
        """
        Initialize all database components with monitoring and health checks.
        
        Sets up PyMongo synchronous client, Motor async client, monitoring integration,
        and health checking capabilities for comprehensive database operations.
        
        Raises:
            DatabaseConnectionError: If database initialization fails
            DatabaseException: If monitoring setup fails
        """
        if self._initialized:
            logger.debug("Database manager already initialized")
            return
        
        try:
            # Initialize monitoring components first
            if self.config.enable_monitoring:
                self._monitoring_components = initialize_database_monitoring()
                logger.info("Database monitoring components initialized successfully")
            
            # Initialize PyMongo synchronous client
            mongodb_config = self.config.to_mongodb_config()
            self._mongodb_client = create_mongodb_client(mongodb_config)
            self._mongodb_client.initialize()
            
            logger.info(
                "PyMongo synchronous client initialized",
                database_name=self.config.database_name,
                max_pool_size=self.config.max_pool_size
            )
            
            # Initialize Motor async client if enabled
            if self.config.enable_motor_async:
                motor_options = self.config.get_motor_client_options()
                self._motor_client = await initialize_motor_client(
                    self.config.mongodb_uri,
                    **motor_options
                )
                self._motor_database = await get_motor_database(
                    self.config.database_name,
                    client=self._motor_client
                )
                
                logger.info(
                    "Motor async client initialized",
                    database_name=self.config.database_name,
                    motor_max_pool_size=self.config.motor_max_pool_size
                )
            
            # Initialize health checker
            if self.config.enable_health_checks and self._monitoring_components:
                self._health_checker = self._monitoring_components['health_checker']
                logger.info("Database health checker initialized")
            
            self._initialized = True
            
            logger.info(
                "Database manager initialization completed successfully",
                mongodb_client=self._mongodb_client is not None,
                motor_client=self._motor_client is not None,
                monitoring_enabled=self._monitoring_components is not None,
                health_checks_enabled=self._health_checker is not None
            )
            
        except Exception as e:
            logger.error(
                "Database manager initialization failed",
                error=str(e),
                database_name=self.config.database_name
            )
            raise
    
    async def initialize_async(self) -> None:
        """
        Initialize async components (Motor client and database).
        
        Separate async initialization method for Motor components that require
        async context for proper initialization and connection verification.
        """
        if self.config.enable_motor_async and not self._motor_client:
            try:
                motor_options = self.config.get_motor_client_options()
                self._motor_client = await initialize_motor_client(
                    self.config.mongodb_uri,
                    **motor_options
                )
                self._motor_database = await get_motor_database(
                    self.config.database_name,
                    client=self._motor_client
                )
                
                logger.info(
                    "Motor async components initialized",
                    database_name=self.config.database_name,
                    motor_max_pool_size=self.config.motor_max_pool_size
                )
                
            except Exception as e:
                logger.error(
                    "Motor async initialization failed",
                    error=str(e),
                    database_name=self.config.database_name
                )
                raise
    
    def init_app(self, app: Flask) -> None:
        """
        Initialize database manager with Flask application factory pattern.
        
        Integrates database clients with Flask application configuration, registers
        health check and metrics endpoints, and sets up application context support.
        
        Args:
            app: Flask application instance
        """
        self._flask_app = app
        
        # Store database manager in app extensions
        if not hasattr(app, 'extensions'):
            app.extensions = {}
        app.extensions['database_manager'] = self
        
        # Configure from Flask app config if available
        if self.config.flask_config_key in app.config:
            flask_db_config = app.config[self.config.flask_config_key]
            self._update_config_from_flask(flask_db_config)
        
        # Register teardown handlers
        app.teardown_appcontext(self._teardown_request)
        app.teardown_request(self._close_db_connection)
        
        # Register health check endpoint if enabled
        if self.config.enable_health_checks:
            self._register_health_endpoint(app)
        
        # Register metrics endpoint if monitoring enabled
        if self.config.enable_monitoring:
            self._register_metrics_endpoint(app)
        
        # Initialize database components
        with app.app_context():
            self.initialize()
        
        logger.info(
            "Database manager integrated with Flask application",
            app_name=app.name,
            health_endpoint=self.config.health_check_endpoint,
            metrics_endpoint=self.config.metrics_endpoint
        )
    
    def _update_config_from_flask(self, flask_config: Dict[str, Any]) -> None:
        """Update database configuration from Flask app config."""
        if 'MONGODB_URI' in flask_config:
            self.config.mongodb_uri = flask_config['MONGODB_URI']
        if 'DATABASE_NAME' in flask_config:
            self.config.database_name = flask_config['DATABASE_NAME']
        if 'MAX_POOL_SIZE' in flask_config:
            self.config.max_pool_size = flask_config['MAX_POOL_SIZE']
        if 'ENABLE_MONITORING' in flask_config:
            self.config.enable_monitoring = flask_config['ENABLE_MONITORING']
        
        logger.debug(
            "Database configuration updated from Flask config",
            database_name=self.config.database_name,
            max_pool_size=self.config.max_pool_size
        )
    
    def _register_health_endpoint(self, app: Flask) -> None:
        """Register database health check endpoint."""
        @app.route(self.config.health_check_endpoint)
        def database_health():
            """Database health check endpoint for monitoring and load balancer integration."""
            try:
                health_status = self.get_health_status()
                status_code = 200 if health_status['overall_status'] == 'healthy' else 503
                
                return health_status, status_code
                
            except Exception as e:
                logger.error(f"Health check endpoint error: {e}")
                return {
                    'overall_status': 'error',
                    'error': str(e),
                    'timestamp': time.time()
                }, 503
    
    def _register_metrics_endpoint(self, app: Flask) -> None:
        """Register Prometheus metrics endpoint."""
        @app.route(self.config.metrics_endpoint)
        def database_metrics():
            """Prometheus metrics endpoint for database performance monitoring."""
            try:
                metrics_data = get_database_metrics_exposition()
                content_type = get_database_metrics_content_type()
                
                return metrics_data, 200, {'Content-Type': content_type}
                
            except Exception as e:
                logger.error(f"Metrics endpoint error: {e}")
                return f"# Error generating metrics: {str(e)}", 500
    
    def _teardown_request(self, exception: Optional[Exception]) -> None:
        """Flask request teardown handler."""
        if exception:
            logger.debug(f"Request teardown with exception: {exception}")
        
        # Clear request-local database references
        if hasattr(g, 'mongodb_client'):
            delattr(g, 'mongodb_client')
        if hasattr(g, 'motor_database'):
            delattr(g, 'motor_database')
    
    def _close_db_connection(self, response_or_exc) -> None:
        """Flask request cleanup handler."""
        # Connection pools handle cleanup automatically
        pass
    
    @property
    def mongodb_client(self) -> Optional[MongoDBClient]:
        """Get PyMongo synchronous client instance."""
        return self._mongodb_client
    
    @property
    def motor_client(self) -> Optional[AsyncIOMotorClient]:
        """Get Motor async client instance."""
        return self._motor_client
    
    @property
    def motor_database(self) -> Optional[MotorAsyncDatabase]:
        """Get Motor async database instance."""
        return self._motor_database
    
    @property
    def monitoring_components(self) -> Optional[Dict[str, Any]]:
        """Get database monitoring components."""
        return self._monitoring_components
    
    @property
    def health_checker(self) -> Optional[DatabaseHealthChecker]:
        """Get database health checker instance."""
        return self._health_checker
    
    def get_health_status(self) -> Dict[str, Any]:
        """
        Get comprehensive database health status.
        
        Returns:
            Dict containing overall health status and component details
        """
        if not self._health_checker:
            return {
                'overall_status': 'unknown',
                'error': 'Health checker not initialized',
                'timestamp': time.time()
            }
        
        try:
            # Check MongoDB health
            mongodb_health = {}
            if self._mongodb_client:
                mongodb_health = self._health_checker.check_mongodb_health(
                    self._mongodb_client.client,
                    timeout=5.0
                )
            
            # Get overall health status
            overall_health = self._health_checker.get_overall_health_status()
            
            # Add component-specific health information
            overall_health['components']['mongodb'] = mongodb_health
            
            if self._mongodb_client:
                overall_health['components']['mongodb_sync'] = self._mongodb_client.get_health_status()
            
            if self._motor_database:
                overall_health['components']['motor_async'] = {
                    'status': 'healthy',
                    'database_name': self.config.database_name,
                    'async_enabled': True
                }
            
            return overall_health
            
        except Exception as e:
            logger.error(f"Error getting database health status: {e}")
            return {
                'overall_status': 'error',
                'error': str(e),
                'timestamp': time.time()
            }
    
    def close(self) -> None:
        """
        Close all database connections and cleanup resources.
        
        Properly closes PyMongo and Motor clients, cleans up monitoring resources,
        and performs graceful shutdown for application termination.
        """
        try:
            # Close PyMongo client
            if self._mongodb_client:
                self._mongodb_client.close()
                self._mongodb_client = None
                logger.info("PyMongo client closed")
            
            # Close Motor client
            if self._motor_client:
                close_motor_client()
                self._motor_client = None
                self._motor_database = None
                logger.info("Motor async client closed")
            
            # Reset initialization state
            self._initialized = False
            
            logger.info("Database manager closed successfully")
            
        except Exception as e:
            logger.error(f"Error closing database manager: {e}")


# Global database manager instance
_database_manager: Optional[DatabaseManager] = None


def create_database_manager(config: Optional[DatabasePackageConfig] = None) -> DatabaseManager:
    """
    Create configured database manager instance.
    
    Factory function for creating database manager with comprehensive configuration
    and monitoring setup for Flask application integration.
    
    Args:
        config: Database package configuration (creates default if not provided)
        
    Returns:
        DatabaseManager: Configured database manager instance
    """
    global _database_manager
    
    if _database_manager is None:
        _database_manager = DatabaseManager(config)
        logger.info("Database manager created")
    
    return _database_manager


def get_database_manager() -> Optional[DatabaseManager]:
    """
    Get current database manager instance.
    
    Returns:
        DatabaseManager instance or None if not created
    """
    global _database_manager
    return _database_manager


def init_database_app(app: Flask, config: Optional[DatabasePackageConfig] = None) -> DatabaseManager:
    """
    Initialize database package with Flask application factory pattern.
    
    Comprehensive Flask application integration function that creates and configures
    database manager, registers endpoints, and sets up monitoring integration.
    
    Args:
        app: Flask application instance
        config: Database package configuration (optional)
        
    Returns:
        DatabaseManager: Configured and initialized database manager
    """
    # Create or get database manager
    db_manager = create_database_manager(config)
    
    # Initialize with Flask app
    db_manager.init_app(app)
    
    logger.info(
        "Database package initialized with Flask application",
        app_name=app.name,
        database_name=db_manager.config.database_name
    )
    
    return db_manager


def get_mongodb_client() -> Optional[MongoDBClient]:
    """
    Get PyMongo synchronous client from current Flask application context.
    
    Returns:
        MongoDBClient instance or None if not available
    """
    try:
        if hasattr(g, 'mongodb_client'):
            return g.mongodb_client
        
        db_manager = get_database_manager()
        if db_manager and db_manager.mongodb_client:
            g.mongodb_client = db_manager.mongodb_client
            return g.mongodb_client
        
        return None
        
    except Exception as e:
        logger.error(f"Error getting MongoDB client: {e}")
        return None


def get_motor_database() -> Optional[MotorAsyncDatabase]:
    """
    Get Motor async database from current Flask application context.
    
    Returns:
        MotorAsyncDatabase instance or None if not available
    """
    try:
        if hasattr(g, 'motor_database'):
            return g.motor_database
        
        db_manager = get_database_manager()
        if db_manager and db_manager.motor_database:
            g.motor_database = db_manager.motor_database
            return g.motor_database
        
        return None
        
    except Exception as e:
        logger.error(f"Error getting Motor database: {e}")
        return None


@contextmanager
def database_transaction():
    """
    Context manager for database transactions with automatic rollback.
    
    Provides transaction management for PyMongo operations with automatic
    commit on success and rollback on error.
    
    Yields:
        ClientSession: MongoDB session for transaction operations
    """
    mongodb_client = get_mongodb_client()
    if not mongodb_client:
        raise RuntimeError("MongoDB client not available for transaction")
    
    with mongodb_client.transaction() as session:
        yield session


async def async_database_transaction():
    """
    Async context manager for Motor database transactions.
    
    Provides async transaction management for Motor operations with automatic
    commit on success and rollback on error.
    
    Yields:
        AsyncIOMotorClientSession: Motor session for async transaction operations
    """
    motor_db = get_motor_database()
    if not motor_db:
        raise RuntimeError("Motor database not available for async transaction")
    
    async with motor_db.start_transaction() as session:
        yield session


# Convenience functions for common database operations
def execute_query(
    collection_name: str,
    operation: str,
    *args,
    **kwargs
) -> QueryResult:
    """
    Execute database query with automatic client selection and error handling.
    
    Args:
        collection_name: Name of the MongoDB collection
        operation: Database operation name (find_one, insert_one, etc.)
        *args: Operation arguments
        **kwargs: Operation keyword arguments
        
    Returns:
        QueryResult: Standardized query result
    """
    mongodb_client = get_mongodb_client()
    if not mongodb_client:
        raise RuntimeError("MongoDB client not available")
    
    operation_method = getattr(mongodb_client, operation, None)
    if not operation_method:
        raise ValueError(f"Unknown operation: {operation}")
    
    return operation_method(collection_name, *args, **kwargs)


async def execute_async_query(
    collection_name: str,
    operation: str,
    *args,
    **kwargs
) -> Any:
    """
    Execute async database query with Motor client.
    
    Args:
        collection_name: Name of the MongoDB collection
        operation: Database operation name (find_one, insert_one, etc.)
        *args: Operation arguments
        **kwargs: Operation keyword arguments
        
    Returns:
        Operation result from Motor async database
    """
    motor_db = get_motor_database()
    if not motor_db:
        raise RuntimeError("Motor database not available")
    
    operation_method = getattr(motor_db, operation, None)
    if not operation_method:
        raise ValueError(f"Unknown async operation: {operation}")
    
    return await operation_method(collection_name, *args, **kwargs)


# Public API exports
__all__ = [
    # Main database manager and configuration
    'DatabaseManager',
    'DatabasePackageConfig',
    'create_database_manager',
    'get_database_manager',
    'init_database_app',
    
    # Client access functions
    'get_mongodb_client',
    'get_motor_database',
    
    # Transaction management
    'database_transaction',
    'async_database_transaction',
    
    # Convenience query functions
    'execute_query',
    'execute_async_query',
    
    # Core database classes and functions from submodules
    'MongoDBClient',
    'MongoDBConfig',
    'QueryResult',
    'create_mongodb_client',
    'get_object_id',
    'serialize_for_json',
    
    # Motor async classes and functions
    'MotorAsyncDatabase',
    'initialize_motor_client',
    'close_motor_client',
    'DocumentType',
    'FilterType',
    'UpdateType',
    'ProjectionType',
    
    # Monitoring and health check classes
    'DatabaseMetrics',
    'DatabaseMonitoringListener',
    'ConnectionPoolMonitoringListener',
    'ServerMonitoringListener',
    'MotorMonitoringIntegration',
    'DatabaseHealthChecker',
    'initialize_database_monitoring',
    'get_database_monitoring_components',
    'get_database_metrics_exposition',
    'get_database_metrics_content_type',
    'monitor_transaction',
    'database_registry',
    
    # Configuration constants
    'DEFAULT_CONNECTION_TIMEOUT_MS',
    'DEFAULT_SERVER_SELECTION_TIMEOUT_MS',
    'DEFAULT_SOCKET_TIMEOUT_MS',
    'DEFAULT_MAX_POOL_SIZE',
    'DEFAULT_MIN_POOL_SIZE',
    'DEFAULT_MAX_IDLE_TIME_MS',
    'DEFAULT_WAIT_QUEUE_TIMEOUT_MS',
    'DEFAULT_TRANSACTION_TIMEOUT_SECONDS',
    'MAX_TRANSACTION_RETRY_ATTEMPTS',
    'DEFAULT_BATCH_SIZE',
    'MAX_BATCH_SIZE',
    'PERFORMANCE_VARIANCE_THRESHOLD',
    'NODEJS_BASELINE_PERCENTILES'
]

# Package initialization logging
logger.info(
    "Database access layer package initialized",
    pymongo_support=True,
    motor_support=True,
    monitoring_support=True,
    flask_integration=True,
    performance_threshold=PERFORMANCE_VARIANCE_THRESHOLD
)