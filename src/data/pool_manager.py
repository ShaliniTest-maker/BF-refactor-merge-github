"""
Database connection pool management for optimized PyMongo and Motor drivers.

This module implements comprehensive connection pool management providing optimized
connection pooling for both PyMongo synchronous and Motor asynchronous MongoDB drivers.
Manages connection lifecycle, pool sizing, health monitoring, resource optimization, 
and performance metrics collection to ensure efficient database connectivity and 
≤10% performance variance from Node.js baseline.

Implements requirements from:
- Section 0.1.2: Data access components with connection pool management equivalent to Node.js patterns
- Section 5.2.5: Database access layer with connection pooling and resource optimization
- Section 6.2.4: Performance optimization with connection pool tuning and metrics collection
- Section 6.2.2: Data management with pool health monitoring for system reliability
"""

import asyncio
import logging
import os
import threading
import time
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union, Callable, AsyncGenerator, Iterator
from urllib.parse import urlparse

import structlog
from prometheus_client import Counter, Gauge, Histogram, Info
import pymongo
from pymongo import MongoClient, monitoring
from pymongo.errors import (
    ConnectionFailure,
    ServerSelectionTimeoutError,
    NetworkTimeout,
    AutoReconnect,
    ConfigurationError
)
import motor
from motor import motor_asyncio

# Import dependency modules
from src.data.exceptions import (
    DatabaseConnectionError,
    DatabaseException,
    with_database_retry,
    database_error_context
)

# Structured logger instance
logger = structlog.get_logger(__name__)

# Prometheus metrics for connection pool monitoring
connection_pool_size = Gauge(
    'mongodb_connection_pool_size',
    'Current connection pool size',
    ['pool_type', 'database', 'server']
)

connection_pool_active = Gauge(
    'mongodb_connection_pool_active',
    'Active connections in pool',
    ['pool_type', 'database', 'server']
)

connection_pool_checked_out = Gauge(
    'mongodb_connection_pool_checked_out',
    'Checked out connections from pool',
    ['pool_type', 'database', 'server']
)

connection_pool_wait_time = Histogram(
    'mongodb_connection_pool_wait_time_seconds',
    'Time waiting for connection from pool',
    ['pool_type', 'database', 'server']
)

connection_pool_operations = Counter(
    'mongodb_connection_pool_operations_total',
    'Total connection pool operations',
    ['pool_type', 'database', 'server', 'operation', 'status']
)

connection_pool_errors = Counter(
    'mongodb_connection_pool_errors_total',
    'Total connection pool errors',
    ['pool_type', 'database', 'server', 'error_type']
)

connection_pool_health_status = Gauge(
    'mongodb_connection_pool_health_status',
    'Connection pool health status (1=healthy, 0=unhealthy)',
    ['pool_type', 'database', 'server']
)

connection_pool_info = Info(
    'mongodb_connection_pool_info',
    'Connection pool configuration information',
    ['pool_type', 'database', 'server']
)


@dataclass
class PoolConfiguration:
    """
    Configuration settings for database connection pools.
    
    Provides comprehensive configuration for both PyMongo and Motor connection pools
    with performance optimization settings equivalent to Node.js MongoDB drivers.
    """
    
    # Core pool settings
    max_pool_size: int = 50
    min_pool_size: int = 5
    max_idle_time_ms: int = 300000  # 5 minutes
    wait_queue_timeout_ms: int = 30000  # 30 seconds
    
    # Connection settings
    connect_timeout_ms: int = 10000  # 10 seconds
    socket_timeout_ms: int = 30000   # 30 seconds
    server_selection_timeout_ms: int = 10000  # 10 seconds
    heartbeat_frequency_ms: int = 10000  # 10 seconds
    
    # Performance optimization
    max_staleness_seconds: int = 120
    retry_writes: bool = True
    retry_reads: bool = True
    
    # Health monitoring
    health_check_interval: float = 60.0  # seconds
    health_check_timeout: float = 5.0    # seconds
    max_consecutive_failures: int = 3
    
    # Resource optimization
    connection_pool_monitor: bool = True
    event_listeners: bool = True
    
    def __post_init__(self):
        """Validate configuration parameters."""
        if self.max_pool_size <= 0:
            raise ValueError("max_pool_size must be positive")
        
        if self.min_pool_size < 0:
            raise ValueError("min_pool_size must be non-negative")
        
        if self.min_pool_size > self.max_pool_size:
            raise ValueError("min_pool_size cannot exceed max_pool_size")
        
        if self.wait_queue_timeout_ms <= 0:
            raise ValueError("wait_queue_timeout_ms must be positive")


@dataclass
class PoolStats:
    """
    Connection pool statistics for monitoring and optimization.
    
    Tracks comprehensive pool performance metrics for health monitoring
    and performance optimization analysis.
    """
    
    # Pool utilization
    total_connections: int = 0
    active_connections: int = 0
    checked_out_connections: int = 0
    available_connections: int = 0
    
    # Performance metrics
    total_checkouts: int = 0
    total_checkins: int = 0
    checkout_failures: int = 0
    average_wait_time: float = 0.0
    
    # Health metrics
    consecutive_failures: int = 0
    last_health_check: float = 0.0
    is_healthy: bool = True
    
    # Pool lifecycle
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)
    
    def update_access_time(self) -> None:
        """Update last accessed timestamp."""
        self.last_accessed = time.time()
    
    def increment_checkout(self, wait_time: float = 0.0) -> None:
        """Record successful connection checkout."""
        self.total_checkouts += 1
        self.checked_out_connections += 1
        
        # Update running average of wait time
        if self.total_checkouts > 1:
            self.average_wait_time = (
                (self.average_wait_time * (self.total_checkouts - 1) + wait_time) / 
                self.total_checkouts
            )
        else:
            self.average_wait_time = wait_time
        
        self.update_access_time()
    
    def increment_checkin(self) -> None:
        """Record connection checkin."""
        self.total_checkins += 1
        if self.checked_out_connections > 0:
            self.checked_out_connections -= 1
        self.update_access_time()
    
    def increment_failure(self) -> None:
        """Record connection failure."""
        self.checkout_failures += 1
        self.consecutive_failures += 1
        self.update_access_time()
    
    def reset_failures(self) -> None:
        """Reset failure counters on successful operation."""
        self.consecutive_failures = 0


class ConnectionPoolMonitoringListener(monitoring.PoolListener):
    """
    PyMongo pool event listener for comprehensive monitoring.
    
    Implements PyMongo monitoring API to capture connection pool events
    and emit Prometheus metrics for observability and performance tracking.
    """
    
    def __init__(self, pool_type: str, database: str):
        """
        Initialize monitoring listener with pool context.
        
        Args:
            pool_type: Type of pool ('pymongo' or 'motor')
            database: Database name for metric labeling
        """
        self.pool_type = pool_type
        self.database = database
        self.checkout_times = {}
        self.server_address = None
        
        logger.debug(
            "Initialized connection pool monitoring listener",
            pool_type=pool_type,
            database=database
        )
    
    def pool_created(self, event: monitoring.PoolCreatedEvent) -> None:
        """Handle pool creation event."""
        self.server_address = str(event.address)
        
        connection_pool_size.labels(
            pool_type=self.pool_type,
            database=self.database,
            server=self.server_address
        ).set(event.options.max_pool_size)
        
        connection_pool_info.labels(
            pool_type=self.pool_type,
            database=self.database,
            server=self.server_address
        ).info({
            'max_pool_size': str(event.options.max_pool_size),
            'wait_queue_timeout_ms': str(event.options.wait_queue_timeout_ms),
            'max_idle_time_ms': str(event.options.max_idle_time_ms)
        })
        
        connection_pool_operations.labels(
            pool_type=self.pool_type,
            database=self.database,
            server=self.server_address,
            operation='pool_created',
            status='success'
        ).inc()
        
        logger.info(
            "Connection pool created",
            pool_type=self.pool_type,
            database=self.database,
            server=self.server_address,
            max_pool_size=event.options.max_pool_size
        )
    
    def pool_cleared(self, event: monitoring.PoolClearedEvent) -> None:
        """Handle pool cleared event."""
        server = str(event.address)
        
        connection_pool_operations.labels(
            pool_type=self.pool_type,
            database=self.database,
            server=server,
            operation='pool_cleared',
            status='success'
        ).inc()
        
        logger.warning(
            "Connection pool cleared",
            pool_type=self.pool_type,
            database=self.database,
            server=server
        )
    
    def pool_closed(self, event: monitoring.PoolClosedEvent) -> None:
        """Handle pool closed event."""
        server = str(event.address)
        
        connection_pool_operations.labels(
            pool_type=self.pool_type,
            database=self.database,
            server=server,
            operation='pool_closed',
            status='success'
        ).inc()
        
        logger.info(
            "Connection pool closed",
            pool_type=self.pool_type,
            database=self.database,
            server=server
        )
    
    def connection_created(self, event: monitoring.ConnectionCreatedEvent) -> None:
        """Handle connection created event."""
        server = str(event.address)
        
        connection_pool_active.labels(
            pool_type=self.pool_type,
            database=self.database,
            server=server
        ).inc()
        
        connection_pool_operations.labels(
            pool_type=self.pool_type,
            database=self.database,
            server=server,
            operation='connection_created',
            status='success'
        ).inc()
        
        logger.debug(
            "Connection created",
            pool_type=self.pool_type,
            database=self.database,
            server=server,
            connection_id=event.connection_id
        )
    
    def connection_closed(self, event: monitoring.ConnectionClosedEvent) -> None:
        """Handle connection closed event."""
        server = str(event.address)
        
        connection_pool_active.labels(
            pool_type=self.pool_type,
            database=self.database,
            server=server
        ).dec()
        
        connection_pool_operations.labels(
            pool_type=self.pool_type,
            database=self.database,
            server=server,
            operation='connection_closed',
            status='success'
        ).inc()
        
        logger.debug(
            "Connection closed",
            pool_type=self.pool_type,
            database=self.database,
            server=server,
            connection_id=event.connection_id,
            reason=getattr(event, 'reason', 'unknown')
        )
    
    def connection_check_out_started(self, event: monitoring.ConnectionCheckOutStartedEvent) -> None:
        """Handle connection checkout started event."""
        server = str(event.address)
        self.checkout_times[event.address] = time.time()
        
        logger.debug(
            "Connection checkout started",
            pool_type=self.pool_type,
            database=self.database,
            server=server
        )
    
    def connection_checked_out(self, event: monitoring.ConnectionCheckedOutEvent) -> None:
        """Handle connection checked out event."""
        server = str(event.address)
        
        # Calculate wait time
        wait_time = 0.0
        if event.address in self.checkout_times:
            wait_time = time.time() - self.checkout_times.pop(event.address)
            
            connection_pool_wait_time.labels(
                pool_type=self.pool_type,
                database=self.database,
                server=server
            ).observe(wait_time)
        
        connection_pool_checked_out.labels(
            pool_type=self.pool_type,
            database=self.database,
            server=server
        ).inc()
        
        connection_pool_operations.labels(
            pool_type=self.pool_type,
            database=self.database,
            server=server,
            operation='connection_checked_out',
            status='success'
        ).inc()
        
        logger.debug(
            "Connection checked out",
            pool_type=self.pool_type,
            database=self.database,
            server=server,
            connection_id=event.connection_id,
            wait_time=wait_time
        )
    
    def connection_checked_in(self, event: monitoring.ConnectionCheckedInEvent) -> None:
        """Handle connection checked in event."""
        server = str(event.address)
        
        connection_pool_checked_out.labels(
            pool_type=self.pool_type,
            database=self.database,
            server=server
        ).dec()
        
        connection_pool_operations.labels(
            pool_type=self.pool_type,
            database=self.database,
            server=server,
            operation='connection_checked_in',
            status='success'
        ).inc()
        
        logger.debug(
            "Connection checked in",
            pool_type=self.pool_type,
            database=self.database,
            server=server,
            connection_id=event.connection_id
        )
    
    def connection_check_out_failed(self, event: monitoring.ConnectionCheckOutFailedEvent) -> None:
        """Handle connection checkout failure event."""
        server = str(event.address)
        
        # Clean up checkout timing
        self.checkout_times.pop(event.address, None)
        
        connection_pool_errors.labels(
            pool_type=self.pool_type,
            database=self.database,
            server=server,
            error_type='checkout_failed'
        ).inc()
        
        connection_pool_operations.labels(
            pool_type=self.pool_type,
            database=self.database,
            server=server,
            operation='connection_check_out_failed',
            status='failure'
        ).inc()
        
        logger.warning(
            "Connection checkout failed",
            pool_type=self.pool_type,
            database=self.database,
            server=server,
            reason=event.reason
        )


class PoolManager:
    """
    Centralized database connection pool management system.
    
    Manages connection pools for both PyMongo synchronous and Motor asynchronous
    MongoDB drivers with comprehensive health monitoring, performance optimization,
    and resource management equivalent to Node.js connection patterns.
    """
    
    def __init__(self, config: Optional[PoolConfiguration] = None):
        """
        Initialize pool manager with configuration.
        
        Args:
            config: Pool configuration settings (defaults to PoolConfiguration())
        """
        self.config = config or PoolConfiguration()
        self.pools: Dict[str, Union[MongoClient, motor_asyncio.AsyncIOMotorClient]] = {}
        self.pool_stats: Dict[str, PoolStats] = {}
        self.monitoring_listeners: Dict[str, ConnectionPoolMonitoringListener] = {}
        self._lock = threading.RLock()
        self._health_check_task = None
        self._shutdown_event = threading.Event()
        
        # Register monitoring listeners if enabled
        if self.config.event_listeners:
            self._setup_global_monitoring()
        
        logger.info(
            "Pool manager initialized",
            max_pool_size=self.config.max_pool_size,
            min_pool_size=self.config.min_pool_size,
            health_check_interval=self.config.health_check_interval
        )
    
    def _setup_global_monitoring(self) -> None:
        """Set up global PyMongo monitoring for all connections."""
        # Note: Global listeners will be added when pools are created
        logger.debug("Global PyMongo monitoring configured")
    
    def _get_pool_key(self, uri: str, database: str, pool_type: str) -> str:
        """Generate unique pool key for identification."""
        parsed = urlparse(uri)
        host_port = f"{parsed.hostname}:{parsed.port or 27017}"
        return f"{pool_type}:{database}:{host_port}"
    
    def _create_pymongo_client_options(self) -> Dict[str, Any]:
        """Create PyMongo client options from configuration."""
        return {
            'maxPoolSize': self.config.max_pool_size,
            'minPoolSize': self.config.min_pool_size,
            'maxIdleTimeMS': self.config.max_idle_time_ms,
            'waitQueueTimeoutMS': self.config.wait_queue_timeout_ms,
            'connectTimeoutMS': self.config.connect_timeout_ms,
            'socketTimeoutMS': self.config.socket_timeout_ms,
            'serverSelectionTimeoutMS': self.config.server_selection_timeout_ms,
            'heartbeatFrequencyMS': self.config.heartbeat_frequency_ms,
            'maxStalenessSeconds': self.config.max_staleness_seconds,
            'retryWrites': self.config.retry_writes,
            'retryReads': self.config.retry_reads,
            'appName': 'Flask-MongoDB-Migration'
        }
    
    def _create_motor_client_options(self) -> Dict[str, Any]:
        """Create Motor client options from configuration."""
        # Motor uses the same options as PyMongo
        return self._create_pymongo_client_options()
    
    @with_database_retry(max_attempts=3, circuit_breaker=True, operation_name='create_pymongo_pool')
    def create_pymongo_pool(
        self,
        uri: str,
        database: str,
        pool_name: Optional[str] = None
    ) -> MongoClient:
        """
        Create and register a PyMongo synchronous connection pool.
        
        Implements optimized connection pooling with monitoring and health checks
        for PyMongo synchronous database operations.
        
        Args:
            uri: MongoDB connection URI
            database: Database name
            pool_name: Optional custom pool name (auto-generated if None)
            
        Returns:
            Configured PyMongo MongoClient instance
            
        Raises:
            DatabaseConnectionError: On connection or configuration errors
        """
        pool_key = pool_name or self._get_pool_key(uri, database, 'pymongo')
        
        with self._lock:
            # Return existing pool if available
            if pool_key in self.pools:
                logger.debug(
                    "Returning existing PyMongo pool",
                    pool_key=pool_key,
                    database=database
                )
                return self.pools[pool_key]
            
            try:
                # Create monitoring listener
                if self.config.event_listeners:
                    listener = ConnectionPoolMonitoringListener('pymongo', database)
                    self.monitoring_listeners[pool_key] = listener
                    monitoring.register(listener)
                
                # Create client options
                client_options = self._create_pymongo_client_options()
                
                # Create PyMongo client
                client = MongoClient(uri, **client_options)
                
                # Verify connection
                with database_error_context('ping', database):
                    client.admin.command('ping')
                
                # Register pool
                self.pools[pool_key] = client
                self.pool_stats[pool_key] = PoolStats()
                
                # Update metrics
                parsed = urlparse(uri)
                server = f"{parsed.hostname}:{parsed.port or 27017}"
                
                connection_pool_health_status.labels(
                    pool_type='pymongo',
                    database=database,
                    server=server
                ).set(1)
                
                logger.info(
                    "PyMongo connection pool created successfully",
                    pool_key=pool_key,
                    database=database,
                    uri=uri,
                    max_pool_size=self.config.max_pool_size
                )
                
                return client
                
            except Exception as e:
                # Clean up on failure
                if pool_key in self.monitoring_listeners:
                    monitoring.unregister(self.monitoring_listeners.pop(pool_key))
                
                error_msg = f"Failed to create PyMongo pool: {str(e)}"
                logger.error(
                    "PyMongo pool creation failed",
                    pool_key=pool_key,
                    database=database,
                    error=str(e),
                    error_type=type(e).__name__
                )
                
                raise DatabaseConnectionError(
                    message=error_msg,
                    operation='create_pymongo_pool',
                    database=database,
                    original_error=e
                )
    
    @with_database_retry(max_attempts=3, circuit_breaker=True, operation_name='create_motor_pool')
    async def create_motor_pool(
        self,
        uri: str,
        database: str,
        pool_name: Optional[str] = None
    ) -> motor_asyncio.AsyncIOMotorClient:
        """
        Create and register a Motor asynchronous connection pool.
        
        Implements high-performance async connection pooling with monitoring
        for Motor asynchronous database operations.
        
        Args:
            uri: MongoDB connection URI
            database: Database name
            pool_name: Optional custom pool name (auto-generated if None)
            
        Returns:
            Configured Motor AsyncIOMotorClient instance
            
        Raises:
            DatabaseConnectionError: On connection or configuration errors
        """
        pool_key = pool_name or self._get_pool_key(uri, database, 'motor')
        
        with self._lock:
            # Return existing pool if available
            if pool_key in self.pools:
                logger.debug(
                    "Returning existing Motor pool",
                    pool_key=pool_key,
                    database=database
                )
                return self.pools[pool_key]
            
            try:
                # Create monitoring listener
                if self.config.event_listeners:
                    listener = ConnectionPoolMonitoringListener('motor', database)
                    self.monitoring_listeners[pool_key] = listener
                    monitoring.register(listener)
                
                # Create client options
                client_options = self._create_motor_client_options()
                
                # Create Motor client
                client = motor_asyncio.AsyncIOMotorClient(uri, **client_options)
                
                # Verify connection
                with database_error_context('ping', database):
                    await client.admin.command('ping')
                
                # Register pool
                self.pools[pool_key] = client
                self.pool_stats[pool_key] = PoolStats()
                
                # Update metrics
                parsed = urlparse(uri)
                server = f"{parsed.hostname}:{parsed.port or 27017}"
                
                connection_pool_health_status.labels(
                    pool_type='motor',
                    database=database,
                    server=server
                ).set(1)
                
                logger.info(
                    "Motor connection pool created successfully",
                    pool_key=pool_key,
                    database=database,
                    uri=uri,
                    max_pool_size=self.config.max_pool_size
                )
                
                return client
                
            except Exception as e:
                # Clean up on failure
                if pool_key in self.monitoring_listeners:
                    monitoring.unregister(self.monitoring_listeners.pop(pool_key))
                
                error_msg = f"Failed to create Motor pool: {str(e)}"
                logger.error(
                    "Motor pool creation failed",
                    pool_key=pool_key,
                    database=database,
                    error=str(e),
                    error_type=type(e).__name__
                )
                
                raise DatabaseConnectionError(
                    message=error_msg,
                    operation='create_motor_pool',
                    database=database,
                    original_error=e
                )
    
    def get_pool(self, pool_key: str) -> Optional[Union[MongoClient, motor_asyncio.AsyncIOMotorClient]]:
        """
        Retrieve an existing connection pool by key.
        
        Args:
            pool_key: Pool identifier
            
        Returns:
            Connection pool client or None if not found
        """
        with self._lock:
            pool = self.pools.get(pool_key)
            if pool and pool_key in self.pool_stats:
                self.pool_stats[pool_key].update_access_time()
            return pool
    
    def get_pool_stats(self, pool_key: str) -> Optional[PoolStats]:
        """
        Retrieve pool statistics for monitoring.
        
        Args:
            pool_key: Pool identifier
            
        Returns:
            Pool statistics or None if pool not found
        """
        with self._lock:
            return self.pool_stats.get(pool_key)
    
    def list_pools(self) -> List[str]:
        """
        List all registered pool keys.
        
        Returns:
            List of pool identifiers
        """
        with self._lock:
            return list(self.pools.keys())
    
    @contextmanager
    def get_pymongo_connection(
        self,
        pool_key: str,
        database: str
    ) -> Iterator[pymongo.database.Database]:
        """
        Context manager for PyMongo database connections.
        
        Provides connection checkout/checkin with automatic resource management,
        error handling, and performance monitoring.
        
        Args:
            pool_key: Pool identifier
            database: Database name
            
        Yields:
            PyMongo Database instance
            
        Raises:
            DatabaseConnectionError: On connection errors
        """
        client = self.get_pool(pool_key)
        if not client or not isinstance(client, MongoClient):
            raise DatabaseConnectionError(
                message=f"PyMongo pool not found: {pool_key}",
                operation='get_pymongo_connection',
                database=database
            )
        
        start_time = time.time()
        
        try:
            # Get database reference
            db = client[database]
            
            # Update pool stats
            if pool_key in self.pool_stats:
                wait_time = time.time() - start_time
                self.pool_stats[pool_key].increment_checkout(wait_time)
            
            yield db
            
            # Record successful operation
            if pool_key in self.pool_stats:
                self.pool_stats[pool_key].reset_failures()
            
        except Exception as e:
            # Record failure
            if pool_key in self.pool_stats:
                self.pool_stats[pool_key].increment_failure()
            
            raise DatabaseConnectionError(
                message=f"PyMongo connection error: {str(e)}",
                operation='get_pymongo_connection',
                database=database,
                original_error=e
            )
        
        finally:
            # Record checkin
            if pool_key in self.pool_stats:
                self.pool_stats[pool_key].increment_checkin()
    
    @asynccontextmanager
    async def get_motor_connection(
        self,
        pool_key: str,
        database: str
    ) -> AsyncGenerator[motor_asyncio.AsyncIOMotorDatabase, None]:
        """
        Async context manager for Motor database connections.
        
        Provides async connection checkout/checkin with automatic resource management,
        error handling, and performance monitoring.
        
        Args:
            pool_key: Pool identifier
            database: Database name
            
        Yields:
            Motor AsyncIOMotorDatabase instance
            
        Raises:
            DatabaseConnectionError: On connection errors
        """
        client = self.get_pool(pool_key)
        if not client or not isinstance(client, motor_asyncio.AsyncIOMotorClient):
            raise DatabaseConnectionError(
                message=f"Motor pool not found: {pool_key}",
                operation='get_motor_connection',
                database=database
            )
        
        start_time = time.time()
        
        try:
            # Get database reference
            db = client[database]
            
            # Update pool stats
            if pool_key in self.pool_stats:
                wait_time = time.time() - start_time
                self.pool_stats[pool_key].increment_checkout(wait_time)
            
            yield db
            
            # Record successful operation
            if pool_key in self.pool_stats:
                self.pool_stats[pool_key].reset_failures()
            
        except Exception as e:
            # Record failure
            if pool_key in self.pool_stats:
                self.pool_stats[pool_key].increment_failure()
            
            raise DatabaseConnectionError(
                message=f"Motor connection error: {str(e)}",
                operation='get_motor_connection',
                database=database,
                original_error=e
            )
        
        finally:
            # Record checkin
            if pool_key in self.pool_stats:
                self.pool_stats[pool_key].increment_checkin()
    
    def check_pool_health(self, pool_key: str) -> bool:
        """
        Check health of a specific connection pool.
        
        Performs connectivity test and updates pool health status
        with comprehensive error handling and recovery.
        
        Args:
            pool_key: Pool identifier
            
        Returns:
            True if pool is healthy, False otherwise
        """
        try:
            pool = self.get_pool(pool_key)
            if not pool:
                logger.warning(
                    "Pool not found for health check",
                    pool_key=pool_key
                )
                return False
            
            # Determine pool type and perform health check
            if isinstance(pool, MongoClient):
                # PyMongo synchronous health check
                with database_error_context('health_check', 'admin'):
                    pool.admin.command('ping', maxTimeMS=int(self.config.health_check_timeout * 1000))
                
            elif isinstance(pool, motor_asyncio.AsyncIOMotorClient):
                # Motor async health check (run in thread for sync context)
                async def async_health_check():
                    with database_error_context('health_check', 'admin'):
                        await pool.admin.command('ping', maxTimeMS=int(self.config.health_check_timeout * 1000))
                
                # Run async health check
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    loop.run_until_complete(async_health_check())
                finally:
                    loop.close()
            
            # Update health status
            if pool_key in self.pool_stats:
                self.pool_stats[pool_key].is_healthy = True
                self.pool_stats[pool_key].last_health_check = time.time()
                self.pool_stats[pool_key].reset_failures()
            
            logger.debug(
                "Pool health check passed",
                pool_key=pool_key
            )
            
            return True
            
        except Exception as e:
            # Update health status
            if pool_key in self.pool_stats:
                self.pool_stats[pool_key].is_healthy = False
                self.pool_stats[pool_key].increment_failure()
            
            logger.warning(
                "Pool health check failed",
                pool_key=pool_key,
                error=str(e),
                error_type=type(e).__name__
            )
            
            return False
    
    def check_all_pools_health(self) -> Dict[str, bool]:
        """
        Check health of all registered pools.
        
        Returns:
            Dictionary mapping pool keys to health status
        """
        health_status = {}
        
        for pool_key in self.list_pools():
            health_status[pool_key] = self.check_pool_health(pool_key)
        
        logger.debug(
            "Completed health check for all pools",
            total_pools=len(health_status),
            healthy_pools=sum(health_status.values())
        )
        
        return health_status
    
    def start_health_monitoring(self) -> None:
        """
        Start background health monitoring for all pools.
        
        Runs periodic health checks in a background thread with
        configurable interval and failure handling.
        """
        if self._health_check_task is not None:
            logger.warning("Health monitoring already started")
            return
        
        def health_check_worker():
            """Background health check worker thread."""
            while not self._shutdown_event.is_set():
                try:
                    health_status = self.check_all_pools_health()
                    
                    # Update Prometheus metrics
                    for pool_key, is_healthy in health_status.items():
                        pool_stats = self.get_pool_stats(pool_key)
                        if pool_stats:
                            # Parse pool key for metrics labels
                            parts = pool_key.split(':', 2)
                            if len(parts) >= 3:
                                pool_type, database, server = parts[0], parts[1], parts[2]
                                
                                connection_pool_health_status.labels(
                                    pool_type=pool_type,
                                    database=database,
                                    server=server
                                ).set(1 if is_healthy else 0)
                    
                    # Sleep until next check or shutdown
                    self._shutdown_event.wait(self.config.health_check_interval)
                    
                except Exception as e:
                    logger.error(
                        "Health monitoring error",
                        error=str(e),
                        error_type=type(e).__name__
                    )
                    
                    # Wait before retrying
                    self._shutdown_event.wait(min(self.config.health_check_interval, 30.0))
        
        # Start health check thread
        self._health_check_task = threading.Thread(
            target=health_check_worker,
            name="pool-health-monitor",
            daemon=True
        )
        self._health_check_task.start()
        
        logger.info(
            "Health monitoring started",
            check_interval=self.config.health_check_interval
        )
    
    def stop_health_monitoring(self) -> None:
        """Stop background health monitoring."""
        if self._health_check_task is None:
            return
        
        self._shutdown_event.set()
        
        if self._health_check_task.is_alive():
            self._health_check_task.join(timeout=5.0)
        
        self._health_check_task = None
        logger.info("Health monitoring stopped")
    
    def close_pool(self, pool_key: str) -> None:
        """
        Close and remove a specific connection pool.
        
        Performs graceful pool shutdown with resource cleanup
        and monitoring deregistration.
        
        Args:
            pool_key: Pool identifier
        """
        with self._lock:
            if pool_key not in self.pools:
                logger.warning(
                    "Attempted to close non-existent pool",
                    pool_key=pool_key
                )
                return
            
            try:
                pool = self.pools[pool_key]
                
                # Close the connection pool
                if hasattr(pool, 'close'):
                    pool.close()
                
                # Remove monitoring listener
                if pool_key in self.monitoring_listeners:
                    monitoring.unregister(self.monitoring_listeners.pop(pool_key))
                
                # Clean up references
                del self.pools[pool_key]
                if pool_key in self.pool_stats:
                    del self.pool_stats[pool_key]
                
                logger.info(
                    "Connection pool closed successfully",
                    pool_key=pool_key
                )
                
            except Exception as e:
                logger.error(
                    "Error closing connection pool",
                    pool_key=pool_key,
                    error=str(e),
                    error_type=type(e).__name__
                )
    
    def close_all_pools(self) -> None:
        """
        Close all connection pools and clean up resources.
        
        Performs graceful shutdown of all managed pools with
        comprehensive resource cleanup.
        """
        logger.info("Closing all connection pools")
        
        # Stop health monitoring
        self.stop_health_monitoring()
        
        # Close all pools
        pool_keys = list(self.pools.keys())
        for pool_key in pool_keys:
            self.close_pool(pool_key)
        
        logger.info(
            "All connection pools closed",
            pools_closed=len(pool_keys)
        )
    
    def get_pool_metrics(self) -> Dict[str, Dict[str, Any]]:
        """
        Get comprehensive metrics for all pools.
        
        Returns:
            Dictionary mapping pool keys to metrics data
        """
        metrics = {}
        
        with self._lock:
            for pool_key, stats in self.pool_stats.items():
                metrics[pool_key] = {
                    'total_connections': stats.total_connections,
                    'active_connections': stats.active_connections,
                    'checked_out_connections': stats.checked_out_connections,
                    'available_connections': stats.available_connections,
                    'total_checkouts': stats.total_checkouts,
                    'total_checkins': stats.total_checkins,
                    'checkout_failures': stats.checkout_failures,
                    'average_wait_time': stats.average_wait_time,
                    'consecutive_failures': stats.consecutive_failures,
                    'is_healthy': stats.is_healthy,
                    'last_health_check': stats.last_health_check,
                    'created_at': stats.created_at,
                    'last_accessed': stats.last_accessed
                }
        
        return metrics
    
    def optimize_pool_sizes(self) -> None:
        """
        Optimize pool sizes based on usage patterns and performance metrics.
        
        Analyzes pool utilization patterns and adjusts configuration
        for optimal resource usage and performance.
        """
        with self._lock:
            for pool_key, stats in self.pool_stats.items():
                # Calculate utilization metrics
                if stats.total_checkouts > 0:
                    utilization_rate = stats.checked_out_connections / self.config.max_pool_size
                    failure_rate = stats.checkout_failures / stats.total_checkouts
                    
                    # Log optimization recommendations
                    if utilization_rate > 0.8:
                        logger.info(
                            "High pool utilization detected",
                            pool_key=pool_key,
                            utilization_rate=utilization_rate,
                            recommendation="Consider increasing max_pool_size"
                        )
                    
                    if failure_rate > 0.05:  # 5% failure rate threshold
                        logger.warning(
                            "High failure rate detected",
                            pool_key=pool_key,
                            failure_rate=failure_rate,
                            recommendation="Check connection timeout settings"
                        )
                    
                    if stats.average_wait_time > 1.0:  # 1 second threshold
                        logger.warning(
                            "High average wait time detected",
                            pool_key=pool_key,
                            average_wait_time=stats.average_wait_time,
                            recommendation="Consider increasing pool size or timeout"
                        )
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        self.close_all_pools()


# Global pool manager instance
_global_pool_manager: Optional[PoolManager] = None
_global_pool_lock = threading.Lock()


def get_pool_manager(config: Optional[PoolConfiguration] = None) -> PoolManager:
    """
    Get the global pool manager instance.
    
    Provides singleton access to the pool manager with optional configuration
    for first-time initialization.
    
    Args:
        config: Pool configuration (used only for first initialization)
        
    Returns:
        Global PoolManager instance
    """
    global _global_pool_manager
    
    with _global_pool_lock:
        if _global_pool_manager is None:
            _global_pool_manager = PoolManager(config)
            logger.info("Global pool manager initialized")
        
        return _global_pool_manager


def close_global_pool_manager() -> None:
    """
    Close and reset the global pool manager.
    
    Performs cleanup of global pool manager for application shutdown
    or testing scenarios.
    """
    global _global_pool_manager
    
    with _global_pool_lock:
        if _global_pool_manager is not None:
            _global_pool_manager.close_all_pools()
            _global_pool_manager = None
            logger.info("Global pool manager closed")


# Export public interface
__all__ = [
    # Configuration classes
    'PoolConfiguration',
    'PoolStats',
    
    # Core pool manager
    'PoolManager',
    'ConnectionPoolMonitoringListener',
    
    # Global instance management
    'get_pool_manager',
    'close_global_pool_manager',
    
    # Prometheus metrics (for external monitoring integration)
    'connection_pool_size',
    'connection_pool_active',
    'connection_pool_checked_out',
    'connection_pool_wait_time',
    'connection_pool_operations',
    'connection_pool_errors',
    'connection_pool_health_status',
    'connection_pool_info'
]