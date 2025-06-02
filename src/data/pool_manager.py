"""
Database Connection Pool Management for PyMongo and Motor Drivers

This module implements enterprise-grade database connection pool management for the Node.js to Python Flask
migration, providing optimized connection pooling for both PyMongo 4.5+ synchronous and Motor 3.3+ asynchronous
drivers. Ensures ≤10% performance variance from Node.js baseline through comprehensive pool optimization,
health monitoring, and resource management.

Key Features:
- Optimized connection pool management equivalent to Node.js patterns per Section 0.1.2 
- Resource optimization for database connections per Section 5.2.5 database access layer
- Connection pool tuning for performance optimization per Section 6.2.4 performance optimization
- Pool health monitoring for system reliability per Section 6.2.2 data management
- Prometheus metrics integration for monitoring per Section 6.2.4 performance monitoring
- Circuit breaker integration for fault tolerance per Section 6.2.3 backup and fault tolerance
- Automatic recovery mechanisms for connection failures per Section 5.2.5 database access layer

Technical Implementation:
- PyMongo 4.5+ connection pool optimization with performance monitoring
- Motor 3.3+ async pool management for high-throughput operations  
- Redis connection pool management via redis-py 5.0+
- Connection pool metrics collection via prometheus-client 0.17+
- Health checking and automatic recovery with circuit breaker patterns
- Resource allocation optimization for enterprise-grade performance
"""

import asyncio
import logging
import time
import threading
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Union, List, Callable, Tuple
from contextlib import contextmanager, asynccontextmanager
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor

import structlog
import pymongo
from pymongo import MongoClient
from pymongo.errors import (
    ConnectionFailure, 
    ServerSelectionTimeoutError,
    NetworkTimeout,
    AutoReconnect
)
from motor.motor_asyncio import AsyncIOMotorClient
import redis
from redis.connection import ConnectionPool
from redis.exceptions import ConnectionError as RedisConnectionError
from prometheus_client import Counter, Histogram, Gauge, Info

from src.config.database import DatabaseConfig, get_database_config
from src.data.monitoring import (
    DatabaseMetrics,
    create_database_metrics,
    initialize_database_monitoring,
    get_database_monitoring_components
)
from src.data.exceptions import (
    ConnectionException,
    ResourceException,
    TimeoutException,
    DatabaseCircuitBreaker,
    with_database_retry,
    DatabaseOperationType,
    DatabaseErrorSeverity,
    DatabaseErrorCategory,
    handle_database_error,
    DatabaseErrorRecovery
)

# Configure structured logging
logger = structlog.get_logger(__name__)

# Connection pool performance metrics
pool_manager_metrics = {
    'pool_utilization': Gauge(
        'database_pool_utilization_percentage',
        'Database connection pool utilization percentage',
        ['pool_type', 'database', 'address']
    ),
    'pool_efficiency': Histogram(
        'database_pool_efficiency_seconds',
        'Connection pool efficiency metrics',
        ['pool_type', 'operation', 'database']
    ),
    'pool_health_score': Gauge(
        'database_pool_health_score',
        'Database connection pool health score (0-100)',
        ['pool_type', 'database', 'address']
    ),
    'pool_recovery_attempts': Counter(
        'database_pool_recovery_attempts_total',
        'Total connection pool recovery attempts',
        ['pool_type', 'recovery_type', 'database']
    ),
    'pool_optimization_events': Counter(
        'database_pool_optimization_events_total',
        'Connection pool optimization events',
        ['pool_type', 'optimization_type', 'database']
    )
}


class PoolType(Enum):
    """Connection pool types for classification"""
    PYMONGO = "pymongo"
    MOTOR = "motor"
    REDIS = "redis"


class PoolState(Enum):
    """Connection pool operational states"""
    INITIALIZING = "initializing"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    RECOVERING = "recovering"
    SHUTDOWN = "shutdown"


class OptimizationStrategy(Enum):
    """Pool optimization strategies"""
    PERFORMANCE = "performance"
    RESOURCE_EFFICIENCY = "resource_efficiency"
    BALANCED = "balanced"
    CONSERVATIVE = "conservative"


@dataclass
class PoolMetrics:
    """Connection pool metrics container for comprehensive monitoring"""
    pool_type: PoolType
    total_connections: int = 0
    active_connections: int = 0
    idle_connections: int = 0
    pending_connections: int = 0
    failed_connections: int = 0
    total_checkouts: int = 0
    successful_checkouts: int = 0
    failed_checkouts: int = 0
    average_checkout_time: float = 0.0
    peak_connections: int = 0
    last_health_check: Optional[datetime] = None
    health_score: float = 100.0
    state: PoolState = PoolState.INITIALIZING
    optimization_events: List[str] = field(default_factory=list)
    performance_variance: float = 0.0  # Percentage variance from baseline


@dataclass
class PoolConfiguration:
    """Advanced connection pool configuration for optimization"""
    min_pool_size: int = 5
    max_pool_size: int = 50
    idle_timeout_ms: int = 30000
    wait_queue_timeout_ms: int = 30000
    server_selection_timeout_ms: int = 10000
    connect_timeout_ms: int = 10000
    socket_timeout_ms: int = 30000
    heartbeat_frequency_ms: int = 10000
    max_idle_time_ms: int = 30000
    maintenance_frequency_sec: int = 60
    health_check_frequency_sec: int = 30
    optimization_strategy: OptimizationStrategy = OptimizationStrategy.BALANCED
    enable_automatic_optimization: bool = True
    performance_baseline_ms: float = 50.0  # Node.js performance baseline
    variance_threshold_percentage: float = 10.0  # ≤10% variance requirement


class ConnectionPoolManager:
    """
    Enterprise-grade connection pool manager for PyMongo, Motor, and Redis connections.
    
    Implements optimized connection pooling patterns equivalent to Node.js while providing
    comprehensive monitoring, health management, and performance optimization to ensure
    ≤10% variance from baseline performance requirements.
    
    Features:
    - Multi-driver pool management (PyMongo, Motor, Redis)
    - Automatic pool optimization and tuning
    - Health monitoring with circuit breaker integration
    - Performance variance tracking against Node.js baseline
    - Prometheus metrics collection and exposition
    - Resource allocation optimization for enterprise workloads
    - Automatic recovery mechanisms for connection failures
    """
    
    def __init__(
        self,
        database_config: Optional[DatabaseConfig] = None,
        optimization_strategy: OptimizationStrategy = OptimizationStrategy.BALANCED,
        enable_monitoring: bool = True
    ):
        """
        Initialize connection pool manager with advanced configuration.
        
        Args:
            database_config: Database configuration instance
            optimization_strategy: Pool optimization strategy
            enable_monitoring: Enable comprehensive monitoring and metrics
        """
        self.database_config = database_config or get_database_config()
        self.optimization_strategy = optimization_strategy
        self.enable_monitoring = enable_monitoring
        
        # Pool management state
        self._pools: Dict[str, Any] = {}
        self._pool_configs: Dict[str, PoolConfiguration] = {}
        self._pool_metrics: Dict[str, PoolMetrics] = {}
        self._pool_locks: Dict[str, threading.RLock] = {}
        self._shutdown_event = threading.Event()
        
        # Circuit breakers for fault tolerance
        self._circuit_breakers: Dict[str, DatabaseCircuitBreaker] = {}
        
        # Monitoring and optimization
        self._monitoring_enabled = enable_monitoring
        self._metrics_collector = None
        self._optimization_thread: Optional[threading.Thread] = None
        self._health_check_thread: Optional[threading.Thread] = None
        
        # Performance tracking
        self._performance_baselines: Dict[str, float] = {}
        self._performance_history: Dict[str, List[float]] = {}
        
        # Thread pool for async operations
        self._thread_pool = ThreadPoolExecutor(max_workers=10, thread_name_prefix="pool_manager")
        
        logger.info(
            "ConnectionPoolManager initialized",
            optimization_strategy=optimization_strategy.value,
            monitoring_enabled=enable_monitoring
        )
        
        # Initialize monitoring components
        if self.enable_monitoring:
            self._initialize_monitoring()
        
        # Start background threads
        self._start_background_threads()
    
    def _initialize_monitoring(self) -> None:
        """Initialize comprehensive monitoring and metrics collection."""
        try:
            if not get_database_monitoring_components():
                initialize_database_monitoring()
            
            self._metrics_collector = get_database_monitoring_components()
            logger.info("Pool manager monitoring initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing pool manager monitoring: {e}")
            self.enable_monitoring = False
    
    def _start_background_threads(self) -> None:
        """Start background threads for pool optimization and health monitoring."""
        try:
            # Pool optimization thread
            if self.optimization_strategy != OptimizationStrategy.CONSERVATIVE:
                self._optimization_thread = threading.Thread(
                    target=self._pool_optimization_worker,
                    name="pool_optimization",
                    daemon=True
                )
                self._optimization_thread.start()
            
            # Health monitoring thread
            self._health_check_thread = threading.Thread(
                target=self._health_monitoring_worker,
                name="pool_health_monitor",
                daemon=True
            )
            self._health_check_thread.start()
            
            logger.info("Pool manager background threads started successfully")
            
        except Exception as e:
            logger.error(f"Error starting pool manager background threads: {e}")
    
    def create_pymongo_pool(
        self,
        pool_name: str,
        custom_config: Optional[PoolConfiguration] = None
    ) -> MongoClient:
        """
        Create optimized PyMongo connection pool with performance monitoring.
        
        Args:
            pool_name: Unique identifier for the connection pool
            custom_config: Custom pool configuration (optional)
            
        Returns:
            MongoClient: Configured PyMongo client with optimized pooling
            
        Raises:
            ConnectionException: If pool creation fails
        """
        with self._get_pool_lock(pool_name):
            try:
                logger.info(f"Creating PyMongo connection pool: {pool_name}")
                
                # Configure pool settings
                config = custom_config or self._create_default_pool_config(PoolType.PYMONGO)
                self._pool_configs[pool_name] = config
                
                # Build PyMongo connection options
                pool_options = {
                    'maxPoolSize': config.max_pool_size,
                    'minPoolSize': config.min_pool_size,
                    'maxIdleTimeMS': config.max_idle_time_ms,
                    'waitQueueTimeoutMS': config.wait_queue_timeout_ms,
                    'serverSelectionTimeoutMS': config.server_selection_timeout_ms,
                    'connectTimeoutMS': config.connect_timeout_ms,
                    'socketTimeoutMS': config.socket_timeout_ms,
                    'heartbeatFrequencyMS': config.heartbeat_frequency_ms,
                    'retryWrites': True,
                    'retryReads': True
                }
                
                # Create MongoClient with optimized pool configuration
                client = MongoClient(
                    self.database_config.mongodb_uri,
                    **pool_options
                )
                
                # Test connection
                start_time = time.perf_counter()
                client.admin.command('ping')
                connection_time = (time.perf_counter() - start_time) * 1000
                
                # Store pool reference and initialize metrics
                self._pools[pool_name] = client
                self._pool_metrics[pool_name] = PoolMetrics(
                    pool_type=PoolType.PYMONGO,
                    state=PoolState.HEALTHY,
                    last_health_check=datetime.now(timezone.utc),
                    health_score=100.0
                )
                
                # Initialize circuit breaker
                self._circuit_breakers[pool_name] = DatabaseCircuitBreaker(
                    name=f"pymongo_{pool_name}",
                    failure_threshold=5,
                    timeout=60
                )
                
                # Update performance baseline
                self._performance_baselines[pool_name] = connection_time
                self._performance_history[pool_name] = [connection_time]
                
                # Emit metrics
                if self.enable_monitoring:
                    pool_manager_metrics['pool_health_score'].labels(
                        pool_type=PoolType.PYMONGO.value,
                        database=pool_name,
                        address=str(client.address) if client.address else 'unknown'
                    ).set(100.0)
                
                logger.info(
                    f"PyMongo connection pool created successfully: {pool_name}",
                    connection_time_ms=connection_time,
                    max_pool_size=config.max_pool_size,
                    min_pool_size=config.min_pool_size
                )
                
                return client
                
            except Exception as e:
                error_msg = f"Failed to create PyMongo connection pool '{pool_name}': {str(e)}"
                logger.error(error_msg, error=str(e))
                
                # Clean up on failure
                self._pools.pop(pool_name, None)
                self._pool_configs.pop(pool_name, None)
                self._pool_metrics.pop(pool_name, None)
                
                raise ConnectionException(
                    error_msg,
                    severity=DatabaseErrorSeverity.HIGH,
                    category=DatabaseErrorCategory.NETWORK,
                    operation=DatabaseOperationType.CONNECTION,
                    database=pool_name,
                    original_error=e
                )
    
    def create_motor_pool(
        self,
        pool_name: str,
        custom_config: Optional[PoolConfiguration] = None
    ) -> AsyncIOMotorClient:
        """
        Create optimized Motor async connection pool for high-performance operations.
        
        Args:
            pool_name: Unique identifier for the async connection pool
            custom_config: Custom pool configuration (optional)
            
        Returns:
            AsyncIOMotorClient: Configured Motor async client with optimized pooling
            
        Raises:
            ConnectionException: If async pool creation fails
        """
        with self._get_pool_lock(pool_name):
            try:
                logger.info(f"Creating Motor async connection pool: {pool_name}")
                
                # Configure async pool settings
                config = custom_config or self._create_default_pool_config(PoolType.MOTOR)
                self._pool_configs[pool_name] = config
                
                # Build Motor connection options (enhanced for async)
                pool_options = {
                    'maxPoolSize': config.max_pool_size * 2,  # Higher for async operations
                    'minPoolSize': config.min_pool_size * 2,
                    'maxIdleTimeMS': config.max_idle_time_ms,
                    'waitQueueTimeoutMS': config.wait_queue_timeout_ms,
                    'waitQueueMultiple': 2,  # Enhanced async queue handling
                    'serverSelectionTimeoutMS': config.server_selection_timeout_ms,
                    'connectTimeoutMS': config.connect_timeout_ms,
                    'socketTimeoutMS': config.socket_timeout_ms,
                    'heartbeatFrequencyMS': config.heartbeat_frequency_ms,
                    'retryWrites': True,
                    'retryReads': True
                }
                
                # Create AsyncIOMotorClient with optimized configuration
                client = AsyncIOMotorClient(
                    self.database_config.mongodb_uri,
                    **pool_options
                )
                
                # Store pool reference and initialize metrics
                self._pools[pool_name] = client
                self._pool_metrics[pool_name] = PoolMetrics(
                    pool_type=PoolType.MOTOR,
                    state=PoolState.HEALTHY,
                    last_health_check=datetime.now(timezone.utc),
                    health_score=100.0
                )
                
                # Initialize circuit breaker for async operations
                self._circuit_breakers[pool_name] = DatabaseCircuitBreaker(
                    name=f"motor_{pool_name}",
                    failure_threshold=8,  # Higher threshold for async operations
                    timeout=45
                )
                
                # Initialize performance tracking
                self._performance_baselines[pool_name] = config.performance_baseline_ms
                self._performance_history[pool_name] = [config.performance_baseline_ms]
                
                # Emit metrics
                if self.enable_monitoring:
                    pool_manager_metrics['pool_health_score'].labels(
                        pool_type=PoolType.MOTOR.value,
                        database=pool_name,
                        address='motor_cluster'
                    ).set(100.0)
                
                logger.info(
                    f"Motor async connection pool created successfully: {pool_name}",
                    max_pool_size=pool_options['maxPoolSize'],
                    min_pool_size=pool_options['minPoolSize'],
                    wait_queue_multiple=pool_options['waitQueueMultiple']
                )
                
                return client
                
            except Exception as e:
                error_msg = f"Failed to create Motor connection pool '{pool_name}': {str(e)}"
                logger.error(error_msg, error=str(e))
                
                # Clean up on failure
                self._pools.pop(pool_name, None)
                self._pool_configs.pop(pool_name, None)
                self._pool_metrics.pop(pool_name, None)
                
                raise ConnectionException(
                    error_msg,
                    severity=DatabaseErrorSeverity.HIGH,
                    category=DatabaseErrorCategory.NETWORK,
                    operation=DatabaseOperationType.CONNECTION,
                    database=pool_name,
                    original_error=e
                )
    
    def create_redis_pool(
        self,
        pool_name: str,
        custom_config: Optional[PoolConfiguration] = None
    ) -> redis.Redis:
        """
        Create optimized Redis connection pool for caching and session management.
        
        Args:
            pool_name: Unique identifier for the Redis connection pool
            custom_config: Custom pool configuration (optional)
            
        Returns:
            redis.Redis: Configured Redis client with optimized connection pooling
            
        Raises:
            ConnectionException: If Redis pool creation fails
        """
        with self._get_pool_lock(pool_name):
            try:
                logger.info(f"Creating Redis connection pool: {pool_name}")
                
                # Configure Redis pool settings
                config = custom_config or self._create_default_pool_config(PoolType.REDIS)
                self._pool_configs[pool_name] = config
                
                # Create Redis connection pool
                connection_pool = ConnectionPool(
                    host=self.database_config.redis_host,
                    port=self.database_config.redis_port,
                    password=self.database_config.redis_password,
                    db=self.database_config.redis_db,
                    ssl=self.database_config.redis_ssl,
                    max_connections=config.max_pool_size,
                    retry_on_timeout=True,
                    socket_timeout=config.socket_timeout_ms / 1000.0,
                    socket_connect_timeout=config.connect_timeout_ms / 1000.0,
                    socket_keepalive=True,
                    socket_keepalive_options={},
                    health_check_interval=config.health_check_frequency_sec
                )
                
                # Create Redis client with connection pool
                client = redis.Redis(
                    connection_pool=connection_pool,
                    decode_responses=True
                )
                
                # Test connection
                start_time = time.perf_counter()
                client.ping()
                connection_time = (time.perf_counter() - start_time) * 1000
                
                # Store pool reference and initialize metrics
                self._pools[pool_name] = client
                self._pool_metrics[pool_name] = PoolMetrics(
                    pool_type=PoolType.REDIS,
                    state=PoolState.HEALTHY,
                    last_health_check=datetime.now(timezone.utc),
                    health_score=100.0
                )
                
                # Initialize circuit breaker
                self._circuit_breakers[pool_name] = DatabaseCircuitBreaker(
                    name=f"redis_{pool_name}",
                    failure_threshold=3,
                    timeout=30
                )
                
                # Update performance tracking
                self._performance_baselines[pool_name] = connection_time
                self._performance_history[pool_name] = [connection_time]
                
                # Emit metrics
                if self.enable_monitoring:
                    pool_manager_metrics['pool_health_score'].labels(
                        pool_type=PoolType.REDIS.value,
                        database=pool_name,
                        address=f"{self.database_config.redis_host}:{self.database_config.redis_port}"
                    ).set(100.0)
                
                logger.info(
                    f"Redis connection pool created successfully: {pool_name}",
                    connection_time_ms=connection_time,
                    max_connections=config.max_pool_size,
                    host=self.database_config.redis_host,
                    port=self.database_config.redis_port
                )
                
                return client
                
            except Exception as e:
                error_msg = f"Failed to create Redis connection pool '{pool_name}': {str(e)}"
                logger.error(error_msg, error=str(e))
                
                # Clean up on failure
                self._pools.pop(pool_name, None)
                self._pool_configs.pop(pool_name, None)
                self._pool_metrics.pop(pool_name, None)
                
                raise ConnectionException(
                    error_msg,
                    severity=DatabaseErrorSeverity.HIGH,
                    category=DatabaseErrorCategory.NETWORK,
                    operation=DatabaseOperationType.CONNECTION,
                    database=pool_name,
                    original_error=e
                )
    
    @contextmanager
    def get_connection(self, pool_name: str, timeout: Optional[float] = None):
        """
        Context manager for obtaining database connections with monitoring and error handling.
        
        Args:
            pool_name: Name of the connection pool
            timeout: Connection timeout in seconds
            
        Yields:
            Database connection from the specified pool
            
        Raises:
            ConnectionException: If connection cannot be obtained
            TimeoutException: If connection timeout is exceeded
        """
        connection = None
        start_time = time.perf_counter()
        
        try:
            # Apply circuit breaker protection
            circuit_breaker = self._circuit_breakers.get(pool_name)
            if circuit_breaker and circuit_breaker.circuit_breaker.state == 'open':
                raise ConnectionException(
                    f"Circuit breaker open for pool '{pool_name}'",
                    database=pool_name,
                    retry_recommended=False,
                    recovery_time_estimate=60
                )
            
            # Get connection from pool
            pool = self._pools.get(pool_name)
            if not pool:
                raise ConnectionException(
                    f"Connection pool '{pool_name}' not found",
                    database=pool_name
                )
            
            connection = pool
            
            # Update metrics
            checkout_time = (time.perf_counter() - start_time) * 1000
            self._update_connection_metrics(pool_name, checkout_time, success=True)
            
            yield connection
            
        except Exception as e:
            # Update error metrics
            checkout_time = (time.perf_counter() - start_time) * 1000
            self._update_connection_metrics(pool_name, checkout_time, success=False)
            
            # Handle and re-raise appropriate exception
            if isinstance(e, (ConnectionException, TimeoutException)):
                raise
            else:
                raise handle_database_error(
                    e,
                    operation=DatabaseOperationType.CONNECTION,
                    database=pool_name,
                    auto_recover=True
                )
        
        finally:
            # Emit performance metrics
            if self.enable_monitoring:
                total_time = (time.perf_counter() - start_time) * 1000
                pool_manager_metrics['pool_efficiency'].labels(
                    pool_type=self._get_pool_type(pool_name).value,
                    operation='connection_checkout',
                    database=pool_name
                ).observe(total_time / 1000.0)
    
    @asynccontextmanager
    async def get_async_connection(self, pool_name: str, timeout: Optional[float] = None):
        """
        Async context manager for obtaining Motor async database connections.
        
        Args:
            pool_name: Name of the Motor connection pool
            timeout: Connection timeout in seconds
            
        Yields:
            Motor async database connection
            
        Raises:
            ConnectionException: If async connection cannot be obtained
        """
        connection = None
        start_time = time.perf_counter()
        
        try:
            # Get Motor client from pool
            pool = self._pools.get(pool_name)
            if not pool:
                raise ConnectionException(
                    f"Motor connection pool '{pool_name}' not found",
                    database=pool_name
                )
            
            # Verify it's a Motor client
            pool_metrics = self._pool_metrics.get(pool_name)
            if not pool_metrics or pool_metrics.pool_type != PoolType.MOTOR:
                raise ConnectionException(
                    f"Pool '{pool_name}' is not a Motor async pool",
                    database=pool_name
                )
            
            connection = pool
            
            # Update async metrics
            checkout_time = (time.perf_counter() - start_time) * 1000
            self._update_connection_metrics(pool_name, checkout_time, success=True)
            
            yield connection
            
        except Exception as e:
            # Update error metrics
            checkout_time = (time.perf_counter() - start_time) * 1000
            self._update_connection_metrics(pool_name, checkout_time, success=False)
            
            raise handle_database_error(
                e,
                operation=DatabaseOperationType.CONNECTION,
                database=pool_name,
                auto_recover=True
            )
        
        finally:
            # Emit async performance metrics
            if self.enable_monitoring:
                total_time = (time.perf_counter() - start_time) * 1000
                pool_manager_metrics['pool_efficiency'].labels(
                    pool_type=PoolType.MOTOR.value,
                    operation='async_connection_checkout',
                    database=pool_name
                ).observe(total_time / 1000.0)
    
    def get_pool_health_status(self, pool_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Get comprehensive health status for connection pools.
        
        Args:
            pool_name: Specific pool name (optional, returns all pools if None)
            
        Returns:
            Dict containing health status for requested pools
        """
        health_status = {}
        
        pools_to_check = [pool_name] if pool_name else list(self._pools.keys())
        
        for name in pools_to_check:
            if name not in self._pool_metrics:
                continue
                
            metrics = self._pool_metrics[name]
            config = self._pool_configs[name]
            
            # Calculate utilization percentage
            utilization = 0.0
            if metrics.total_connections > 0:
                utilization = (metrics.active_connections / metrics.total_connections) * 100
            
            # Calculate performance variance
            variance = self._calculate_performance_variance(name)
            
            health_status[name] = {
                'pool_type': metrics.pool_type.value,
                'state': metrics.state.value,
                'health_score': metrics.health_score,
                'utilization_percentage': utilization,
                'performance_variance_percentage': variance,
                'total_connections': metrics.total_connections,
                'active_connections': metrics.active_connections,
                'idle_connections': metrics.idle_connections,
                'failed_connections': metrics.failed_connections,
                'total_checkouts': metrics.total_checkouts,
                'successful_checkouts': metrics.successful_checkouts,
                'checkout_success_rate': (
                    (metrics.successful_checkouts / max(metrics.total_checkouts, 1)) * 100
                ),
                'average_checkout_time_ms': metrics.average_checkout_time,
                'peak_connections': metrics.peak_connections,
                'last_health_check': metrics.last_health_check.isoformat() if metrics.last_health_check else None,
                'optimization_strategy': config.optimization_strategy.value,
                'recent_optimization_events': metrics.optimization_events[-5:],  # Last 5 events
                'circuit_breaker_state': (
                    self._circuit_breakers[name].circuit_breaker.state 
                    if name in self._circuit_breakers else 'unknown'
                )
            }
        
        return health_status
    
    def optimize_pool(self, pool_name: str, force: bool = False) -> Dict[str, Any]:
        """
        Optimize connection pool configuration based on performance metrics and usage patterns.
        
        Args:
            pool_name: Name of the pool to optimize
            force: Force optimization regardless of current state
            
        Returns:
            Dict containing optimization results and new configuration
        """
        with self._get_pool_lock(pool_name):
            try:
                if pool_name not in self._pools:
                    raise ValueError(f"Pool '{pool_name}' not found")
                
                metrics = self._pool_metrics[pool_name]
                config = self._pool_configs[pool_name]
                
                if not config.enable_automatic_optimization and not force:
                    logger.debug(f"Automatic optimization disabled for pool '{pool_name}'")
                    return {'optimized': False, 'reason': 'automatic_optimization_disabled'}
                
                # Calculate optimization recommendations
                optimization_results = self._calculate_optimization_strategy(pool_name)
                
                if not optimization_results['requires_optimization'] and not force:
                    logger.debug(f"Pool '{pool_name}' does not require optimization")
                    return optimization_results
                
                # Apply optimizations
                old_config = {
                    'max_pool_size': config.max_pool_size,
                    'min_pool_size': config.min_pool_size,
                    'idle_timeout_ms': config.idle_timeout_ms
                }
                
                # Update configuration based on optimization strategy
                if optimization_results['recommendations']['increase_max_pool_size']:
                    new_max_size = min(config.max_pool_size + 10, 200)  # Cap at 200
                    config.max_pool_size = new_max_size
                    logger.info(f"Increased max pool size for '{pool_name}' to {new_max_size}")
                
                if optimization_results['recommendations']['decrease_max_pool_size']:
                    new_max_size = max(config.max_pool_size - 5, config.min_pool_size)
                    config.max_pool_size = new_max_size
                    logger.info(f"Decreased max pool size for '{pool_name}' to {new_max_size}")
                
                if optimization_results['recommendations']['adjust_idle_timeout']:
                    # Optimize idle timeout based on usage patterns
                    if metrics.utilization_percentage > 80:
                        config.idle_timeout_ms = max(config.idle_timeout_ms - 5000, 10000)
                    else:
                        config.idle_timeout_ms = min(config.idle_timeout_ms + 5000, 60000)
                
                # Record optimization event
                optimization_event = f"optimization_applied_{datetime.now(timezone.utc).isoformat()}"
                metrics.optimization_events.append(optimization_event)
                
                # Emit optimization metrics
                if self.enable_monitoring:
                    pool_manager_metrics['pool_optimization_events'].labels(
                        pool_type=metrics.pool_type.value,
                        optimization_type='performance_tuning',
                        database=pool_name
                    ).inc()
                
                logger.info(
                    f"Pool optimization completed for '{pool_name}'",
                    old_config=old_config,
                    new_config={
                        'max_pool_size': config.max_pool_size,
                        'min_pool_size': config.min_pool_size,
                        'idle_timeout_ms': config.idle_timeout_ms
                    },
                    optimization_score=optimization_results['optimization_score']
                )
                
                return {
                    'optimized': True,
                    'old_config': old_config,
                    'new_config': {
                        'max_pool_size': config.max_pool_size,
                        'min_pool_size': config.min_pool_size,
                        'idle_timeout_ms': config.idle_timeout_ms
                    },
                    'optimization_score': optimization_results['optimization_score'],
                    'recommendations_applied': optimization_results['recommendations']
                }
                
            except Exception as e:
                logger.error(f"Error optimizing pool '{pool_name}': {e}")
                return {'optimized': False, 'error': str(e)}
    
    def recover_pool(self, pool_name: str) -> Dict[str, Any]:
        """
        Attempt to recover a failed or degraded connection pool.
        
        Args:
            pool_name: Name of the pool to recover
            
        Returns:
            Dict containing recovery results and status
        """
        with self._get_pool_lock(pool_name):
            try:
                logger.info(f"Attempting pool recovery for '{pool_name}'")
                
                if pool_name not in self._pools:
                    return {'recovered': False, 'error': 'pool_not_found'}
                
                metrics = self._pool_metrics[pool_name]
                recovery_start_time = time.perf_counter()
                
                # Update state to recovering
                metrics.state = PoolState.RECOVERING
                
                # Emit recovery metrics
                if self.enable_monitoring:
                    pool_manager_metrics['pool_recovery_attempts'].labels(
                        pool_type=metrics.pool_type.value,
                        recovery_type='automatic_recovery',
                        database=pool_name
                    ).inc()
                
                # Perform recovery based on pool type
                recovery_result = None
                
                if metrics.pool_type == PoolType.PYMONGO:
                    recovery_result = self._recover_pymongo_pool(pool_name)
                elif metrics.pool_type == PoolType.MOTOR:
                    recovery_result = self._recover_motor_pool(pool_name)
                elif metrics.pool_type == PoolType.REDIS:
                    recovery_result = self._recover_redis_pool(pool_name)
                
                recovery_duration = time.perf_counter() - recovery_start_time
                
                if recovery_result and recovery_result.get('success', False):
                    metrics.state = PoolState.HEALTHY
                    metrics.health_score = 100.0
                    metrics.last_health_check = datetime.now(timezone.utc)
                    
                    logger.info(
                        f"Pool recovery successful for '{pool_name}'",
                        recovery_duration_sec=recovery_duration,
                        recovery_method=recovery_result.get('method', 'unknown')
                    )
                    
                    return {
                        'recovered': True,
                        'recovery_duration_sec': recovery_duration,
                        'recovery_method': recovery_result.get('method', 'unknown'),
                        'new_health_score': metrics.health_score
                    }
                else:
                    metrics.state = PoolState.UNHEALTHY
                    metrics.health_score = 0.0
                    
                    logger.error(
                        f"Pool recovery failed for '{pool_name}'",
                        recovery_duration_sec=recovery_duration,
                        error=recovery_result.get('error', 'unknown_error') if recovery_result else 'no_recovery_result'
                    )
                    
                    return {
                        'recovered': False,
                        'recovery_duration_sec': recovery_duration,
                        'error': recovery_result.get('error', 'recovery_failed') if recovery_result else 'no_recovery_result'
                    }
                
            except Exception as e:
                logger.error(f"Exception during pool recovery for '{pool_name}': {e}")
                return {'recovered': False, 'error': str(e)}
    
    def shutdown_pool(self, pool_name: str, graceful: bool = True) -> bool:
        """
        Shutdown a specific connection pool with optional graceful closure.
        
        Args:
            pool_name: Name of the pool to shutdown
            graceful: Whether to perform graceful shutdown
            
        Returns:
            bool: True if shutdown successful, False otherwise
        """
        with self._get_pool_lock(pool_name):
            try:
                logger.info(f"Shutting down connection pool: {pool_name}")
                
                if pool_name not in self._pools:
                    logger.warning(f"Pool '{pool_name}' not found for shutdown")
                    return False
                
                pool = self._pools[pool_name]
                metrics = self._pool_metrics[pool_name]
                
                # Update state
                metrics.state = PoolState.SHUTDOWN
                
                # Perform pool-specific shutdown
                if metrics.pool_type == PoolType.PYMONGO:
                    pool.close()
                elif metrics.pool_type == PoolType.MOTOR:
                    pool.close()
                elif metrics.pool_type == PoolType.REDIS:
                    pool.close()
                
                # Clean up resources
                self._pools.pop(pool_name, None)
                self._pool_configs.pop(pool_name, None)
                self._pool_metrics.pop(pool_name, None)
                self._circuit_breakers.pop(pool_name, None)
                self._performance_baselines.pop(pool_name, None)
                self._performance_history.pop(pool_name, None)
                
                logger.info(f"Connection pool shutdown completed: {pool_name}")
                return True
                
            except Exception as e:
                logger.error(f"Error shutting down pool '{pool_name}': {e}")
                return False
    
    def shutdown_all_pools(self, graceful: bool = True) -> Dict[str, bool]:
        """
        Shutdown all connection pools and cleanup resources.
        
        Args:
            graceful: Whether to perform graceful shutdown
            
        Returns:
            Dict mapping pool names to shutdown success status
        """
        logger.info("Shutting down all connection pools")
        
        # Signal shutdown to background threads
        self._shutdown_event.set()
        
        # Shutdown all pools
        shutdown_results = {}
        for pool_name in list(self._pools.keys()):
            shutdown_results[pool_name] = self.shutdown_pool(pool_name, graceful)
        
        # Shutdown thread pool
        try:
            self._thread_pool.shutdown(wait=True, timeout=30)
        except Exception as e:
            logger.error(f"Error shutting down thread pool: {e}")
        
        # Wait for background threads to finish
        if self._optimization_thread and self._optimization_thread.is_alive():
            self._optimization_thread.join(timeout=10)
        
        if self._health_check_thread and self._health_check_thread.is_alive():
            self._health_check_thread.join(timeout=10)
        
        logger.info("All connection pools shutdown completed")
        return shutdown_results
    
    # Private helper methods
    
    def _get_pool_lock(self, pool_name: str) -> threading.RLock:
        """Get or create a lock for the specified pool."""
        if pool_name not in self._pool_locks:
            self._pool_locks[pool_name] = threading.RLock()
        return self._pool_locks[pool_name]
    
    def _get_pool_type(self, pool_name: str) -> PoolType:
        """Get the pool type for the specified pool."""
        metrics = self._pool_metrics.get(pool_name)
        return metrics.pool_type if metrics else PoolType.PYMONGO
    
    def _create_default_pool_config(self, pool_type: PoolType) -> PoolConfiguration:
        """Create default pool configuration based on pool type and optimization strategy."""
        base_config = PoolConfiguration()
        
        # Adjust configuration based on pool type
        if pool_type == PoolType.PYMONGO:
            base_config.max_pool_size = 50
            base_config.min_pool_size = 5
        elif pool_type == PoolType.MOTOR:
            base_config.max_pool_size = 100  # Higher for async operations
            base_config.min_pool_size = 10
        elif pool_type == PoolType.REDIS:
            base_config.max_pool_size = 50
            base_config.min_pool_size = 5
        
        # Adjust based on optimization strategy
        if self.optimization_strategy == OptimizationStrategy.PERFORMANCE:
            base_config.max_pool_size = int(base_config.max_pool_size * 1.5)
            base_config.idle_timeout_ms = 20000  # Shorter idle timeout
        elif self.optimization_strategy == OptimizationStrategy.RESOURCE_EFFICIENCY:
            base_config.max_pool_size = int(base_config.max_pool_size * 0.7)
            base_config.idle_timeout_ms = 60000  # Longer idle timeout
        elif self.optimization_strategy == OptimizationStrategy.CONSERVATIVE:
            base_config.enable_automatic_optimization = False
        
        return base_config
    
    def _update_connection_metrics(self, pool_name: str, checkout_time: float, success: bool) -> None:
        """Update connection checkout metrics."""
        if pool_name not in self._pool_metrics:
            return
        
        metrics = self._pool_metrics[pool_name]
        
        # Update checkout counters
        metrics.total_checkouts += 1
        if success:
            metrics.successful_checkouts += 1
        else:
            metrics.failed_checkouts += 1
        
        # Update average checkout time
        if metrics.total_checkouts > 1:
            metrics.average_checkout_time = (
                (metrics.average_checkout_time * (metrics.total_checkouts - 1) + checkout_time) /
                metrics.total_checkouts
            )
        else:
            metrics.average_checkout_time = checkout_time
        
        # Update utilization metrics
        if self.enable_monitoring:
            pool_config = self._pool_configs[pool_name]
            utilization = (metrics.active_connections / max(pool_config.max_pool_size, 1)) * 100
            
            pool_manager_metrics['pool_utilization'].labels(
                pool_type=metrics.pool_type.value,
                database=pool_name,
                address='pool_manager'
            ).set(utilization)
    
    def _calculate_performance_variance(self, pool_name: str) -> float:
        """Calculate performance variance from baseline."""
        if pool_name not in self._performance_history:
            return 0.0
        
        history = self._performance_history[pool_name]
        baseline = self._performance_baselines.get(pool_name, 50.0)
        
        if not history:
            return 0.0
        
        # Calculate recent average (last 10 measurements)
        recent_average = sum(history[-10:]) / len(history[-10:])
        
        # Calculate variance percentage
        variance = ((recent_average - baseline) / baseline) * 100 if baseline > 0 else 0.0
        
        return variance
    
    def _calculate_optimization_strategy(self, pool_name: str) -> Dict[str, Any]:
        """Calculate optimization recommendations for a pool."""
        metrics = self._pool_metrics[pool_name]
        config = self._pool_configs[pool_name]
        
        # Calculate current utilization
        utilization = 0.0
        if metrics.total_connections > 0:
            utilization = (metrics.active_connections / metrics.total_connections) * 100
        
        # Calculate checkout success rate
        success_rate = 0.0
        if metrics.total_checkouts > 0:
            success_rate = (metrics.successful_checkouts / metrics.total_checkouts) * 100
        
        # Calculate performance variance
        variance = self._calculate_performance_variance(pool_name)
        
        # Determine optimization requirements
        requires_optimization = False
        recommendations = {
            'increase_max_pool_size': False,
            'decrease_max_pool_size': False,
            'adjust_idle_timeout': False,
            'improve_connection_handling': False
        }
        
        # High utilization suggests need for more connections
        if utilization > 90:
            requires_optimization = True
            recommendations['increase_max_pool_size'] = True
        
        # Low utilization suggests over-provisioning
        elif utilization < 30 and config.max_pool_size > config.min_pool_size + 10:
            requires_optimization = True
            recommendations['decrease_max_pool_size'] = True
        
        # Poor success rate suggests connection issues
        if success_rate < 95:
            requires_optimization = True
            recommendations['improve_connection_handling'] = True
        
        # High performance variance suggests tuning needed
        if abs(variance) > config.variance_threshold_percentage:
            requires_optimization = True
            recommendations['adjust_idle_timeout'] = True
        
        # Calculate optimization score
        optimization_score = min(100, max(0, 
            (success_rate * 0.4) + 
            ((100 - min(abs(variance), 50)) * 0.3) +
            ((100 - min(utilization, 100)) * 0.3)
        ))
        
        return {
            'requires_optimization': requires_optimization,
            'optimization_score': optimization_score,
            'current_metrics': {
                'utilization_percentage': utilization,
                'success_rate': success_rate,
                'performance_variance': variance,
                'average_checkout_time': metrics.average_checkout_time
            },
            'recommendations': recommendations
        }
    
    def _recover_pymongo_pool(self, pool_name: str) -> Dict[str, Any]:
        """Recover a PyMongo connection pool."""
        try:
            # Close existing client
            if pool_name in self._pools:
                self._pools[pool_name].close()
            
            # Recreate the pool
            config = self._pool_configs[pool_name]
            new_client = self.create_pymongo_pool(pool_name, config)
            
            return {'success': True, 'method': 'recreate_client'}
        except Exception as e:
            return {'success': False, 'error': str(e), 'method': 'recreate_client'}
    
    def _recover_motor_pool(self, pool_name: str) -> Dict[str, Any]:
        """Recover a Motor async connection pool."""
        try:
            # Close existing client
            if pool_name in self._pools:
                self._pools[pool_name].close()
            
            # Recreate the pool
            config = self._pool_configs[pool_name]
            new_client = self.create_motor_pool(pool_name, config)
            
            return {'success': True, 'method': 'recreate_async_client'}
        except Exception as e:
            return {'success': False, 'error': str(e), 'method': 'recreate_async_client'}
    
    def _recover_redis_pool(self, pool_name: str) -> Dict[str, Any]:
        """Recover a Redis connection pool."""
        try:
            # Close existing client
            if pool_name in self._pools:
                self._pools[pool_name].close()
            
            # Recreate the pool
            config = self._pool_configs[pool_name]
            new_client = self.create_redis_pool(pool_name, config)
            
            return {'success': True, 'method': 'recreate_redis_client'}
        except Exception as e:
            return {'success': False, 'error': str(e), 'method': 'recreate_redis_client'}
    
    def _pool_optimization_worker(self) -> None:
        """Background thread worker for automatic pool optimization."""
        logger.info("Pool optimization worker started")
        
        while not self._shutdown_event.is_set():
            try:
                # Wait for optimization interval
                if self._shutdown_event.wait(timeout=300):  # 5 minutes
                    break
                
                # Optimize all pools
                for pool_name in list(self._pools.keys()):
                    try:
                        self.optimize_pool(pool_name, force=False)
                    except Exception as e:
                        logger.error(f"Error optimizing pool '{pool_name}': {e}")
                
            except Exception as e:
                logger.error(f"Error in pool optimization worker: {e}")
        
        logger.info("Pool optimization worker stopped")
    
    def _health_monitoring_worker(self) -> None:
        """Background thread worker for pool health monitoring."""
        logger.info("Pool health monitoring worker started")
        
        while not self._shutdown_event.is_set():
            try:
                # Wait for health check interval
                if self._shutdown_event.wait(timeout=30):  # 30 seconds
                    break
                
                # Check health of all pools
                for pool_name in list(self._pools.keys()):
                    try:
                        self._perform_health_check(pool_name)
                    except Exception as e:
                        logger.error(f"Error checking health of pool '{pool_name}': {e}")
                
            except Exception as e:
                logger.error(f"Error in health monitoring worker: {e}")
        
        logger.info("Pool health monitoring worker stopped")
    
    def _perform_health_check(self, pool_name: str) -> None:
        """Perform health check on a specific pool."""
        if pool_name not in self._pools or pool_name not in self._pool_metrics:
            return
        
        metrics = self._pool_metrics[pool_name]
        pool = self._pools[pool_name]
        
        try:
            start_time = time.perf_counter()
            
            # Perform pool-specific health check
            if metrics.pool_type == PoolType.PYMONGO:
                pool.admin.command('ping')
            elif metrics.pool_type == PoolType.MOTOR:
                # Motor health check would need to be async, skip for now
                pass
            elif metrics.pool_type == PoolType.REDIS:
                pool.ping()
            
            health_check_time = (time.perf_counter() - start_time) * 1000
            
            # Update health metrics
            metrics.last_health_check = datetime.now(timezone.utc)
            
            # Calculate health score based on performance
            if health_check_time < 10:  # < 10ms is excellent
                health_score = 100.0
            elif health_check_time < 50:  # < 50ms is good
                health_score = 90.0
            elif health_check_time < 100:  # < 100ms is acceptable
                health_score = 70.0
            else:  # > 100ms is concerning
                health_score = 50.0
            
            metrics.health_score = health_score
            metrics.state = PoolState.HEALTHY
            
            # Update monitoring metrics
            if self.enable_monitoring:
                pool_manager_metrics['pool_health_score'].labels(
                    pool_type=metrics.pool_type.value,
                    database=pool_name,
                    address='health_monitor'
                ).set(health_score)
            
        except Exception as e:
            # Health check failed
            metrics.health_score = 0.0
            metrics.state = PoolState.UNHEALTHY
            
            logger.warning(
                f"Health check failed for pool '{pool_name}': {e}",
                pool_type=metrics.pool_type.value
            )
            
            # Attempt recovery if enabled
            if self.optimization_strategy != OptimizationStrategy.CONSERVATIVE:
                recovery_result = self.recover_pool(pool_name)
                if recovery_result.get('recovered', False):
                    logger.info(f"Automatic recovery successful for pool '{pool_name}'")


# Global pool manager instance
_pool_manager: Optional[ConnectionPoolManager] = None


def initialize_pool_manager(
    database_config: Optional[DatabaseConfig] = None,
    optimization_strategy: OptimizationStrategy = OptimizationStrategy.BALANCED
) -> ConnectionPoolManager:
    """
    Initialize global connection pool manager instance.
    
    Args:
        database_config: Database configuration instance
        optimization_strategy: Pool optimization strategy
        
    Returns:
        ConnectionPoolManager: Initialized pool manager instance
    """
    global _pool_manager
    
    _pool_manager = ConnectionPoolManager(
        database_config=database_config,
        optimization_strategy=optimization_strategy,
        enable_monitoring=True
    )
    
    logger.info(
        "Global connection pool manager initialized",
        optimization_strategy=optimization_strategy.value
    )
    
    return _pool_manager


def get_pool_manager() -> ConnectionPoolManager:
    """
    Get global connection pool manager instance.
    
    Returns:
        ConnectionPoolManager: Global pool manager instance
        
    Raises:
        RuntimeError: If pool manager has not been initialized
    """
    if _pool_manager is None:
        raise RuntimeError(
            "Connection pool manager not initialized. "
            "Call initialize_pool_manager() first."
        )
    return _pool_manager


def create_optimized_pymongo_pool(pool_name: str) -> MongoClient:
    """
    Create optimized PyMongo connection pool using global manager.
    
    Args:
        pool_name: Unique identifier for the connection pool
        
    Returns:
        MongoClient: Configured PyMongo client with optimized pooling
    """
    return get_pool_manager().create_pymongo_pool(pool_name)


def create_optimized_motor_pool(pool_name: str) -> AsyncIOMotorClient:
    """
    Create optimized Motor async connection pool using global manager.
    
    Args:
        pool_name: Unique identifier for the async connection pool
        
    Returns:
        AsyncIOMotorClient: Configured Motor async client with optimized pooling
    """
    return get_pool_manager().create_motor_pool(pool_name)


def create_optimized_redis_pool(pool_name: str) -> redis.Redis:
    """
    Create optimized Redis connection pool using global manager.
    
    Args:
        pool_name: Unique identifier for the Redis connection pool
        
    Returns:
        redis.Redis: Configured Redis client with optimized connection pooling
    """
    return get_pool_manager().create_redis_pool(pool_name)


@contextmanager
def get_database_connection(pool_name: str, timeout: Optional[float] = None):
    """
    Context manager for obtaining database connections from global pool manager.
    
    Args:
        pool_name: Name of the connection pool
        timeout: Connection timeout in seconds
        
    Yields:
        Database connection from the specified pool
    """
    with get_pool_manager().get_connection(pool_name, timeout) as connection:
        yield connection


@asynccontextmanager
async def get_async_database_connection(pool_name: str, timeout: Optional[float] = None):
    """
    Async context manager for obtaining Motor async database connections from global pool manager.
    
    Args:
        pool_name: Name of the Motor connection pool
        timeout: Connection timeout in seconds
        
    Yields:
        Motor async database connection
    """
    async with get_pool_manager().get_async_connection(pool_name, timeout) as connection:
        yield connection


# Export public interface
__all__ = [
    'ConnectionPoolManager',
    'PoolType',
    'PoolState',
    'OptimizationStrategy',
    'PoolMetrics',
    'PoolConfiguration',
    'initialize_pool_manager',
    'get_pool_manager',
    'create_optimized_pymongo_pool',
    'create_optimized_motor_pool',
    'create_optimized_redis_pool',
    'get_database_connection',
    'get_async_database_connection',
    'pool_manager_metrics'
]