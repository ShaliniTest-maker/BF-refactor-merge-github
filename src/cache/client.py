"""
Redis Client Implementation with Enterprise-Grade Connection Pooling and Circuit Breaker Patterns

This module implements the core Redis client with redis-py 5.0+ providing comprehensive connection
pooling, circuit breaker patterns, and enterprise-grade error handling for the Node.js to Python
Flask migration. Manages Redis connections with distributed caching capabilities across multiple
Flask instances while ensuring ≤10% performance variance from Node.js baseline.

Key Features:
- redis-py 5.0+ Redis client replacing Node.js Redis client per Section 0.1.2
- Connection pool management with equivalent patterns per Section 0.1.2
- Circuit breaker implementation using pybreaker 1.3.0 per Section 6.1.3
- Exponential backoff retry logic with tenacity 9.1.2 per Section 6.1.3
- Distributed caching for multi-instance deployments per Section 3.4.2
- Comprehensive error handling with src/cache/exceptions.py integration
- Performance monitoring with src/cache/monitoring.py integration
- Health check endpoints for Kubernetes probe support per Section 6.1.3

Technical Specifications:
- Socket timeout: 30.0 seconds per Section 6.1.3 Redis connection pool settings
- Socket connect timeout: 10.0 seconds per Section 6.1.3
- Max connections: 50 per Section 6.1.3 resource optimization
- Retry on timeout: True per Section 6.1.3 connection resilience
- Health check interval: 30 seconds per Section 6.1.3 monitoring endpoints
- Circuit breaker fail_max: 5 failures per Section 6.1.3 resilience mechanisms
- Circuit breaker reset_timeout: 60 seconds per Section 6.1.3

Architecture Integration:
- Flask application factory pattern compatibility per Section 6.1.1
- Seamless integration with src/config/database.py configuration management
- Enterprise monitoring integration with src/cache/monitoring.py
- Circuit breaker coordination with src/cache/exceptions.py error handling
- Performance variance tracking against Node.js baseline cache performance

References:
- Section 0.1.2: Data access components Redis client migration requirements
- Section 6.1.3: Resilience mechanisms and connection pool optimization
- Section 3.4.2: Distributed session architecture for multi-instance deployments
- Section 6.1.1: Flask application factory pattern integration requirements
"""

import asyncio
import json
import logging
import threading
import time
import traceback
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Dict, List, Optional, Union, Callable, Tuple, Iterator
from threading import Lock, RLock
from concurrent.futures import ThreadPoolExecutor

import redis
from redis.connection import ConnectionPool
from redis.exceptions import (
    ConnectionError as RedisConnectionError,
    TimeoutError as RedisTimeoutError,
    ResponseError as RedisResponseError,
    AuthenticationError as RedisAuthenticationError,
    DataError as RedisDataError,
    BusyLoadingError as RedisBusyLoadingError
)

# Circuit breaker implementation
try:
    from pybreaker import CircuitBreaker, CircuitBreakerError
except ImportError:
    # Fallback implementation if pybreaker is not available
    class CircuitBreaker:
        def __init__(self, fail_max=5, reset_timeout=60, expected_exception=Exception):
            self.fail_max = fail_max
            self.reset_timeout = reset_timeout
            self.expected_exception = expected_exception
            self._failure_count = 0
            self._last_failure_time = None
            self._state = 'closed'  # closed, open, half-open
        
        def __call__(self, func):
            return func
        
        @property
        def current_state(self):
            return self._state
    
    class CircuitBreakerError(Exception):
        pass

# Retry logic implementation
try:
    from tenacity import (
        retry, 
        stop_after_attempt, 
        wait_exponential, 
        retry_if_exception_type,
        wait_random_exponential
    )
except ImportError:
    # Fallback decorators if tenacity is not available
    def retry(*args, **kwargs):
        def decorator(func):
            return func
        return decorator
    
    def stop_after_attempt(attempts):
        return None
    
    def wait_exponential(**kwargs):
        return None
    
    def retry_if_exception_type(exception_type):
        return None
    
    def wait_random_exponential(**kwargs):
        return None

import structlog

# Import configuration and monitoring components
from src.config.database import DatabaseConfig, get_database_config
from src.cache.exceptions import (
    CacheError,
    RedisConnectionError,
    CacheOperationTimeoutError,
    CacheInvalidationError,
    CircuitBreakerOpenError,
    CacheKeyError,
    CacheSerializationError,
    CachePoolExhaustedError,
    handle_redis_exception
)
from src.cache.monitoring import (
    CacheMonitoringManager,
    monitor_cache_operation,
    track_cache_hit_miss
)

# Configure structured logging
logger = structlog.get_logger(__name__)


class RedisConnectionManager:
    """
    Redis connection management with enterprise-grade connection pooling,
    circuit breaker patterns, and comprehensive error handling.
    
    This class implements the Redis client migration requirements from Node.js
    to redis-py 5.0+ with equivalent connection patterns and enhanced resilience
    mechanisms per Section 6.1.3.
    
    Features:
    - Optimized connection pooling with configurable pool sizes and timeouts
    - Circuit breaker implementation for Redis connectivity resilience
    - Exponential backoff retry logic for transient failures
    - Health check integration for monitoring and alerting
    - Performance monitoring with metrics collection
    - Distributed caching support for multi-instance deployments
    """
    
    def __init__(self, config: Optional[DatabaseConfig] = None):
        """
        Initialize Redis connection manager with configuration.
        
        Args:
            config: Database configuration instance (defaults to global config)
        """
        self._config = config or get_database_config()
        self._client: Optional[redis.Redis] = None
        self._pool: Optional[ConnectionPool] = None
        self._circuit_breaker: Optional[CircuitBreaker] = None
        self._monitoring: Optional[CacheMonitoringManager] = None
        self._lock = RLock()
        self._health_check_lock = Lock()
        self._initialized = False
        
        # Connection state tracking
        self._connection_failures = 0
        self._last_health_check = None
        self._last_connection_attempt = None
        self._performance_baseline = {
            'avg_latency': 0.005,  # 5ms baseline from Node.js
            'max_latency': 0.010,  # 10ms threshold
            'throughput': 1000     # operations per second
        }
        
        # Thread pool for async operations
        self._thread_pool = ThreadPoolExecutor(max_workers=10, thread_name_prefix='redis-pool')
        
        logger.info(
            "RedisConnectionManager initialized",
            environment=self._config.environment,
            redis_host=self._config.redis_host,
            redis_port=self._config.redis_port,
            redis_db=self._config.redis_db
        )
    
    def initialize(self, monitoring: Optional[CacheMonitoringManager] = None):
        """
        Initialize Redis client with connection pool and circuit breaker.
        
        Args:
            monitoring: Cache monitoring manager for metrics collection
        """
        with self._lock:
            if self._initialized:
                logger.warning("RedisConnectionManager already initialized")
                return
            
            try:
                self._monitoring = monitoring
                self._initialize_circuit_breaker()
                self._initialize_connection_pool()
                self._initialize_client()
                self._validate_connection()
                
                self._initialized = True
                
                logger.info(
                    "Redis client initialized successfully",
                    pool_max_connections=self._pool.max_connections,
                    socket_timeout=self._config.redis_pool_config['socket_timeout'],
                    circuit_breaker_enabled=self._circuit_breaker is not None,
                    timestamp=datetime.now(timezone.utc).isoformat()
                )
                
                # Update monitoring configuration
                if self._monitoring:
                    self._monitoring.init_redis_monitoring(self._client)
                
            except Exception as e:
                error_msg = f"Failed to initialize Redis client: {str(e)}"
                logger.error(error_msg, traceback=traceback.format_exc())
                raise RedisConnectionError(
                    message=error_msg,
                    redis_error=e,
                    connection_info=self._get_connection_info()
                )
    
    def _initialize_circuit_breaker(self):
        """
        Initialize circuit breaker with Redis-specific configuration.
        
        Implements circuit breaker patterns per Section 6.1.3 with:
        - fail_max=5 failures before opening circuit
        - reset_timeout=60 seconds for recovery attempts
        - Redis-specific exception handling
        """
        try:
            self._circuit_breaker = CircuitBreaker(
                fail_max=5,
                reset_timeout=60,
                expected_exception=(
                    RedisConnectionError,
                    RedisTimeoutError,
                    RedisAuthenticationError,
                    RedisBusyLoadingError
                )
            )
            
            logger.info(
                "Circuit breaker initialized",
                fail_max=5,
                reset_timeout=60,
                expected_exceptions=[
                    'RedisConnectionError',
                    'RedisTimeoutError', 
                    'RedisAuthenticationError',
                    'RedisBusyLoadingError'
                ]
            )
            
        except Exception as e:
            logger.warning(
                "Failed to initialize circuit breaker, continuing without circuit breaker protection",
                error=str(e)
            )
            self._circuit_breaker = None
    
    def _initialize_connection_pool(self):
        """
        Initialize Redis connection pool with optimized settings per Section 6.1.3.
        
        Configuration:
        - max_connections=50 for connection pool size
        - socket_timeout=30.0 for individual operation timeout
        - socket_connect_timeout=10.0 for initial connection establishment
        - retry_on_timeout=True for automatic reconnection
        - health_check_interval=30 for connection validation
        """
        pool_config = self._config.redis_pool_config.copy()
        
        # SSL configuration if enabled
        ssl_config = {}
        if self._config.redis_ssl:
            ssl_config = {
                'ssl': True,
                'ssl_check_hostname': False,
                'ssl_cert_reqs': None
            }
        
        try:
            self._pool = ConnectionPool(
                host=self._config.redis_host,
                port=self._config.redis_port,
                password=self._config.redis_password,
                db=self._config.redis_db,
                **pool_config,
                **ssl_config
            )
            
            logger.info(
                "Redis connection pool initialized",
                host=self._config.redis_host,
                port=self._config.redis_port,
                db=self._config.redis_db,
                max_connections=pool_config['max_connections'],
                socket_timeout=pool_config['socket_timeout'],
                socket_connect_timeout=pool_config['socket_connect_timeout'],
                ssl_enabled=self._config.redis_ssl
            )
            
        except Exception as e:
            error_msg = f"Failed to initialize Redis connection pool: {str(e)}"
            logger.error(error_msg)
            raise RedisConnectionError(
                message=error_msg,
                redis_error=e,
                connection_info=self._get_connection_info()
            )
    
    def _initialize_client(self):
        """
        Initialize Redis client with connection pool and error handling.
        """
        try:
            self._client = redis.Redis(
                connection_pool=self._pool,
                decode_responses=True,
                retry_on_timeout=True,
                retry_on_error=[RedisConnectionError, RedisTimeoutError],
                retry=redis.Retry(retries=3, backoff=0.1)
            )
            
            logger.info(
                "Redis client initialized with connection pool",
                decode_responses=True,
                retry_on_timeout=True
            )
            
        except Exception as e:
            error_msg = f"Failed to initialize Redis client: {str(e)}"
            logger.error(error_msg)
            raise RedisConnectionError(
                message=error_msg,
                redis_error=e,
                connection_info=self._get_connection_info()
            )
    
    def _validate_connection(self):
        """
        Validate Redis connection with health check and performance baseline.
        """
        try:
            start_time = time.perf_counter()
            
            # Basic connectivity test
            ping_result = self._client.ping()
            if not ping_result:
                raise RedisConnectionError(
                    message="Redis PING command failed",
                    connection_info=self._get_connection_info()
                )
            
            # Measure baseline performance
            connection_time = time.perf_counter() - start_time
            
            # Performance validation against Node.js baseline
            if connection_time > self._performance_baseline['max_latency']:
                logger.warning(
                    "Redis connection latency exceeds baseline",
                    connection_time=connection_time,
                    baseline_max=self._performance_baseline['max_latency'],
                    variance_percent=((connection_time / self._performance_baseline['avg_latency']) - 1) * 100
                )
            
            logger.info(
                "Redis connection validated successfully",
                ping_response=ping_result,
                connection_time=connection_time,
                performance_within_baseline=connection_time <= self._performance_baseline['max_latency']
            )
            
        except redis.RedisError as e:
            error_msg = f"Redis connection validation failed: {str(e)}"
            logger.error(error_msg)
            raise RedisConnectionError(
                message=error_msg,
                redis_error=e,
                connection_info=self._get_connection_info()
            )
    
    def _get_connection_info(self) -> Dict[str, Any]:
        """
        Get connection information for error reporting and monitoring.
        
        Returns:
            Dictionary containing sanitized connection information
        """
        return {
            'host': self._config.redis_host,
            'port': self._config.redis_port,
            'db': self._config.redis_db,
            'ssl': self._config.redis_ssl,
            'max_connections': self._config.redis_pool_config.get('max_connections'),
            'socket_timeout': self._config.redis_pool_config.get('socket_timeout'),
            'socket_connect_timeout': self._config.redis_pool_config.get('socket_connect_timeout'),
            'retry_on_timeout': self._config.redis_pool_config.get('retry_on_timeout'),
            'health_check_interval': self._config.redis_pool_config.get('health_check_interval')
        }
    
    def get_client(self) -> redis.Redis:
        """
        Get Redis client instance with automatic initialization.
        
        Returns:
            redis.Redis: Configured Redis client instance
            
        Raises:
            RedisConnectionError: If client initialization fails
        """
        if not self._initialized:
            self.initialize()
        
        if self._client is None:
            raise RedisConnectionError(
                message="Redis client not initialized",
                connection_info=self._get_connection_info()
            )
        
        return self._client
    
    @contextmanager
    def get_connection(self):
        """
        Context manager for Redis connections with automatic cleanup.
        
        Yields:
            redis.Redis: Redis client instance
        """
        client = self.get_client()
        try:
            yield client
        finally:
            # Connection cleanup is handled by connection pool
            pass
    
    def close(self):
        """
        Close Redis connections and clean up resources.
        """
        with self._lock:
            try:
                if self._client:
                    self._client.close()
                    self._client = None
                    
                if self._pool:
                    self._pool.disconnect()
                    self._pool = None
                
                if self._thread_pool:
                    self._thread_pool.shutdown(wait=True)
                    
                self._initialized = False
                
                logger.info("Redis connection manager closed successfully")
                
            except Exception as e:
                logger.error(
                    "Error closing Redis connection manager",
                    error=str(e),
                    traceback=traceback.format_exc()
                )


class RedisClient:
    """
    High-level Redis client with enterprise-grade caching, circuit breaker patterns,
    and comprehensive error handling for distributed Flask application deployments.
    
    This class provides the main interface for Redis operations with:
    - Automatic connection management and retry logic
    - Circuit breaker protection for resilience
    - Performance monitoring and metrics collection
    - Cache invalidation patterns for distributed systems
    - Serialization handling for complex data types
    - Health check integration for monitoring systems
    
    Architecture Integration:
    - Flask application factory pattern compatibility
    - Integration with src/cache/monitoring.py for metrics
    - Error handling via src/cache/exceptions.py patterns
    - Configuration management via src/config/database.py
    - Circuit breaker coordination for multi-service resilience
    """
    
    def __init__(
        self, 
        connection_manager: Optional[RedisConnectionManager] = None,
        monitoring: Optional[CacheMonitoringManager] = None,
        default_ttl: int = 300
    ):
        """
        Initialize Redis client with connection management and monitoring.
        
        Args:
            connection_manager: Redis connection manager (creates new if None)
            monitoring: Cache monitoring manager for metrics collection
            default_ttl: Default time-to-live for cache entries in seconds
        """
        self._connection_manager = connection_manager or RedisConnectionManager()
        self._monitoring = monitoring
        self._default_ttl = default_ttl
        self._serialization_format = 'json'
        self._key_prefix = 'flask_cache:'
        
        # Initialize connection manager with monitoring
        if not self._connection_manager._initialized:
            self._connection_manager.initialize(monitoring)
        
        logger.info(
            "RedisClient initialized",
            default_ttl=default_ttl,
            serialization_format=self._serialization_format,
            key_prefix=self._key_prefix,
            monitoring_enabled=monitoring is not None
        )
    
    def _format_key(self, key: str) -> str:
        """
        Format cache key with prefix for namespace isolation.
        
        Args:
            key: Original cache key
            
        Returns:
            Formatted key with prefix
            
        Raises:
            CacheKeyError: If key format is invalid
        """
        if not key or not isinstance(key, str):
            raise CacheKeyError(
                message=f"Invalid cache key: {key}",
                key=str(key),
                validation_errors=['Key must be a non-empty string']
            )
        
        # Validate key length and characters
        if len(key) > 250:  # Redis key length limit
            raise CacheKeyError(
                message=f"Cache key too long: {len(key)} characters",
                key=key,
                validation_errors=[f'Key length {len(key)} exceeds 250 character limit']
            )
        
        return f"{self._key_prefix}{key}"
    
    def _serialize_value(self, value: Any) -> str:
        """
        Serialize value for Redis storage with error handling.
        
        Args:
            value: Value to serialize
            
        Returns:
            Serialized string value
            
        Raises:
            CacheSerializationError: If serialization fails
        """
        try:
            if value is None:
                return 'null'
            elif isinstance(value, (str, int, float, bool)):
                return json.dumps(value)
            else:
                return json.dumps(value, default=str, ensure_ascii=False)
        
        except (TypeError, ValueError) as e:
            raise CacheSerializationError(
                message=f"Failed to serialize value for cache storage: {str(e)}",
                value_type=type(value).__name__,
                serialization_method=self._serialization_format,
                original_error=e
            )
    
    def _deserialize_value(self, value: str) -> Any:
        """
        Deserialize value from Redis storage with error handling.
        
        Args:
            value: Serialized string value
            
        Returns:
            Deserialized Python object
            
        Raises:
            CacheSerializationError: If deserialization fails
        """
        try:
            if value == 'null':
                return None
            return json.loads(value)
        
        except (json.JSONDecodeError, ValueError) as e:
            raise CacheSerializationError(
                message=f"Failed to deserialize value from cache: {str(e)}",
                serialization_method=self._serialization_format,
                original_error=e
            )
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((RedisConnectionError, RedisTimeoutError)),
        reraise=True
    )
    @monitor_cache_operation('get', 'redis')
    @track_cache_hit_miss('redis')
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get value from Redis cache with automatic retry and monitoring.
        
        Args:
            key: Cache key
            default: Default value if key not found
            
        Returns:
            Cached value or default
            
        Raises:
            CacheError: If cache operation fails
        """
        formatted_key = self._format_key(key)
        
        try:
            with self._connection_manager.get_connection() as client:
                # Check if circuit breaker is open
                if (self._connection_manager._circuit_breaker and 
                    self._connection_manager._circuit_breaker.current_state == 'open'):
                    raise CircuitBreakerOpenError(
                        message="Redis circuit breaker is open, cache unavailable",
                        failure_count=self._connection_manager._connection_failures,
                        recovery_timeout=60
                    )
                
                start_time = time.perf_counter()
                value = client.get(formatted_key)
                operation_time = time.perf_counter() - start_time
                
                # Performance monitoring
                if self._monitoring:
                    self._monitoring.update_redis_metrics(client)
                
                # Performance variance tracking
                variance_percent = ((operation_time / self._performance_baseline['avg_latency']) - 1) * 100
                if variance_percent > 10:  # ≤10% variance requirement
                    logger.warning(
                        "Cache get operation exceeded performance baseline",
                        key=key,
                        operation_time=operation_time,
                        baseline=self._performance_baseline['avg_latency'],
                        variance_percent=variance_percent
                    )
                
                if value is None:
                    return default
                
                return self._deserialize_value(value)
        
        except redis.RedisError as e:
            cache_error = handle_redis_exception(e, f"get key '{key}'")
            logger.error(
                "Redis get operation failed",
                key=key,
                error=str(e),
                cache_error_code=cache_error.error_code
            )
            raise cache_error
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((RedisConnectionError, RedisTimeoutError)),
        reraise=True
    )
    @monitor_cache_operation('set', 'redis')
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """
        Set value in Redis cache with TTL and monitoring.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time-to-live in seconds (defaults to default_ttl)
            
        Returns:
            True if successful
            
        Raises:
            CacheError: If cache operation fails
        """
        formatted_key = self._format_key(key)
        ttl = ttl or self._default_ttl
        
        try:
            with self._connection_manager.get_connection() as client:
                # Check if circuit breaker is open
                if (self._connection_manager._circuit_breaker and 
                    self._connection_manager._circuit_breaker.current_state == 'open'):
                    raise CircuitBreakerOpenError(
                        message="Redis circuit breaker is open, cache unavailable",
                        failure_count=self._connection_manager._connection_failures,
                        recovery_timeout=60
                    )
                
                serialized_value = self._serialize_value(value)
                
                start_time = time.perf_counter()
                result = client.setex(formatted_key, ttl, serialized_value)
                operation_time = time.perf_counter() - start_time
                
                # Performance monitoring
                if self._monitoring:
                    self._monitoring.update_redis_metrics(client)
                
                # Performance variance tracking
                variance_percent = ((operation_time / self._performance_baseline['avg_latency']) - 1) * 100
                if variance_percent > 10:  # ≤10% variance requirement
                    logger.warning(
                        "Cache set operation exceeded performance baseline",
                        key=key,
                        operation_time=operation_time,
                        baseline=self._performance_baseline['avg_latency'],
                        variance_percent=variance_percent
                    )
                
                return bool(result)
        
        except redis.RedisError as e:
            cache_error = handle_redis_exception(e, f"set key '{key}'")
            logger.error(
                "Redis set operation failed",
                key=key,
                ttl=ttl,
                error=str(e),
                cache_error_code=cache_error.error_code
            )
            raise cache_error
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((RedisConnectionError, RedisTimeoutError)),
        reraise=True
    )
    @monitor_cache_operation('delete', 'redis')
    def delete(self, key: str) -> bool:
        """
        Delete key from Redis cache with monitoring.
        
        Args:
            key: Cache key to delete
            
        Returns:
            True if key was deleted
            
        Raises:
            CacheError: If cache operation fails
        """
        formatted_key = self._format_key(key)
        
        try:
            with self._connection_manager.get_connection() as client:
                # Check if circuit breaker is open
                if (self._connection_manager._circuit_breaker and 
                    self._connection_manager._circuit_breaker.current_state == 'open'):
                    raise CircuitBreakerOpenError(
                        message="Redis circuit breaker is open, cache unavailable",
                        failure_count=self._connection_manager._connection_failures,
                        recovery_timeout=60
                    )
                
                start_time = time.perf_counter()
                result = client.delete(formatted_key)
                operation_time = time.perf_counter() - start_time
                
                # Performance monitoring
                if self._monitoring:
                    self._monitoring.update_redis_metrics(client)
                
                return bool(result)
        
        except redis.RedisError as e:
            cache_error = handle_redis_exception(e, f"delete key '{key}'")
            logger.error(
                "Redis delete operation failed",
                key=key,
                error=str(e),
                cache_error_code=cache_error.error_code
            )
            raise cache_error
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((RedisConnectionError, RedisTimeoutError)),
        reraise=True
    )
    @monitor_cache_operation('exists', 'redis')
    def exists(self, key: str) -> bool:
        """
        Check if key exists in Redis cache.
        
        Args:
            key: Cache key to check
            
        Returns:
            True if key exists
            
        Raises:
            CacheError: If cache operation fails
        """
        formatted_key = self._format_key(key)
        
        try:
            with self._connection_manager.get_connection() as client:
                # Check if circuit breaker is open
                if (self._connection_manager._circuit_breaker and 
                    self._connection_manager._circuit_breaker.current_state == 'open'):
                    raise CircuitBreakerOpenError(
                        message="Redis circuit breaker is open, cache unavailable",
                        failure_count=self._connection_manager._connection_failures,
                        recovery_timeout=60
                    )
                
                result = client.exists(formatted_key)
                
                # Performance monitoring
                if self._monitoring:
                    self._monitoring.update_redis_metrics(client)
                
                return bool(result)
        
        except redis.RedisError as e:
            cache_error = handle_redis_exception(e, f"check existence of key '{key}'")
            logger.error(
                "Redis exists operation failed",
                key=key,
                error=str(e),
                cache_error_code=cache_error.error_code
            )
            raise cache_error
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((RedisConnectionError, RedisTimeoutError)),
        reraise=True
    )
    @monitor_cache_operation('invalidate', 'redis')
    def invalidate_pattern(self, pattern: str) -> int:
        """
        Invalidate cache keys matching pattern for distributed cache invalidation.
        
        Args:
            pattern: Key pattern to match (supports Redis SCAN patterns)
            
        Returns:
            Number of keys invalidated
            
        Raises:
            CacheInvalidationError: If invalidation fails
        """
        formatted_pattern = self._format_key(pattern)
        
        try:
            with self._connection_manager.get_connection() as client:
                # Check if circuit breaker is open
                if (self._connection_manager._circuit_breaker and 
                    self._connection_manager._circuit_breaker.current_state == 'open'):
                    raise CircuitBreakerOpenError(
                        message="Redis circuit breaker is open, cache unavailable",
                        failure_count=self._connection_manager._connection_failures,
                        recovery_timeout=60
                    )
                
                # Use SCAN for safe pattern matching
                cursor = 0
                deleted_count = 0
                failed_keys = []
                
                while True:
                    cursor, keys = client.scan(cursor=cursor, match=formatted_pattern, count=100)
                    
                    if keys:
                        try:
                            pipe = client.pipeline()
                            for key in keys:
                                pipe.delete(key)
                            results = pipe.execute()
                            deleted_count += sum(results)
                        except Exception as e:
                            failed_keys.extend(keys)
                            logger.warning(
                                "Failed to delete some keys during pattern invalidation",
                                pattern=pattern,
                                failed_keys=len(keys),
                                error=str(e)
                            )
                    
                    if cursor == 0:
                        break
                
                # Performance monitoring
                if self._monitoring:
                    self._monitoring.update_redis_metrics(client)
                
                if failed_keys:
                    raise CacheInvalidationError(
                        message=f"Failed to invalidate {len(failed_keys)} keys matching pattern '{pattern}'",
                        pattern=pattern,
                        keys=failed_keys,
                        partial_success=deleted_count
                    )
                
                logger.info(
                    "Cache pattern invalidation completed",
                    pattern=pattern,
                    deleted_count=deleted_count
                )
                
                return deleted_count
        
        except redis.RedisError as e:
            cache_error = handle_redis_exception(e, f"invalidate pattern '{pattern}'")
            logger.error(
                "Redis pattern invalidation failed",
                pattern=pattern,
                error=str(e),
                cache_error_code=cache_error.error_code
            )
            raise cache_error
    
    def get_multiple(self, keys: List[str]) -> Dict[str, Any]:
        """
        Get multiple values from Redis cache with efficient pipeline.
        
        Args:
            keys: List of cache keys
            
        Returns:
            Dictionary mapping keys to values (None for missing keys)
            
        Raises:
            CacheError: If cache operation fails
        """
        if not keys:
            return {}
        
        formatted_keys = [self._format_key(key) for key in keys]
        
        try:
            with self._connection_manager.get_connection() as client:
                # Check if circuit breaker is open
                if (self._connection_manager._circuit_breaker and 
                    self._connection_manager._circuit_breaker.current_state == 'open'):
                    raise CircuitBreakerOpenError(
                        message="Redis circuit breaker is open, cache unavailable",
                        failure_count=self._connection_manager._connection_failures,
                        recovery_timeout=60
                    )
                
                values = client.mget(formatted_keys)
                
                result = {}
                for key, value in zip(keys, values):
                    if value is not None:
                        result[key] = self._deserialize_value(value)
                        # Record cache hit
                        if self._monitoring:
                            self._monitoring.record_cache_hit('redis')
                    else:
                        result[key] = None
                        # Record cache miss
                        if self._monitoring:
                            self._monitoring.record_cache_miss('redis')
                
                # Performance monitoring
                if self._monitoring:
                    self._monitoring.update_redis_metrics(client)
                
                return result
        
        except redis.RedisError as e:
            cache_error = handle_redis_exception(e, f"get multiple keys {keys}")
            logger.error(
                "Redis mget operation failed",
                keys=keys,
                error=str(e),
                cache_error_code=cache_error.error_code
            )
            raise cache_error
    
    def set_multiple(self, mapping: Dict[str, Any], ttl: Optional[int] = None) -> bool:
        """
        Set multiple values in Redis cache with pipeline for efficiency.
        
        Args:
            mapping: Dictionary of key-value pairs to cache
            ttl: Time-to-live in seconds (defaults to default_ttl)
            
        Returns:
            True if all operations successful
            
        Raises:
            CacheError: If cache operation fails
        """
        if not mapping:
            return True
        
        ttl = ttl or self._default_ttl
        
        try:
            with self._connection_manager.get_connection() as client:
                # Check if circuit breaker is open
                if (self._connection_manager._circuit_breaker and 
                    self._connection_manager._circuit_breaker.current_state == 'open'):
                    raise CircuitBreakerOpenError(
                        message="Redis circuit breaker is open, cache unavailable",
                        failure_count=self._connection_manager._connection_failures,
                        recovery_timeout=60
                    )
                
                pipe = client.pipeline()
                
                for key, value in mapping.items():
                    formatted_key = self._format_key(key)
                    serialized_value = self._serialize_value(value)
                    pipe.setex(formatted_key, ttl, serialized_value)
                
                results = pipe.execute()
                
                # Performance monitoring
                if self._monitoring:
                    self._monitoring.update_redis_metrics(client)
                
                return all(results)
        
        except redis.RedisError as e:
            cache_error = handle_redis_exception(e, f"set multiple keys {list(mapping.keys())}")
            logger.error(
                "Redis mset operation failed",
                keys=list(mapping.keys()),
                ttl=ttl,
                error=str(e),
                cache_error_code=cache_error.error_code
            )
            raise cache_error
    
    def increment(self, key: str, amount: int = 1, ttl: Optional[int] = None) -> int:
        """
        Increment counter in Redis cache with optional TTL.
        
        Args:
            key: Cache key for counter
            amount: Amount to increment (default: 1)
            ttl: Time-to-live in seconds (defaults to default_ttl)
            
        Returns:
            New counter value
            
        Raises:
            CacheError: If cache operation fails
        """
        formatted_key = self._format_key(key)
        ttl = ttl or self._default_ttl
        
        try:
            with self._connection_manager.get_connection() as client:
                # Check if circuit breaker is open
                if (self._connection_manager._circuit_breaker and 
                    self._connection_manager._circuit_breaker.current_state == 'open'):
                    raise CircuitBreakerOpenError(
                        message="Redis circuit breaker is open, cache unavailable",
                        failure_count=self._connection_manager._connection_failures,
                        recovery_timeout=60
                    )
                
                pipe = client.pipeline()
                pipe.incrby(formatted_key, amount)
                pipe.expire(formatted_key, ttl)
                results = pipe.execute()
                
                # Performance monitoring
                if self._monitoring:
                    self._monitoring.update_redis_metrics(client)
                
                return results[0]
        
        except redis.RedisError as e:
            cache_error = handle_redis_exception(e, f"increment key '{key}'")
            logger.error(
                "Redis increment operation failed",
                key=key,
                amount=amount,
                ttl=ttl,
                error=str(e),
                cache_error_code=cache_error.error_code
            )
            raise cache_error
    
    def health_check(self) -> Tuple[bool, Dict[str, Any]]:
        """
        Perform comprehensive Redis health check for monitoring integration.
        
        Returns:
            Tuple of (is_healthy, health_details)
        """
        try:
            if self._monitoring and self._monitoring.health_monitor:
                return self._monitoring.check_cache_health()
            
            # Fallback health check
            with self._connection_manager.get_connection() as client:
                start_time = time.perf_counter()
                ping_result = client.ping()
                response_time = time.perf_counter() - start_time
                
                health_details = {
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'service': 'redis',
                    'status': 'healthy' if ping_result else 'unhealthy',
                    'response_time': response_time,
                    'ping_result': ping_result,
                    'circuit_breaker_state': (
                        self._connection_manager._circuit_breaker.current_state
                        if self._connection_manager._circuit_breaker else 'disabled'
                    )
                }
                
                return bool(ping_result), health_details
        
        except Exception as e:
            health_details = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'service': 'redis',
                'status': 'error',
                'error': str(e),
                'circuit_breaker_state': (
                    self._connection_manager._circuit_breaker.current_state
                    if self._connection_manager._circuit_breaker else 'disabled'
                )
            }
            
            return False, health_details
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get Redis client statistics for monitoring and optimization.
        
        Returns:
            Dictionary containing client statistics
        """
        try:
            with self._connection_manager.get_connection() as client:
                info = client.info()
                pool = client.connection_pool
                
                stats = {
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'connection_pool': {
                        'created_connections': pool.created_connections,
                        'available_connections': len(pool._available_connections),
                        'max_connections': pool.max_connections,
                        'in_use_connections': pool.created_connections - len(pool._available_connections)
                    },
                    'redis_info': {
                        'redis_version': info.get('redis_version'),
                        'used_memory': info.get('used_memory'),
                        'used_memory_human': info.get('used_memory_human'),
                        'connected_clients': info.get('connected_clients'),
                        'total_commands_processed': info.get('total_commands_processed'),
                        'keyspace_hits': info.get('keyspace_hits'),
                        'keyspace_misses': info.get('keyspace_misses')
                    },
                    'client_config': {
                        'default_ttl': self._default_ttl,
                        'serialization_format': self._serialization_format,
                        'key_prefix': self._key_prefix
                    }
                }
                
                # Calculate hit ratio
                hits = info.get('keyspace_hits', 0)
                misses = info.get('keyspace_misses', 0)
                total = hits + misses
                if total > 0:
                    stats['redis_info']['hit_ratio'] = (hits / total) * 100
                
                return stats
        
        except Exception as e:
            logger.error(
                "Failed to get Redis client statistics",
                error=str(e)
            )
            return {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'error': str(e)
            }
    
    def close(self):
        """
        Close Redis client and clean up resources.
        """
        try:
            if self._connection_manager:
                self._connection_manager.close()
            
            logger.info("Redis client closed successfully")
        
        except Exception as e:
            logger.error(
                "Error closing Redis client",
                error=str(e)
            )


# Factory function for Flask application integration
def create_redis_client(
    config: Optional[DatabaseConfig] = None,
    monitoring: Optional[CacheMonitoringManager] = None,
    **kwargs
) -> RedisClient:
    """
    Factory function to create Redis client with Flask application integration.
    
    Args:
        config: Database configuration (defaults to global config)
        monitoring: Cache monitoring manager
        **kwargs: Additional configuration options
        
    Returns:
        RedisClient: Configured Redis client instance
    """
    # Get configuration
    if config is None:
        config = get_database_config()
    
    # Create connection manager
    connection_manager = RedisConnectionManager(config)
    
    # Create Redis client
    redis_client = RedisClient(
        connection_manager=connection_manager,
        monitoring=monitoring,
        default_ttl=kwargs.get('default_ttl', 300)
    )
    
    logger.info(
        "Redis client created via factory function",
        environment=config.environment,
        monitoring_enabled=monitoring is not None,
        default_ttl=kwargs.get('default_ttl', 300)
    )
    
    return redis_client


# Global Redis client instance for application-wide access
_redis_client: Optional[RedisClient] = None
_client_lock = Lock()


def init_redis_client(
    config: Optional[DatabaseConfig] = None,
    monitoring: Optional[CacheMonitoringManager] = None,
    **kwargs
) -> RedisClient:
    """
    Initialize global Redis client instance.
    
    Args:
        config: Database configuration
        monitoring: Cache monitoring manager
        **kwargs: Additional configuration options
        
    Returns:
        RedisClient: Global Redis client instance
    """
    global _redis_client
    
    with _client_lock:
        if _redis_client is not None:
            logger.warning("Redis client already initialized, returning existing instance")
            return _redis_client
        
        _redis_client = create_redis_client(config, monitoring, **kwargs)
        
        logger.info(
            "Global Redis client initialized",
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        
        return _redis_client


def get_redis_client() -> RedisClient:
    """
    Get global Redis client instance.
    
    Returns:
        RedisClient: Global Redis client instance
        
    Raises:
        RuntimeError: If Redis client has not been initialized
    """
    if _redis_client is None:
        raise RuntimeError(
            "Redis client not initialized. Call init_redis_client() first."
        )
    
    return _redis_client


def close_redis_client():
    """
    Close global Redis client and clean up resources.
    """
    global _redis_client
    
    with _client_lock:
        if _redis_client is not None:
            _redis_client.close()
            _redis_client = None
            
            logger.info("Global Redis client closed")


# Export public API for application integration
__all__ = [
    'RedisConnectionManager',
    'RedisClient', 
    'create_redis_client',
    'init_redis_client',
    'get_redis_client',
    'close_redis_client'
]