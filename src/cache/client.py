"""
Redis Client Implementation

Core Redis client implementation with redis-py 5.0+ providing connection pooling,
circuit breaker patterns, and comprehensive error handling. Manages Redis connections
with enterprise-grade configuration including connection pooling, timeout management,
and resilience patterns for distributed caching across multiple Flask instances.

This module implements the complete Redis client functionality as specified in 
Section 0.1.2 data access components and Section 6.1.3 resource optimization,
providing production-ready caching capabilities with ≤10% performance variance
from Node.js baseline requirements.

Key Features:
- Redis connection pooling with max_connections=50 and optimized timeout settings
- Circuit breaker patterns for Redis connectivity resilience 
- Distributed caching capabilities for multi-instance Flask deployments
- Comprehensive error handling with enterprise monitoring integration
- Performance optimization equivalent to Node.js connection patterns
- Enterprise observability through Prometheus metrics and structured logging

Performance Requirements:
- Socket timeout: 30.0 seconds for individual operations
- Connect timeout: 10.0 seconds for initial connection establishment
- Connection pool: maximum 50 connections with retry_on_timeout=True
- Circuit breaker: automatic failover and recovery for service resilience
"""

import time
import json
import logging
import threading
from typing import Any, Dict, List, Optional, Union, Callable, TypeVar, Generic
from contextlib import contextmanager
from functools import wraps
from datetime import datetime, timedelta
import redis
from redis.connection import ConnectionPool
from redis.exceptions import (
    ConnectionError, TimeoutError, ResponseError, 
    DataError, RedisError, BusyLoadingError
)
import structlog
from .exceptions import (
    CacheError, CacheConnectionError, CacheTimeoutError,
    CacheCircuitBreakerError, CacheSerializationError,
    CachePoolExhaustedError, CacheMemoryError
)
from .monitoring import cache_monitor, monitor_cache_operation


# Configure structured logging for enterprise integration
logger = structlog.get_logger(__name__)

# Type variable for generic cache operations
T = TypeVar('T')


class CircuitBreaker:
    """
    Circuit breaker implementation for Redis connectivity resilience per 
    Section 6.1.3 resilience mechanisms.
    
    Implements intelligent failure detection, automatic recovery, and graceful
    degradation patterns to prevent cascade failures during Redis service
    degradation. Provides configurable failure thresholds and recovery timeouts.
    """
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        expected_exception: type = RedisError
    ):
        """
        Initialize circuit breaker with failure detection and recovery settings.
        
        Args:
            failure_threshold: Number of consecutive failures before opening circuit
            recovery_timeout: Seconds to wait before attempting recovery
            expected_exception: Exception type that triggers circuit breaker
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        
        self.failure_count = 0
        self.last_failure_time: Optional[datetime] = None
        self.state = 'closed'  # closed, open, half-open
        self._lock = threading.RLock()
        
        logger.info(
            "circuit_breaker_initialized",
            failure_threshold=failure_threshold,
            recovery_timeout=recovery_timeout,
            expected_exception=expected_exception.__name__
        )
    
    def __call__(self, func: Callable) -> Callable:
        """Decorator for applying circuit breaker to functions."""
        @wraps(func)
        def wrapper(*args, **kwargs):
            return self.call(func, *args, **kwargs)
        return wrapper
    
    def call(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute function with circuit breaker protection.
        
        Args:
            func: Function to execute
            *args: Function arguments
            **kwargs: Function keyword arguments
            
        Returns:
            Function result
            
        Raises:
            CacheCircuitBreakerError: When circuit is open
        """
        with self._lock:
            if self.state == 'open':
                if self._should_attempt_reset():
                    self.state = 'half-open'
                    logger.info("circuit_breaker_half_open_transition")
                else:
                    next_attempt = self.last_failure_time + timedelta(seconds=self.recovery_timeout)
                    raise CacheCircuitBreakerError(
                        message="Circuit breaker is open - Redis service unavailable",
                        circuit_state=self.state,
                        failure_count=self.failure_count,
                        last_failure_time=self.last_failure_time,
                        next_attempt_time=next_attempt
                    )
        
        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except self.expected_exception as e:
            self._on_failure()
            raise
    
    def _should_attempt_reset(self) -> bool:
        """Check if circuit breaker should attempt recovery."""
        if self.last_failure_time is None:
            return True
        
        return (
            datetime.utcnow() - self.last_failure_time
        ).total_seconds() >= self.recovery_timeout
    
    def _on_success(self) -> None:
        """Handle successful operation."""
        with self._lock:
            if self.state == 'half-open':
                self.state = 'closed'
                self.failure_count = 0
                self.last_failure_time = None
                logger.info("circuit_breaker_closed_successful_recovery")
    
    def _on_failure(self) -> None:
        """Handle failed operation."""
        with self._lock:
            self.failure_count += 1
            self.last_failure_time = datetime.utcnow()
            
            if self.failure_count >= self.failure_threshold:
                self.state = 'open'
                logger.warning(
                    "circuit_breaker_opened",
                    failure_count=self.failure_count,
                    failure_threshold=self.failure_threshold,
                    recovery_timeout=self.recovery_timeout
                )
    
    def get_state(self) -> Dict[str, Any]:
        """Get current circuit breaker state for monitoring."""
        return {
            'state': self.state,
            'failure_count': self.failure_count,
            'last_failure_time': self.last_failure_time.isoformat() if self.last_failure_time else None,
            'failure_threshold': self.failure_threshold,
            'recovery_timeout': self.recovery_timeout
        }


class RedisClient:
    """
    Enterprise-grade Redis client with connection pooling, circuit breaker patterns,
    and comprehensive error handling per Section 0.1.2 data access components.
    
    Provides production-ready Redis connectivity with optimized connection pooling,
    timeout management, and resilience patterns for distributed caching across
    multiple Flask instances. Implements performance optimization to ensure ≤10%
    variance from Node.js baseline per Section 0.1.1 primary objective.
    """
    
    def __init__(
        self,
        host: str = 'localhost',
        port: int = 6379,
        db: int = 0,
        password: Optional[str] = None,
        ssl: bool = False,
        max_connections: int = 50,
        socket_timeout: float = 30.0,
        socket_connect_timeout: float = 10.0,
        retry_on_timeout: bool = True,
        health_check_interval: int = 30,
        decode_responses: bool = True,
        encoding: str = 'utf-8',
        **kwargs
    ):
        """
        Initialize Redis client with enterprise-grade configuration.
        
        Args:
            host: Redis server hostname
            port: Redis server port
            db: Redis database number
            password: Redis authentication password
            ssl: Enable SSL/TLS connection
            max_connections: Maximum connection pool size per Section 6.1.3
            socket_timeout: Individual operation timeout (30.0s per spec)
            socket_connect_timeout: Connection establishment timeout (10.0s per spec)
            retry_on_timeout: Enable automatic retry on timeout per Section 6.1.3
            health_check_interval: Seconds between connection health checks
            decode_responses: Automatically decode byte responses to strings
            encoding: String encoding for response decoding
            **kwargs: Additional Redis connection parameters
        """
        self.host = host
        self.port = port
        self.db = db
        self.password = password
        self.ssl = ssl
        self.max_connections = max_connections
        self.socket_timeout = socket_timeout
        self.socket_connect_timeout = socket_connect_timeout
        self.retry_on_timeout = retry_on_timeout
        self.health_check_interval = health_check_interval
        self.decode_responses = decode_responses
        self.encoding = encoding
        
        # Initialize connection pool with optimized settings per Section 6.1.3
        self._connection_pool = None
        self._redis_client = None
        self._circuit_breaker = CircuitBreaker(
            failure_threshold=5,
            recovery_timeout=60,
            expected_exception=RedisError
        )
        
        # Thread safety for connection management
        self._lock = threading.RLock()
        
        # Performance tracking for baseline comparison
        self._performance_stats = {
            'total_operations': 0,
            'total_latency_ms': 0.0,
            'connection_pool_hits': 0,
            'connection_pool_misses': 0,
            'circuit_breaker_trips': 0
        }
        
        # Initialize connection pool
        self._initialize_connection_pool()
        
        logger.info(
            "redis_client_initialized",
            host=self.host,
            port=self.port,
            db=self.db,
            max_connections=self.max_connections,
            socket_timeout=self.socket_timeout,
            socket_connect_timeout=self.socket_connect_timeout,
            ssl=self.ssl
        )
    
    def _initialize_connection_pool(self) -> None:
        """
        Initialize Redis connection pool with enterprise-grade settings
        per Section 6.1.3 Redis connection pool settings.
        """
        try:
            # Create connection pool with optimized parameters
            self._connection_pool = ConnectionPool(
                host=self.host,
                port=self.port,
                db=self.db,
                password=self.password,
                ssl=self.ssl,
                max_connections=self.max_connections,
                socket_timeout=self.socket_timeout,
                socket_connect_timeout=self.socket_connect_timeout,
                retry_on_timeout=self.retry_on_timeout,
                health_check_interval=self.health_check_interval,
                decode_responses=self.decode_responses,
                encoding=self.encoding
            )
            
            # Create Redis client with connection pool
            self._redis_client = redis.Redis(
                connection_pool=self._connection_pool
            )
            
            # Test initial connection
            self._test_connection()
            
            logger.info(
                "redis_connection_pool_initialized",
                max_connections=self.max_connections,
                socket_timeout=self.socket_timeout,
                socket_connect_timeout=self.socket_connect_timeout,
                pool_created_connections=self._connection_pool.created_connections,
                pool_available_connections=len(self._connection_pool._available_connections)
            )
            
        except Exception as e:
            logger.error(
                "redis_connection_pool_initialization_failed",
                error_message=str(e),
                error_type=type(e).__name__,
                host=self.host,
                port=self.port
            )
            raise CacheConnectionError(
                message=f"Failed to initialize Redis connection pool: {str(e)}",
                host=self.host,
                port=self.port,
                db=self.db,
                connection_pool_size=self.max_connections
            )
    
    def _test_connection(self) -> None:
        """Test Redis connection and validate client functionality."""
        try:
            with self._circuit_breaker.call(self._redis_client.ping):
                response = self._redis_client.ping()
                if not response:
                    raise ConnectionError("Redis ping failed")
                    
        except Exception as e:
            logger.error(
                "redis_connection_test_failed",
                error_message=str(e),
                error_type=type(e).__name__
            )
            raise CacheConnectionError(
                message=f"Redis connection test failed: {str(e)}",
                host=self.host,
                port=self.port,
                db=self.db
            )
    
    @contextmanager
    def _operation_context(self, operation: str, key: Optional[str] = None):
        """
        Context manager for Redis operations with monitoring and error handling.
        
        Args:
            operation: Type of Redis operation (get, set, delete, etc.)
            key: Redis key being operated on
        """
        start_time = time.time()
        operation_success = True
        error_type = None
        
        try:
            yield
        except ConnectionError as e:
            operation_success = False
            error_type = 'connection_error'
            logger.error(
                "redis_connection_error",
                operation=operation,
                key=key,
                error_message=str(e)
            )
            raise CacheConnectionError(
                message=f"Redis connection error during {operation}",
                operation=operation,
                key=key,
                host=self.host,
                port=self.port
            )
        except TimeoutError as e:
            operation_success = False
            error_type = 'timeout'
            logger.warning(
                "redis_timeout_error",
                operation=operation,
                key=key,
                timeout_duration=self.socket_timeout,
                error_message=str(e)
            )
            raise CacheTimeoutError(
                message=f"Redis operation timeout during {operation}",
                operation=operation,
                key=key,
                timeout_duration=self.socket_timeout,
                operation_start_time=datetime.utcnow() - timedelta(seconds=time.time() - start_time)
            )
        except ResponseError as e:
            operation_success = False
            error_type = 'response_error'
            if 'OOM' in str(e) or 'out of memory' in str(e).lower():
                logger.critical(
                    "redis_memory_error",
                    operation=operation,
                    key=key,
                    error_message=str(e)
                )
                raise CacheMemoryError(
                    message=f"Redis memory limit exceeded during {operation}",
                    operation=operation,
                    key=key
                )
            else:
                logger.error(
                    "redis_response_error",
                    operation=operation,
                    key=key,
                    error_message=str(e)
                )
                raise CacheError(
                    message=f"Redis response error during {operation}: {str(e)}",
                    operation=operation,
                    key=key,
                    error_code="REDIS_RESPONSE_ERROR"
                )
        except Exception as e:
            operation_success = False
            error_type = 'unexpected_error'
            logger.error(
                "redis_unexpected_error",
                operation=operation,
                key=key,
                error_message=str(e),
                error_type=type(e).__name__
            )
            raise CacheError(
                message=f"Unexpected Redis error during {operation}: {str(e)}",
                operation=operation,
                key=key,
                error_code="REDIS_UNEXPECTED_ERROR"
            )
        finally:
            # Record performance metrics
            duration_ms = (time.time() - start_time) * 1000
            
            with self._lock:
                self._performance_stats['total_operations'] += 1
                self._performance_stats['total_latency_ms'] += duration_ms
                
                if not operation_success:
                    if error_type == 'connection_error':
                        self._performance_stats['circuit_breaker_trips'] += 1
            
            # Update cache monitoring
            if operation_success:
                cache_monitor.record_cache_hit('redis', key or 'unknown')
            else:
                cache_monitor.record_cache_miss('redis', key or 'unknown')
            
            logger.debug(
                "redis_operation_completed",
                operation=operation,
                key=key,
                duration_ms=duration_ms,
                success=operation_success,
                error_type=error_type
            )
    
    def _serialize_value(self, value: Any) -> str:
        """
        Serialize Python value for Redis storage.
        
        Args:
            value: Python object to serialize
            
        Returns:
            JSON-serialized string
            
        Raises:
            CacheSerializationError: If serialization fails
        """
        try:
            if isinstance(value, (str, bytes)):
                return value
            return json.dumps(value, default=str, ensure_ascii=False)
        except (TypeError, ValueError) as e:
            logger.error(
                "redis_serialization_error",
                value_type=type(value).__name__,
                error_message=str(e)
            )
            raise CacheSerializationError(
                message=f"Failed to serialize value: {str(e)}",
                data_type=type(value).__name__,
                serialization_format='json'
            )
    
    def _deserialize_value(self, value: Optional[str]) -> Any:
        """
        Deserialize Redis value to Python object.
        
        Args:
            value: JSON string from Redis
            
        Returns:
            Deserialized Python object
            
        Raises:
            CacheSerializationError: If deserialization fails
        """
        if value is None:
            return None
        
        if isinstance(value, bytes):
            value = value.decode(self.encoding)
        
        if not isinstance(value, str):
            return value
        
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError) as e:
            # Return original value if JSON parsing fails
            logger.warning(
                "redis_deserialization_warning",
                value_preview=value[:100] if len(value) > 100 else value,
                error_message=str(e)
            )
            return value
    
    @monitor_cache_operation('get', 'redis')
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get value from Redis cache with circuit breaker protection.
        
        Args:
            key: Redis key to retrieve
            default: Default value if key doesn't exist
            
        Returns:
            Cached value or default
        """
        with self._operation_context('get', key):
            with self._circuit_breaker.call(self._redis_client.get, key) as result:
                raw_value = result
                if raw_value is None:
                    return default
                return self._deserialize_value(raw_value)
    
    @monitor_cache_operation('set', 'redis')
    def set(
        self, 
        key: str, 
        value: Any, 
        ttl: Optional[int] = None,
        nx: bool = False,
        xx: bool = False
    ) -> bool:
        """
        Set value in Redis cache with optional TTL and conditions.
        
        Args:
            key: Redis key to set
            value: Value to cache
            ttl: Time-to-live in seconds
            nx: Only set if key doesn't exist
            xx: Only set if key exists
            
        Returns:
            True if value was set, False otherwise
        """
        with self._operation_context('set', key):
            serialized_value = self._serialize_value(value)
            with self._circuit_breaker.call(
                self._redis_client.set, 
                key, 
                serialized_value, 
                ex=ttl, 
                nx=nx, 
                xx=xx
            ) as result:
                return bool(result)
    
    @monitor_cache_operation('delete', 'redis')
    def delete(self, *keys: str) -> int:
        """
        Delete one or more keys from Redis cache.
        
        Args:
            *keys: Redis keys to delete
            
        Returns:
            Number of keys deleted
        """
        if not keys:
            return 0
        
        with self._operation_context('delete', str(keys)):
            with self._circuit_breaker.call(self._redis_client.delete, *keys) as result:
                return int(result)
    
    @monitor_cache_operation('exists', 'redis')
    def exists(self, *keys: str) -> int:
        """
        Check if keys exist in Redis cache.
        
        Args:
            *keys: Redis keys to check
            
        Returns:
            Number of keys that exist
        """
        if not keys:
            return 0
        
        with self._operation_context('exists', str(keys)):
            with self._circuit_breaker.call(self._redis_client.exists, *keys) as result:
                return int(result)
    
    @monitor_cache_operation('expire', 'redis')
    def expire(self, key: str, seconds: int) -> bool:
        """
        Set expiration time for a key.
        
        Args:
            key: Redis key to set expiration for
            seconds: Expiration time in seconds
            
        Returns:
            True if expiration was set, False if key doesn't exist
        """
        with self._operation_context('expire', key):
            with self._circuit_breaker.call(self._redis_client.expire, key, seconds) as result:
                return bool(result)
    
    @monitor_cache_operation('ttl', 'redis')
    def ttl(self, key: str) -> int:
        """
        Get time-to-live for a key.
        
        Args:
            key: Redis key to check TTL for
            
        Returns:
            TTL in seconds (-1 if no expiration, -2 if key doesn't exist)
        """
        with self._operation_context('ttl', key):
            with self._circuit_breaker.call(self._redis_client.ttl, key) as result:
                return int(result)
    
    @monitor_cache_operation('increment', 'redis')
    def increment(self, key: str, amount: int = 1) -> int:
        """
        Increment numeric value in Redis cache.
        
        Args:
            key: Redis key to increment
            amount: Amount to increment by
            
        Returns:
            New value after increment
        """
        with self._operation_context('increment', key):
            with self._circuit_breaker.call(self._redis_client.incrby, key, amount) as result:
                return int(result)
    
    @monitor_cache_operation('decrement', 'redis')
    def decrement(self, key: str, amount: int = 1) -> int:
        """
        Decrement numeric value in Redis cache.
        
        Args:
            key: Redis key to decrement
            amount: Amount to decrement by
            
        Returns:
            New value after decrement
        """
        with self._operation_context('decrement', key):
            with self._circuit_breaker.call(self._redis_client.decrby, key, amount) as result:
                return int(result)
    
    @monitor_cache_operation('hash_get', 'redis')
    def hash_get(self, key: str, field: str) -> Any:
        """
        Get field value from Redis hash.
        
        Args:
            key: Redis hash key
            field: Hash field name
            
        Returns:
            Field value or None if not found
        """
        with self._operation_context('hash_get', key):
            with self._circuit_breaker.call(self._redis_client.hget, key, field) as result:
                return self._deserialize_value(result)
    
    @monitor_cache_operation('hash_set', 'redis')
    def hash_set(self, key: str, field: str, value: Any) -> bool:
        """
        Set field value in Redis hash.
        
        Args:
            key: Redis hash key
            field: Hash field name
            value: Value to set
            
        Returns:
            True if field was created, False if updated
        """
        with self._operation_context('hash_set', key):
            serialized_value = self._serialize_value(value)
            with self._circuit_breaker.call(self._redis_client.hset, key, field, serialized_value) as result:
                return bool(result)
    
    @monitor_cache_operation('hash_delete', 'redis')
    def hash_delete(self, key: str, *fields: str) -> int:
        """
        Delete fields from Redis hash.
        
        Args:
            key: Redis hash key
            *fields: Hash field names to delete
            
        Returns:
            Number of fields deleted
        """
        if not fields:
            return 0
        
        with self._operation_context('hash_delete', key):
            with self._circuit_breaker.call(self._redis_client.hdel, key, *fields) as result:
                return int(result)
    
    @monitor_cache_operation('list_push', 'redis')
    def list_push(self, key: str, *values: Any, left: bool = True) -> int:
        """
        Push values to Redis list.
        
        Args:
            key: Redis list key
            *values: Values to push
            left: If True, push to left (LPUSH), else right (RPUSH)
            
        Returns:
            New length of list
        """
        if not values:
            return 0
        
        with self._operation_context('list_push', key):
            serialized_values = [self._serialize_value(v) for v in values]
            if left:
                with self._circuit_breaker.call(self._redis_client.lpush, key, *serialized_values) as result:
                    return int(result)
            else:
                with self._circuit_breaker.call(self._redis_client.rpush, key, *serialized_values) as result:
                    return int(result)
    
    @monitor_cache_operation('list_pop', 'redis')
    def list_pop(self, key: str, left: bool = True) -> Any:
        """
        Pop value from Redis list.
        
        Args:
            key: Redis list key
            left: If True, pop from left (LPOP), else right (RPOP)
            
        Returns:
            Popped value or None if list is empty
        """
        with self._operation_context('list_pop', key):
            if left:
                with self._circuit_breaker.call(self._redis_client.lpop, key) as result:
                    return self._deserialize_value(result)
            else:
                with self._circuit_breaker.call(self._redis_client.rpop, key) as result:
                    return self._deserialize_value(result)
    
    def pipeline(self) -> 'RedisPipeline':
        """
        Create Redis pipeline for batch operations.
        
        Returns:
            Redis pipeline wrapper with circuit breaker protection
        """
        return RedisPipeline(self._redis_client.pipeline(), self._circuit_breaker)
    
    def get_connection_info(self) -> Dict[str, Any]:
        """
        Get current Redis connection information for monitoring.
        
        Returns:
            Dictionary containing connection pool and client statistics
        """
        connection_info = {
            'host': self.host,
            'port': self.port,
            'db': self.db,
            'max_connections': self.max_connections,
            'socket_timeout': self.socket_timeout,
            'socket_connect_timeout': self.socket_connect_timeout,
            'circuit_breaker_state': self._circuit_breaker.get_state(),
            'performance_stats': self._performance_stats.copy()
        }
        
        if self._connection_pool:
            connection_info.update({
                'pool_created_connections': self._connection_pool.created_connections,
                'pool_available_connections': len(self._connection_pool._available_connections),
                'pool_in_use_connections': len(self._connection_pool._in_use_connections)
            })
        
        return connection_info
    
    def health_check(self) -> Dict[str, Any]:
        """
        Perform comprehensive Redis health check.
        
        Returns:
            Dictionary containing health status and diagnostic information
        """
        health_status = {
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'connection_active': False,
            'latency_ms': None,
            'memory_info': {},
            'circuit_breaker_state': self._circuit_breaker.get_state()
        }
        
        try:
            start_time = time.time()
            ping_result = self._redis_client.ping()
            latency_ms = (time.time() - start_time) * 1000
            
            health_status['connection_active'] = ping_result
            health_status['latency_ms'] = latency_ms
            
            if ping_result:
                # Get Redis server information
                server_info = self._redis_client.info()
                health_status['memory_info'] = {
                    'used_memory': server_info.get('used_memory', 0),
                    'used_memory_peak': server_info.get('used_memory_peak', 0),
                    'used_memory_rss': server_info.get('used_memory_rss', 0),
                    'maxmemory': server_info.get('maxmemory', 0),
                    'mem_fragmentation_ratio': server_info.get('mem_fragmentation_ratio', 0)
                }
                
                # Check for high memory usage
                if server_info.get('used_memory', 0) > 0 and server_info.get('maxmemory', 0) > 0:
                    memory_usage_percent = (server_info['used_memory'] / server_info['maxmemory']) * 100
                    if memory_usage_percent > 90:
                        health_status['status'] = 'degraded'
                        health_status['warning'] = 'High memory usage detected'
                
                logger.info(
                    "redis_health_check_completed",
                    status=health_status['status'],
                    latency_ms=latency_ms,
                    used_memory_mb=server_info.get('used_memory', 0) / (1024 * 1024)
                )
            else:
                health_status['status'] = 'unhealthy'
                health_status['error'] = 'Redis ping failed'
                
        except Exception as e:
            health_status['status'] = 'unhealthy'
            health_status['error'] = str(e)
            health_status['error_type'] = type(e).__name__
            
            logger.error(
                "redis_health_check_failed",
                error_message=str(e),
                error_type=type(e).__name__
            )
        
        return health_status
    
    def close(self) -> None:
        """Close Redis connection pool and cleanup resources."""
        try:
            if self._connection_pool:
                self._connection_pool.disconnect()
                logger.info("redis_connection_pool_closed")
        except Exception as e:
            logger.warning(
                "redis_connection_pool_close_error",
                error_message=str(e)
            )


class RedisPipeline:
    """
    Redis pipeline wrapper with circuit breaker protection for batch operations.
    
    Provides enterprise-grade batch operation capabilities with automatic
    error handling and circuit breaker integration for optimal performance
    and reliability during high-throughput operations.
    """
    
    def __init__(self, pipeline: redis.client.Pipeline, circuit_breaker: CircuitBreaker):
        """
        Initialize Redis pipeline wrapper.
        
        Args:
            pipeline: Redis pipeline instance
            circuit_breaker: Circuit breaker for resilience
        """
        self._pipeline = pipeline
        self._circuit_breaker = circuit_breaker
        self._commands = []
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> 'RedisPipeline':
        """Add SET command to pipeline."""
        serialized_value = json.dumps(value, default=str) if not isinstance(value, (str, bytes)) else value
        self._pipeline.set(key, serialized_value, ex=ttl)
        self._commands.append(f"SET {key}")
        return self
    
    def get(self, key: str) -> 'RedisPipeline':
        """Add GET command to pipeline."""
        self._pipeline.get(key)
        self._commands.append(f"GET {key}")
        return self
    
    def delete(self, *keys: str) -> 'RedisPipeline':
        """Add DELETE command to pipeline."""
        self._pipeline.delete(*keys)
        self._commands.append(f"DELETE {keys}")
        return self
    
    def execute(self) -> List[Any]:
        """
        Execute pipeline with circuit breaker protection.
        
        Returns:
            List of command results
        """
        try:
            with self._circuit_breaker.call(self._pipeline.execute) as results:
                logger.debug(
                    "redis_pipeline_executed",
                    command_count=len(self._commands),
                    commands=self._commands[:10]  # Limit logging to first 10 commands
                )
                return results
        except Exception as e:
            logger.error(
                "redis_pipeline_execution_failed",
                command_count=len(self._commands),
                error_message=str(e),
                error_type=type(e).__name__
            )
            raise


def create_redis_client(
    host: str = 'localhost',
    port: int = 6379,
    db: int = 0,
    password: Optional[str] = None,
    ssl: bool = False,
    **kwargs
) -> RedisClient:
    """
    Factory function for creating Redis client instances with standard configuration.
    
    Args:
        host: Redis server hostname
        port: Redis server port
        db: Redis database number
        password: Redis authentication password
        ssl: Enable SSL/TLS connection
        **kwargs: Additional configuration parameters
        
    Returns:
        Configured RedisClient instance
    """
    # Apply enterprise-grade defaults per Section 6.1.3
    default_config = {
        'max_connections': 50,
        'socket_timeout': 30.0,
        'socket_connect_timeout': 10.0,
        'retry_on_timeout': True,
        'health_check_interval': 30,
        'decode_responses': True,
        'encoding': 'utf-8'
    }
    
    # Merge provided configuration with defaults
    config = {**default_config, **kwargs}
    
    return RedisClient(
        host=host,
        port=port,
        db=db,
        password=password,
        ssl=ssl,
        **config
    )


# Global Redis client instance for Flask application integration
_redis_client: Optional[RedisClient] = None


def get_redis_client() -> RedisClient:
    """
    Get global Redis client instance for Flask application integration.
    
    Returns:
        Global RedisClient instance
        
    Raises:
        CacheError: If Redis client is not initialized
    """
    global _redis_client
    
    if _redis_client is None:
        raise CacheError(
            message="Redis client not initialized. Call init_redis_client() first.",
            error_code="REDIS_CLIENT_NOT_INITIALIZED"
        )
    
    return _redis_client


def init_redis_client(
    host: str = 'localhost',
    port: int = 6379,
    db: int = 0,
    password: Optional[str] = None,
    ssl: bool = False,
    **kwargs
) -> RedisClient:
    """
    Initialize global Redis client for Flask application factory pattern.
    
    Args:
        host: Redis server hostname
        port: Redis server port
        db: Redis database number
        password: Redis authentication password
        ssl: Enable SSL/TLS connection
        **kwargs: Additional configuration parameters
        
    Returns:
        Initialized RedisClient instance
    """
    global _redis_client
    
    _redis_client = create_redis_client(
        host=host,
        port=port,
        db=db,
        password=password,
        ssl=ssl,
        **kwargs
    )
    
    # Configure cache monitoring with Redis client
    cache_monitor.configure_redis_client(_redis_client._redis_client)
    
    # Update circuit breaker state in monitoring
    cache_monitor.update_circuit_breaker_state('redis', 'closed')
    
    logger.info(
        "global_redis_client_initialized",
        host=host,
        port=port,
        db=db,
        ssl=ssl
    )
    
    return _redis_client


def close_redis_client() -> None:
    """Close global Redis client and cleanup resources."""
    global _redis_client
    
    if _redis_client:
        _redis_client.close()
        _redis_client = None
        logger.info("global_redis_client_closed")


# Export public interface
__all__ = [
    'RedisClient',
    'RedisPipeline', 
    'CircuitBreaker',
    'create_redis_client',
    'get_redis_client',
    'init_redis_client',
    'close_redis_client'
]