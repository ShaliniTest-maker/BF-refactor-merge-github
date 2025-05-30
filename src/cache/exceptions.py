"""
Cache-specific exception classes providing comprehensive error handling for Redis connection 
failures, cache operation timeouts, and cache invalidation errors. Implements integration 
with Flask error handlers and circuit breaker patterns for enterprise-grade cache error 
management.

This module implements the complete cache exception hierarchy as specified in Section 4.2.3
of the technical specification, providing robust error handling patterns for Redis-based
caching operations with enterprise-grade resilience mechanisms.
"""

import structlog
from typing import Any, Dict, Optional, Union
from datetime import datetime


# Initialize structured logger for cache exception logging
logger = structlog.get_logger(__name__)


class CacheError(Exception):
    """
    Base cache exception class providing comprehensive error handling foundation
    for all cache-related operations per Section 4.2.3 error handling hierarchy.
    
    This base class establishes the foundation for cache error management with
    structured error information, timing data, and enterprise logging integration.
    All cache-specific exceptions inherit from this base class to ensure consistent
    error handling patterns throughout the cache layer.
    """
    
    def __init__(
        self, 
        message: str, 
        operation: Optional[str] = None,
        key: Optional[str] = None,
        error_code: Optional[str] = None,
        retry_after: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Initialize cache error with comprehensive error context.
        
        Args:
            message: Human-readable error description
            operation: Cache operation that failed (get, set, delete, etc.)
            key: Redis key involved in the operation
            error_code: Standardized error code for monitoring and alerting
            retry_after: Suggested retry delay in seconds
            metadata: Additional error context for debugging and monitoring
        """
        super().__init__(message)
        self.message = message
        self.operation = operation
        self.key = key
        self.error_code = error_code or "CACHE_ERROR"
        self.retry_after = retry_after
        self.metadata = metadata or {}
        self.timestamp = datetime.utcnow()
        
        # Log error for enterprise monitoring and alerting
        logger.error(
            "Cache operation failed",
            error_type=self.__class__.__name__,
            error_code=self.error_code,
            message=self.message,
            operation=self.operation,
            cache_key=self.key,
            retry_after=self.retry_after,
            metadata=self.metadata,
            timestamp=self.timestamp.isoformat()
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert exception to dictionary for JSON serialization and API responses.
        
        Returns:
            Dict containing structured error information for Flask error handlers
        """
        return {
            "error": self.__class__.__name__,
            "message": self.message,
            "error_code": self.error_code,
            "operation": self.operation,
            "key": self.key,
            "retry_after": self.retry_after,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata
        }


class CacheConnectionError(CacheError):
    """
    Redis connection failure exception with circuit breaker integration
    per Section 4.2.3 Redis circuit breaker check.
    
    This exception is raised when Redis connection cannot be established or
    is lost during operation. Integrates with circuit breaker patterns to
    prevent cascade failures and enable intelligent fallback mechanisms.
    """
    
    def __init__(
        self,
        message: str = "Redis connection failed",
        host: Optional[str] = None,
        port: Optional[int] = None,
        db: Optional[int] = None,
        connection_pool_size: Optional[int] = None,
        retry_count: int = 0,
        **kwargs
    ) -> None:
        """
        Initialize Redis connection error with connection details.
        
        Args:
            message: Error description
            host: Redis server hostname
            port: Redis server port
            db: Redis database number
            connection_pool_size: Current connection pool size
            retry_count: Number of connection attempts made
            **kwargs: Additional arguments passed to parent class
        """
        super().__init__(
            message=message,
            error_code="CACHE_CONNECTION_ERROR",
            **kwargs
        )
        self.host = host
        self.port = port
        self.db = db
        self.connection_pool_size = connection_pool_size
        self.retry_count = retry_count
        
        # Add connection details to metadata for debugging
        self.metadata.update({
            "redis_host": self.host,
            "redis_port": self.port,
            "redis_db": self.db,
            "connection_pool_size": self.connection_pool_size,
            "retry_count": self.retry_count
        })
        
        logger.error(
            "Redis connection failure detected",
            redis_host=self.host,
            redis_port=self.port,
            redis_db=self.db,
            connection_pool_size=self.connection_pool_size,
            retry_count=self.retry_count
        )


class CacheTimeoutError(CacheError):
    """
    Cache operation timeout exception per Section 4.2.3 cache operation timeouts.
    
    Raised when cache operations exceed configured timeout thresholds. Supports
    circuit breaker integration and intelligent retry strategies with exponential
    backoff patterns.
    """
    
    def __init__(
        self,
        message: str = "Cache operation timed out",
        timeout_duration: Optional[float] = None,
        operation_start_time: Optional[datetime] = None,
        **kwargs
    ) -> None:
        """
        Initialize cache timeout error with timing information.
        
        Args:
            message: Error description
            timeout_duration: Configured timeout duration in seconds
            operation_start_time: When the operation began
            **kwargs: Additional arguments passed to parent class
        """
        super().__init__(
            message=message,
            error_code="CACHE_TIMEOUT_ERROR",
            retry_after=30,  # Suggest 30-second retry delay for timeouts
            **kwargs
        )
        self.timeout_duration = timeout_duration
        self.operation_start_time = operation_start_time
        
        # Calculate actual operation duration if start time provided
        actual_duration = None
        if operation_start_time:
            actual_duration = (self.timestamp - operation_start_time).total_seconds()
        
        self.metadata.update({
            "timeout_duration": self.timeout_duration,
            "operation_start_time": operation_start_time.isoformat() if operation_start_time else None,
            "actual_duration": actual_duration
        })
        
        logger.warning(
            "Cache operation timeout",
            timeout_duration=self.timeout_duration,
            actual_duration=actual_duration,
            operation=self.operation,
            cache_key=self.key
        )


class CacheCircuitBreakerError(CacheError):
    """
    Circuit breaker exception for cache service protection per Section 4.2.3
    circuit breaker patterns and Section 6.1.3 resilience mechanisms.
    
    Raised when circuit breaker is open to prevent additional failures and
    protect system stability during Redis service degradation.
    """
    
    def __init__(
        self,
        message: str = "Cache circuit breaker is open",
        circuit_state: str = "OPEN",
        failure_count: int = 0,
        last_failure_time: Optional[datetime] = None,
        next_attempt_time: Optional[datetime] = None,
        **kwargs
    ) -> None:
        """
        Initialize circuit breaker error with circuit state information.
        
        Args:
            message: Error description
            circuit_state: Current circuit breaker state (OPEN, HALF_OPEN, CLOSED)
            failure_count: Number of consecutive failures
            last_failure_time: Timestamp of last failure
            next_attempt_time: When next attempt is allowed
            **kwargs: Additional arguments passed to parent class
        """
        # Calculate retry_after based on next attempt time
        retry_after = None
        if next_attempt_time:
            retry_after = max(0, int((next_attempt_time - datetime.utcnow()).total_seconds()))
        
        super().__init__(
            message=message,
            error_code="CACHE_CIRCUIT_BREAKER_ERROR",
            retry_after=retry_after,
            **kwargs
        )
        self.circuit_state = circuit_state
        self.failure_count = failure_count
        self.last_failure_time = last_failure_time
        self.next_attempt_time = next_attempt_time
        
        self.metadata.update({
            "circuit_state": self.circuit_state,
            "failure_count": self.failure_count,
            "last_failure_time": last_failure_time.isoformat() if last_failure_time else None,
            "next_attempt_time": next_attempt_time.isoformat() if next_attempt_time else None
        })
        
        logger.warning(
            "Cache circuit breaker triggered",
            circuit_state=self.circuit_state,
            failure_count=self.failure_count,
            retry_after=self.retry_after
        )


class CacheSerializationError(CacheError):
    """
    Cache data serialization/deserialization exception per Section 4.2.3
    error handling for data transformation failures.
    
    Raised when cache data cannot be properly serialized for storage or
    deserialized during retrieval, indicating data corruption or format issues.
    """
    
    def __init__(
        self,
        message: str = "Cache data serialization failed",
        data_type: Optional[str] = None,
        serialization_format: str = "json",
        **kwargs
    ) -> None:
        """
        Initialize serialization error with data format information.
        
        Args:
            message: Error description
            data_type: Type of data being serialized/deserialized
            serialization_format: Format used (json, pickle, etc.)
            **kwargs: Additional arguments passed to parent class
        """
        super().__init__(
            message=message,
            error_code="CACHE_SERIALIZATION_ERROR",
            **kwargs
        )
        self.data_type = data_type
        self.serialization_format = serialization_format
        
        self.metadata.update({
            "data_type": self.data_type,
            "serialization_format": self.serialization_format
        })
        
        logger.error(
            "Cache data serialization failure",
            data_type=self.data_type,
            serialization_format=self.serialization_format,
            cache_key=self.key
        )


class CacheInvalidationError(CacheError):
    """
    Cache invalidation failure exception per Section 4.2.3 cache invalidation
    error handling flows.
    
    Raised when cache invalidation operations fail, potentially leading to
    stale data being served. Critical for maintaining data consistency across
    the distributed cache infrastructure.
    """
    
    def __init__(
        self,
        message: str = "Cache invalidation failed",
        invalidation_pattern: Optional[str] = None,
        affected_keys: Optional[list] = None,
        partial_failure: bool = False,
        **kwargs
    ) -> None:
        """
        Initialize cache invalidation error with invalidation details.
        
        Args:
            message: Error description
            invalidation_pattern: Pattern used for invalidation (key pattern, tag, etc.)
            affected_keys: List of keys that were supposed to be invalidated
            partial_failure: Whether some keys were successfully invalidated
            **kwargs: Additional arguments passed to parent class
        """
        super().__init__(
            message=message,
            error_code="CACHE_INVALIDATION_ERROR",
            **kwargs
        )
        self.invalidation_pattern = invalidation_pattern
        self.affected_keys = affected_keys or []
        self.partial_failure = partial_failure
        
        self.metadata.update({
            "invalidation_pattern": self.invalidation_pattern,
            "affected_keys_count": len(self.affected_keys),
            "affected_keys": self.affected_keys[:10],  # Limit to first 10 keys for logging
            "partial_failure": self.partial_failure
        })
        
        logger.error(
            "Cache invalidation operation failed",
            invalidation_pattern=self.invalidation_pattern,
            affected_keys_count=len(self.affected_keys),
            partial_failure=self.partial_failure
        )


class CacheKeyError(CacheError):
    """
    Invalid cache key exception for key validation failures.
    
    Raised when cache keys violate Redis key constraints or application-specific
    key pattern requirements. Helps maintain cache key consistency and prevents
    Redis errors from invalid key formats.
    """
    
    def __init__(
        self,
        message: str = "Invalid cache key",
        invalid_key: Optional[str] = None,
        validation_rule: Optional[str] = None,
        **kwargs
    ) -> None:
        """
        Initialize cache key error with validation details.
        
        Args:
            message: Error description
            invalid_key: The problematic cache key
            validation_rule: The validation rule that was violated
            **kwargs: Additional arguments passed to parent class
        """
        super().__init__(
            message=message,
            error_code="CACHE_KEY_ERROR",
            key=invalid_key,
            **kwargs
        )
        self.invalid_key = invalid_key
        self.validation_rule = validation_rule
        
        self.metadata.update({
            "invalid_key": self.invalid_key,
            "validation_rule": self.validation_rule
        })
        
        logger.warning(
            "Invalid cache key detected",
            invalid_key=self.invalid_key,
            validation_rule=self.validation_rule
        )


class CachePoolExhaustedError(CacheError):
    """
    Connection pool exhaustion exception per Section 6.1.3 resource optimization.
    
    Raised when Redis connection pool has no available connections, indicating
    high load or connection leaks. Critical for monitoring connection pool health
    and preventing resource exhaustion.
    """
    
    def __init__(
        self,
        message: str = "Redis connection pool exhausted",
        max_connections: Optional[int] = None,
        active_connections: Optional[int] = None,
        pool_timeout: Optional[float] = None,
        **kwargs
    ) -> None:
        """
        Initialize connection pool exhaustion error with pool statistics.
        
        Args:
            message: Error description
            max_connections: Maximum pool size
            active_connections: Current active connections
            pool_timeout: Pool acquisition timeout
            **kwargs: Additional arguments passed to parent class
        """
        super().__init__(
            message=message,
            error_code="CACHE_POOL_EXHAUSTED_ERROR",
            retry_after=60,  # Suggest 60-second retry for pool exhaustion
            **kwargs
        )
        self.max_connections = max_connections
        self.active_connections = active_connections
        self.pool_timeout = pool_timeout
        
        self.metadata.update({
            "max_connections": self.max_connections,
            "active_connections": self.active_connections,
            "pool_timeout": self.pool_timeout
        })
        
        logger.critical(
            "Redis connection pool exhausted",
            max_connections=self.max_connections,
            active_connections=self.active_connections,
            pool_timeout=self.pool_timeout
        )


class CacheMemoryError(CacheError):
    """
    Redis memory limitation exception for memory management failures.
    
    Raised when Redis server runs out of memory or hits configured memory limits.
    Critical for monitoring Redis memory usage and preventing service degradation.
    """
    
    def __init__(
        self,
        message: str = "Redis memory limit exceeded",
        used_memory: Optional[int] = None,
        max_memory: Optional[int] = None,
        memory_policy: Optional[str] = None,
        **kwargs
    ) -> None:
        """
        Initialize Redis memory error with memory statistics.
        
        Args:
            message: Error description
            used_memory: Current memory usage in bytes
            max_memory: Maximum memory limit in bytes
            memory_policy: Redis eviction policy (allkeys-lru, etc.)
            **kwargs: Additional arguments passed to parent class
        """
        super().__init__(
            message=message,
            error_code="CACHE_MEMORY_ERROR",
            retry_after=120,  # Suggest 2-minute retry for memory issues
            **kwargs
        )
        self.used_memory = used_memory
        self.max_memory = max_memory
        self.memory_policy = memory_policy
        
        self.metadata.update({
            "used_memory": self.used_memory,
            "max_memory": self.max_memory,
            "memory_policy": self.memory_policy,
            "memory_usage_percent": (
                (self.used_memory / self.max_memory * 100) 
                if self.used_memory and self.max_memory else None
            )
        })
        
        logger.critical(
            "Redis memory limit exceeded",
            used_memory=self.used_memory,
            max_memory=self.max_memory,
            memory_policy=self.memory_policy
        )


# Exception mapping for Flask error handlers per Section 4.2.3
# Flask @errorhandler decorators integration
CACHE_EXCEPTION_MAPPING = {
    CacheConnectionError: {
        "status_code": 503,  # Service Unavailable
        "error_type": "service_unavailable",
        "user_message": "Cache service is temporarily unavailable. Please try again later."
    },
    CacheTimeoutError: {
        "status_code": 504,  # Gateway Timeout
        "error_type": "timeout",
        "user_message": "Operation timed out. Please try again."
    },
    CacheCircuitBreakerError: {
        "status_code": 503,  # Service Unavailable
        "error_type": "service_unavailable",
        "user_message": "Cache service is temporarily unavailable due to circuit breaker protection."
    },
    CacheSerializationError: {
        "status_code": 500,  # Internal Server Error
        "error_type": "internal_error",
        "user_message": "An internal error occurred while processing cache data."
    },
    CacheInvalidationError: {
        "status_code": 500,  # Internal Server Error
        "error_type": "internal_error",
        "user_message": "An error occurred while updating cache. Data may be temporarily inconsistent."
    },
    CacheKeyError: {
        "status_code": 400,  # Bad Request
        "error_type": "bad_request",
        "user_message": "Invalid cache key format."
    },
    CachePoolExhaustedError: {
        "status_code": 503,  # Service Unavailable
        "error_type": "service_unavailable",
        "user_message": "Service is temporarily overloaded. Please try again later."
    },
    CacheMemoryError: {
        "status_code": 503,  # Service Unavailable
        "error_type": "service_unavailable",
        "user_message": "Cache service is temporarily unavailable due to memory constraints."
    },
    CacheError: {
        "status_code": 500,  # Internal Server Error
        "error_type": "internal_error",
        "user_message": "An unexpected cache error occurred."
    }
}


def get_cache_error_response(exception: CacheError) -> Dict[str, Any]:
    """
    Generate standardized error response for Flask error handlers per Section 4.2.3
    Flask @errorhandler decorators.
    
    This function creates consistent error responses that can be used by Flask
    error handlers to return standardized JSON error responses to clients while
    maintaining enterprise security practices by not exposing internal details.
    
    Args:
        exception: Cache exception instance
        
    Returns:
        Dict containing standardized error response for JSON serialization
    """
    # Get error mapping configuration
    error_config = CACHE_EXCEPTION_MAPPING.get(
        type(exception),
        CACHE_EXCEPTION_MAPPING[CacheError]
    )
    
    # Build standardized error response
    error_response = {
        "error": {
            "type": error_config["error_type"],
            "message": error_config["user_message"],
            "code": exception.error_code,
            "timestamp": exception.timestamp.isoformat()
        }
    }
    
    # Add retry information if available
    if exception.retry_after:
        error_response["error"]["retry_after"] = exception.retry_after
    
    # Add operation context for debugging (non-sensitive information only)
    if exception.operation:
        error_response["error"]["operation"] = exception.operation
    
    # Log error response generation for monitoring
    logger.info(
        "Generated cache error response",
        error_type=error_config["error_type"],
        status_code=error_config["status_code"],
        error_code=exception.error_code,
        operation=exception.operation
    )
    
    return {
        "response": error_response,
        "status_code": error_config["status_code"]
    }


# Expose all exception classes for import
__all__ = [
    "CacheError",
    "CacheConnectionError", 
    "CacheTimeoutError",
    "CacheCircuitBreakerError",
    "CacheSerializationError",
    "CacheInvalidationError",
    "CacheKeyError",
    "CachePoolExhaustedError",
    "CacheMemoryError",
    "CACHE_EXCEPTION_MAPPING",
    "get_cache_error_response"
]