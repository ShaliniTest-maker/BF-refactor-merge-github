"""
Cache-specific exception classes providing comprehensive error handling for Redis connection
failures, cache operation timeouts, and cache invalidation errors. Implements integration
with Flask error handlers and circuit breaker patterns for enterprise-grade cache error
management.

This module implements the error handling architecture specified in Section 4.2.3 of the
technical specification, providing resilience mechanisms per Section 6.1.3 and ensuring
comprehensive error management for cache operations in the Flask application migration.
"""

import logging
from typing import Optional, Dict, Any, Union
from datetime import datetime, timedelta

# Redis and HTTP client exceptions for inheritance and handling
try:
    import redis.exceptions as redis_exceptions
    import redis
except ImportError:
    # Graceful fallback for testing environments
    redis_exceptions = None
    redis = None

try:
    import httpx
except ImportError:
    httpx = None

try:
    from pybreaker import CircuitBreakerError
except ImportError:
    # Define a placeholder for environments without pybreaker
    class CircuitBreakerError(Exception):
        """Placeholder for circuit breaker errors when pybreaker is not available."""
        pass

# Structured logging for enterprise integration
import structlog

logger = structlog.get_logger(__name__)


class CacheError(Exception):
    """
    Base exception class for all cache-related errors.
    
    Provides foundation for cache error hierarchy with enterprise-grade error tracking,
    structured logging integration, and Flask error handler compatibility.
    
    Attributes:
        message: Human-readable error description
        error_code: Standardized error code for monitoring and alerting
        details: Additional error context for debugging and observability
        timestamp: Error occurrence timestamp for correlation with logs
        retry_after: Optional hint for retry delay (in seconds)
    """
    
    def __init__(
        self,
        message: str,
        error_code: str = "CACHE_ERROR",
        details: Optional[Dict[str, Any]] = None,
        retry_after: Optional[int] = None
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        self.timestamp = datetime.utcnow()
        self.retry_after = retry_after
        
        # Log error occurrence for enterprise observability
        logger.error(
            "Cache error occurred",
            error_code=self.error_code,
            message=message,
            details=self.details,
            timestamp=self.timestamp.isoformat(),
            retry_after=retry_after
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert exception to dictionary for JSON serialization in Flask error responses.
        
        Returns:
            Dictionary containing error information suitable for HTTP responses
        """
        return {
            "error": self.error_code,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp.isoformat(),
            "retry_after": self.retry_after
        }


class RedisConnectionError(CacheError):
    """
    Exception raised when Redis connection operations fail.
    
    Handles Redis connectivity issues including network failures, authentication errors,
    and connection pool exhaustion. Integrates with circuit breaker patterns for
    enterprise resilience per Section 6.1.3.
    
    Attributes:
        redis_error: Original Redis exception for detailed diagnostics
        connection_info: Redis connection details (sanitized for security)
        circuit_breaker_state: Current circuit breaker state if applicable
    """
    
    def __init__(
        self,
        message: str,
        redis_error: Optional[Exception] = None,
        connection_info: Optional[Dict[str, Any]] = None,
        circuit_breaker_state: Optional[str] = None,
        retry_after: Optional[int] = 30
    ):
        # Sanitize connection info to prevent credential exposure
        safe_connection_info = {}
        if connection_info:
            safe_connection_info = {
                "host": connection_info.get("host", "unknown"),
                "port": connection_info.get("port", "unknown"),
                "db": connection_info.get("db", "unknown"),
                "ssl": connection_info.get("ssl", False),
                "max_connections": connection_info.get("max_connections"),
                "retry_on_timeout": connection_info.get("retry_on_timeout")
            }
        
        details = {
            "redis_error_type": type(redis_error).__name__ if redis_error else None,
            "redis_error_message": str(redis_error) if redis_error else None,
            "connection_info": safe_connection_info,
            "circuit_breaker_state": circuit_breaker_state
        }
        
        super().__init__(
            message=message,
            error_code="REDIS_CONNECTION_ERROR",
            details=details,
            retry_after=retry_after
        )
        
        self.redis_error = redis_error
        self.connection_info = safe_connection_info
        self.circuit_breaker_state = circuit_breaker_state


class CacheOperationTimeoutError(CacheError):
    """
    Exception raised when cache operations exceed configured timeout limits.
    
    Handles timeout scenarios for Redis operations including command execution timeouts,
    connection acquisition timeouts, and circuit breaker timeout scenarios.
    
    Attributes:
        operation: Cache operation that timed out
        timeout_duration: Configured timeout value in seconds
        elapsed_time: Actual time elapsed before timeout
    """
    
    def __init__(
        self,
        message: str,
        operation: str,
        timeout_duration: float,
        elapsed_time: Optional[float] = None,
        retry_after: Optional[int] = 10
    ):
        details = {
            "operation": operation,
            "timeout_duration": timeout_duration,
            "elapsed_time": elapsed_time,
            "timeout_ratio": elapsed_time / timeout_duration if elapsed_time else None
        }
        
        super().__init__(
            message=message,
            error_code="CACHE_OPERATION_TIMEOUT",
            details=details,
            retry_after=retry_after
        )
        
        self.operation = operation
        self.timeout_duration = timeout_duration
        self.elapsed_time = elapsed_time


class CacheInvalidationError(CacheError):
    """
    Exception raised when cache invalidation operations fail.
    
    Handles errors during cache key deletion, pattern-based invalidation,
    and distributed cache invalidation across multiple instances.
    
    Attributes:
        keys: Cache keys that failed to invalidate
        pattern: Key pattern used for batch invalidation (if applicable)
        partial_success: List of keys that were successfully invalidated
    """
    
    def __init__(
        self,
        message: str,
        keys: Optional[Union[str, list]] = None,
        pattern: Optional[str] = None,
        partial_success: Optional[list] = None,
        retry_after: Optional[int] = 5
    ):
        # Normalize keys to list format
        if keys is None:
            keys = []
        elif isinstance(keys, str):
            keys = [keys]
        
        details = {
            "failed_keys": keys,
            "invalidation_pattern": pattern,
            "partially_successful_keys": partial_success or [],
            "total_failed": len(keys),
            "total_partial_success": len(partial_success) if partial_success else 0
        }
        
        super().__init__(
            message=message,
            error_code="CACHE_INVALIDATION_ERROR",
            details=details,
            retry_after=retry_after
        )
        
        self.keys = keys
        self.pattern = pattern
        self.partial_success = partial_success or []


class CircuitBreakerOpenError(CacheError):
    """
    Exception raised when cache operations fail due to open circuit breaker.
    
    Implements circuit breaker pattern integration per Section 6.1.3 resilience
    mechanisms, providing fallback mechanisms and recovery guidance.
    
    Attributes:
        failure_count: Number of consecutive failures that triggered circuit breaker
        recovery_timeout: Time until circuit breaker attempts recovery
        last_failure_time: Timestamp of most recent failure
    """
    
    def __init__(
        self,
        message: str,
        failure_count: int,
        recovery_timeout: int,
        last_failure_time: Optional[datetime] = None,
        retry_after: Optional[int] = None
    ):
        # Calculate retry_after based on recovery_timeout if not provided
        if retry_after is None:
            retry_after = recovery_timeout
        
        details = {
            "failure_count": failure_count,
            "recovery_timeout": recovery_timeout,
            "last_failure_time": last_failure_time.isoformat() if last_failure_time else None,
            "estimated_recovery_time": (
                (last_failure_time + timedelta(seconds=recovery_timeout)).isoformat()
                if last_failure_time else None
            )
        }
        
        super().__init__(
            message=message,
            error_code="CIRCUIT_BREAKER_OPEN",
            details=details,
            retry_after=retry_after
        )
        
        self.failure_count = failure_count
        self.recovery_timeout = recovery_timeout
        self.last_failure_time = last_failure_time


class CacheKeyError(CacheError):
    """
    Exception raised for cache key related errors including invalid formats,
    missing keys, and key generation failures.
    
    Attributes:
        key: Cache key that caused the error
        key_pattern: Key pattern if pattern matching was involved
        validation_errors: Specific key validation failures
    """
    
    def __init__(
        self,
        message: str,
        key: Optional[str] = None,
        key_pattern: Optional[str] = None,
        validation_errors: Optional[list] = None,
        retry_after: Optional[int] = None
    ):
        details = {
            "invalid_key": key,
            "key_pattern": key_pattern,
            "validation_errors": validation_errors or [],
            "key_length": len(key) if key else None
        }
        
        super().__init__(
            message=message,
            error_code="CACHE_KEY_ERROR",
            details=details,
            retry_after=retry_after
        )
        
        self.key = key
        self.key_pattern = key_pattern
        self.validation_errors = validation_errors or []


class CacheSerializationError(CacheError):
    """
    Exception raised when cache value serialization or deserialization fails.
    
    Handles errors during JSON encoding/decoding, pickle operations, and
    custom serialization formats used in cache operations.
    
    Attributes:
        value_type: Type of value that failed serialization
        serialization_method: Method used for serialization (json, pickle, etc.)
        original_error: Original serialization exception
    """
    
    def __init__(
        self,
        message: str,
        value_type: Optional[str] = None,
        serialization_method: str = "json",
        original_error: Optional[Exception] = None,
        retry_after: Optional[int] = None
    ):
        details = {
            "value_type": value_type,
            "serialization_method": serialization_method,
            "original_error_type": type(original_error).__name__ if original_error else None,
            "original_error_message": str(original_error) if original_error else None
        }
        
        super().__init__(
            message=message,
            error_code="CACHE_SERIALIZATION_ERROR",
            details=details,
            retry_after=retry_after
        )
        
        self.value_type = value_type
        self.serialization_method = serialization_method
        self.original_error = original_error


class CachePoolExhaustedError(CacheError):
    """
    Exception raised when Redis connection pool is exhausted.
    
    Handles scenarios where all available connections in the pool are in use,
    indicating potential resource contention or configuration issues.
    
    Attributes:
        max_connections: Maximum number of connections in pool
        active_connections: Current number of active connections
        pool_timeout: Configured timeout for pool acquisition
    """
    
    def __init__(
        self,
        message: str,
        max_connections: int,
        active_connections: int,
        pool_timeout: float,
        retry_after: Optional[int] = 15
    ):
        details = {
            "max_connections": max_connections,
            "active_connections": active_connections,
            "pool_utilization": active_connections / max_connections if max_connections > 0 else 0,
            "pool_timeout": pool_timeout
        }
        
        super().__init__(
            message=message,
            error_code="CACHE_POOL_EXHAUSTED",
            details=details,
            retry_after=retry_after
        )
        
        self.max_connections = max_connections
        self.active_connections = active_connections
        self.pool_timeout = pool_timeout


# Exception mapping for Flask error handler registration
CACHE_EXCEPTION_MAPPING = {
    CacheError: 500,
    RedisConnectionError: 503,
    CacheOperationTimeoutError: 504,
    CacheInvalidationError: 500,
    CircuitBreakerOpenError: 503,
    CacheKeyError: 400,
    CacheSerializationError: 500,
    CachePoolExhaustedError: 503
}

# HTTP status code mappings for different error types
HTTP_STATUS_CODES = {
    "CACHE_ERROR": 500,
    "REDIS_CONNECTION_ERROR": 503,
    "CACHE_OPERATION_TIMEOUT": 504,
    "CACHE_INVALIDATION_ERROR": 500,
    "CIRCUIT_BREAKER_OPEN": 503,
    "CACHE_KEY_ERROR": 400,
    "CACHE_SERIALIZATION_ERROR": 500,
    "CACHE_POOL_EXHAUSTED": 503
}


def handle_redis_exception(redis_error: Exception, operation: str = "unknown") -> CacheError:
    """
    Convert Redis exceptions to appropriate cache exceptions.
    
    Provides centralized exception translation from redis-py exceptions to
    application-specific cache exceptions for consistent error handling.
    
    Args:
        redis_error: Original Redis exception
        operation: Description of the operation that failed
        
    Returns:
        Appropriate CacheError subclass based on Redis error type
    """
    if not redis_exceptions:
        # Fallback when redis is not available
        return CacheError(
            message=f"Cache operation '{operation}' failed: {str(redis_error)}",
            details={"operation": operation, "original_error": str(redis_error)}
        )
    
    error_message = f"Redis operation '{operation}' failed: {str(redis_error)}"
    
    # Connection-related errors
    if isinstance(redis_error, (redis_exceptions.ConnectionError, redis_exceptions.TimeoutError)):
        return RedisConnectionError(
            message=error_message,
            redis_error=redis_error
        )
    
    # Authentication and authorization errors
    elif isinstance(redis_error, redis_exceptions.AuthenticationError):
        return RedisConnectionError(
            message=f"Redis authentication failed for operation '{operation}'",
            redis_error=redis_error
        )
    
    # Response-related errors (timeout, protocol issues)
    elif isinstance(redis_error, redis_exceptions.ResponseError):
        if "timeout" in str(redis_error).lower():
            return CacheOperationTimeoutError(
                message=error_message,
                operation=operation,
                timeout_duration=30.0  # Default timeout assumption
            )
        else:
            return CacheError(
                message=error_message,
                error_code="REDIS_RESPONSE_ERROR",
                details={"operation": operation, "redis_error": str(redis_error)}
            )
    
    # Data type and encoding errors
    elif isinstance(redis_error, redis_exceptions.DataError):
        return CacheSerializationError(
            message=error_message,
            serialization_method="redis",
            original_error=redis_error
        )
    
    # Generic Redis errors
    else:
        return CacheError(
            message=error_message,
            error_code="REDIS_ERROR",
            details={"operation": operation, "redis_error_type": type(redis_error).__name__}
        )


def register_cache_error_handlers(app):
    """
    Register Flask error handlers for cache exceptions.
    
    Implements Flask @errorhandler decorator integration per Section 4.2.3,
    providing consistent error response formatting for all cache-related exceptions.
    
    Args:
        app: Flask application instance
    """
    from flask import jsonify, request
    
    def create_error_response(error: CacheError, status_code: int):
        """Create standardized JSON error response."""
        response_data = error.to_dict()
        
        # Add request context for debugging
        response_data["request_id"] = getattr(request, "request_id", None)
        response_data["path"] = request.path if request else None
        response_data["method"] = request.method if request else None
        
        # Log error with structured logging for enterprise observability
        logger.error(
            "Cache error in HTTP request",
            error_code=error.error_code,
            status_code=status_code,
            path=response_data["path"],
            method=response_data["method"],
            request_id=response_data["request_id"],
            error_details=error.details
        )
        
        response = jsonify(response_data)
        response.status_code = status_code
        
        # Add cache-related headers for client guidance
        if error.retry_after:
            response.headers["Retry-After"] = str(error.retry_after)
        
        # Prevent caching of error responses
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        
        return response
    
    # Register individual error handlers for each exception type
    @app.errorhandler(CacheError)
    def handle_cache_error(error):
        return create_error_response(error, HTTP_STATUS_CODES.get(error.error_code, 500))
    
    @app.errorhandler(RedisConnectionError)
    def handle_redis_connection_error(error):
        return create_error_response(error, 503)
    
    @app.errorhandler(CacheOperationTimeoutError)
    def handle_cache_timeout_error(error):
        return create_error_response(error, 504)
    
    @app.errorhandler(CacheInvalidationError)
    def handle_cache_invalidation_error(error):
        return create_error_response(error, 500)
    
    @app.errorhandler(CircuitBreakerOpenError)
    def handle_circuit_breaker_error(error):
        return create_error_response(error, 503)
    
    @app.errorhandler(CacheKeyError)
    def handle_cache_key_error(error):
        return create_error_response(error, 400)
    
    @app.errorhandler(CacheSerializationError)
    def handle_cache_serialization_error(error):
        return create_error_response(error, 500)
    
    @app.errorhandler(CachePoolExhaustedError)
    def handle_cache_pool_exhausted_error(error):
        return create_error_response(error, 503)
    
    # Handle circuit breaker exceptions from pybreaker library
    @app.errorhandler(CircuitBreakerError)
    def handle_pybreaker_error(error):
        cache_error = CircuitBreakerOpenError(
            message=f"Circuit breaker is open: {str(error)}",
            failure_count=0,  # Unknown from pybreaker exception
            recovery_timeout=60  # Default recovery timeout
        )
        return create_error_response(cache_error, 503)
    
    logger.info("Cache error handlers registered with Flask application")


# Export public API
__all__ = [
    "CacheError",
    "RedisConnectionError", 
    "CacheOperationTimeoutError",
    "CacheInvalidationError",
    "CircuitBreakerOpenError",
    "CacheKeyError",
    "CacheSerializationError", 
    "CachePoolExhaustedError",
    "handle_redis_exception",
    "register_cache_error_handlers",
    "CACHE_EXCEPTION_MAPPING",
    "HTTP_STATUS_CODES"
]