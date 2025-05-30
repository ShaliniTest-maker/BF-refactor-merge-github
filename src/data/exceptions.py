"""
Database-specific exception handling and error management module.

This module implements comprehensive error handling for PyMongo and Motor operations,
providing custom exception classes, retry logic with exponential backoff, circuit breaker
patterns for database resilience, and monitoring integration for fault tolerance.

Implements requirements from:
- Section 4.2.3: Error handling and recovery with Tenacity exponential backoff
- Section 6.2.3: Fault tolerance and backup policies with circuit breaker patterns
- Section 5.2.5: Database access layer error handling and monitoring
- Section 6.2.2: Compliance monitoring with Prometheus metrics integration
"""

import functools
import logging
import time
from contextlib import contextmanager
from typing import Any, Callable, Dict, List, Optional, Type, Union

import structlog
from prometheus_client import Counter, Histogram, Gauge
from pybreaker import CircuitBreaker, CircuitBreakerState
from pymongo import errors as pymongo_errors
from motor import core as motor_core
from tenacity import (
    Retrying,
    RetryError,
    after_log,
    before_sleep_log,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
    wait_random_exponential
)

# Structured logger instance
logger = structlog.get_logger(__name__)

# Prometheus metrics for database error monitoring
database_errors_total = Counter(
    'database_errors_total',
    'Total number of database errors',
    ['error_type', 'operation', 'database', 'collection']
)

database_operation_duration = Histogram(
    'database_operation_duration_seconds',
    'Database operation execution time including retries',
    ['operation', 'database', 'collection', 'status']
)

database_retries_total = Counter(
    'database_retries_total',
    'Total number of database operation retries',
    ['error_type', 'operation', 'database', 'collection']
)

circuit_breaker_state = Gauge(
    'database_circuit_breaker_state',
    'Circuit breaker state (0=closed, 1=open, 2=half_open)',
    ['database', 'operation']
)

database_connection_failures = Counter(
    'database_connection_failures_total',
    'Total number of database connection failures',
    ['database', 'error_type']
)


class DatabaseException(Exception):
    """
    Base exception class for all database-related errors.
    
    Provides standardized error handling with operation context, 
    metrics emission, and structured logging integration.
    """
    
    def __init__(
        self,
        message: str,
        operation: Optional[str] = None,
        database: Optional[str] = None,
        collection: Optional[str] = None,
        original_error: Optional[Exception] = None,
        retry_count: int = 0
    ):
        """
        Initialize database exception with comprehensive context.
        
        Args:
            message: Human-readable error description
            operation: Database operation that failed (e.g., 'find', 'insert', 'update')
            database: Database name where error occurred
            collection: Collection name where error occurred
            original_error: Original exception that triggered this error
            retry_count: Number of retries attempted before failure
        """
        super().__init__(message)
        self.message = message
        self.operation = operation or 'unknown'
        self.database = database or 'unknown'
        self.collection = collection or 'unknown'
        self.original_error = original_error
        self.retry_count = retry_count
        self.timestamp = time.time()
        
        # Emit error metrics
        self._emit_error_metrics()
        
        # Log structured error details
        self._log_error_details()
    
    def _emit_error_metrics(self) -> None:
        """Emit Prometheus metrics for error tracking and monitoring."""
        error_type = self.__class__.__name__
        database_errors_total.labels(
            error_type=error_type,
            operation=self.operation,
            database=self.database,
            collection=self.collection
        ).inc()
        
        if self.retry_count > 0:
            database_retries_total.labels(
                error_type=error_type,
                operation=self.operation,
                database=self.database,
                collection=self.collection
            ).inc(self.retry_count)
    
    def _log_error_details(self) -> None:
        """Log structured error details for enterprise monitoring."""
        logger.error(
            "Database operation failed",
            error_type=self.__class__.__name__,
            message=self.message,
            operation=self.operation,
            database=self.database,
            collection=self.collection,
            retry_count=self.retry_count,
            original_error=str(self.original_error) if self.original_error else None,
            timestamp=self.timestamp
        )


class DatabaseConnectionError(DatabaseException):
    """
    Exception for database connection failures.
    
    Handles connection pool exhaustion, network connectivity issues,
    authentication failures, and server unavailability scenarios.
    """
    
    def __init__(
        self,
        message: str,
        connection_info: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        """
        Initialize connection error with connection context.
        
        Args:
            message: Error description
            connection_info: Connection details (host, port, authentication info)
            **kwargs: Additional context from DatabaseException
        """
        super().__init__(message, **kwargs)
        self.connection_info = connection_info or {}
        
        # Emit connection-specific metrics
        database_connection_failures.labels(
            database=self.database,
            error_type='connection_failure'
        ).inc()


class DatabaseQueryError(DatabaseException):
    """
    Exception for database query execution failures.
    
    Handles query syntax errors, index issues, document validation failures,
    and other operation-specific errors during database operations.
    """
    
    def __init__(
        self,
        message: str,
        query: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        """
        Initialize query error with query context.
        
        Args:
            message: Error description
            query: Query that failed (sanitized for logging)
            **kwargs: Additional context from DatabaseException
        """
        super().__init__(message, **kwargs)
        self.query = query


class DatabaseTransactionError(DatabaseException):
    """
    Exception for database transaction failures.
    
    Handles transaction timeout, deadlock, rollback failures,
    and other transaction-specific error scenarios.
    """
    
    def __init__(
        self,
        message: str,
        transaction_id: Optional[str] = None,
        session_info: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        """
        Initialize transaction error with transaction context.
        
        Args:
            message: Error description
            transaction_id: Transaction identifier if available
            session_info: Session details for transaction context
            **kwargs: Additional context from DatabaseException
        """
        super().__init__(message, **kwargs)
        self.transaction_id = transaction_id
        self.session_info = session_info or {}


class DatabaseTimeoutError(DatabaseException):
    """
    Exception for database operation timeouts.
    
    Handles connection timeouts, query execution timeouts,
    and network timeout scenarios with retry coordination.
    """
    
    def __init__(
        self,
        message: str,
        timeout_duration: Optional[float] = None,
        **kwargs
    ):
        """
        Initialize timeout error with timing context.
        
        Args:
            message: Error description
            timeout_duration: Timeout value that was exceeded
            **kwargs: Additional context from DatabaseException
        """
        super().__init__(message, **kwargs)
        self.timeout_duration = timeout_duration


class DatabaseValidationError(DatabaseException):
    """
    Exception for database document validation failures.
    
    Handles schema validation errors, constraint violations,
    and data integrity issues during document operations.
    """
    
    def __init__(
        self,
        message: str,
        validation_errors: Optional[List[str]] = None,
        document: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        """
        Initialize validation error with validation context.
        
        Args:
            message: Error description
            validation_errors: List of specific validation failures
            document: Document that failed validation (sanitized)
            **kwargs: Additional context from DatabaseException
        """
        super().__init__(message, **kwargs)
        self.validation_errors = validation_errors or []
        self.document = document


# Circuit breaker configuration for database operations
_circuit_breakers: Dict[str, CircuitBreaker] = {}


def get_circuit_breaker(
    operation: str,
    database: str = 'default',
    failure_threshold: int = 5,
    recovery_timeout: int = 30,
    expected_exception: Type[Exception] = DatabaseException
) -> CircuitBreaker:
    """
    Get or create a circuit breaker for database operations.
    
    Implements circuit breaker pattern per Section 6.2.3 fault tolerance
    requirements with configurable thresholds and recovery patterns.
    
    Args:
        operation: Database operation name (e.g., 'find', 'insert')
        database: Database name for circuit breaker scoping
        failure_threshold: Number of failures before opening circuit
        recovery_timeout: Seconds to wait before attempting recovery
        expected_exception: Exception type that triggers circuit breaker
        
    Returns:
        CircuitBreaker instance for the specified operation
    """
    breaker_key = f"{database}:{operation}"
    
    if breaker_key not in _circuit_breakers:
        def state_change_listener(breaker, old_state, new_state):
            """Monitor circuit breaker state changes for metrics."""
            state_value = {
                CircuitBreakerState.CLOSED: 0,
                CircuitBreakerState.OPEN: 1,
                CircuitBreakerState.HALF_OPEN: 2
            }.get(new_state, -1)
            
            circuit_breaker_state.labels(
                database=database,
                operation=operation
            ).set(state_value)
            
            logger.info(
                "Circuit breaker state changed",
                operation=operation,
                database=database,
                old_state=old_state.name,
                new_state=new_state.name,
                failure_threshold=failure_threshold,
                recovery_timeout=recovery_timeout
            )
        
        _circuit_breakers[breaker_key] = CircuitBreaker(
            failure_threshold=failure_threshold,
            recovery_timeout=recovery_timeout,
            expected_exception=expected_exception,
            listeners=[state_change_listener]
        )
    
    return _circuit_breakers[breaker_key]


def create_retry_strategy(
    max_attempts: int = 3,
    min_wait: float = 1.0,
    max_wait: float = 10.0,
    exponential_base: int = 2,
    jitter: bool = True
):
    """
    Create retry strategy with exponential backoff.
    
    Implements Tenacity exponential backoff per Section 4.2.3 error handling
    requirements with configurable timing and jitter for collision avoidance.
    
    Args:
        max_attempts: Maximum number of retry attempts
        min_wait: Minimum wait time between retries (seconds)
        max_wait: Maximum wait time between retries (seconds)
        exponential_base: Base for exponential backoff calculation
        jitter: Whether to add randomization to wait times
        
    Returns:
        Configured Retrying instance for database operations
    """
    wait_strategy = (
        wait_random_exponential(multiplier=min_wait, max=max_wait)
        if jitter
        else wait_exponential(multiplier=min_wait, max=max_wait, exp_base=exponential_base)
    )
    
    return Retrying(
        stop=stop_after_attempt(max_attempts),
        wait=wait_strategy,
        retry=retry_if_exception_type((
            pymongo_errors.ConnectionFailure,
            pymongo_errors.ServerSelectionTimeoutError,
            pymongo_errors.NetworkTimeout,
            pymongo_errors.AutoReconnect,
            DatabaseConnectionError,
            DatabaseTimeoutError
        )),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        after=after_log(logger, logging.INFO),
        reraise=True
    )


def with_database_retry(
    max_attempts: int = 3,
    min_wait: float = 1.0,
    max_wait: float = 10.0,
    circuit_breaker: bool = True,
    operation_name: Optional[str] = None
):
    """
    Decorator for database operations with retry logic and circuit breaker.
    
    Combines retry strategy with circuit breaker pattern for comprehensive
    fault tolerance per Section 4.2.3 and Section 6.2.3 requirements.
    
    Args:
        max_attempts: Maximum retry attempts
        min_wait: Minimum wait time between retries
        max_wait: Maximum wait time between retries
        circuit_breaker: Whether to enable circuit breaker protection
        operation_name: Operation name for monitoring (inferred if None)
        
    Returns:
        Decorated function with retry and circuit breaker protection
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Extract operation context for monitoring
            op_name = operation_name or func.__name__
            database_name = kwargs.get('database', 'unknown')
            collection_name = kwargs.get('collection', 'unknown')
            
            # Get circuit breaker if enabled
            breaker = (
                get_circuit_breaker(op_name, database_name)
                if circuit_breaker
                else None
            )
            
            # Create retry strategy
            retry_strategy = create_retry_strategy(
                max_attempts=max_attempts,
                min_wait=min_wait,
                max_wait=max_wait
            )
            
            start_time = time.time()
            retry_count = 0
            last_exception = None
            
            try:
                # Execute with circuit breaker protection
                if breaker:
                    def protected_operation():
                        return retry_strategy(func, *args, **kwargs)
                    return breaker(protected_operation)
                else:
                    return retry_strategy(func, *args, **kwargs)
                    
            except RetryError as e:
                # Handle retry exhaustion
                retry_count = max_attempts
                last_exception = e.last_attempt.exception()
                
                # Convert to appropriate database exception
                db_error = _convert_to_database_exception(
                    last_exception,
                    operation=op_name,
                    database=database_name,
                    collection=collection_name,
                    retry_count=retry_count
                )
                
                # Record operation failure metrics
                database_operation_duration.labels(
                    operation=op_name,
                    database=database_name,
                    collection=collection_name,
                    status='failure'
                ).observe(time.time() - start_time)
                
                raise db_error
                
            except Exception as e:
                # Handle unexpected errors
                last_exception = e
                
                db_error = _convert_to_database_exception(
                    e,
                    operation=op_name,
                    database=database_name,
                    collection=collection_name,
                    retry_count=retry_count
                )
                
                # Record operation failure metrics
                database_operation_duration.labels(
                    operation=op_name,
                    database=database_name,
                    collection=collection_name,
                    status='failure'
                ).observe(time.time() - start_time)
                
                raise db_error
                
            else:
                # Record successful operation metrics
                database_operation_duration.labels(
                    operation=op_name,
                    database=database_name,
                    collection=collection_name,
                    status='success'
                ).observe(time.time() - start_time)
        
        return wrapper
    return decorator


@contextmanager
def database_error_context(
    operation: str,
    database: str = 'unknown',
    collection: str = 'unknown'
):
    """
    Context manager for database operations with automatic error handling.
    
    Provides standardized error handling context for database operations
    with proper exception conversion and metrics emission.
    
    Args:
        operation: Database operation being performed
        database: Database name
        collection: Collection name
        
    Yields:
        Context for database operation execution
        
    Raises:
        DatabaseException: Converted database-specific exception
    """
    start_time = time.time()
    
    try:
        logger.debug(
            "Starting database operation",
            operation=operation,
            database=database,
            collection=collection
        )
        
        yield
        
        # Record successful operation
        database_operation_duration.labels(
            operation=operation,
            database=database,
            collection=collection,
            status='success'
        ).observe(time.time() - start_time)
        
        logger.debug(
            "Database operation completed successfully",
            operation=operation,
            database=database,
            collection=collection,
            duration=time.time() - start_time
        )
        
    except Exception as e:
        # Convert and re-raise as database exception
        db_error = _convert_to_database_exception(
            e,
            operation=operation,
            database=database,
            collection=collection
        )
        
        # Record failed operation
        database_operation_duration.labels(
            operation=operation,
            database=database,
            collection=collection,
            status='failure'
        ).observe(time.time() - start_time)
        
        raise db_error


def _convert_to_database_exception(
    exception: Exception,
    operation: str = 'unknown',
    database: str = 'unknown',
    collection: str = 'unknown',
    retry_count: int = 0
) -> DatabaseException:
    """
    Convert PyMongo/Motor exceptions to appropriate database exceptions.
    
    Maps PyMongo and Motor specific exceptions to custom database exception
    types for consistent error handling and monitoring integration.
    
    Args:
        exception: Original exception to convert
        operation: Database operation context
        database: Database name context
        collection: Collection name context
        retry_count: Number of retries attempted
        
    Returns:
        Appropriate DatabaseException subclass
    """
    error_message = str(exception)
    
    # Connection-related errors
    if isinstance(exception, (
        pymongo_errors.ConnectionFailure,
        pymongo_errors.ServerSelectionTimeoutError,
        pymongo_errors.AutoReconnect,
        pymongo_errors.NetworkTimeout
    )):
        return DatabaseConnectionError(
            message=f"Database connection failed: {error_message}",
            operation=operation,
            database=database,
            collection=collection,
            original_error=exception,
            retry_count=retry_count
        )
    
    # Timeout-related errors
    if isinstance(exception, (
        pymongo_errors.ExecutionTimeout,
        pymongo_errors.WTimeoutError
    )):
        return DatabaseTimeoutError(
            message=f"Database operation timed out: {error_message}",
            operation=operation,
            database=database,
            collection=collection,
            original_error=exception,
            retry_count=retry_count
        )
    
    # Transaction-related errors
    if isinstance(exception, (
        pymongo_errors.OperationFailure,
    )) and 'transaction' in error_message.lower():
        return DatabaseTransactionError(
            message=f"Database transaction failed: {error_message}",
            operation=operation,
            database=database,
            collection=collection,
            original_error=exception,
            retry_count=retry_count
        )
    
    # Validation and schema errors
    if isinstance(exception, (
        pymongo_errors.DocumentTooLarge,
        pymongo_errors.DuplicateKeyError,
        pymongo_errors.WriteError
    )):
        return DatabaseValidationError(
            message=f"Database validation failed: {error_message}",
            operation=operation,
            database=database,
            collection=collection,
            original_error=exception,
            retry_count=retry_count
        )
    
    # Query-related errors
    if isinstance(exception, (
        pymongo_errors.OperationFailure,
        pymongo_errors.InvalidOperation,
        pymongo_errors.CursorNotFound
    )):
        return DatabaseQueryError(
            message=f"Database query failed: {error_message}",
            operation=operation,
            database=database,
            collection=collection,
            original_error=exception,
            retry_count=retry_count
        )
    
    # Generic database exception for unknown errors
    return DatabaseException(
        message=f"Database operation failed: {error_message}",
        operation=operation,
        database=database,
        collection=collection,
        original_error=exception,
        retry_count=retry_count
    )


def reset_circuit_breakers() -> None:
    """
    Reset all circuit breakers to closed state.
    
    Utility function for testing and recovery scenarios where
    circuit breakers need to be manually reset.
    """
    for breaker_key, breaker in _circuit_breakers.items():
        breaker.close()
        logger.info(
            "Circuit breaker reset",
            breaker_key=breaker_key,
            state="closed"
        )


def get_circuit_breaker_status() -> Dict[str, Dict[str, Any]]:
    """
    Get status information for all circuit breakers.
    
    Returns:
        Dictionary mapping breaker keys to status information
    """
    status = {}
    
    for breaker_key, breaker in _circuit_breakers.items():
        status[breaker_key] = {
            'state': breaker.current_state.name,
            'failure_count': breaker.fail_counter,
            'failure_threshold': breaker.failure_threshold,
            'recovery_timeout': breaker.recovery_timeout,
            'last_failure_time': getattr(breaker, '_last_failure_time', None)
        }
    
    return status


# Export public interface
__all__ = [
    # Exception classes
    'DatabaseException',
    'DatabaseConnectionError',
    'DatabaseQueryError',
    'DatabaseTransactionError',
    'DatabaseTimeoutError',
    'DatabaseValidationError',
    
    # Retry and circuit breaker utilities
    'with_database_retry',
    'database_error_context',
    'get_circuit_breaker',
    'create_retry_strategy',
    
    # Management utilities
    'reset_circuit_breakers',
    'get_circuit_breaker_status',
    
    # Prometheus metrics (for external monitoring integration)
    'database_errors_total',
    'database_operation_duration',
    'database_retries_total',
    'circuit_breaker_state',
    'database_connection_failures'
]