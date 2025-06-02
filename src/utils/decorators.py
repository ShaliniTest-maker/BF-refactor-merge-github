"""
General-purpose decorators providing cross-cutting functionality including timing decorators,
caching decorators, logging decorators, and validation decorators.

This module implements reusable decorator patterns with comprehensive type hints and 
enterprise-grade functionality support as specified in Section 5.4.1 cross-cutting concerns
and Section 5.4.4 performance requirements.

Key Features:
- Performance measurement decorators supporting ≤10% variance monitoring
- Caching decorators with Redis integration for performance optimization
- Logging decorators with structured logging for enterprise observability
- Validation decorators supporting marshmallow and pydantic schemas
- Circuit breaker integration for resilience patterns
- Prometheus metrics collection for monitoring integration
- Comprehensive error handling with custom exception support
"""

import asyncio
import functools
import time
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Type, TypeVar, Union
from uuid import uuid4

import structlog
from flask import current_app, g, request
from marshmallow import Schema, ValidationError as MarshmallowValidationError
from prometheus_client import Counter, Histogram, Summary
from pydantic import BaseModel, ValidationError as PydanticValidationError

try:
    import redis
    from redis import Redis
except ImportError:
    # Fallback for testing environments without Redis
    redis = None
    Redis = None

# Import application-specific exceptions
from src.utils.exceptions import (
    BaseApplicationError,
    CircuitBreakerError,
    ExternalServiceError,
    PerformanceError,
    ValidationError
)

# Type variables for generic decorator support
F = TypeVar('F', bound=Callable[..., Any])
T = TypeVar('T')

# Get structured logger
logger = structlog.get_logger(__name__)

# Prometheus metrics for decorator performance tracking
decorator_execution_time = Histogram(
    'decorator_execution_seconds',
    'Time spent in decorator execution',
    ['decorator_type', 'function_name', 'status']
)

decorator_call_counter = Counter(
    'decorator_calls_total',
    'Total number of decorator calls',
    ['decorator_type', 'function_name', 'status']
)

performance_variance_gauge = Summary(
    'performance_variance_ratio',
    'Performance variance ratio from baseline',
    ['function_name', 'measurement_type']
)

cache_operation_time = Histogram(
    'cache_operation_seconds',
    'Time spent in cache operations',
    ['operation_type', 'cache_key_pattern', 'status']
)

validation_time = Histogram(
    'validation_execution_seconds',
    'Time spent in validation operations',
    ['validation_type', 'schema_name', 'status']
)


class PerformanceBaseline:
    """
    Performance baseline tracking for ≤10% variance compliance.
    
    Implements performance measurement and comparison against Node.js baseline
    as specified in Section 5.4.4 performance requirements.
    """
    
    _baselines: Dict[str, Dict[str, float]] = {}
    _measurements: Dict[str, List[float]] = {}
    
    @classmethod
    def set_baseline(cls, function_name: str, baseline_time: float) -> None:
        """Set performance baseline for a function."""
        if function_name not in cls._baselines:
            cls._baselines[function_name] = {}
        cls._baselines[function_name]['time'] = baseline_time
        logger.info(
            "Performance baseline set",
            function=function_name,
            baseline_time=baseline_time
        )
    
    @classmethod
    def record_measurement(cls, function_name: str, execution_time: float) -> float:
        """Record measurement and calculate variance from baseline."""
        if function_name not in cls._measurements:
            cls._measurements[function_name] = []
        
        cls._measurements[function_name].append(execution_time)
        
        # Keep only last 100 measurements
        if len(cls._measurements[function_name]) > 100:
            cls._measurements[function_name] = cls._measurements[function_name][-100:]
        
        # Calculate variance if baseline exists
        if function_name in cls._baselines:
            baseline = cls._baselines[function_name]['time']
            variance_ratio = (execution_time - baseline) / baseline
            
            # Update Prometheus metrics
            performance_variance_gauge.labels(
                function_name=function_name,
                measurement_type='execution_time'
            ).observe(variance_ratio)
            
            # Alert if variance exceeds 10%
            if variance_ratio > 0.10:
                logger.warning(
                    "Performance variance exceeded threshold",
                    function=function_name,
                    execution_time=execution_time,
                    baseline_time=baseline,
                    variance_ratio=variance_ratio,
                    threshold=0.10
                )
            
            return variance_ratio
        
        return 0.0


def timing(
    baseline: Optional[float] = None,
    alert_threshold: float = 0.10,
    include_args: bool = False,
    metrics_labels: Optional[Dict[str, str]] = None
) -> Callable[[F], F]:
    """
    Decorator for measuring function execution time and performance variance.
    
    Implements performance measurement decorators supporting ≤10% variance monitoring
    per Section 5.4.4 performance requirements.
    
    Args:
        baseline: Expected baseline execution time in seconds
        alert_threshold: Variance threshold for performance alerts (default: 10%)
        include_args: Whether to include function arguments in logging
        metrics_labels: Additional labels for Prometheus metrics
    
    Returns:
        Decorated function with timing capabilities
    
    Example:
        @timing(baseline=0.1, alert_threshold=0.10)
        def process_data(data):
            # Function implementation
            pass
    """
    def decorator(func: F) -> F:
        function_name = f"{func.__module__}.{func.__qualname__}"
        
        # Set baseline if provided
        if baseline is not None:
            PerformanceBaseline.set_baseline(function_name, baseline)
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.perf_counter()
            correlation_id = getattr(g, 'correlation_id', str(uuid4()))
            status = 'success'
            
            try:
                # Log function entry
                log_data = {
                    'function': function_name,
                    'correlation_id': correlation_id,
                    'action': 'function_start'
                }
                
                if include_args:
                    log_data['args'] = str(args)[:200]  # Truncate for security
                    log_data['kwargs'] = {k: str(v)[:100] for k, v in kwargs.items()}
                
                logger.debug("Function execution started", **log_data)
                
                # Execute function
                result = func(*args, **kwargs)
                
                return result
                
            except Exception as e:
                status = 'error'
                logger.error(
                    "Function execution failed",
                    function=function_name,
                    correlation_id=correlation_id,
                    error=str(e),
                    exception_type=e.__class__.__name__
                )
                raise
                
            finally:
                # Measure execution time
                end_time = time.perf_counter()
                execution_time = end_time - start_time
                
                # Record measurement and check variance
                variance_ratio = PerformanceBaseline.record_measurement(
                    function_name, execution_time
                )
                
                # Update Prometheus metrics
                labels = {
                    'function_name': function_name,
                    'status': status
                }
                if metrics_labels:
                    labels.update(metrics_labels)
                
                decorator_execution_time.labels(
                    decorator_type='timing',
                    **labels
                ).observe(execution_time)
                
                decorator_call_counter.labels(
                    decorator_type='timing',
                    **labels
                ).inc()
                
                # Log execution completion
                logger.info(
                    "Function execution completed",
                    function=function_name,
                    correlation_id=correlation_id,
                    execution_time=execution_time,
                    variance_ratio=variance_ratio,
                    status=status
                )
        
        return wrapper
    return decorator


def cache(
    ttl: int = 300,
    key_prefix: Optional[str] = None,
    cache_null_values: bool = False,
    ignore_exceptions: bool = True,
    redis_client: Optional[Redis] = None
) -> Callable[[F], F]:
    """
    Decorator for Redis-based function result caching.
    
    Implements caching decorators with Redis integration for performance optimization
    per Section 5.4.4 cache strategy.
    
    Args:
        ttl: Time-to-live in seconds for cached values
        key_prefix: Optional prefix for cache keys
        cache_null_values: Whether to cache None/null return values
        ignore_exceptions: Whether to ignore cache failures and execute function
        redis_client: Optional Redis client instance
    
    Returns:
        Decorated function with caching capabilities
    
    Example:
        @cache(ttl=600, key_prefix="user_data")
        def get_user_data(user_id):
            # Expensive database operation
            return user_data
    """
    def decorator(func: F) -> F:
        function_name = f"{func.__module__}.{func.__qualname__}"
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Skip caching if Redis is not available
            if redis is None or not hasattr(current_app, 'redis'):
                logger.warning(
                    "Redis not available, executing function without caching",
                    function=function_name
                )
                return func(*args, **kwargs)
            
            # Get Redis client
            client = redis_client or getattr(current_app, 'redis', None)
            if not client:
                if ignore_exceptions:
                    return func(*args, **kwargs)
                raise ExternalServiceError(
                    "Redis client not available",
                    service_name="redis"
                )
            
            # Generate cache key
            cache_key = _generate_cache_key(
                function_name, args, kwargs, key_prefix
            )
            
            correlation_id = getattr(g, 'correlation_id', str(uuid4()))
            
            try:
                # Try to get from cache
                start_time = time.perf_counter()
                cached_value = client.get(cache_key)
                cache_get_time = time.perf_counter() - start_time
                
                # Update cache operation metrics
                cache_operation_time.labels(
                    operation_type='get',
                    cache_key_pattern=_get_key_pattern(cache_key),
                    status='success'
                ).observe(cache_get_time)
                
                if cached_value is not None:
                    # Cache hit
                    import pickle
                    result = pickle.loads(cached_value)
                    
                    logger.debug(
                        "Cache hit",
                        function=function_name,
                        cache_key=cache_key,
                        correlation_id=correlation_id,
                        cache_get_time=cache_get_time
                    )
                    
                    return result
                
                # Cache miss - execute function
                logger.debug(
                    "Cache miss",
                    function=function_name,
                    cache_key=cache_key,
                    correlation_id=correlation_id
                )
                
            except Exception as e:
                # Cache get failed
                cache_operation_time.labels(
                    operation_type='get',
                    cache_key_pattern=_get_key_pattern(cache_key),
                    status='error'
                ).observe(0)
                
                logger.warning(
                    "Cache get failed",
                    function=function_name,
                    cache_key=cache_key,
                    error=str(e),
                    correlation_id=correlation_id
                )
                
                if not ignore_exceptions:
                    raise ExternalServiceError(
                        "Cache operation failed",
                        service_name="redis",
                        details={'operation': 'get', 'error': str(e)}
                    )
            
            # Execute original function
            result = func(*args, **kwargs)
            
            # Cache the result if appropriate
            if result is not None or cache_null_values:
                try:
                    import pickle
                    start_time = time.perf_counter()
                    serialized_result = pickle.dumps(result)
                    client.setex(cache_key, ttl, serialized_result)
                    cache_set_time = time.perf_counter() - start_time
                    
                    # Update cache operation metrics
                    cache_operation_time.labels(
                        operation_type='set',
                        cache_key_pattern=_get_key_pattern(cache_key),
                        status='success'
                    ).observe(cache_set_time)
                    
                    logger.debug(
                        "Result cached",
                        function=function_name,
                        cache_key=cache_key,
                        ttl=ttl,
                        correlation_id=correlation_id,
                        cache_set_time=cache_set_time
                    )
                    
                except Exception as e:
                    # Cache set failed
                    cache_operation_time.labels(
                        operation_type='set',
                        cache_key_pattern=_get_key_pattern(cache_key),
                        status='error'
                    ).observe(0)
                    
                    logger.warning(
                        "Cache set failed",
                        function=function_name,
                        cache_key=cache_key,
                        error=str(e),
                        correlation_id=correlation_id
                    )
                    
                    if not ignore_exceptions:
                        raise ExternalServiceError(
                            "Cache operation failed",
                            service_name="redis",
                            details={'operation': 'set', 'error': str(e)}
                        )
            
            return result
        
        return wrapper
    return decorator


def logged(
    level: str = 'info',
    include_args: bool = False,
    include_result: bool = False,
    exclude_fields: Optional[List[str]] = None,
    mask_fields: Optional[List[str]] = None
) -> Callable[[F], F]:
    """
    Decorator for structured logging with enterprise observability.
    
    Implements logging decorators with structlog integration per Section 5.4.1
    structured logging strategy.
    
    Args:
        level: Logging level ('debug', 'info', 'warning', 'error')
        include_args: Whether to include function arguments in logs
        include_result: Whether to include function result in logs
        exclude_fields: Fields to exclude from logging
        mask_fields: Fields to mask for security (replace with '***')
    
    Returns:
        Decorated function with structured logging
    
    Example:
        @logged(level='info', include_args=True, mask_fields=['password'])
        def authenticate_user(username, password):
            # Authentication logic
            return user_data
    """
    def decorator(func: F) -> F:
        function_name = f"{func.__module__}.{func.__qualname__}"
        exclude_fields = exclude_fields or []
        mask_fields = mask_fields or ['password', 'token', 'secret', 'key']
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            correlation_id = getattr(g, 'correlation_id', str(uuid4()))
            start_time = time.perf_counter()
            
            # Prepare log data
            log_data = {
                'function': function_name,
                'correlation_id': correlation_id,
                'timestamp': datetime.utcnow().isoformat(),
                'endpoint': getattr(request, 'endpoint', None) if request else None,
                'method': getattr(request, 'method', None) if request else None,
                'user_id': getattr(g, 'user_id', None) if hasattr(g, 'user_id') else None
            }
            
            # Include arguments if requested
            if include_args:
                # Safely process arguments with masking
                safe_args = []
                for arg in args:
                    safe_args.append(_mask_sensitive_data(arg, mask_fields))
                
                safe_kwargs = {}
                for key, value in kwargs.items():
                    if key not in exclude_fields:
                        safe_kwargs[key] = _mask_sensitive_data(value, mask_fields)
                
                log_data['args'] = safe_args
                log_data['kwargs'] = safe_kwargs
            
            # Log function entry
            getattr(logger, level.lower())(
                f"Function {function_name} started",
                **log_data
            )
            
            try:
                # Execute function
                result = func(*args, **kwargs)
                
                # Calculate execution time
                execution_time = time.perf_counter() - start_time
                
                # Prepare success log data
                success_log_data = {
                    **log_data,
                    'execution_time': execution_time,
                    'status': 'success'
                }
                
                # Include result if requested
                if include_result and result is not None:
                    success_log_data['result'] = _mask_sensitive_data(
                        result, mask_fields
                    )
                
                # Log successful completion
                getattr(logger, level.lower())(
                    f"Function {function_name} completed successfully",
                    **success_log_data
                )
                
                return result
                
            except Exception as e:
                # Calculate execution time for failed calls
                execution_time = time.perf_counter() - start_time
                
                # Log error
                error_log_data = {
                    **log_data,
                    'execution_time': execution_time,
                    'status': 'error',
                    'error': str(e),
                    'exception_type': e.__class__.__name__
                }
                
                logger.error(
                    f"Function {function_name} failed",
                    **error_log_data
                )
                
                # Re-raise the exception
                raise
        
        return wrapper
    return decorator


def validate_input(
    schema: Union[Type[Schema], Type[BaseModel], Schema, BaseModel],
    validate_json: bool = True,
    validate_args: bool = False,
    location: str = 'json'
) -> Callable[[F], F]:
    """
    Decorator for input validation using marshmallow or pydantic schemas.
    
    Implements validation decorators supporting marshmallow and pydantic
    per Section 3.2.3 validation requirements.
    
    Args:
        schema: Marshmallow schema class/instance or Pydantic model class
        validate_json: Whether to validate JSON request body
        validate_args: Whether to validate function arguments
        location: Location of data to validate ('json', 'args', 'form')
    
    Returns:
        Decorated function with input validation
    
    Example:
        @validate_input(UserSchema, validate_json=True)
        def create_user():
            # Function receives validated data in g.validated_data
            user_data = g.validated_data
            return create_user_in_db(user_data)
    """
    def decorator(func: F) -> F:
        function_name = f"{func.__module__}.{func.__qualname__}"
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            correlation_id = getattr(g, 'correlation_id', str(uuid4()))
            
            try:
                start_time = time.perf_counter()
                
                # Determine validation data source
                if validate_json and request and request.is_json:
                    data_to_validate = request.get_json()
                elif location == 'form' and request:
                    data_to_validate = request.form.to_dict()
                elif validate_args:
                    # Validate function arguments
                    # Combine args and kwargs into a dictionary
                    import inspect
                    sig = inspect.signature(func)
                    bound_args = sig.bind(*args, **kwargs)
                    bound_args.apply_defaults()
                    data_to_validate = dict(bound_args.arguments)
                else:
                    data_to_validate = {}
                
                # Perform validation based on schema type
                if isinstance(schema, type) and issubclass(schema, BaseModel):
                    # Pydantic validation
                    try:
                        validated_data = schema(**data_to_validate)
                        # Convert to dict for consistent handling
                        g.validated_data = validated_data.dict()
                    except PydanticValidationError as e:
                        validation_time.labels(
                            validation_type='pydantic',
                            schema_name=schema.__name__,
                            status='error'
                        ).observe(time.perf_counter() - start_time)
                        
                        # Convert pydantic errors to our format
                        field_errors = {}
                        for error in e.errors():
                            field_name = '.'.join(str(loc) for loc in error['loc'])
                            if field_name not in field_errors:
                                field_errors[field_name] = []
                            field_errors[field_name].append(error['msg'])
                        
                        raise ValidationError(
                            message="Input validation failed",
                            field_errors=field_errors,
                            correlation_id=correlation_id
                        )
                
                elif isinstance(schema, (type, Schema)) and (
                    isinstance(schema, Schema) or issubclass(schema, Schema)
                ):
                    # Marshmallow validation
                    try:
                        schema_instance = schema if isinstance(schema, Schema) else schema()
                        validated_data = schema_instance.load(data_to_validate)
                        g.validated_data = validated_data
                    except MarshmallowValidationError as e:
                        validation_time.labels(
                            validation_type='marshmallow',
                            schema_name=schema.__class__.__name__,
                            status='error'
                        ).observe(time.perf_counter() - start_time)
                        
                        raise ValidationError(
                            message="Input validation failed",
                            field_errors=e.messages,
                            correlation_id=correlation_id
                        )
                
                else:
                    raise ValueError(f"Unsupported schema type: {type(schema)}")
                
                # Record successful validation
                validation_time.labels(
                    validation_type='pydantic' if issubclass(schema, BaseModel) else 'marshmallow',
                    schema_name=schema.__name__ if hasattr(schema, '__name__') else schema.__class__.__name__,
                    status='success'
                ).observe(time.perf_counter() - start_time)
                
                logger.debug(
                    "Input validation successful",
                    function=function_name,
                    schema_name=schema.__name__ if hasattr(schema, '__name__') else schema.__class__.__name__,
                    correlation_id=correlation_id,
                    validation_time=time.perf_counter() - start_time
                )
                
                # Execute function with validated data
                return func(*args, **kwargs)
                
            except ValidationError:
                # Re-raise validation errors
                raise
            except Exception as e:
                # Handle unexpected validation errors
                logger.error(
                    "Validation decorator error",
                    function=function_name,
                    error=str(e),
                    correlation_id=correlation_id
                )
                raise ValidationError(
                    message="Validation processing failed",
                    details={'error': str(e)},
                    correlation_id=correlation_id
                )
        
        return wrapper
    return decorator


def circuit_breaker(
    failure_threshold: int = 5,
    recovery_timeout: int = 60,
    expected_exception: Type[Exception] = Exception
) -> Callable[[F], F]:
    """
    Circuit breaker decorator for external service protection.
    
    Implements circuit breaker patterns per Section 5.4.2 error recovery mechanisms.
    
    Args:
        failure_threshold: Number of failures before opening circuit
        recovery_timeout: Time in seconds before attempting recovery
        expected_exception: Exception type that triggers circuit breaker
    
    Returns:
        Decorated function with circuit breaker protection
    
    Example:
        @circuit_breaker(failure_threshold=3, recovery_timeout=30)
        def call_external_api():
            # External service call
            return api_response
    """
    def decorator(func: F) -> F:
        function_name = f"{func.__module__}.{func.__qualname__}"
        
        # Circuit breaker state
        state = {
            'failure_count': 0,
            'last_failure_time': None,
            'state': 'closed'  # closed, open, half_open
        }
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            correlation_id = getattr(g, 'correlation_id', str(uuid4()))
            current_time = time.time()
            
            # Check circuit state
            if state['state'] == 'open':
                # Check if recovery timeout has passed
                if (current_time - state['last_failure_time']) >= recovery_timeout:
                    state['state'] = 'half_open'
                    logger.info(
                        "Circuit breaker attempting recovery",
                        function=function_name,
                        correlation_id=correlation_id,
                        failure_count=state['failure_count']
                    )
                else:
                    # Circuit is still open
                    raise CircuitBreakerError(
                        message=f"Circuit breaker is open for {function_name}",
                        service_name=function_name,
                        circuit_state='open',
                        correlation_id=correlation_id
                    )
            
            try:
                # Execute function
                result = func(*args, **kwargs)
                
                # Success - reset circuit breaker if it was half_open
                if state['state'] == 'half_open':
                    state['state'] = 'closed'
                    state['failure_count'] = 0
                    state['last_failure_time'] = None
                    
                    logger.info(
                        "Circuit breaker recovered",
                        function=function_name,
                        correlation_id=correlation_id
                    )
                
                return result
                
            except expected_exception as e:
                # Handle expected failures
                state['failure_count'] += 1
                state['last_failure_time'] = current_time
                
                # Check if we should open the circuit
                if state['failure_count'] >= failure_threshold:
                    state['state'] = 'open'
                    
                    logger.error(
                        "Circuit breaker opened",
                        function=function_name,
                        correlation_id=correlation_id,
                        failure_count=state['failure_count'],
                        threshold=failure_threshold,
                        error=str(e)
                    )
                    
                    raise CircuitBreakerError(
                        message=f"Circuit breaker opened for {function_name}",
                        service_name=function_name,
                        circuit_state='open',
                        correlation_id=correlation_id,
                        details={'original_error': str(e)}
                    )
                else:
                    logger.warning(
                        "Circuit breaker failure recorded",
                        function=function_name,
                        correlation_id=correlation_id,
                        failure_count=state['failure_count'],
                        threshold=failure_threshold,
                        error=str(e)
                    )
                    
                    # Re-raise original exception
                    raise
        
        return wrapper
    return decorator


def retry(
    max_attempts: int = 3,
    delay: float = 1.0,
    backoff_factor: float = 2.0,
    exceptions: tuple = (Exception,)
) -> Callable[[F], F]:
    """
    Retry decorator with exponential backoff.
    
    Implements retry logic for transient failures per Section 5.4.2
    error recovery mechanisms.
    
    Args:
        max_attempts: Maximum number of retry attempts
        delay: Initial delay between retries in seconds
        backoff_factor: Multiplier for exponential backoff
        exceptions: Tuple of exception types to retry on
    
    Returns:
        Decorated function with retry capabilities
    
    Example:
        @retry(max_attempts=3, delay=1.0, backoff_factor=2.0)
        def unstable_external_call():
            # Call that might fail transiently
            return response
    """
    def decorator(func: F) -> F:
        function_name = f"{func.__module__}.{func.__qualname__}"
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            correlation_id = getattr(g, 'correlation_id', str(uuid4()))
            last_exception = None
            
            for attempt in range(max_attempts):
                try:
                    # Log retry attempt
                    if attempt > 0:
                        logger.info(
                            "Retrying function call",
                            function=function_name,
                            attempt=attempt + 1,
                            max_attempts=max_attempts,
                            correlation_id=correlation_id
                        )
                    
                    # Execute function
                    result = func(*args, **kwargs)
                    
                    # Success
                    if attempt > 0:
                        logger.info(
                            "Function retry successful",
                            function=function_name,
                            successful_attempt=attempt + 1,
                            correlation_id=correlation_id
                        )
                    
                    return result
                    
                except exceptions as e:
                    last_exception = e
                    
                    if attempt < max_attempts - 1:
                        # Calculate delay with exponential backoff
                        current_delay = delay * (backoff_factor ** attempt)
                        
                        logger.warning(
                            "Function call failed, will retry",
                            function=function_name,
                            attempt=attempt + 1,
                            max_attempts=max_attempts,
                            error=str(e),
                            retry_delay=current_delay,
                            correlation_id=correlation_id
                        )
                        
                        time.sleep(current_delay)
                    else:
                        # Final attempt failed
                        logger.error(
                            "Function retry exhausted",
                            function=function_name,
                            total_attempts=max_attempts,
                            final_error=str(e),
                            correlation_id=correlation_id
                        )
                
                except Exception as e:
                    # Non-retryable exception
                    logger.error(
                        "Non-retryable exception in function",
                        function=function_name,
                        attempt=attempt + 1,
                        error=str(e),
                        exception_type=e.__class__.__name__,
                        correlation_id=correlation_id
                    )
                    raise
            
            # All retries exhausted
            if last_exception:
                raise last_exception
        
        return wrapper
    return decorator


# Helper functions

def _generate_cache_key(
    function_name: str,
    args: tuple,
    kwargs: dict,
    prefix: Optional[str] = None
) -> str:
    """Generate cache key from function name and arguments."""
    import hashlib
    import json
    
    # Create a deterministic representation of arguments
    key_data = {
        'function': function_name,
        'args': [str(arg) for arg in args],
        'kwargs': {k: str(v) for k, v in sorted(kwargs.items())}
    }
    
    # Generate hash
    key_string = json.dumps(key_data, sort_keys=True)
    key_hash = hashlib.sha256(key_string.encode('utf-8')).hexdigest()[:16]
    
    # Add prefix if provided
    if prefix:
        return f"{prefix}:{function_name}:{key_hash}"
    else:
        return f"cache:{function_name}:{key_hash}"


def _get_key_pattern(cache_key: str) -> str:
    """Extract pattern from cache key for metrics labeling."""
    parts = cache_key.split(':')
    if len(parts) >= 2:
        return ':'.join(parts[:-1]) + ':*'
    return cache_key


def _mask_sensitive_data(data: Any, mask_fields: List[str]) -> Any:
    """Mask sensitive fields in data for logging."""
    if isinstance(data, dict):
        masked_data = {}
        for key, value in data.items():
            if any(field.lower() in key.lower() for field in mask_fields):
                masked_data[key] = '***'
            else:
                masked_data[key] = _mask_sensitive_data(value, mask_fields)
        return masked_data
    elif isinstance(data, (list, tuple)):
        return [_mask_sensitive_data(item, mask_fields) for item in data]
    elif isinstance(data, str) and len(data) > 100:
        # Truncate long strings
        return data[:100] + '...'
    else:
        return data


# Export decorator functions
__all__ = [
    'timing',
    'cache',
    'logged',
    'validate_input',
    'circuit_breaker',
    'retry',
    'PerformanceBaseline'
]