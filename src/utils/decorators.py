"""
General-purpose decorators providing cross-cutting functionality for the Flask application.

This module implements enterprise-grade decorators for performance monitoring, caching,
logging, validation, and other cross-cutting concerns. All decorators are designed to
maintain ≤10% performance variance from the Node.js baseline while providing enhanced
observability and reliability features.

Key Features:
- Performance measurement and monitoring decorators
- Redis-backed caching decorators with TTL support
- Structured logging decorators with enterprise integration
- Validation decorators supporting marshmallow and pydantic
- Authentication and authorization decorators with JWT validation
- Rate limiting decorators for external service protection
- Metrics collection decorators for Prometheus integration
- Error handling decorators with circuit breaker patterns

Dependencies:
- structlog 23.1+ for structured logging
- redis-py 5.0+ for caching operations
- prometheus-client 0.17+ for metrics collection
- PyJWT 2.8+ for authentication validation
- marshmallow 3.20+ and pydantic 2.3+ for validation
- Flask-Limiter for rate limiting functionality
"""

import time
import functools
import hashlib
import json
import inspect
from typing import Any, Callable, Dict, List, Optional, Union, TypeVar, cast
from datetime import datetime, timedelta

import structlog
import redis
from flask import request, g, current_app
from werkzeug.exceptions import BadRequest, Unauthorized, TooManyRequests
from prometheus_client import Counter, Histogram, Gauge
import jwt
from marshmallow import Schema, ValidationError
from pydantic import BaseModel, ValidationError as PydanticValidationError

# Type definitions for enhanced type safety
F = TypeVar('F', bound=Callable[..., Any])
DecoratorFunction = Callable[[F], F]

# Global logger instance with structured logging
logger = structlog.get_logger(__name__)

# Prometheus metrics for performance monitoring
REQUEST_COUNT = Counter('flask_requests_total', 'Total Flask requests', ['method', 'endpoint', 'status'])
REQUEST_DURATION = Histogram('flask_request_duration_seconds', 'Flask request duration')
CACHE_OPERATIONS = Counter('redis_cache_operations_total', 'Redis cache operations', ['operation', 'result'])
VALIDATION_ERRORS = Counter('validation_errors_total', 'Validation errors', ['validator_type', 'error_type'])
AUTH_ATTEMPTS = Counter('auth_attempts_total', 'Authentication attempts', ['result'])

# Redis client instance for caching operations
redis_client: Optional[redis.Redis] = None


def initialize_redis(app=None) -> None:
    """
    Initialize Redis client for caching decorators.
    
    Args:
        app: Flask application instance for configuration
    """
    global redis_client
    try:
        if app:
            redis_url = app.config.get('REDIS_URL', 'redis://localhost:6379/0')
        else:
            redis_url = 'redis://localhost:6379/0'
            
        redis_client = redis.from_url(
            redis_url,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True,
            health_check_interval=30
        )
        
        # Test connection
        redis_client.ping()
        logger.info("Redis client initialized successfully", redis_url=redis_url)
        
    except Exception as e:
        logger.error("Failed to initialize Redis client", error=str(e))
        redis_client = None


class DecoratorError(Exception):
    """Base exception for decorator-related errors."""
    pass


class CacheError(DecoratorError):
    """Exception raised for cache-related errors."""
    pass


class ValidationDecoratorError(DecoratorError):
    """Exception raised for validation decorator errors."""
    pass


class AuthenticationDecoratorError(DecoratorError):
    """Exception raised for authentication decorator errors."""
    pass


def timeit(
    metric_name: Optional[str] = None,
    include_args: bool = False,
    log_slow_threshold: float = 1.0
) -> DecoratorFunction:
    """
    Performance timing decorator with enterprise-grade monitoring.
    
    Measures function execution time and logs performance metrics. Supports
    Prometheus metrics collection and slow query detection for ≤10% variance monitoring.
    
    Args:
        metric_name: Optional custom metric name for Prometheus
        include_args: Whether to include function arguments in logs
        log_slow_threshold: Threshold in seconds for slow operation logging
        
    Returns:
        Decorated function with timing measurement
        
    Example:
        @timeit(metric_name='user_lookup', log_slow_threshold=0.5)
        def get_user(user_id: str) -> Dict[str, Any]:
            return database.find_user(user_id)
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            func_name = f"{func.__module__}.{func.__qualname__}"
            
            # Create execution context for logging
            context = {
                'function': func_name,
                'start_time': datetime.utcnow().isoformat()
            }
            
            if include_args and args:
                context['args_count'] = len(args)
            if include_args and kwargs:
                context['kwargs_keys'] = list(kwargs.keys())
            
            try:
                # Execute function with timing measurement
                with REQUEST_DURATION.time():
                    result = func(*args, **kwargs)
                
                execution_time = time.time() - start_time
                
                # Log performance metrics
                context.update({
                    'execution_time': execution_time,
                    'status': 'success'
                })
                
                if execution_time > log_slow_threshold:
                    logger.warning("Slow operation detected", **context)
                else:
                    logger.debug("Function execution completed", **context)
                
                # Record Prometheus metrics
                if metric_name:
                    metric_histogram = Histogram(
                        f'{metric_name}_duration_seconds',
                        f'Execution time for {metric_name}'
                    )
                    metric_histogram.observe(execution_time)
                
                return result
                
            except Exception as e:
                execution_time = time.time() - start_time
                context.update({
                    'execution_time': execution_time,
                    'status': 'error',
                    'error': str(e),
                    'error_type': type(e).__name__
                })
                
                logger.error("Function execution failed", **context)
                raise
                
        return cast(F, wrapper)
    return decorator


def cached(
    ttl: int = 300,
    key_prefix: str = '',
    exclude_args: Optional[List[str]] = None,
    cache_none: bool = False,
    serializer: str = 'json'
) -> DecoratorFunction:
    """
    Redis-backed caching decorator with TTL and key management.
    
    Provides high-performance caching with Redis integration supporting
    enterprise-grade cache patterns including TTL management, key prefixing,
    and selective argument caching.
    
    Args:
        ttl: Time-to-live in seconds (default: 300)
        key_prefix: Prefix for cache keys (default: '')
        exclude_args: Arguments to exclude from cache key generation
        cache_none: Whether to cache None results (default: False)
        serializer: Serialization method ('json' or 'pickle')
        
    Returns:
        Decorated function with caching capability
        
    Example:
        @cached(ttl=600, key_prefix='user_data', exclude_args=['request_id'])
        def get_user_profile(user_id: str, request_id: str = None) -> Dict[str, Any]:
            return fetch_user_from_database(user_id)
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not redis_client:
                logger.warning("Redis client not available, executing without cache")
                return func(*args, **kwargs)
            
            # Generate cache key
            cache_key = _generate_cache_key(
                func, args, kwargs, key_prefix, exclude_args or []
            )
            
            try:
                # Attempt to retrieve from cache
                cached_result = redis_client.get(cache_key)
                if cached_result is not None:
                    CACHE_OPERATIONS.labels(operation='get', result='hit').inc()
                    logger.debug("Cache hit", cache_key=cache_key, function=func.__qualname__)
                    
                    if serializer == 'json':
                        return json.loads(cached_result)
                    else:
                        import pickle
                        return pickle.loads(cached_result.encode('latin1'))
                
                CACHE_OPERATIONS.labels(operation='get', result='miss').inc()
                
                # Execute function and cache result
                result = func(*args, **kwargs)
                
                # Cache the result if it's not None or if cache_none is True
                if result is not None or cache_none:
                    try:
                        if serializer == 'json':
                            serialized_result = json.dumps(result, default=str)
                        else:
                            import pickle
                            serialized_result = pickle.dumps(result).decode('latin1')
                            
                        redis_client.setex(cache_key, ttl, serialized_result)
                        CACHE_OPERATIONS.labels(operation='set', result='success').inc()
                        
                        logger.debug(
                            "Result cached",
                            cache_key=cache_key,
                            function=func.__qualname__,
                            ttl=ttl
                        )
                    except Exception as e:
                        CACHE_OPERATIONS.labels(operation='set', result='error').inc()
                        logger.error("Cache set operation failed", error=str(e), cache_key=cache_key)
                
                return result
                
            except Exception as e:
                CACHE_OPERATIONS.labels(operation='get', result='error').inc()
                logger.error("Cache operation failed", error=str(e), cache_key=cache_key)
                # Fallback to executing function without cache
                return func(*args, **kwargs)
                
        return cast(F, wrapper)
    return decorator


def logged(
    level: str = 'info',
    include_result: bool = False,
    include_args: bool = False,
    exclude_fields: Optional[List[str]] = None,
    sensitive_fields: Optional[List[str]] = None
) -> DecoratorFunction:
    """
    Structured logging decorator with enterprise integration.
    
    Provides comprehensive logging with structured format, sensitive data protection,
    and enterprise log aggregation compatibility. Supports Splunk and ELK Stack integration.
    
    Args:
        level: Logging level ('debug', 'info', 'warning', 'error')
        include_result: Whether to include function result in logs
        include_args: Whether to include function arguments in logs
        exclude_fields: Fields to exclude from logging
        sensitive_fields: Fields to mask in logs for security
        
    Returns:
        Decorated function with structured logging
        
    Example:
        @logged(level='info', include_args=True, sensitive_fields=['password', 'token'])
        def authenticate_user(username: str, password: str) -> Dict[str, Any]:
            return perform_authentication(username, password)
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            func_name = f"{func.__module__}.{func.__qualname__}"
            start_time = datetime.utcnow()
            
            # Build log context
            context = {
                'function': func_name,
                'timestamp': start_time.isoformat(),
                'execution_id': hashlib.md5(f"{func_name}_{start_time}".encode()).hexdigest()[:8]
            }
            
            # Add request context if available
            if request:
                context.update({
                    'request_id': getattr(request, 'id', None),
                    'user_id': getattr(g, 'user_id', None),
                    'endpoint': request.endpoint,
                    'method': request.method
                })
            
            # Include arguments if requested
            if include_args:
                func_signature = inspect.signature(func)
                bound_args = func_signature.bind(*args, **kwargs)
                bound_args.apply_defaults()
                
                sanitized_args = _sanitize_log_data(
                    dict(bound_args.arguments),
                    exclude_fields or [],
                    sensitive_fields or []
                )
                context['arguments'] = sanitized_args
            
            # Log function entry
            log_method = getattr(logger, level, logger.info)
            log_method("Function execution started", **context)
            
            try:
                result = func(*args, **kwargs)
                
                # Calculate execution time
                execution_time = (datetime.utcnow() - start_time).total_seconds()
                context.update({
                    'execution_time': execution_time,
                    'status': 'success'
                })
                
                # Include result if requested and not sensitive
                if include_result and result is not None:
                    sanitized_result = _sanitize_log_data(
                        result if isinstance(result, dict) else {'result': result},
                        exclude_fields or [],
                        sensitive_fields or []
                    )
                    context['result'] = sanitized_result
                
                log_method("Function execution completed", **context)
                return result
                
            except Exception as e:
                execution_time = (datetime.utcnow() - start_time).total_seconds()
                context.update({
                    'execution_time': execution_time,
                    'status': 'error',
                    'error': str(e),
                    'error_type': type(e).__name__
                })
                
                logger.error("Function execution failed", **context)
                raise
                
        return cast(F, wrapper)
    return decorator


def validate_input(
    schema: Union[Schema, BaseModel, Dict[str, Any]],
    source: str = 'json',
    validate_args: bool = False
) -> DecoratorFunction:
    """
    Input validation decorator supporting marshmallow and pydantic.
    
    Provides comprehensive input validation with support for multiple validation
    frameworks and flexible data source handling. Includes enterprise-grade
    error reporting and validation metrics collection.
    
    Args:
        schema: Validation schema (marshmallow Schema, pydantic BaseModel, or dict)
        source: Data source ('json', 'form', 'args', or 'function_args')
        validate_args: Whether to validate function arguments directly
        
    Returns:
        Decorated function with input validation
        
    Example:
        from marshmallow import Schema, fields
        
        class UserSchema(Schema):
            username = fields.Str(required=True)
            email = fields.Email(required=True)
            
        @validate_input(UserSchema(), source='json')
        def create_user():
            data = request.get_json()
            return create_user_in_database(data)
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                if validate_args:
                    # Validate function arguments
                    _validate_function_args(func, args, kwargs, schema)
                else:
                    # Validate request data
                    _validate_request_data(schema, source)
                
                return func(*args, **kwargs)
                
            except ValidationError as e:
                VALIDATION_ERRORS.labels(validator_type='marshmallow', error_type='validation').inc()
                logger.warning(
                    "Marshmallow validation failed",
                    function=func.__qualname__,
                    errors=e.messages,
                    source=source
                )
                raise BadRequest(f"Validation error: {e.messages}")
                
            except PydanticValidationError as e:
                VALIDATION_ERRORS.labels(validator_type='pydantic', error_type='validation').inc()
                logger.warning(
                    "Pydantic validation failed",
                    function=func.__qualname__,
                    errors=e.errors(),
                    source=source
                )
                raise BadRequest(f"Validation error: {e.errors()}")
                
            except Exception as e:
                VALIDATION_ERRORS.labels(validator_type='unknown', error_type='error').inc()
                logger.error(
                    "Validation decorator error",
                    function=func.__qualname__,
                    error=str(e),
                    error_type=type(e).__name__
                )
                raise
                
        return cast(F, wrapper)
    return decorator


def require_auth(
    required_scopes: Optional[List[str]] = None,
    allow_anonymous: bool = False,
    jwt_secret_key: Optional[str] = None
) -> DecoratorFunction:
    """
    JWT authentication decorator with scope-based authorization.
    
    Provides enterprise-grade authentication with JWT token validation,
    scope-based authorization, and comprehensive security logging.
    
    Args:
        required_scopes: List of required permission scopes
        allow_anonymous: Whether to allow anonymous access
        jwt_secret_key: Custom JWT secret key (defaults to app config)
        
    Returns:
        Decorated function with authentication requirement
        
    Example:
        @require_auth(required_scopes=['user:read', 'user:write'])
        def update_user_profile(user_id: str):
            return update_user_data(user_id, request.get_json())
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                # Extract JWT token from request
                token = _extract_jwt_token()
                
                if not token and not allow_anonymous:
                    AUTH_ATTEMPTS.labels(result='missing_token').inc()
                    logger.warning("Authentication required but no token provided")
                    raise Unauthorized("Authentication token required")
                
                if token:
                    # Validate JWT token
                    user_context = _validate_jwt_token(token, jwt_secret_key)
                    
                    # Check required scopes
                    if required_scopes:
                        _validate_user_scopes(user_context, required_scopes)
                    
                    # Store user context in Flask g object
                    g.current_user = user_context
                    g.user_id = user_context.get('sub', user_context.get('user_id'))
                    
                    AUTH_ATTEMPTS.labels(result='success').inc()
                    logger.debug(
                        "Authentication successful",
                        user_id=g.user_id,
                        scopes=user_context.get('scopes', [])
                    )
                elif allow_anonymous:
                    g.current_user = None
                    g.user_id = None
                    logger.debug("Anonymous access allowed")
                
                return func(*args, **kwargs)
                
            except jwt.ExpiredSignatureError:
                AUTH_ATTEMPTS.labels(result='expired_token').inc()
                logger.warning("JWT token has expired")
                raise Unauthorized("Token has expired")
                
            except jwt.InvalidTokenError as e:
                AUTH_ATTEMPTS.labels(result='invalid_token').inc()
                logger.warning("Invalid JWT token", error=str(e))
                raise Unauthorized("Invalid authentication token")
                
            except Exception as e:
                AUTH_ATTEMPTS.labels(result='error').inc()
                logger.error("Authentication error", error=str(e), error_type=type(e).__name__)
                raise
                
        return cast(F, wrapper)
    return decorator


def rate_limit(
    max_requests: int = 100,
    window: int = 3600,
    per_user: bool = True,
    key_func: Optional[Callable] = None
) -> DecoratorFunction:
    """
    Rate limiting decorator with Redis-backed storage.
    
    Provides enterprise-grade rate limiting with configurable windows,
    per-user or global limits, and custom key generation functions.
    
    Args:
        max_requests: Maximum requests allowed in the time window
        window: Time window in seconds (default: 1 hour)
        per_user: Whether to apply rate limit per user (default: True)
        key_func: Custom function to generate rate limit keys
        
    Returns:
        Decorated function with rate limiting
        
    Example:
        @rate_limit(max_requests=50, window=900, per_user=True)
        def api_endpoint():
            return {"message": "API response"}
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not redis_client:
                logger.warning("Redis client not available, skipping rate limit")
                return func(*args, **kwargs)
            
            try:
                # Generate rate limit key
                rate_limit_key = _generate_rate_limit_key(func, per_user, key_func)
                
                # Check current request count
                current_requests = redis_client.get(rate_limit_key)
                if current_requests is None:
                    current_requests = 0
                else:
                    current_requests = int(current_requests)
                
                if current_requests >= max_requests:
                    logger.warning(
                        "Rate limit exceeded",
                        function=func.__qualname__,
                        key=rate_limit_key,
                        current_requests=current_requests,
                        max_requests=max_requests
                    )
                    raise TooManyRequests(f"Rate limit exceeded: {max_requests} requests per {window} seconds")
                
                # Increment request count
                pipe = redis_client.pipeline()
                pipe.incr(rate_limit_key)
                pipe.expire(rate_limit_key, window)
                pipe.execute()
                
                logger.debug(
                    "Rate limit check passed",
                    function=func.__qualname__,
                    key=rate_limit_key,
                    current_requests=current_requests + 1,
                    max_requests=max_requests
                )
                
                return func(*args, **kwargs)
                
            except TooManyRequests:
                raise
            except Exception as e:
                logger.error("Rate limiting error", error=str(e), function=func.__qualname__)
                # Allow request to proceed if rate limiting fails
                return func(*args, **kwargs)
                
        return cast(F, wrapper)
    return decorator


def circuit_breaker(
    failure_threshold: int = 5,
    recovery_timeout: int = 60,
    expected_exception: type = Exception
) -> DecoratorFunction:
    """
    Circuit breaker decorator for external service resilience.
    
    Implements the circuit breaker pattern to prevent cascading failures
    in external service integrations with automatic recovery detection.
    
    Args:
        failure_threshold: Number of failures before opening circuit
        recovery_timeout: Seconds to wait before attempting recovery
        expected_exception: Exception type that triggers circuit breaking
        
    Returns:
        Decorated function with circuit breaker protection
        
    Example:
        @circuit_breaker(failure_threshold=3, recovery_timeout=30)
        def call_external_api():
            return requests.get('https://external-api.com/data')
    """
    def decorator(func: F) -> F:
        circuit_state = {
            'failures': 0,
            'last_failure_time': None,
            'state': 'closed'  # closed, open, half-open
        }
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            current_time = time.time()
            
            # Check if circuit should transition from open to half-open
            if (circuit_state['state'] == 'open' and 
                circuit_state['last_failure_time'] and
                current_time - circuit_state['last_failure_time'] > recovery_timeout):
                circuit_state['state'] = 'half-open'
                logger.info(
                    "Circuit breaker transitioning to half-open",
                    function=func.__qualname__
                )
            
            # Reject requests if circuit is open
            if circuit_state['state'] == 'open':
                logger.warning(
                    "Circuit breaker is open, rejecting request",
                    function=func.__qualname__,
                    failures=circuit_state['failures']
                )
                raise Exception(f"Circuit breaker is open for {func.__qualname__}")
            
            try:
                result = func(*args, **kwargs)
                
                # Reset circuit on successful call
                if circuit_state['failures'] > 0:
                    circuit_state['failures'] = 0
                    circuit_state['state'] = 'closed'
                    logger.info(
                        "Circuit breaker reset to closed",
                        function=func.__qualname__
                    )
                
                return result
                
            except expected_exception as e:
                circuit_state['failures'] += 1
                circuit_state['last_failure_time'] = current_time
                
                # Open circuit if failure threshold reached
                if circuit_state['failures'] >= failure_threshold:
                    circuit_state['state'] = 'open'
                    logger.error(
                        "Circuit breaker opened due to repeated failures",
                        function=func.__qualname__,
                        failures=circuit_state['failures'],
                        threshold=failure_threshold
                    )
                else:
                    logger.warning(
                        "Circuit breaker failure recorded",
                        function=func.__qualname__,
                        failures=circuit_state['failures'],
                        threshold=failure_threshold
                    )
                
                raise
                
        return cast(F, wrapper)
    return decorator


# Helper Functions

def _generate_cache_key(
    func: Callable,
    args: tuple,
    kwargs: dict,
    prefix: str,
    exclude_args: List[str]
) -> str:
    """Generate a consistent cache key for function calls."""
    func_name = f"{func.__module__}.{func.__qualname__}"
    
    # Create a signature for the arguments
    func_signature = inspect.signature(func)
    bound_args = func_signature.bind(*args, **kwargs)
    bound_args.apply_defaults()
    
    # Filter out excluded arguments
    filtered_args = {
        k: v for k, v in bound_args.arguments.items()
        if k not in exclude_args
    }
    
    # Create hash of arguments
    args_hash = hashlib.md5(
        json.dumps(filtered_args, sort_keys=True, default=str).encode()
    ).hexdigest()
    
    # Combine prefix, function name, and arguments hash
    cache_key = f"{prefix}:{func_name}:{args_hash}" if prefix else f"{func_name}:{args_hash}"
    return cache_key


def _sanitize_log_data(
    data: Dict[str, Any],
    exclude_fields: List[str],
    sensitive_fields: List[str]
) -> Dict[str, Any]:
    """Sanitize data for logging by excluding and masking sensitive fields."""
    if not isinstance(data, dict):
        return data
    
    sanitized = {}
    for key, value in data.items():
        if key in exclude_fields:
            continue
        elif key in sensitive_fields:
            sanitized[key] = '***MASKED***'
        elif isinstance(value, dict):
            sanitized[key] = _sanitize_log_data(value, exclude_fields, sensitive_fields)
        else:
            sanitized[key] = value
    
    return sanitized


def _validate_function_args(
    func: Callable,
    args: tuple,
    kwargs: dict,
    schema: Union[Schema, BaseModel, Dict[str, Any]]
) -> None:
    """Validate function arguments against a schema."""
    func_signature = inspect.signature(func)
    bound_args = func_signature.bind(*args, **kwargs)
    bound_args.apply_defaults()
    
    if isinstance(schema, Schema):
        schema.load(bound_args.arguments)
    elif isinstance(schema, type) and issubclass(schema, BaseModel):
        schema(**bound_args.arguments)
    else:
        # Simple dict validation
        for key, validator in schema.items():
            if key in bound_args.arguments:
                if not validator(bound_args.arguments[key]):
                    raise ValidationError(f"Validation failed for argument: {key}")


def _validate_request_data(
    schema: Union[Schema, BaseModel, Dict[str, Any]],
    source: str
) -> None:
    """Validate request data from the specified source."""
    if source == 'json':
        data = request.get_json()
    elif source == 'form':
        data = request.form.to_dict()
    elif source == 'args':
        data = request.args.to_dict()
    else:
        raise ValidationDecoratorError(f"Unsupported validation source: {source}")
    
    if data is None:
        raise BadRequest("No data provided for validation")
    
    if isinstance(schema, Schema):
        schema.load(data)
    elif isinstance(schema, type) and issubclass(schema, BaseModel):
        schema(**data)
    else:
        # Simple dict validation
        for key, validator in schema.items():
            if key in data:
                if not validator(data[key]):
                    raise ValidationError(f"Validation failed for field: {key}")


def _extract_jwt_token() -> Optional[str]:
    """Extract JWT token from request headers."""
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        return auth_header[7:]  # Remove 'Bearer ' prefix
    return None


def _validate_jwt_token(token: str, secret_key: Optional[str] = None) -> Dict[str, Any]:
    """Validate JWT token and return decoded payload."""
    if not secret_key:
        secret_key = current_app.config.get('JWT_SECRET_KEY')
        if not secret_key:
            raise AuthenticationDecoratorError("JWT secret key not configured")
    
    try:
        payload = jwt.decode(
            token,
            secret_key,
            algorithms=['HS256'],
            verify=True
        )
        return payload
    except jwt.InvalidTokenError:
        raise


def _validate_user_scopes(user_context: Dict[str, Any], required_scopes: List[str]) -> None:
    """Validate that user has required scopes."""
    user_scopes = user_context.get('scopes', [])
    if isinstance(user_scopes, str):
        user_scopes = user_scopes.split(' ')
    
    missing_scopes = set(required_scopes) - set(user_scopes)
    if missing_scopes:
        logger.warning(
            "Insufficient permissions",
            user_id=user_context.get('sub', user_context.get('user_id')),
            required_scopes=required_scopes,
            user_scopes=user_scopes,
            missing_scopes=list(missing_scopes)
        )
        raise Unauthorized(f"Insufficient permissions. Missing scopes: {list(missing_scopes)}")


def _generate_rate_limit_key(
    func: Callable,
    per_user: bool,
    key_func: Optional[Callable]
) -> str:
    """Generate rate limit key."""
    if key_func:
        return key_func()
    
    base_key = f"rate_limit:{func.__module__}.{func.__qualname__}"
    
    if per_user:
        user_id = getattr(g, 'user_id', None)
        if user_id:
            return f"{base_key}:user:{user_id}"
        else:
            # Fall back to IP address if no user context
            client_ip = request.remote_addr
            return f"{base_key}:ip:{client_ip}"
    
    return base_key


# Export public decorator functions
__all__ = [
    'timeit',
    'cached',
    'logged',
    'validate_input',
    'require_auth',
    'rate_limit',
    'circuit_breaker',
    'initialize_redis',
    'DecoratorError',
    'CacheError',
    'ValidationDecoratorError',
    'AuthenticationDecoratorError'
]