"""
Custom exception classes for external service integration failures.

This module provides a comprehensive exception hierarchy for handling external service
integration failures, HTTP client errors, circuit breaker states, and retry exhaustion
scenarios. It implements detailed error context, service-specific exceptions, and
integration with Flask error handlers for consistent error responses.

Aligned with:
- Section 4.2.3: Error Handling and Recovery patterns
- Section 6.3.3: External Systems integration resilience patterns
- Section 3.2.2: Authentication & Security Libraries error handling
- Section 3.6.1: Logging & Monitoring integration
"""

import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Union


class IntegrationError(Exception):
    """
    Base exception class for all external service integration failures.
    
    Provides comprehensive error context including service information, request details,
    error classification, and metadata for monitoring and debugging purposes.
    
    Attributes:
        service_name: Name of the external service that failed
        operation: Specific operation that was being performed
        error_code: Service-specific error code or HTTP status code
        error_context: Additional context information about the error
        retry_count: Number of retry attempts made
        timestamp: When the error occurred
        correlation_id: Unique identifier for tracking across services
    """
    
    def __init__(
        self,
        message: str,
        service_name: str,
        operation: str,
        error_code: Optional[Union[str, int]] = None,
        error_context: Optional[Dict[str, Any]] = None,
        retry_count: int = 0,
        correlation_id: Optional[str] = None,
        **kwargs
    ):
        super().__init__(message)
        self.service_name = service_name
        self.operation = operation
        self.error_code = error_code
        self.error_context = error_context or {}
        self.retry_count = retry_count
        self.timestamp = datetime.utcnow()
        self.correlation_id = correlation_id
        
        # Additional context from kwargs
        for key, value in kwargs.items():
            if not hasattr(self, key):
                setattr(self, key, value)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert exception to dictionary for logging and monitoring.
        
        Returns:
            Dictionary containing all error details for structured logging
        """
        return {
            'error_type': self.__class__.__name__,
            'message': str(self),
            'service_name': self.service_name,
            'operation': self.operation,
            'error_code': self.error_code,
            'error_context': self.error_context,
            'retry_count': self.retry_count,
            'timestamp': self.timestamp.isoformat(),
            'correlation_id': self.correlation_id
        }
    
    def __str__(self) -> str:
        """Enhanced string representation with context."""
        base_msg = super().__str__()
        context_parts = [f"service={self.service_name}", f"operation={self.operation}"]
        
        if self.error_code:
            context_parts.append(f"code={self.error_code}")
        
        if self.retry_count > 0:
            context_parts.append(f"retries={self.retry_count}")
        
        context_str = ", ".join(context_parts)
        return f"{base_msg} ({context_str})"


# HTTP Client Exception Hierarchy

class HTTPClientError(IntegrationError):
    """
    Base exception for HTTP client errors (requests and httpx libraries).
    
    Handles both synchronous (requests) and asynchronous (httpx) HTTP client failures
    with detailed request/response information for debugging and monitoring.
    """
    
    def __init__(
        self,
        message: str,
        service_name: str,
        operation: str,
        url: Optional[str] = None,
        method: Optional[str] = None,
        status_code: Optional[int] = None,
        response_headers: Optional[Dict[str, str]] = None,
        request_headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
        **kwargs
    ):
        super().__init__(
            message=message,
            service_name=service_name,
            operation=operation,
            error_code=status_code,
            **kwargs
        )
        self.url = url
        self.method = method
        self.status_code = status_code
        self.response_headers = response_headers or {}
        self.request_headers = request_headers or {}
        self.timeout = timeout
        
        # Add HTTP context to error_context
        self.error_context.update({
            'url': url,
            'method': method,
            'status_code': status_code,
            'timeout': timeout,
            'request_headers': self._sanitize_headers(request_headers or {}),
            'response_headers': self._sanitize_headers(response_headers or {})
        })
    
    @staticmethod
    def _sanitize_headers(headers: Dict[str, str]) -> Dict[str, str]:
        """
        Remove sensitive information from headers for logging.
        
        Args:
            headers: Original headers dictionary
            
        Returns:
            Sanitized headers with sensitive values masked
        """
        sensitive_keys = {'authorization', 'x-api-key', 'cookie', 'set-cookie'}
        sanitized = {}
        
        for key, value in headers.items():
            if key.lower() in sensitive_keys:
                sanitized[key] = '[REDACTED]'
            else:
                sanitized[key] = value
        
        return sanitized


class RequestsHTTPError(HTTPClientError):
    """Specific exception for requests library HTTP errors."""
    
    def __init__(self, message: str, **kwargs):
        kwargs.setdefault('service_name', 'requests_client')
        super().__init__(message=message, **kwargs)


class HttpxHTTPError(HTTPClientError):
    """Specific exception for httpx library HTTP errors."""
    
    def __init__(self, message: str, **kwargs):
        kwargs.setdefault('service_name', 'httpx_client')
        super().__init__(message=message, **kwargs)


class ConnectionError(HTTPClientError):
    """Exception for network connection failures."""
    
    def __init__(self, message: str, **kwargs):
        super().__init__(message=message, operation="connection", **kwargs)


class TimeoutError(HTTPClientError):
    """Exception for HTTP request timeout failures."""
    
    def __init__(self, message: str, timeout_duration: Optional[float] = None, **kwargs):
        super().__init__(message=message, operation="timeout", timeout=timeout_duration, **kwargs)
        self.timeout_duration = timeout_duration


class HTTPResponseError(HTTPClientError):
    """Exception for HTTP response errors (4xx, 5xx status codes)."""
    
    def __init__(
        self,
        message: str,
        status_code: int,
        response_text: Optional[str] = None,
        **kwargs
    ):
        super().__init__(message=message, status_code=status_code, **kwargs)
        self.response_text = response_text
        self.error_context['response_text'] = response_text


# Circuit Breaker Exception Hierarchy

class CircuitBreakerError(IntegrationError):
    """
    Base exception for circuit breaker state-related errors.
    
    Provides detailed information about circuit breaker state, failure thresholds,
    and recovery mechanisms for external service protection.
    """
    
    def __init__(
        self,
        message: str,
        service_name: str,
        operation: str,
        circuit_state: str,
        failure_count: int = 0,
        failure_threshold: int = 5,
        reset_timeout: int = 60,
        **kwargs
    ):
        super().__init__(
            message=message,
            service_name=service_name,
            operation=operation,
            **kwargs
        )
        self.circuit_state = circuit_state
        self.failure_count = failure_count
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        
        # Add circuit breaker context
        self.error_context.update({
            'circuit_state': circuit_state,
            'failure_count': failure_count,
            'failure_threshold': failure_threshold,
            'reset_timeout': reset_timeout
        })


class CircuitBreakerOpenError(CircuitBreakerError):
    """Exception raised when circuit breaker is in OPEN state."""
    
    def __init__(
        self,
        service_name: str,
        operation: str,
        time_until_reset: Optional[int] = None,
        **kwargs
    ):
        message = f"Circuit breaker OPEN for {service_name}.{operation}"
        if time_until_reset:
            message += f" (resets in {time_until_reset}s)"
        
        super().__init__(
            message=message,
            service_name=service_name,
            operation=operation,
            circuit_state="OPEN",
            **kwargs
        )
        self.time_until_reset = time_until_reset


class CircuitBreakerHalfOpenError(CircuitBreakerError):
    """Exception raised when circuit breaker test call fails in HALF-OPEN state."""
    
    def __init__(self, service_name: str, operation: str, **kwargs):
        message = f"Circuit breaker test call failed for {service_name}.{operation}, returning to OPEN state"
        super().__init__(
            message=message,
            service_name=service_name,
            operation=operation,
            circuit_state="HALF_OPEN",
            **kwargs
        )


# Retry Logic Exception Hierarchy

class RetryError(IntegrationError):
    """
    Base exception for retry logic failures.
    
    Tracks retry attempts, backoff strategies, and final exhaustion for
    comprehensive retry pattern debugging and monitoring.
    """
    
    def __init__(
        self,
        message: str,
        service_name: str,
        operation: str,
        max_retries: int,
        retry_count: int,
        last_exception: Optional[Exception] = None,
        retry_history: Optional[List[Dict[str, Any]]] = None,
        **kwargs
    ):
        super().__init__(
            message=message,
            service_name=service_name,
            operation=operation,
            retry_count=retry_count,
            **kwargs
        )
        self.max_retries = max_retries
        self.last_exception = last_exception
        self.retry_history = retry_history or []
        
        # Add retry context
        self.error_context.update({
            'max_retries': max_retries,
            'retry_count': retry_count,
            'retry_history': retry_history,
            'last_exception': str(last_exception) if last_exception else None
        })


class RetryExhaustedError(RetryError):
    """Exception raised when maximum retry attempts are exhausted."""
    
    def __init__(
        self,
        service_name: str,
        operation: str,
        max_retries: int,
        last_exception: Optional[Exception] = None,
        total_duration: Optional[float] = None,
        **kwargs
    ):
        message = f"Retry exhausted for {service_name}.{operation} after {max_retries} attempts"
        if total_duration:
            message += f" (duration: {total_duration:.2f}s)"
        
        super().__init__(
            message=message,
            service_name=service_name,
            operation=operation,
            max_retries=max_retries,
            retry_count=max_retries,
            last_exception=last_exception,
            **kwargs
        )
        self.total_duration = total_duration


class RetryBackoffError(RetryError):
    """Exception raised during exponential backoff calculations."""
    
    def __init__(
        self,
        service_name: str,
        operation: str,
        backoff_duration: float,
        retry_attempt: int,
        **kwargs
    ):
        message = f"Retry backoff error for {service_name}.{operation} (attempt {retry_attempt}, backoff: {backoff_duration}s)"
        super().__init__(
            message=message,
            service_name=service_name,
            operation=operation,
            retry_count=retry_attempt,
            **kwargs
        )
        self.backoff_duration = backoff_duration


# Service-Specific Exception Classes

class Auth0Error(IntegrationError):
    """Exception for Auth0 authentication service failures."""
    
    def __init__(
        self,
        message: str,
        operation: str,
        auth0_error_code: Optional[str] = None,
        user_id: Optional[str] = None,
        tenant: Optional[str] = None,
        **kwargs
    ):
        super().__init__(
            message=message,
            service_name="auth0",
            operation=operation,
            error_code=auth0_error_code,
            **kwargs
        )
        self.auth0_error_code = auth0_error_code
        self.user_id = user_id
        self.tenant = tenant
        
        # Add Auth0-specific context
        self.error_context.update({
            'auth0_error_code': auth0_error_code,
            'user_id': user_id,
            'tenant': tenant
        })


class JWTValidationError(Auth0Error):
    """Exception for JWT token validation failures."""
    
    def __init__(
        self,
        message: str,
        token_type: str = "access_token",
        jwt_error: Optional[str] = None,
        **kwargs
    ):
        super().__init__(
            message=message,
            operation="jwt_validation",
            **kwargs
        )
        self.token_type = token_type
        self.jwt_error = jwt_error
        
        self.error_context.update({
            'token_type': token_type,
            'jwt_error': jwt_error
        })


class AWSServiceError(IntegrationError):
    """Exception for AWS service failures."""
    
    def __init__(
        self,
        message: str,
        operation: str,
        aws_service: str,
        aws_error_code: Optional[str] = None,
        aws_request_id: Optional[str] = None,
        region: Optional[str] = None,
        **kwargs
    ):
        super().__init__(
            message=message,
            service_name=f"aws_{aws_service}",
            operation=operation,
            error_code=aws_error_code,
            **kwargs
        )
        self.aws_service = aws_service
        self.aws_error_code = aws_error_code
        self.aws_request_id = aws_request_id
        self.region = region
        
        # Add AWS-specific context
        self.error_context.update({
            'aws_service': aws_service,
            'aws_error_code': aws_error_code,
            'aws_request_id': aws_request_id,
            'region': region
        })


class S3Error(AWSServiceError):
    """Exception for AWS S3 storage operations."""
    
    def __init__(
        self,
        message: str,
        operation: str,
        bucket: Optional[str] = None,
        key: Optional[str] = None,
        **kwargs
    ):
        super().__init__(
            message=message,
            operation=operation,
            aws_service="s3",
            **kwargs
        )
        self.bucket = bucket
        self.key = key
        
        self.error_context.update({
            'bucket': bucket,
            'key': key
        })


class MongoDBError(IntegrationError):
    """Exception for MongoDB database operations."""
    
    def __init__(
        self,
        message: str,
        operation: str,
        collection: Optional[str] = None,
        database: Optional[str] = None,
        query: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        super().__init__(
            message=message,
            service_name="mongodb",
            operation=operation,
            **kwargs
        )
        self.collection = collection
        self.database = database
        self.query = query
        
        # Add MongoDB-specific context (sanitize sensitive query data)
        self.error_context.update({
            'collection': collection,
            'database': database,
            'query': self._sanitize_query(query) if query else None
        })
    
    @staticmethod
    def _sanitize_query(query: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive information from MongoDB queries for logging."""
        sensitive_fields = {'password', 'secret', 'token', 'key', 'hash'}
        sanitized = {}
        
        for key, value in query.items():
            if any(sensitive_field in key.lower() for sensitive_field in sensitive_fields):
                sanitized[key] = '[REDACTED]'
            elif isinstance(value, dict):
                sanitized[key] = MongoDBError._sanitize_query(value)
            else:
                sanitized[key] = value
        
        return sanitized


class RedisError(IntegrationError):
    """Exception for Redis cache operations."""
    
    def __init__(
        self,
        message: str,
        operation: str,
        key: Optional[str] = None,
        database: Optional[int] = None,
        **kwargs
    ):
        super().__init__(
            message=message,
            service_name="redis",
            operation=operation,
            **kwargs
        )
        self.key = key
        self.database = database
        
        # Add Redis-specific context
        self.error_context.update({
            'key': key,
            'database': database
        })


# Validation and Input Exception Hierarchy

class ValidationError(IntegrationError):
    """Exception for data validation failures."""
    
    def __init__(
        self,
        message: str,
        operation: str,
        validation_errors: Optional[Dict[str, List[str]]] = None,
        schema_name: Optional[str] = None,
        **kwargs
    ):
        super().__init__(
            message=message,
            service_name="validation",
            operation=operation,
            **kwargs
        )
        self.validation_errors = validation_errors or {}
        self.schema_name = schema_name
        
        # Add validation context
        self.error_context.update({
            'validation_errors': validation_errors,
            'schema_name': schema_name
        })


class MarshmallowValidationError(ValidationError):
    """Exception for marshmallow schema validation failures."""
    
    def __init__(
        self,
        message: str,
        operation: str,
        marshmallow_errors: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        super().__init__(
            message=message,
            operation=operation,
            schema_name="marshmallow",
            **kwargs
        )
        self.marshmallow_errors = marshmallow_errors
        
        # Convert marshmallow errors to standard format
        if marshmallow_errors:
            self.validation_errors = self._convert_marshmallow_errors(marshmallow_errors)
    
    @staticmethod
    def _convert_marshmallow_errors(errors: Dict[str, Any]) -> Dict[str, List[str]]:
        """Convert marshmallow error format to standard validation error format."""
        converted = {}
        for field, field_errors in errors.items():
            if isinstance(field_errors, list):
                converted[field] = field_errors
            elif isinstance(field_errors, str):
                converted[field] = [field_errors]
            else:
                converted[field] = [str(field_errors)]
        return converted


# Integration Exception Factory

class IntegrationExceptionFactory:
    """
    Factory class for creating appropriate integration exceptions.
    
    Provides convenient methods for creating service-specific exceptions
    with consistent error context and metadata.
    """
    
    @staticmethod
    def create_http_error(
        client_type: str,
        message: str,
        service_name: str,
        operation: str,
        **kwargs
    ) -> HTTPClientError:
        """Create HTTP client error based on client type."""
        if client_type.lower() == 'requests':
            return RequestsHTTPError(message=message, service_name=service_name, operation=operation, **kwargs)
        elif client_type.lower() == 'httpx':
            return HttpxHTTPError(message=message, service_name=service_name, operation=operation, **kwargs)
        else:
            return HTTPClientError(message=message, service_name=service_name, operation=operation, **kwargs)
    
    @staticmethod
    def create_timeout_error(
        client_type: str,
        service_name: str,
        operation: str,
        timeout_duration: float,
        **kwargs
    ) -> TimeoutError:
        """Create timeout error with duration context."""
        message = f"Request timeout after {timeout_duration}s for {service_name}.{operation}"
        return TimeoutError(
            message=message,
            service_name=service_name,
            operation=operation,
            timeout_duration=timeout_duration,
            **kwargs
        )
    
    @staticmethod
    def create_circuit_breaker_error(
        service_name: str,
        operation: str,
        circuit_state: str,
        **kwargs
    ) -> CircuitBreakerError:
        """Create circuit breaker error based on state."""
        if circuit_state.upper() == 'OPEN':
            return CircuitBreakerOpenError(service_name=service_name, operation=operation, **kwargs)
        elif circuit_state.upper() == 'HALF_OPEN':
            return CircuitBreakerHalfOpenError(service_name=service_name, operation=operation, **kwargs)
        else:
            return CircuitBreakerError(
                message=f"Circuit breaker error in {circuit_state} state",
                service_name=service_name,
                operation=operation,
                circuit_state=circuit_state,
                **kwargs
            )
    
    @staticmethod
    def create_retry_exhausted_error(
        service_name: str,
        operation: str,
        max_retries: int,
        last_exception: Optional[Exception] = None,
        **kwargs
    ) -> RetryExhaustedError:
        """Create retry exhausted error with exception context."""
        return RetryExhaustedError(
            service_name=service_name,
            operation=operation,
            max_retries=max_retries,
            last_exception=last_exception,
            **kwargs
        )


# Exception Mapping for Flask Error Handlers
FLASK_ERROR_HANDLER_MAPPING = {
    # HTTP Client Errors
    'requests.exceptions.RequestException': RequestsHTTPError,
    'requests.exceptions.ConnectionError': ConnectionError,
    'requests.exceptions.Timeout': TimeoutError,
    'requests.exceptions.HTTPError': HTTPResponseError,
    
    # HTTPX Errors
    'httpx.RequestError': HttpxHTTPError,
    'httpx.ConnectError': ConnectionError,
    'httpx.TimeoutException': TimeoutError,
    'httpx.HTTPStatusError': HTTPResponseError,
    
    # Authentication Errors
    'jwt.exceptions.PyJWTError': JWTValidationError,
    'jwt.exceptions.InvalidTokenError': JWTValidationError,
    'jwt.exceptions.ExpiredSignatureError': JWTValidationError,
    
    # Database Errors
    'pymongo.errors.PyMongoError': MongoDBError,
    'pymongo.errors.ConnectionFailure': MongoDBError,
    'pymongo.errors.OperationFailure': MongoDBError,
    
    # AWS Errors
    'boto3.exceptions.Boto3Error': AWSServiceError,
    'botocore.exceptions.ClientError': AWSServiceError,
    'botocore.exceptions.NoCredentialsError': AWSServiceError,
    
    # Redis Errors
    'redis.exceptions.RedisError': RedisError,
    'redis.exceptions.ConnectionError': RedisError,
    'redis.exceptions.TimeoutError': RedisError,
    
    # Validation Errors
    'marshmallow.exceptions.ValidationError': MarshmallowValidationError,
    'pydantic.ValidationError': ValidationError,
}


def get_integration_exception_for_stdlib_exception(
    exception: Exception,
    service_name: str = "unknown",
    operation: str = "unknown"
) -> IntegrationError:
    """
    Convert standard library or third-party exceptions to integration exceptions.
    
    Args:
        exception: The original exception
        service_name: Name of the service where the error occurred
        operation: Operation being performed when the error occurred
        
    Returns:
        Appropriate IntegrationError subclass
    """
    exception_type = f"{exception.__class__.__module__}.{exception.__class__.__name__}"
    
    if exception_type in FLASK_ERROR_HANDLER_MAPPING:
        exception_class = FLASK_ERROR_HANDLER_MAPPING[exception_type]
        return exception_class(
            message=str(exception),
            service_name=service_name,
            operation=operation,
            error_context={'original_exception': exception_type}
        )
    
    # Fallback to base IntegrationError
    return IntegrationError(
        message=str(exception),
        service_name=service_name,
        operation=operation,
        error_context={
            'original_exception_type': exception_type,
            'original_exception': str(exception)
        }
    )