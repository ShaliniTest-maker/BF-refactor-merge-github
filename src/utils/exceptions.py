"""
Base exception classes and error handling utilities providing comprehensive exception hierarchy,
error formatting, and integration with Flask error handlers.

This module implements enterprise-grade exception management with structured error reporting
and logging integration as specified in Section 5.4.2 error handling patterns and Section 5.4.1
structured logging strategy.

Key Features:
- Hierarchical exception classes for consistent error categorization
- Structured error response formatting for API consistency
- Flask error handler integration with @errorhandler decorators
- Enterprise logging integration with structlog
- Prometheus metrics integration for error tracking
- Circuit breaker and retry logic support
- Graceful degradation and fallback response patterns
"""

import logging
import traceback
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from uuid import uuid4

import structlog
from flask import Flask, Request, current_app, jsonify, request
from marshmallow import ValidationError
from prometheus_client import Counter, Histogram
from werkzeug.exceptions import HTTPException

# Import third-party exception types for comprehensive handling
try:
    from pymongo.errors import PyMongoError
except ImportError:
    # Fallback for testing environments without PyMongo
    class PyMongoError(Exception):
        pass

try:
    from jwt.exceptions import PyJWTError
except ImportError:
    # Fallback for testing environments without PyJWT
    class PyJWTError(Exception):
        pass

try:
    from httpx import HTTPError as HTTPXError
except ImportError:
    # Fallback for testing environments without httpx
    class HTTPXError(Exception):
        pass

try:
    from botocore.exceptions import BotoCoreError
except ImportError:
    # Fallback for testing environments without boto3
    class BotoCoreError(Exception):
        pass


# Prometheus metrics for error tracking
error_counter = Counter(
    'flask_app_errors_total',
    'Total number of application errors by type',
    ['error_type', 'error_category', 'endpoint']
)

error_response_time = Histogram(
    'flask_app_error_response_seconds',
    'Time spent processing error responses',
    ['error_type', 'error_category']
)

# Get structured logger
logger = structlog.get_logger(__name__)


class ErrorCategory(Enum):
    """Error categories for hierarchical classification per Section 5.4.2."""
    
    VALIDATION = "validation"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    BUSINESS_LOGIC = "business_logic"
    DATABASE = "database"
    EXTERNAL_SERVICE = "external_service"
    CIRCUIT_BREAKER = "circuit_breaker"
    SYSTEM = "system"
    UNKNOWN = "unknown"


class ErrorSeverity(Enum):
    """Error severity levels for monitoring and alerting."""
    
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class BaseApplicationError(Exception):
    """
    Base exception class for all application errors.
    
    Provides consistent error handling infrastructure with structured error reporting,
    logging integration, and metrics collection per Section 5.4.2.
    
    Attributes:
        message: Human-readable error message
        code: Application-specific error code
        category: Error category for classification
        severity: Error severity level
        details: Additional error context
        correlation_id: Unique identifier for error tracking
        recoverable: Whether the error condition can be retried
        user_friendly: Whether the message is safe to display to users
    """
    
    def __init__(
        self,
        message: str,
        code: str = None,
        category: ErrorCategory = ErrorCategory.UNKNOWN,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        details: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None,
        recoverable: bool = False,
        user_friendly: bool = True,
        http_status: int = 500
    ):
        super().__init__(message)
        self.message = message
        self.code = code or self.__class__.__name__
        self.category = category
        self.severity = severity
        self.details = details or {}
        self.correlation_id = correlation_id or str(uuid4())
        self.recoverable = recoverable
        self.user_friendly = user_friendly
        self.http_status = http_status
        self.timestamp = datetime.utcnow().isoformat()
        
        # Extract request context if available
        self.endpoint = getattr(request, 'endpoint', None) if request else None
        self.method = getattr(request, 'method', None) if request else None
        self.path = getattr(request, 'path', None) if request else None
        
        # Log error with structured logging
        self._log_error()
        
        # Update Prometheus metrics
        self._update_metrics()
    
    def _log_error(self) -> None:
        """Log error with structured logging per Section 5.4.1."""
        log_data = {
            'error_code': self.code,
            'error_category': self.category.value,
            'error_severity': self.severity.value,
            'correlation_id': self.correlation_id,
            'recoverable': self.recoverable,
            'http_status': self.http_status,
            'endpoint': self.endpoint,
            'method': self.method,
            'path': self.path,
            'details': self.details,
            'timestamp': self.timestamp
        }
        
        if self.severity in [ErrorSeverity.HIGH, ErrorSeverity.CRITICAL]:
            logger.error(self.message, **log_data)
        elif self.severity == ErrorSeverity.MEDIUM:
            logger.warning(self.message, **log_data)
        else:
            logger.info(self.message, **log_data)
    
    def _update_metrics(self) -> None:
        """Update Prometheus metrics for error tracking."""
        error_counter.labels(
            error_type=self.code,
            error_category=self.category.value,
            endpoint=self.endpoint or 'unknown'
        ).inc()
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert exception to dictionary format for JSON responses.
        
        Returns:
            Dictionary representation of the error
        """
        error_dict = {
            'error': True,
            'message': self.message if self.user_friendly else "An internal error occurred",
            'code': self.code,
            'category': self.category.value,
            'correlation_id': self.correlation_id,
            'timestamp': self.timestamp,
            'recoverable': self.recoverable
        }
        
        # Include details only if user-friendly or in debug mode
        if self.user_friendly or current_app.debug:
            error_dict['details'] = self.details
        
        return error_dict


class ValidationError(BaseApplicationError):
    """
    Validation error for input validation failures.
    
    Handles marshmallow.ValidationError and other input validation scenarios
    per Section 4.2.3 error handling flows.
    """
    
    def __init__(
        self,
        message: str = "Validation failed",
        field_errors: Optional[Dict[str, List[str]]] = None,
        **kwargs
    ):
        super().__init__(
            message=message,
            category=ErrorCategory.VALIDATION,
            severity=ErrorSeverity.LOW,
            http_status=400,
            user_friendly=True,
            **kwargs
        )
        self.field_errors = field_errors or {}
        if self.field_errors:
            self.details['field_errors'] = self.field_errors


class AuthenticationError(BaseApplicationError):
    """
    Authentication error for JWT and authentication failures.
    
    Handles jwt.exceptions.PyJWTError and authentication scenarios
    per Section 4.2.3 error handling flows.
    """
    
    def __init__(
        self,
        message: str = "Authentication failed",
        **kwargs
    ):
        super().__init__(
            message=message,
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.MEDIUM,
            http_status=401,
            user_friendly=True,
            **kwargs
        )


class AuthorizationError(BaseApplicationError):
    """
    Authorization error for permission and access control failures.
    
    Handles PermissionError and authorization scenarios
    per Section 4.2.3 error handling flows.
    """
    
    def __init__(
        self,
        message: str = "Access denied",
        required_permissions: Optional[List[str]] = None,
        **kwargs
    ):
        super().__init__(
            message=message,
            category=ErrorCategory.AUTHORIZATION,
            severity=ErrorSeverity.MEDIUM,
            http_status=403,
            user_friendly=True,
            **kwargs
        )
        if required_permissions:
            self.details['required_permissions'] = required_permissions


class BusinessLogicError(BaseApplicationError):
    """
    Business logic error for application-specific business rule violations.
    
    Handles business logic errors per Section 4.2.3 error handling flows.
    """
    
    def __init__(
        self,
        message: str = "Business logic error",
        business_rule: Optional[str] = None,
        **kwargs
    ):
        super().__init__(
            message=message,
            category=ErrorCategory.BUSINESS_LOGIC,
            severity=ErrorSeverity.MEDIUM,
            http_status=422,
            user_friendly=True,
            recoverable=True,
            **kwargs
        )
        if business_rule:
            self.details['business_rule'] = business_rule


class DatabaseError(BaseApplicationError):
    """
    Database error for MongoDB and database operation failures.
    
    Handles pymongo.errors.PyMongoError scenarios per Section 4.2.3 error handling flows.
    """
    
    def __init__(
        self,
        message: str = "Database operation failed",
        operation: Optional[str] = None,
        collection: Optional[str] = None,
        **kwargs
    ):
        super().__init__(
            message=message,
            category=ErrorCategory.DATABASE,
            severity=ErrorSeverity.HIGH,
            http_status=503,
            user_friendly=False,
            recoverable=True,
            **kwargs
        )
        if operation:
            self.details['operation'] = operation
        if collection:
            self.details['collection'] = collection


class ExternalServiceError(BaseApplicationError):
    """
    External service error for HTTP client and third-party service failures.
    
    Handles httpx.HTTPError and boto3.exceptions scenarios per Section 4.2.3 error handling flows.
    """
    
    def __init__(
        self,
        message: str = "External service unavailable",
        service_name: Optional[str] = None,
        status_code: Optional[int] = None,
        **kwargs
    ):
        super().__init__(
            message=message,
            category=ErrorCategory.EXTERNAL_SERVICE,
            severity=ErrorSeverity.HIGH,
            http_status=502,
            user_friendly=False,
            recoverable=True,
            **kwargs
        )
        if service_name:
            self.details['service_name'] = service_name
        if status_code:
            self.details['service_status_code'] = status_code


class CircuitBreakerError(BaseApplicationError):
    """
    Circuit breaker error for service protection and fallback scenarios.
    
    Handles circuit breaker patterns per Section 5.4.2 error recovery mechanisms.
    """
    
    def __init__(
        self,
        message: str = "Service temporarily unavailable",
        service_name: Optional[str] = None,
        circuit_state: Optional[str] = None,
        **kwargs
    ):
        super().__init__(
            message=message,
            category=ErrorCategory.CIRCUIT_BREAKER,
            severity=ErrorSeverity.HIGH,
            http_status=503,
            user_friendly=True,
            recoverable=True,
            **kwargs
        )
        if service_name:
            self.details['service_name'] = service_name
        if circuit_state:
            self.details['circuit_state'] = circuit_state


class SystemError(BaseApplicationError):
    """
    System error for infrastructure and system-level failures.
    
    Handles system-level errors and infrastructure failures.
    """
    
    def __init__(
        self,
        message: str = "System error occurred",
        **kwargs
    ):
        super().__init__(
            message=message,
            category=ErrorCategory.SYSTEM,
            severity=ErrorSeverity.CRITICAL,
            http_status=500,
            user_friendly=False,
            recoverable=False,
            **kwargs
        )


def format_error_response(
    error: Union[BaseApplicationError, Exception],
    include_traceback: bool = False
) -> Dict[str, Any]:
    """
    Format error response for consistent API error responses.
    
    Args:
        error: Exception to format
        include_traceback: Whether to include stack trace (debug mode only)
    
    Returns:
        Formatted error response dictionary
    """
    if isinstance(error, BaseApplicationError):
        response = error.to_dict()
    else:
        # Handle unexpected errors
        correlation_id = str(uuid4())
        response = {
            'error': True,
            'message': "An unexpected error occurred",
            'code': error.__class__.__name__,
            'category': ErrorCategory.UNKNOWN.value,
            'correlation_id': correlation_id,
            'timestamp': datetime.utcnow().isoformat(),
            'recoverable': False
        }
        
        # Log unexpected error
        logger.error(
            str(error),
            error_code=error.__class__.__name__,
            error_category=ErrorCategory.UNKNOWN.value,
            correlation_id=correlation_id,
            exception_type=error.__class__.__name__
        )
        
        # Update metrics for unexpected errors
        error_counter.labels(
            error_type=error.__class__.__name__,
            error_category=ErrorCategory.UNKNOWN.value,
            endpoint=getattr(request, 'endpoint', 'unknown') if request else 'unknown'
        ).inc()
    
    # Include traceback in debug mode
    if include_traceback and current_app.debug:
        response['traceback'] = traceback.format_exc()
    
    return response


def register_error_handlers(app: Flask) -> None:
    """
    Register Flask error handlers for comprehensive error management.
    
    Implements Flask @errorhandler decorators per Section 4.2.3 error handling flows.
    
    Args:
        app: Flask application instance
    """
    
    @app.errorhandler(ValidationError)
    def handle_validation_error(error: ValidationError):
        """Handle validation errors with structured response."""
        with error_response_time.labels(
            error_type=error.code,
            error_category=error.category.value
        ).time():
            response = jsonify(format_error_response(error))
            response.status_code = error.http_status
            return response
    
    @app.errorhandler(AuthenticationError)
    def handle_authentication_error(error: AuthenticationError):
        """Handle authentication errors with structured response."""
        with error_response_time.labels(
            error_type=error.code,
            error_category=error.category.value
        ).time():
            response = jsonify(format_error_response(error))
            response.status_code = error.http_status
            return response
    
    @app.errorhandler(AuthorizationError)
    def handle_authorization_error(error: AuthorizationError):
        """Handle authorization errors with structured response."""
        with error_response_time.labels(
            error_type=error.code,
            error_category=error.category.value
        ).time():
            response = jsonify(format_error_response(error))
            response.status_code = error.http_status
            return response
    
    @app.errorhandler(BusinessLogicError)
    def handle_business_logic_error(error: BusinessLogicError):
        """Handle business logic errors with structured response."""
        with error_response_time.labels(
            error_type=error.code,
            error_category=error.category.value
        ).time():
            response = jsonify(format_error_response(error))
            response.status_code = error.http_status
            return response
    
    @app.errorhandler(DatabaseError)
    def handle_database_error(error: DatabaseError):
        """Handle database errors with structured response."""
        with error_response_time.labels(
            error_type=error.code,
            error_category=error.category.value
        ).time():
            response = jsonify(format_error_response(error))
            response.status_code = error.http_status
            return response
    
    @app.errorhandler(ExternalServiceError)
    def handle_external_service_error(error: ExternalServiceError):
        """Handle external service errors with structured response."""
        with error_response_time.labels(
            error_type=error.code,
            error_category=error.category.value
        ).time():
            response = jsonify(format_error_response(error))
            response.status_code = error.http_status
            return response
    
    @app.errorhandler(CircuitBreakerError)
    def handle_circuit_breaker_error(error: CircuitBreakerError):
        """Handle circuit breaker errors with structured response."""
        with error_response_time.labels(
            error_type=error.code,
            error_category=error.category.value
        ).time():
            response = jsonify(format_error_response(error))
            response.status_code = error.http_status
            return response
    
    @app.errorhandler(SystemError)
    def handle_system_error(error: SystemError):
        """Handle system errors with structured response."""
        with error_response_time.labels(
            error_type=error.code,
            error_category=error.category.value
        ).time():
            response = jsonify(format_error_response(error))
            response.status_code = error.http_status
            return response
    
    # Handle third-party exceptions with proper conversion
    @app.errorhandler(ValidationError)
    def handle_marshmallow_validation_error(error: ValidationError):
        """Handle marshmallow validation errors."""
        app_error = ValidationError(
            message="Request validation failed",
            field_errors=error.messages if hasattr(error, 'messages') else {}
        )
        return handle_validation_error(app_error)
    
    @app.errorhandler(PyJWTError)
    def handle_jwt_error(error: PyJWTError):
        """Handle PyJWT authentication errors."""
        app_error = AuthenticationError(
            message="Invalid or expired token",
            details={'jwt_error': str(error)}
        )
        return handle_authentication_error(app_error)
    
    @app.errorhandler(PermissionError)
    def handle_permission_error(error: PermissionError):
        """Handle permission errors."""
        app_error = AuthorizationError(
            message="Insufficient permissions",
            details={'permission_error': str(error)}
        )
        return handle_authorization_error(app_error)
    
    @app.errorhandler(PyMongoError)
    def handle_pymongo_error(error: PyMongoError):
        """Handle PyMongo database errors."""
        app_error = DatabaseError(
            message="Database operation failed",
            details={'database_error': str(error)}
        )
        return handle_database_error(app_error)
    
    @app.errorhandler(HTTPXError)
    def handle_httpx_error(error: HTTPXError):
        """Handle HTTPX client errors."""
        app_error = ExternalServiceError(
            message="External service request failed",
            details={'http_error': str(error)}
        )
        return handle_external_service_error(app_error)
    
    @app.errorhandler(BotoCoreError)
    def handle_boto_error(error: BotoCoreError):
        """Handle boto3/botocore AWS service errors."""
        app_error = ExternalServiceError(
            message="AWS service request failed",
            service_name="aws",
            details={'aws_error': str(error)}
        )
        return handle_external_service_error(app_error)
    
    @app.errorhandler(HTTPException)
    def handle_http_exception(error: HTTPException):
        """Handle Werkzeug HTTP exceptions."""
        # Convert Werkzeug exceptions to application errors
        if error.code == 400:
            app_error = ValidationError(message=error.description or "Bad request")
        elif error.code == 401:
            app_error = AuthenticationError(message=error.description or "Unauthorized")
        elif error.code == 403:
            app_error = AuthorizationError(message=error.description or "Forbidden")
        elif error.code == 404:
            app_error = BusinessLogicError(
                message=error.description or "Resource not found",
                http_status=404
            )
        else:
            app_error = SystemError(
                message=error.description or "HTTP error",
                http_status=error.code or 500
            )
        
        return jsonify(format_error_response(app_error)), app_error.http_status
    
    @app.errorhandler(Exception)
    def handle_generic_exception(error: Exception):
        """Handle all other unexpected exceptions."""
        app_error = SystemError(
            message="An unexpected error occurred",
            details={'exception_type': error.__class__.__name__}
        )
        
        # Log full traceback for debugging
        logger.exception(
            "Unexpected exception occurred",
            error_code=app_error.code,
            correlation_id=app_error.correlation_id,
            exception_type=error.__class__.__name__
        )
        
        with error_response_time.labels(
            error_type=app_error.code,
            error_category=app_error.category.value
        ).time():
            response = jsonify(format_error_response(app_error, include_traceback=True))
            response.status_code = app_error.http_status
            return response


def create_error_context(
    operation: str,
    details: Optional[Dict[str, Any]] = None,
    correlation_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create error context for consistent error reporting.
    
    Args:
        operation: Name of the operation that failed
        details: Additional context details
        correlation_id: Optional correlation ID for tracking
    
    Returns:
        Error context dictionary
    """
    context = {
        'operation': operation,
        'timestamp': datetime.utcnow().isoformat(),
        'correlation_id': correlation_id or str(uuid4())
    }
    
    if details:
        context.update(details)
    
    return context


def safe_str(value: Any, max_length: int = 1000) -> str:
    """
    Safely convert value to string with length limits for error messages.
    
    Args:
        value: Value to convert to string
        max_length: Maximum string length
    
    Returns:
        Safe string representation
    """
    try:
        str_value = str(value)
        if len(str_value) > max_length:
            return str_value[:max_length] + "..."
        return str_value
    except Exception:
        return "<unable to convert to string>"


# Exception hierarchy for easy imports
__all__ = [
    'BaseApplicationError',
    'ValidationError',
    'AuthenticationError', 
    'AuthorizationError',
    'BusinessLogicError',
    'DatabaseError',
    'ExternalServiceError',
    'CircuitBreakerError',
    'SystemError',
    'ErrorCategory',
    'ErrorSeverity',
    'format_error_response',
    'register_error_handlers',
    'create_error_context',
    'safe_str'
]