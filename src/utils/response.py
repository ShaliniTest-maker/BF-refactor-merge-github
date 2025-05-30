"""
Standardized API response formatting utilities providing consistent JSON response structures,
error formatting, and status code management for Flask applications.

This module implements enterprise-grade response patterns maintaining 100% compatibility 
with existing API contracts and response formats. It provides standardized utilities for 
creating consistent API responses, handling errors, and ensuring proper HTTP status code 
management throughout the Flask application.

Key Features:
- Standardized JSON response structures preserving existing field names and data types
- Hierarchical error response formatting maintaining existing error codes and formats
- HTTP status code management preserving method support and API contracts
- Business logic integration support for consistent output formatting
- Enterprise-grade logging and monitoring integration
- Performance-optimized response creation with caching support
- Comprehensive type hints and validation support

Response Format Standards:
- Success responses follow standardized structure with data, metadata, and status
- Error responses maintain hierarchical error processing patterns
- All responses preserve ISO 8601 date formatting and timezone awareness
- JSON serialization uses enhanced encoding supporting enterprise data types
"""

import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union, Tuple, Type
from http import HTTPStatus
import logging
import traceback
from flask import Flask, Response, jsonify, request, g
from werkzeug.exceptions import HTTPException

from .json_utils import dumps, EnterpriseJSONEncoder

# Configure structured logging
logger = logging.getLogger(__name__)


class APIResponse:
    """
    Standardized API response container providing consistent structure and formatting
    for all API endpoints. Maintains 100% compatibility with existing Node.js response
    formats while providing enhanced enterprise functionality.
    """
    
    def __init__(self, 
                 data: Any = None,
                 message: Optional[str] = None,
                 status_code: int = 200,
                 success: bool = True,
                 errors: Optional[List[Dict[str, Any]]] = None,
                 metadata: Optional[Dict[str, Any]] = None,
                 pagination: Optional[Dict[str, Any]] = None,
                 links: Optional[Dict[str, str]] = None):
        """
        Initialize API response with standardized structure.
        
        Args:
            data: Response payload data
            message: Human-readable response message
            status_code: HTTP status code
            success: Boolean indicating success/failure status
            errors: List of error objects for failed responses
            metadata: Additional response metadata
            pagination: Pagination information for collection responses
            links: HATEOAS links for related resources
        """
        self.data = data
        self.message = message
        self.status_code = status_code
        self.success = success
        self.errors = errors or []
        self.metadata = metadata or {}
        self.pagination = pagination
        self.links = links
        
        # Add response timing for performance monitoring
        self.timestamp = datetime.now(timezone.utc).isoformat()
        
        # Include request correlation ID if available
        if hasattr(g, 'request_id'):
            self.metadata['request_id'] = g.request_id
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert response to dictionary format maintaining API contract compatibility.
        
        Returns:
            Dictionary representation suitable for JSON serialization
        """
        response_dict = {
            'success': self.success,
            'status': self.status_code,
            'timestamp': self.timestamp
        }
        
        # Include data for successful responses or when explicitly provided
        if self.data is not None:
            response_dict['data'] = self.data
        
        # Include message if provided
        if self.message:
            response_dict['message'] = self.message
        
        # Include errors for failed responses
        if self.errors:
            response_dict['errors'] = self.errors
        
        # Include metadata if provided
        if self.metadata:
            response_dict['metadata'] = self.metadata
        
        # Include pagination for collection responses
        if self.pagination:
            response_dict['pagination'] = self.pagination
        
        # Include HATEOAS links if provided
        if self.links:
            response_dict['_links'] = self.links
        
        return response_dict
    
    def to_flask_response(self) -> Response:
        """
        Convert to Flask Response object with proper headers and formatting.
        
        Returns:
            Flask Response object ready for return from endpoint handlers
        """
        response_data = self.to_dict()
        
        # Use enterprise JSON encoder for consistent serialization
        json_str = dumps(response_data, cls=EnterpriseJSONEncoder, ensure_ascii=False)
        
        response = Response(
            response=json_str,
            status=self.status_code,
            mimetype='application/json'
        )
        
        # Add standard security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Add cache headers for appropriate responses
        if self.status_code == 200 and request.method == 'GET':
            response.headers['Cache-Control'] = 'public, max-age=300'
        else:
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        
        return response


class ErrorDetail:
    """
    Standardized error detail container for consistent error reporting across
    all error types and hierarchical error processing patterns.
    """
    
    def __init__(self,
                 code: str,
                 message: str,
                 field: Optional[str] = None,
                 location: Optional[str] = None,
                 details: Optional[Dict[str, Any]] = None,
                 error_type: str = "general"):
        """
        Initialize error detail with comprehensive error information.
        
        Args:
            code: Error code for programmatic handling
            message: Human-readable error message
            field: Field name for validation errors
            location: Error location (body, query, path, header)
            details: Additional error context
            error_type: Error category (validation, authentication, business, database, service)
        """
        self.code = code
        self.message = message
        self.field = field
        self.location = location
        self.details = details or {}
        self.error_type = error_type
        self.timestamp = datetime.now(timezone.utc).isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert error detail to dictionary format for JSON serialization.
        
        Returns:
            Dictionary representation maintaining error format compatibility
        """
        error_dict = {
            'code': self.code,
            'message': self.message,
            'type': self.error_type,
            'timestamp': self.timestamp
        }
        
        if self.field:
            error_dict['field'] = self.field
        
        if self.location:
            error_dict['location'] = self.location
        
        if self.details:
            error_dict['details'] = self.details
        
        return error_dict


# HTTP Status Code Constants for consistent usage
class APIStatus:
    """
    HTTP status code constants providing consistent status code usage
    throughout the application while maintaining API contract compatibility.
    """
    
    # Success codes
    OK = 200
    CREATED = 201
    ACCEPTED = 202
    NO_CONTENT = 204
    
    # Redirect codes
    MOVED_PERMANENTLY = 301
    FOUND = 302
    NOT_MODIFIED = 304
    
    # Client error codes
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    METHOD_NOT_ALLOWED = 405
    NOT_ACCEPTABLE = 406
    CONFLICT = 409
    GONE = 410
    UNPROCESSABLE_ENTITY = 422
    TOO_MANY_REQUESTS = 429
    
    # Server error codes
    INTERNAL_SERVER_ERROR = 500
    NOT_IMPLEMENTED = 501
    BAD_GATEWAY = 502
    SERVICE_UNAVAILABLE = 503
    GATEWAY_TIMEOUT = 504


def create_success_response(data: Any = None,
                          message: Optional[str] = None,
                          status_code: int = APIStatus.OK,
                          metadata: Optional[Dict[str, Any]] = None,
                          pagination: Optional[Dict[str, Any]] = None,
                          links: Optional[Dict[str, str]] = None) -> APIResponse:
    """
    Create standardized success response maintaining API contract compatibility.
    
    Args:
        data: Response payload data
        message: Success message
        status_code: HTTP status code (default: 200)
        metadata: Additional response metadata
        pagination: Pagination information for collection responses
        links: HATEOAS links for related resources
    
    Returns:
        APIResponse object ready for conversion to Flask response
        
    Examples:
        >>> response = create_success_response({'user': {'id': 1, 'name': 'John'}})
        >>> response = create_success_response(
        ...     data=users_list,
        ...     pagination={'page': 1, 'total': 100, 'per_page': 10}
        ... )
    """
    logger.debug(f"Creating success response with status {status_code}")
    
    return APIResponse(
        data=data,
        message=message,
        status_code=status_code,
        success=True,
        metadata=metadata,
        pagination=pagination,
        links=links
    )


def create_error_response(errors: Union[List[ErrorDetail], List[Dict[str, Any]], ErrorDetail, str],
                         message: Optional[str] = None,
                         status_code: int = APIStatus.BAD_REQUEST,
                         metadata: Optional[Dict[str, Any]] = None) -> APIResponse:
    """
    Create standardized error response maintaining hierarchical error processing patterns
    and existing error code compatibility.
    
    Args:
        errors: Error details (single error, list of errors, or error message)
        message: Primary error message
        status_code: HTTP status code (default: 400)
        metadata: Additional error context
    
    Returns:
        APIResponse object with standardized error formatting
        
    Examples:
        >>> error = ErrorDetail('VALIDATION_ERROR', 'Invalid email format', 'email')
        >>> response = create_error_response(error, status_code=422)
        
        >>> errors = [
        ...     ErrorDetail('REQUIRED_FIELD', 'Name is required', 'name'),
        ...     ErrorDetail('INVALID_FORMAT', 'Invalid email', 'email')
        ... ]
        >>> response = create_error_response(errors, 'Validation failed', 422)
    """
    logger.warning(f"Creating error response with status {status_code}: {message}")
    
    # Normalize errors to list of dictionaries
    normalized_errors = []
    
    if isinstance(errors, str):
        # Simple string error message
        error_detail = ErrorDetail(
            code='GENERAL_ERROR',
            message=errors,
            error_type='general'
        )
        normalized_errors.append(error_detail.to_dict())
    elif isinstance(errors, ErrorDetail):
        # Single ErrorDetail object
        normalized_errors.append(errors.to_dict())
    elif isinstance(errors, list):
        # List of errors (mixed types supported)
        for error in errors:
            if isinstance(error, ErrorDetail):
                normalized_errors.append(error.to_dict())
            elif isinstance(error, dict):
                normalized_errors.append(error)
            else:
                # Convert other types to string
                error_detail = ErrorDetail(
                    code='GENERAL_ERROR',
                    message=str(error),
                    error_type='general'
                )
                normalized_errors.append(error_detail.to_dict())
    
    return APIResponse(
        data=None,
        message=message,
        status_code=status_code,
        success=False,
        errors=normalized_errors,
        metadata=metadata
    )


def create_validation_error_response(validation_errors: List[Dict[str, Any]],
                                   message: str = "Validation failed") -> APIResponse:
    """
    Create standardized validation error response for input validation failures.
    Maintains compatibility with existing validation error formats.
    
    Args:
        validation_errors: List of validation error details
        message: Primary validation error message
    
    Returns:
        APIResponse with validation error formatting
        
    Examples:
        >>> errors = [
        ...     {'field': 'email', 'message': 'Invalid email format'},
        ...     {'field': 'password', 'message': 'Password too short'}
        ... ]
        >>> response = create_validation_error_response(errors)
    """
    logger.info(f"Creating validation error response: {len(validation_errors)} errors")
    
    error_details = []
    for error in validation_errors:
        error_detail = ErrorDetail(
            code=error.get('code', 'VALIDATION_ERROR'),
            message=error.get('message', 'Validation failed'),
            field=error.get('field'),
            location=error.get('location', 'body'),
            details=error.get('details'),
            error_type='validation'
        )
        error_details.append(error_detail)
    
    return create_error_response(
        errors=error_details,
        message=message,
        status_code=APIStatus.UNPROCESSABLE_ENTITY
    )


def create_authentication_error_response(message: str = "Authentication required",
                                       code: str = "AUTHENTICATION_REQUIRED") -> APIResponse:
    """
    Create standardized authentication error response for auth failures.
    
    Args:
        message: Authentication error message
        code: Error code for programmatic handling
    
    Returns:
        APIResponse with authentication error formatting
    """
    logger.warning(f"Creating authentication error response: {message}")
    
    error_detail = ErrorDetail(
        code=code,
        message=message,
        error_type='authentication'
    )
    
    return create_error_response(
        errors=[error_detail],
        message=message,
        status_code=APIStatus.UNAUTHORIZED
    )


def create_authorization_error_response(message: str = "Insufficient permissions",
                                      code: str = "INSUFFICIENT_PERMISSIONS") -> APIResponse:
    """
    Create standardized authorization error response for permission failures.
    
    Args:
        message: Authorization error message
        code: Error code for programmatic handling
    
    Returns:
        APIResponse with authorization error formatting
    """
    logger.warning(f"Creating authorization error response: {message}")
    
    error_detail = ErrorDetail(
        code=code,
        message=message,
        error_type='authorization'
    )
    
    return create_error_response(
        errors=[error_detail],
        message=message,
        status_code=APIStatus.FORBIDDEN
    )


def create_business_error_response(message: str,
                                 code: str = "BUSINESS_RULE_VIOLATION",
                                 details: Optional[Dict[str, Any]] = None) -> APIResponse:
    """
    Create standardized business logic error response for business rule violations.
    
    Args:
        message: Business error message
        code: Business error code
        details: Additional business context
    
    Returns:
        APIResponse with business error formatting
    """
    logger.info(f"Creating business error response: {code} - {message}")
    
    error_detail = ErrorDetail(
        code=code,
        message=message,
        details=details,
        error_type='business'
    )
    
    return create_error_response(
        errors=[error_detail],
        message=message,
        status_code=APIStatus.BAD_REQUEST
    )


def create_database_error_response(message: str = "Database operation failed",
                                 code: str = "DATABASE_ERROR",
                                 operation: Optional[str] = None) -> APIResponse:
    """
    Create standardized database error response for database operation failures.
    
    Args:
        message: Database error message
        code: Database error code
        operation: Database operation that failed
    
    Returns:
        APIResponse with database error formatting
    """
    logger.error(f"Creating database error response: {code} - {message}")
    
    details = {}
    if operation:
        details['operation'] = operation
    
    error_detail = ErrorDetail(
        code=code,
        message=message,
        details=details,
        error_type='database'
    )
    
    return create_error_response(
        errors=[error_detail],
        message=message,
        status_code=APIStatus.INTERNAL_SERVER_ERROR
    )


def create_external_service_error_response(service_name: str,
                                         message: str = "External service unavailable",
                                         code: str = "EXTERNAL_SERVICE_ERROR",
                                         status_code: int = APIStatus.BAD_GATEWAY) -> APIResponse:
    """
    Create standardized external service error response for service communication failures.
    
    Args:
        service_name: Name of the external service
        message: Service error message
        code: Service error code
        status_code: HTTP status code (default: 502)
    
    Returns:
        APIResponse with external service error formatting
    """
    logger.error(f"Creating external service error response for {service_name}: {message}")
    
    error_detail = ErrorDetail(
        code=code,
        message=message,
        details={'service': service_name},
        error_type='external_service'
    )
    
    return create_error_response(
        errors=[error_detail],
        message=f"{service_name}: {message}",
        status_code=status_code
    )


def create_not_found_response(resource: str = "Resource",
                            resource_id: Optional[str] = None) -> APIResponse:
    """
    Create standardized not found error response.
    
    Args:
        resource: Type of resource not found
        resource_id: ID of the resource (if applicable)
    
    Returns:
        APIResponse with not found error formatting
    """
    if resource_id:
        message = f"{resource} with ID '{resource_id}' not found"
    else:
        message = f"{resource} not found"
    
    logger.info(f"Creating not found response: {message}")
    
    error_detail = ErrorDetail(
        code='NOT_FOUND',
        message=message,
        details={'resource': resource, 'resource_id': resource_id} if resource_id else {'resource': resource},
        error_type='not_found'
    )
    
    return create_error_response(
        errors=[error_detail],
        message=message,
        status_code=APIStatus.NOT_FOUND
    )


def create_conflict_response(message: str,
                           code: str = "RESOURCE_CONFLICT",
                           details: Optional[Dict[str, Any]] = None) -> APIResponse:
    """
    Create standardized conflict error response for resource conflicts.
    
    Args:
        message: Conflict error message
        code: Conflict error code
        details: Additional conflict context
    
    Returns:
        APIResponse with conflict error formatting
    """
    logger.warning(f"Creating conflict response: {code} - {message}")
    
    error_detail = ErrorDetail(
        code=code,
        message=message,
        details=details,
        error_type='conflict'
    )
    
    return create_error_response(
        errors=[error_detail],
        message=message,
        status_code=APIStatus.CONFLICT
    )


def create_rate_limit_response(retry_after: Optional[int] = None) -> APIResponse:
    """
    Create standardized rate limit error response.
    
    Args:
        retry_after: Seconds to wait before retrying
    
    Returns:
        APIResponse with rate limit error formatting
    """
    message = "Rate limit exceeded"
    if retry_after:
        message += f". Retry after {retry_after} seconds"
    
    logger.warning(f"Creating rate limit response: {message}")
    
    error_detail = ErrorDetail(
        code='RATE_LIMIT_EXCEEDED',
        message=message,
        details={'retry_after': retry_after} if retry_after else {},
        error_type='rate_limit'
    )
    
    metadata = {}
    if retry_after:
        metadata['retry_after'] = retry_after
    
    return create_error_response(
        errors=[error_detail],
        message=message,
        status_code=APIStatus.TOO_MANY_REQUESTS,
        metadata=metadata
    )


def create_pagination_metadata(page: int,
                             per_page: int,
                             total: int,
                             has_next: bool = None,
                             has_prev: bool = None) -> Dict[str, Any]:
    """
    Create standardized pagination metadata for collection responses.
    
    Args:
        page: Current page number
        per_page: Items per page
        total: Total number of items
        has_next: Whether there is a next page
        has_prev: Whether there is a previous page
    
    Returns:
        Dictionary containing pagination metadata
    """
    total_pages = (total + per_page - 1) // per_page  # Ceiling division
    
    if has_next is None:
        has_next = page < total_pages
    
    if has_prev is None:
        has_prev = page > 1
    
    return {
        'page': page,
        'per_page': per_page,
        'total': total,
        'total_pages': total_pages,
        'has_next': has_next,
        'has_prev': has_prev,
        'next_page': page + 1 if has_next else None,
        'prev_page': page - 1 if has_prev else None
    }


def create_paginated_response(data: List[Any],
                            page: int,
                            per_page: int,
                            total: int,
                            message: Optional[str] = None,
                            metadata: Optional[Dict[str, Any]] = None) -> APIResponse:
    """
    Create standardized paginated collection response.
    
    Args:
        data: List of items for current page
        page: Current page number
        per_page: Items per page
        total: Total number of items
        message: Optional success message
        metadata: Additional response metadata
    
    Returns:
        APIResponse with pagination support
    """
    pagination_meta = create_pagination_metadata(page, per_page, total)
    
    response_metadata = metadata or {}
    response_metadata.update({
        'collection_size': len(data),
        'page_info': pagination_meta
    })
    
    return create_success_response(
        data=data,
        message=message,
        metadata=response_metadata,
        pagination=pagination_meta
    )


def handle_flask_exception(error: Exception) -> APIResponse:
    """
    Convert Flask/Werkzeug exceptions to standardized API responses.
    Maintains compatibility with existing error handling patterns.
    
    Args:
        error: Exception to convert
    
    Returns:
        APIResponse with appropriate error formatting
    """
    if isinstance(error, HTTPException):
        # Handle HTTP exceptions (400, 404, 500, etc.)
        error_detail = ErrorDetail(
            code=f"HTTP_{error.code}",
            message=error.description or HTTPStatus(error.code).phrase,
            error_type='http'
        )
        
        return create_error_response(
            errors=[error_detail],
            message=error.description or "HTTP error occurred",
            status_code=error.code
        )
    else:
        # Handle unexpected exceptions
        logger.error(f"Unhandled exception: {type(error).__name__}: {str(error)}")
        logger.error(f"Exception traceback: {traceback.format_exc()}")
        
        error_detail = ErrorDetail(
            code='INTERNAL_ERROR',
            message="An unexpected error occurred",
            details={'exception_type': type(error).__name__},
            error_type='internal'
        )
        
        return create_error_response(
            errors=[error_detail],
            message="Internal server error",
            status_code=APIStatus.INTERNAL_SERVER_ERROR
        )


def json_response(data: Any = None,
                 message: Optional[str] = None,
                 status_code: int = APIStatus.OK,
                 headers: Optional[Dict[str, str]] = None) -> Response:
    """
    Create Flask JSON response with standardized formatting and enhanced JSON encoding.
    Direct alternative to Flask's jsonify with enterprise features.
    
    Args:
        data: Response data
        message: Response message
        status_code: HTTP status code
        headers: Additional response headers
    
    Returns:
        Flask Response object with JSON content
    """
    if data is None and message is None:
        response_data = {'success': True, 'status': status_code}
    elif isinstance(data, APIResponse):
        response_data = data.to_dict()
        status_code = data.status_code
    else:
        api_response = create_success_response(data, message, status_code)
        response_data = api_response.to_dict()
    
    # Use enterprise JSON encoder
    json_str = dumps(response_data, cls=EnterpriseJSONEncoder, ensure_ascii=False)
    
    response = Response(
        response=json_str,
        status=status_code,
        mimetype='application/json'
    )
    
    # Add security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Add custom headers if provided
    if headers:
        for key, value in headers.items():
            response.headers[key] = value
    
    return response


def register_error_handlers(app: Flask) -> None:
    """
    Register standardized error handlers with Flask application for consistent
    error response formatting across all endpoints.
    
    Args:
        app: Flask application instance
    """
    
    @app.errorhandler(400)
    def handle_bad_request(error):
        """Handle 400 Bad Request errors."""
        api_response = create_error_response(
            errors="Bad request",
            message="The request was invalid",
            status_code=400
        )
        return api_response.to_flask_response()
    
    @app.errorhandler(401)
    def handle_unauthorized(error):
        """Handle 401 Unauthorized errors."""
        api_response = create_authentication_error_response()
        return api_response.to_flask_response()
    
    @app.errorhandler(403)
    def handle_forbidden(error):
        """Handle 403 Forbidden errors."""
        api_response = create_authorization_error_response()
        return api_response.to_flask_response()
    
    @app.errorhandler(404)
    def handle_not_found(error):
        """Handle 404 Not Found errors."""
        api_response = create_not_found_response("Resource")
        return api_response.to_flask_response()
    
    @app.errorhandler(405)
    def handle_method_not_allowed(error):
        """Handle 405 Method Not Allowed errors."""
        api_response = create_error_response(
            errors="Method not allowed",
            message="The request method is not supported for this endpoint",
            status_code=405
        )
        return api_response.to_flask_response()
    
    @app.errorhandler(422)
    def handle_unprocessable_entity(error):
        """Handle 422 Unprocessable Entity errors."""
        api_response = create_validation_error_response(
            [{'message': 'The request data was invalid'}]
        )
        return api_response.to_flask_response()
    
    @app.errorhandler(429)
    def handle_rate_limit_exceeded(error):
        """Handle 429 Too Many Requests errors."""
        api_response = create_rate_limit_response()
        return api_response.to_flask_response()
    
    @app.errorhandler(500)
    def handle_internal_server_error(error):
        """Handle 500 Internal Server Error."""
        api_response = handle_flask_exception(error)
        return api_response.to_flask_response()
    
    @app.errorhandler(502)
    def handle_bad_gateway(error):
        """Handle 502 Bad Gateway errors."""
        api_response = create_external_service_error_response(
            service_name="External Service",
            message="External service unavailable",
            status_code=502
        )
        return api_response.to_flask_response()
    
    @app.errorhandler(503)
    def handle_service_unavailable(error):
        """Handle 503 Service Unavailable errors."""
        api_response = create_error_response(
            errors="Service temporarily unavailable",
            message="The service is temporarily unavailable",
            status_code=503
        )
        return api_response.to_flask_response()
    
    @app.errorhandler(Exception)
    def handle_unexpected_error(error):
        """Handle all other unexpected exceptions."""
        api_response = handle_flask_exception(error)
        return api_response.to_flask_response()


# Convenience aliases for backward compatibility and ease of use
success_response = create_success_response
error_response = create_error_response
validation_error = create_validation_error_response
auth_error = create_authentication_error_response
permission_error = create_authorization_error_response
business_error = create_business_error_response
not_found = create_not_found_response
conflict_error = create_conflict_response
rate_limit_error = create_rate_limit_response
paginated_response = create_paginated_response


# Export all public functions and classes
__all__ = [
    'APIResponse',
    'ErrorDetail',
    'APIStatus',
    'create_success_response',
    'create_error_response',
    'create_validation_error_response',
    'create_authentication_error_response',
    'create_authorization_error_response',
    'create_business_error_response',
    'create_database_error_response',
    'create_external_service_error_response',
    'create_not_found_response',
    'create_conflict_response',
    'create_rate_limit_response',
    'create_pagination_metadata',
    'create_paginated_response',
    'handle_flask_exception',
    'json_response',
    'register_error_handlers',
    # Convenience aliases
    'success_response',
    'error_response',
    'validation_error',
    'auth_error',
    'permission_error',
    'business_error',
    'not_found',
    'conflict_error',
    'rate_limit_error',
    'paginated_response',
]