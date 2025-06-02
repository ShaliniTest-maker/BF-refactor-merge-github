"""
Standardized API response formatting utilities providing consistent JSON response structures,
error formatting, and status code management.

Implements enterprise-grade response patterns maintaining 100% compatibility with existing 
API contracts and response formats per Section 0.1.4 API contracts and interfaces.

This module implements:
- Standardized response formatting maintaining API contract compatibility per Section 0.1.4
- JSON response structures preserving existing field names and data types per Section 0.1.4
- Error response formatting maintaining existing error codes per Section 5.4.2
- Response utilities supporting consistent business logic output per Section 5.2.4
- HTTP status code management preserving existing API behavior per Section 2.2.5
- Enterprise monitoring integration for response tracking per Section 5.4.1
"""

import logging
import traceback
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union, Tuple
from enum import Enum
from http import HTTPStatus
from flask import Request, jsonify, current_app
import uuid

# Import JSON utilities for enhanced serialization and enterprise data type support
from .json_utils import (
    JSONProcessor,
    create_api_response,
    create_error_response,
    paginate_response,
    filter_sensitive_json,
    to_json_compatible
)

# Configure structured logging for enterprise integration
logger = logging.getLogger(__name__)


class ResponseStatus(Enum):
    """
    Response status enumeration providing standardized status indicators
    for consistent API response classification.
    """
    SUCCESS = "success"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
    PARTIAL = "partial"


class ErrorCode(Enum):
    """
    Standardized error codes maintaining compatibility with existing 
    Node.js implementation patterns.
    """
    # Authentication and Authorization Errors
    UNAUTHORIZED = "AUTH_001"
    FORBIDDEN = "AUTH_002"
    TOKEN_EXPIRED = "AUTH_003"
    INVALID_TOKEN = "AUTH_004"
    INSUFFICIENT_PERMISSIONS = "AUTH_005"
    
    # Validation Errors
    VALIDATION_ERROR = "VAL_001"
    INVALID_INPUT = "VAL_002"
    MISSING_REQUIRED_FIELD = "VAL_003"
    INVALID_FORMAT = "VAL_004"
    DATA_CONSTRAINT_VIOLATION = "VAL_005"
    
    # Business Logic Errors
    BUSINESS_RULE_VIOLATION = "BIZ_001"
    OPERATION_NOT_ALLOWED = "BIZ_002"
    RESOURCE_CONFLICT = "BIZ_003"
    STATE_TRANSITION_ERROR = "BIZ_004"
    QUOTA_EXCEEDED = "BIZ_005"
    
    # Database Errors
    DATABASE_ERROR = "DB_001"
    RECORD_NOT_FOUND = "DB_002"
    DUPLICATE_RECORD = "DB_003"
    TRANSACTION_FAILED = "DB_004"
    CONNECTION_ERROR = "DB_005"
    
    # External Service Errors
    EXTERNAL_SERVICE_ERROR = "EXT_001"
    SERVICE_UNAVAILABLE = "EXT_002"
    TIMEOUT_ERROR = "EXT_003"
    RATE_LIMIT_EXCEEDED = "EXT_004"
    API_VERSION_MISMATCH = "EXT_005"
    
    # System Errors
    INTERNAL_SERVER_ERROR = "SYS_001"
    CONFIGURATION_ERROR = "SYS_002"
    RESOURCE_EXHAUSTED = "SYS_003"
    MAINTENANCE_MODE = "SYS_004"
    FEATURE_DISABLED = "SYS_005"


class ResponseFormatter:
    """
    Enterprise-grade response formatter providing comprehensive API response 
    standardization with enhanced features for monitoring, logging, and debugging.
    
    Features:
    - Consistent response structure maintaining Node.js compatibility
    - Comprehensive error handling with enterprise logging integration
    - Performance monitoring integration for response tracking
    - Sensitive data filtering for security compliance
    - Configurable response formats for different client needs
    """
    
    def __init__(self, 
                 include_request_id: bool = True,
                 include_timestamp: bool = True,
                 include_debug_info: bool = False,
                 sensitive_fields: Optional[List[str]] = None,
                 default_page_size: int = 20,
                 max_page_size: int = 1000):
        """
        Initialize response formatter with configuration options.
        
        Args:
            include_request_id: Whether to include request ID in responses
            include_timestamp: Whether to include timestamp in responses
            include_debug_info: Whether to include debug information (development only)
            sensitive_fields: List of field names to filter from responses
            default_page_size: Default page size for paginated responses
            max_page_size: Maximum allowed page size for pagination
        """
        self.include_request_id = include_request_id
        self.include_timestamp = include_timestamp
        self.include_debug_info = include_debug_info
        self.sensitive_fields = sensitive_fields or [
            'password', 'secret', 'token', 'key', 'auth', 'credential',
            'private', 'confidential', 'ssn', 'credit_card', 'cvv', 'pin'
        ]
        self.default_page_size = default_page_size
        self.max_page_size = max_page_size
        
        # Initialize JSON processor for enhanced serialization
        self.json_processor = JSONProcessor(
            datetime_format='iso',
            include_microseconds=False,
            timezone_aware=True,
            sort_keys=False
        )
    
    def success(self, 
                data: Any = None, 
                message: Optional[str] = None,
                meta: Optional[Dict[str, Any]] = None,
                status_code: int = 200,
                request: Optional[Request] = None) -> Tuple[Dict[str, Any], int]:
        """
        Create standardized success response maintaining Node.js API compatibility.
        
        Args:
            data: Response data payload
            message: Optional success message
            meta: Additional metadata for the response
            status_code: HTTP status code (default: 200)
            request: Flask request object for context
            
        Returns:
            Tuple of (response_dict, status_code)
        """
        try:
            # Filter sensitive data for security compliance
            if data is not None:
                data = filter_sensitive_json(data, self.sensitive_fields)
            
            # Create base response structure
            response = {
                'success': True,
                'status': ResponseStatus.SUCCESS.value
            }
            
            # Add timestamp if configured
            if self.include_timestamp:
                response['timestamp'] = datetime.now(timezone.utc).isoformat()
            
            # Add request ID for tracing
            if self.include_request_id and request:
                response['request_id'] = self._get_request_id(request)
            
            # Add data payload
            if data is not None:
                response['data'] = to_json_compatible(data)
            
            # Add optional message
            if message:
                response['message'] = message
            
            # Add metadata
            if meta:
                response['meta'] = meta
            
            # Add debug information in development mode
            if self.include_debug_info and current_app.debug:
                response['debug'] = self._get_debug_info(request)
            
            # Log successful response for monitoring
            self._log_response(response, status_code, request)
            
            return response, status_code
            
        except Exception as e:
            logger.error(f"Error creating success response: {str(e)}")
            # Fallback to basic response structure
            return self._create_fallback_response(data, True, status_code)
    
    def error(self,
              message: str,
              error_code: Optional[Union[str, ErrorCode]] = None,
              errors: Optional[List[str]] = None,
              status_code: int = 400,
              exception: Optional[Exception] = None,
              request: Optional[Request] = None,
              meta: Optional[Dict[str, Any]] = None) -> Tuple[Dict[str, Any], int]:
        """
        Create standardized error response with comprehensive error handling.
        
        Args:
            message: Primary error message
            error_code: Application-specific error code
            errors: List of detailed error messages
            status_code: HTTP status code (default: 400)
            exception: Original exception for logging and debug info
            request: Flask request object for context
            meta: Additional metadata for the response
            
        Returns:
            Tuple of (response_dict, status_code)
        """
        try:
            # Create base error response structure
            response = {
                'success': False,
                'status': ResponseStatus.ERROR.value,
                'message': message
            }
            
            # Add timestamp if configured
            if self.include_timestamp:
                response['timestamp'] = datetime.now(timezone.utc).isoformat()
            
            # Add request ID for tracing
            if self.include_request_id and request:
                response['request_id'] = self._get_request_id(request)
            
            # Add error code
            if error_code:
                if isinstance(error_code, ErrorCode):
                    response['error_code'] = error_code.value
                else:
                    response['error_code'] = str(error_code)
            
            # Add detailed errors
            if errors:
                response['errors'] = errors
            
            # Add metadata
            if meta:
                response['meta'] = meta
            
            # Add debug information in development mode
            if self.include_debug_info and current_app.debug and exception:
                response['debug'] = self._get_exception_debug_info(exception, request)
            
            # Log error response for monitoring and alerting
            self._log_error_response(response, status_code, exception, request)
            
            return response, status_code
            
        except Exception as e:
            logger.error(f"Error creating error response: {str(e)}")
            # Fallback to basic error response
            return self._create_fallback_error_response(message, status_code)
    
    def validation_error(self,
                        message: str = "Validation failed",
                        errors: Optional[List[str]] = None,
                        field_errors: Optional[Dict[str, List[str]]] = None,
                        request: Optional[Request] = None) -> Tuple[Dict[str, Any], int]:
        """
        Create standardized validation error response.
        
        Args:
            message: Primary validation error message
            errors: List of general validation errors
            field_errors: Dictionary mapping field names to their error lists
            request: Flask request object for context
            
        Returns:
            Tuple of (response_dict, status_code)
        """
        meta = {}
        if field_errors:
            meta['field_errors'] = field_errors
        
        all_errors = errors or []
        if field_errors:
            for field, field_error_list in field_errors.items():
                for error in field_error_list:
                    all_errors.append(f"{field}: {error}")
        
        return self.error(
            message=message,
            error_code=ErrorCode.VALIDATION_ERROR,
            errors=all_errors,
            status_code=422,  # Unprocessable Entity
            request=request,
            meta=meta
        )
    
    def not_found(self,
                  resource: str = "Resource",
                  resource_id: Optional[str] = None,
                  request: Optional[Request] = None) -> Tuple[Dict[str, Any], int]:
        """
        Create standardized not found error response.
        
        Args:
            resource: Name of the resource that was not found
            resource_id: ID of the resource (if applicable)
            request: Flask request object for context
            
        Returns:
            Tuple of (response_dict, status_code)
        """
        if resource_id:
            message = f"{resource} with ID '{resource_id}' not found"
        else:
            message = f"{resource} not found"
        
        return self.error(
            message=message,
            error_code=ErrorCode.RECORD_NOT_FOUND,
            status_code=404,
            request=request
        )
    
    def unauthorized(self,
                    message: str = "Authentication required",
                    request: Optional[Request] = None) -> Tuple[Dict[str, Any], int]:
        """
        Create standardized unauthorized error response.
        
        Args:
            message: Unauthorized error message
            request: Flask request object for context
            
        Returns:
            Tuple of (response_dict, status_code)
        """
        return self.error(
            message=message,
            error_code=ErrorCode.UNAUTHORIZED,
            status_code=401,
            request=request
        )
    
    def forbidden(self,
                  message: str = "Access forbidden",
                  request: Optional[Request] = None) -> Tuple[Dict[str, Any], int]:
        """
        Create standardized forbidden error response.
        
        Args:
            message: Forbidden error message
            request: Flask request object for context
            
        Returns:
            Tuple of (response_dict, status_code)
        """
        return self.error(
            message=message,
            error_code=ErrorCode.FORBIDDEN,
            status_code=403,
            request=request
        )
    
    def conflict(self,
                 message: str = "Resource conflict",
                 request: Optional[Request] = None) -> Tuple[Dict[str, Any], int]:
        """
        Create standardized conflict error response.
        
        Args:
            message: Conflict error message
            request: Flask request object for context
            
        Returns:
            Tuple of (response_dict, status_code)
        """
        return self.error(
            message=message,
            error_code=ErrorCode.RESOURCE_CONFLICT,
            status_code=409,
            request=request
        )
    
    def rate_limited(self,
                    message: str = "Rate limit exceeded",
                    retry_after: Optional[int] = None,
                    request: Optional[Request] = None) -> Tuple[Dict[str, Any], int]:
        """
        Create standardized rate limit error response.
        
        Args:
            message: Rate limit error message
            retry_after: Number of seconds to wait before retrying
            request: Flask request object for context
            
        Returns:
            Tuple of (response_dict, status_code)
        """
        meta = {}
        if retry_after:
            meta['retry_after'] = retry_after
        
        return self.error(
            message=message,
            error_code=ErrorCode.RATE_LIMIT_EXCEEDED,
            status_code=429,
            request=request,
            meta=meta
        )
    
    def internal_error(self,
                      message: str = "Internal server error",
                      exception: Optional[Exception] = None,
                      request: Optional[Request] = None) -> Tuple[Dict[str, Any], int]:
        """
        Create standardized internal server error response.
        
        Args:
            message: Internal error message
            exception: Original exception for logging
            request: Flask request object for context
            
        Returns:
            Tuple of (response_dict, status_code)
        """
        return self.error(
            message=message,
            error_code=ErrorCode.INTERNAL_SERVER_ERROR,
            status_code=500,
            exception=exception,
            request=request
        )
    
    def paginated(self,
                  data: List[Any],
                  page: int = 1,
                  page_size: Optional[int] = None,
                  total_count: Optional[int] = None,
                  message: Optional[str] = None,
                  request: Optional[Request] = None) -> Tuple[Dict[str, Any], int]:
        """
        Create standardized paginated response with comprehensive pagination metadata.
        
        Args:
            data: List of data items for the current page
            page: Current page number (1-based)
            page_size: Number of items per page
            total_count: Total number of items (calculated if not provided)
            message: Optional success message
            request: Flask request object for context
            
        Returns:
            Tuple of (response_dict, status_code)
        """
        try:
            # Validate and set page size
            if page_size is None:
                page_size = self.default_page_size
            elif page_size > self.max_page_size:
                page_size = self.max_page_size
            elif page_size < 1:
                page_size = 1
            
            # Validate page number
            if page < 1:
                page = 1
            
            # Calculate pagination metadata
            if total_count is None:
                total_count = len(data)
            
            total_pages = max(1, (total_count + page_size - 1) // page_size)
            
            # Ensure page doesn't exceed total pages
            if page > total_pages:
                page = total_pages
            
            # Calculate data slice for current page
            start_index = (page - 1) * page_size
            end_index = start_index + page_size
            page_data = data[start_index:end_index]
            
            # Filter sensitive data
            page_data = filter_sensitive_json(page_data, self.sensitive_fields)
            
            # Create pagination metadata
            pagination = {
                'page': page,
                'page_size': page_size,
                'total_count': total_count,
                'total_pages': total_pages,
                'has_next': page < total_pages,
                'has_prev': page > 1,
                'next_page': page + 1 if page < total_pages else None,
                'prev_page': page - 1 if page > 1 else None,
                'items_on_page': len(page_data)
            }
            
            # Create response
            return self.success(
                data=page_data,
                message=message,
                meta={'pagination': pagination},
                status_code=200,
                request=request
            )
            
        except Exception as e:
            logger.error(f"Error creating paginated response: {str(e)}")
            return self.error(
                message="Failed to create paginated response",
                error_code=ErrorCode.INTERNAL_SERVER_ERROR,
                status_code=500,
                exception=e,
                request=request
            )
    
    def partial_content(self,
                       data: Any,
                       warnings: Optional[List[str]] = None,
                       message: Optional[str] = None,
                       request: Optional[Request] = None) -> Tuple[Dict[str, Any], int]:
        """
        Create response for partial success scenarios with warnings.
        
        Args:
            data: Response data payload
            warnings: List of warning messages
            message: Optional message
            request: Flask request object for context
            
        Returns:
            Tuple of (response_dict, status_code)
        """
        response, _ = self.success(
            data=data,
            message=message or "Operation completed with warnings",
            request=request
        )
        
        # Update status to partial
        response['status'] = ResponseStatus.PARTIAL.value
        
        # Add warnings
        if warnings:
            response['warnings'] = warnings
        
        return response, 206  # Partial Content
    
    def no_content(self,
                   message: Optional[str] = None,
                   request: Optional[Request] = None) -> Tuple[Dict[str, Any], int]:
        """
        Create standardized no content response.
        
        Args:
            message: Optional message
            request: Flask request object for context
            
        Returns:
            Tuple of (response_dict, status_code)
        """
        return self.success(
            message=message or "Operation completed successfully",
            status_code=204,
            request=request
        )
    
    def created(self,
                data: Any = None,
                resource_id: Optional[str] = None,
                location: Optional[str] = None,
                message: Optional[str] = None,
                request: Optional[Request] = None) -> Tuple[Dict[str, Any], int]:
        """
        Create standardized resource creation response.
        
        Args:
            data: Created resource data
            resource_id: ID of the created resource
            location: Location URL of the created resource
            message: Optional success message
            request: Flask request object for context
            
        Returns:
            Tuple of (response_dict, status_code)
        """
        meta = {}
        if resource_id:
            meta['resource_id'] = resource_id
        if location:
            meta['location'] = location
        
        return self.success(
            data=data,
            message=message or "Resource created successfully",
            meta=meta if meta else None,
            status_code=201,
            request=request
        )
    
    def _get_request_id(self, request: Optional[Request]) -> str:
        """
        Get or generate request ID for tracing.
        
        Args:
            request: Flask request object
            
        Returns:
            Request ID string
        """
        if request and hasattr(request, 'id'):
            return request.id
        elif request and 'X-Request-ID' in request.headers:
            return request.headers['X-Request-ID']
        else:
            return str(uuid.uuid4())
    
    def _get_debug_info(self, request: Optional[Request]) -> Dict[str, Any]:
        """
        Get debug information for development mode.
        
        Args:
            request: Flask request object
            
        Returns:
            Debug information dictionary
        """
        debug_info = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'environment': current_app.config.get('ENV', 'unknown')
        }
        
        if request:
            debug_info.update({
                'method': request.method,
                'url': request.url,
                'remote_addr': request.remote_addr,
                'user_agent': request.headers.get('User-Agent', ''),
                'content_type': request.content_type
            })
        
        return debug_info
    
    def _get_exception_debug_info(self, 
                                 exception: Exception, 
                                 request: Optional[Request]) -> Dict[str, Any]:
        """
        Get exception debug information for development mode.
        
        Args:
            exception: Original exception
            request: Flask request object
            
        Returns:
            Exception debug information dictionary
        """
        debug_info = self._get_debug_info(request)
        debug_info.update({
            'exception_type': type(exception).__name__,
            'exception_message': str(exception),
            'traceback': traceback.format_exc()
        })
        
        return debug_info
    
    def _log_response(self, 
                     response: Dict[str, Any], 
                     status_code: int, 
                     request: Optional[Request]) -> None:
        """
        Log response for monitoring and analytics.
        
        Args:
            response: Response dictionary
            status_code: HTTP status code
            request: Flask request object
        """
        try:
            log_data = {
                'event': 'api_response',
                'status_code': status_code,
                'success': response.get('success', True),
                'request_id': response.get('request_id'),
                'timestamp': response.get('timestamp')
            }
            
            if request:
                log_data.update({
                    'method': request.method,
                    'path': request.path,
                    'remote_addr': request.remote_addr
                })
            
            logger.info("API response", extra=log_data)
            
        except Exception as e:
            logger.error(f"Failed to log response: {str(e)}")
    
    def _log_error_response(self, 
                           response: Dict[str, Any], 
                           status_code: int, 
                           exception: Optional[Exception], 
                           request: Optional[Request]) -> None:
        """
        Log error response for monitoring and alerting.
        
        Args:
            response: Error response dictionary
            status_code: HTTP status code
            exception: Original exception
            request: Flask request object
        """
        try:
            log_data = {
                'event': 'api_error',
                'status_code': status_code,
                'error_code': response.get('error_code'),
                'message': response.get('message'),
                'request_id': response.get('request_id'),
                'timestamp': response.get('timestamp')
            }
            
            if request:
                log_data.update({
                    'method': request.method,
                    'path': request.path,
                    'remote_addr': request.remote_addr
                })
            
            if exception:
                log_data.update({
                    'exception_type': type(exception).__name__,
                    'exception_message': str(exception)
                })
            
            # Log as error for status codes >= 500, warning for 4xx
            if status_code >= 500:
                logger.error("API error response", extra=log_data)
            else:
                logger.warning("API client error", extra=log_data)
                
        except Exception as e:
            logger.error(f"Failed to log error response: {str(e)}")
    
    def _create_fallback_response(self, 
                                 data: Any, 
                                 success: bool, 
                                 status_code: int) -> Tuple[Dict[str, Any], int]:
        """
        Create fallback response when primary response creation fails.
        
        Args:
            data: Response data
            success: Success indicator
            status_code: HTTP status code
            
        Returns:
            Tuple of (response_dict, status_code)
        """
        return {
            'success': success,
            'status': ResponseStatus.SUCCESS.value if success else ResponseStatus.ERROR.value,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'data': str(data) if data is not None else None
        }, status_code
    
    def _create_fallback_error_response(self, 
                                       message: str, 
                                       status_code: int) -> Tuple[Dict[str, Any], int]:
        """
        Create fallback error response when primary error response creation fails.
        
        Args:
            message: Error message
            status_code: HTTP status code
            
        Returns:
            Tuple of (response_dict, status_code)
        """
        return {
            'success': False,
            'status': ResponseStatus.ERROR.value,
            'message': message,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'error_code': ErrorCode.INTERNAL_SERVER_ERROR.value
        }, status_code


# Global response formatter instance for convenient access
_default_formatter = ResponseFormatter()


# Convenience functions using the default formatter
def success_response(data: Any = None, 
                    message: Optional[str] = None,
                    meta: Optional[Dict[str, Any]] = None,
                    status_code: int = 200,
                    request: Optional[Request] = None) -> Tuple[Dict[str, Any], int]:
    """Create success response using default formatter."""
    return _default_formatter.success(data, message, meta, status_code, request)


def error_response(message: str,
                  error_code: Optional[Union[str, ErrorCode]] = None,
                  errors: Optional[List[str]] = None,
                  status_code: int = 400,
                  exception: Optional[Exception] = None,
                  request: Optional[Request] = None) -> Tuple[Dict[str, Any], int]:
    """Create error response using default formatter."""
    return _default_formatter.error(message, error_code, errors, status_code, exception, request)


def validation_error_response(message: str = "Validation failed",
                             errors: Optional[List[str]] = None,
                             field_errors: Optional[Dict[str, List[str]]] = None,
                             request: Optional[Request] = None) -> Tuple[Dict[str, Any], int]:
    """Create validation error response using default formatter."""
    return _default_formatter.validation_error(message, errors, field_errors, request)


def not_found_response(resource: str = "Resource",
                      resource_id: Optional[str] = None,
                      request: Optional[Request] = None) -> Tuple[Dict[str, Any], int]:
    """Create not found error response using default formatter."""
    return _default_formatter.not_found(resource, resource_id, request)


def unauthorized_response(message: str = "Authentication required",
                         request: Optional[Request] = None) -> Tuple[Dict[str, Any], int]:
    """Create unauthorized error response using default formatter."""
    return _default_formatter.unauthorized(message, request)


def forbidden_response(message: str = "Access forbidden",
                      request: Optional[Request] = None) -> Tuple[Dict[str, Any], int]:
    """Create forbidden error response using default formatter."""
    return _default_formatter.forbidden(message, request)


def conflict_response(message: str = "Resource conflict",
                     request: Optional[Request] = None) -> Tuple[Dict[str, Any], int]:
    """Create conflict error response using default formatter."""
    return _default_formatter.conflict(message, request)


def rate_limited_response(message: str = "Rate limit exceeded",
                         retry_after: Optional[int] = None,
                         request: Optional[Request] = None) -> Tuple[Dict[str, Any], int]:
    """Create rate limit error response using default formatter."""
    return _default_formatter.rate_limited(message, retry_after, request)


def internal_error_response(message: str = "Internal server error",
                           exception: Optional[Exception] = None,
                           request: Optional[Request] = None) -> Tuple[Dict[str, Any], int]:
    """Create internal server error response using default formatter."""
    return _default_formatter.internal_error(message, exception, request)


def paginated_response(data: List[Any],
                      page: int = 1,
                      page_size: Optional[int] = None,
                      total_count: Optional[int] = None,
                      message: Optional[str] = None,
                      request: Optional[Request] = None) -> Tuple[Dict[str, Any], int]:
    """Create paginated response using default formatter."""
    return _default_formatter.paginated(data, page, page_size, total_count, message, request)


def created_response(data: Any = None,
                    resource_id: Optional[str] = None,
                    location: Optional[str] = None,
                    message: Optional[str] = None,
                    request: Optional[Request] = None) -> Tuple[Dict[str, Any], int]:
    """Create resource creation response using default formatter."""
    return _default_formatter.created(data, resource_id, location, message, request)


def no_content_response(message: Optional[str] = None,
                       request: Optional[Request] = None) -> Tuple[Dict[str, Any], int]:
    """Create no content response using default formatter."""
    return _default_formatter.no_content(message, request)


def partial_content_response(data: Any,
                            warnings: Optional[List[str]] = None,
                            message: Optional[str] = None,
                            request: Optional[Request] = None) -> Tuple[Dict[str, Any], int]:
    """Create partial content response using default formatter."""
    return _default_formatter.partial_content(data, warnings, message, request)


# Flask-specific response utilities
def make_json_response(response_tuple: Tuple[Dict[str, Any], int]):
    """
    Convert response tuple to Flask JSON response object.
    
    Args:
        response_tuple: Tuple of (response_dict, status_code)
        
    Returns:
        Flask JSON response object
    """
    response_dict, status_code = response_tuple
    return jsonify(response_dict), status_code


def make_response_headers(response_dict: Dict[str, Any], 
                         additional_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """
    Create standard response headers for API responses.
    
    Args:
        response_dict: Response dictionary
        additional_headers: Additional headers to include
        
    Returns:
        Dictionary of response headers
    """
    headers = {
        'Content-Type': 'application/json',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block'
    }
    
    # Add request ID header if available
    if 'request_id' in response_dict:
        headers['X-Request-ID'] = response_dict['request_id']
    
    # Add pagination headers for paginated responses
    if 'meta' in response_dict and 'pagination' in response_dict['meta']:
        pagination = response_dict['meta']['pagination']
        headers.update({
            'X-Total-Count': str(pagination['total_count']),
            'X-Page': str(pagination['page']),
            'X-Page-Size': str(pagination['page_size']),
            'X-Total-Pages': str(pagination['total_pages'])
        })
        
        # Add Link header for pagination navigation
        links = []
        if pagination.get('next_page'):
            links.append(f'<page={pagination["next_page"]}>; rel="next"')
        if pagination.get('prev_page'):
            links.append(f'<page={pagination["prev_page"]}>; rel="prev"')
        if links:
            headers['Link'] = ', '.join(links)
    
    # Add rate limiting headers if available
    if 'meta' in response_dict and 'retry_after' in response_dict['meta']:
        headers['Retry-After'] = str(response_dict['meta']['retry_after'])
    
    # Add additional headers
    if additional_headers:
        headers.update(additional_headers)
    
    return headers


# Status code mapping utilities
def get_status_code_from_error_code(error_code: Union[str, ErrorCode]) -> int:
    """
    Map error codes to appropriate HTTP status codes.
    
    Args:
        error_code: Application error code
        
    Returns:
        Appropriate HTTP status code
    """
    if isinstance(error_code, str):
        try:
            error_code = ErrorCode(error_code)
        except ValueError:
            return 400  # Bad Request as default
    
    status_mapping = {
        # Authentication errors
        ErrorCode.UNAUTHORIZED: 401,
        ErrorCode.FORBIDDEN: 403,
        ErrorCode.TOKEN_EXPIRED: 401,
        ErrorCode.INVALID_TOKEN: 401,
        ErrorCode.INSUFFICIENT_PERMISSIONS: 403,
        
        # Validation errors
        ErrorCode.VALIDATION_ERROR: 422,
        ErrorCode.INVALID_INPUT: 400,
        ErrorCode.MISSING_REQUIRED_FIELD: 400,
        ErrorCode.INVALID_FORMAT: 400,
        ErrorCode.DATA_CONSTRAINT_VIOLATION: 400,
        
        # Business logic errors
        ErrorCode.BUSINESS_RULE_VIOLATION: 400,
        ErrorCode.OPERATION_NOT_ALLOWED: 403,
        ErrorCode.RESOURCE_CONFLICT: 409,
        ErrorCode.STATE_TRANSITION_ERROR: 400,
        ErrorCode.QUOTA_EXCEEDED: 429,
        
        # Database errors
        ErrorCode.DATABASE_ERROR: 500,
        ErrorCode.RECORD_NOT_FOUND: 404,
        ErrorCode.DUPLICATE_RECORD: 409,
        ErrorCode.TRANSACTION_FAILED: 500,
        ErrorCode.CONNECTION_ERROR: 503,
        
        # External service errors
        ErrorCode.EXTERNAL_SERVICE_ERROR: 502,
        ErrorCode.SERVICE_UNAVAILABLE: 503,
        ErrorCode.TIMEOUT_ERROR: 504,
        ErrorCode.RATE_LIMIT_EXCEEDED: 429,
        ErrorCode.API_VERSION_MISMATCH: 400,
        
        # System errors
        ErrorCode.INTERNAL_SERVER_ERROR: 500,
        ErrorCode.CONFIGURATION_ERROR: 500,
        ErrorCode.RESOURCE_EXHAUSTED: 503,
        ErrorCode.MAINTENANCE_MODE: 503,
        ErrorCode.FEATURE_DISABLED: 501
    }
    
    return status_mapping.get(error_code, 400)


# Response validation utilities
def validate_response_structure(response: Dict[str, Any]) -> bool:
    """
    Validate response structure against expected format.
    
    Args:
        response: Response dictionary to validate
        
    Returns:
        True if response structure is valid
    """
    required_fields = ['success', 'status']
    
    # Check required fields
    for field in required_fields:
        if field not in response:
            return False
    
    # Validate success field type
    if not isinstance(response['success'], bool):
        return False
    
    # Validate status field value
    valid_statuses = [status.value for status in ResponseStatus]
    if response['status'] not in valid_statuses:
        return False
    
    # For error responses, message is required
    if not response['success'] and 'message' not in response:
        return False
    
    return True


# Export key classes and functions
__all__ = [
    # Main classes
    'ResponseFormatter',
    'ResponseStatus',
    'ErrorCode',
    
    # Response creation functions
    'success_response',
    'error_response',
    'validation_error_response',
    'not_found_response',
    'unauthorized_response',
    'forbidden_response',
    'conflict_response',
    'rate_limited_response',
    'internal_error_response',
    'paginated_response',
    'created_response',
    'no_content_response',
    'partial_content_response',
    
    # Flask utilities
    'make_json_response',
    'make_response_headers',
    
    # Utility functions
    'get_status_code_from_error_code',
    'validate_response_structure',
]