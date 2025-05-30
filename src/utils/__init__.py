"""
Utils package initialization providing centralized imports for common utility functions.

This module serves as the central shared utility provider across all application layers,
implementing the cross-cutting concerns architecture per Section 5.4.1 and providing
modular utility organization per Section 6.1.1 Flask Blueprint architecture patterns.

Key Features:
- Centralized access point for date/time processing utilities with python-dateutil 2.8+
- HTTP client utilities with requests 2.31+ and httpx 0.24+ for external service communication
- Comprehensive validation utilities using marshmallow 3.20+ and pydantic 2.3+
- HTML and input sanitization using bleach 6.0+ for XSS prevention
- Standardized API response formatting maintaining 100% API contract compatibility
- Enterprise-grade JSON processing with enhanced data type support
- Comprehensive exception handling with structured error reporting

Module Organization:
- datetime_utils: Date/time processing with ISO 8601 compliance and timezone support
- http: HTTP clients with circuit breaker patterns and retry logic
- validators: Input validation with security checks and business rule enforcement
- sanitizers: HTML/input sanitization with configurable security policies
- response: API response formatting with consistent error handling
- exceptions: Application exception hierarchy with structured error reporting
- json_utils: Enhanced JSON processing with enterprise data type support

This initialization follows Flask application factory patterns and provides enterprise-grade
utility access supporting the monolithic Blueprint architecture per Section 6.1.1.
"""

# Core datetime processing utilities
from .datetime_utils import (
    # Core processor class
    DateTimeProcessor,
    
    # Exception classes
    DateTimeError,
    DateParseError,
    TimezoneError,
    DateValidationError,
    
    # Primary utility functions
    parse,
    now,
    utc_now,
    to_iso,
    to_local_iso,
    format_datetime,
    to_timestamp,
    
    # Date manipulation functions
    add_time,
    subtract_time,
    diff,
    
    # Validation and business logic utilities
    is_valid_date,
    validate_date_range,
    get_business_days,
    get_quarter,
    get_week_of_year,
    is_leap_year,
    get_days_in_month,
    create_date_range,
    
    # Timezone utilities
    get_available_timezones,
    convert_timezone,
    
    # Business logic helpers
    get_age,
    is_business_hour,
    format_duration,
)

# HTTP client utilities for external service communication
from .http import (
    # Configuration and client classes
    HTTPClientConfig,
    SyncHTTPClient,
    AsyncHTTPClient,
    HTTPClientFactory,
    
    # Convenience functions
    create_sync_client,
    create_async_client,
    
    # Exception classes (from exceptions module)
    ExternalServiceError,
    CircuitBreakerError,
)

# Comprehensive validation utilities
from .validators import (
    # Validation result container
    ValidationResult,
    
    # Core validation functions
    validate_email_address,
    validate_password_strength,
    validate_url,
    validate_phone_number,
    validate_uuid,
    validate_date_range as validate_date_range_validator,
    validate_numeric_range,
    validate_json_schema,
    validate_file_upload,
    
    # Sanitization functions
    sanitize_html_input,
    validate_sql_injection_risk,
    sanitize_input,
    
    # Validator composition
    create_composite_validator,
    
    # Convenience validators
    validate_required_string,
    validate_optional_string,
    
    # Regex patterns for reuse
    EMAIL_REGEX,
    URL_REGEX,
    PHONE_PATTERNS,
    PASSWORD_PATTERNS,
)

# HTML and input sanitization utilities
from .sanitizers import (
    # Core sanitizer classes
    InputSanitizer,
    SanitizationResult,
    SanitizationContext,
    SecurityViolationType,
    HTMLSanitizationPolicy,
    
    # Predefined policies
    SANITIZATION_POLICIES,
    
    # Global sanitizer instance
    sanitizer,
    
    # Convenience functions
    sanitize_html,
    sanitize_text,
    sanitize_email,
    sanitize_url,
    sanitize_filename,
)

# Standardized API response formatting
from .response import (
    # Core response classes
    APIResponse,
    ErrorDetail,
    APIStatus,
    
    # Success response functions
    create_success_response,
    create_paginated_response,
    create_pagination_metadata,
    
    # Error response functions
    create_error_response,
    create_validation_error_response,
    create_authentication_error_response,
    create_authorization_error_response,
    create_business_error_response,
    create_database_error_response,
    create_external_service_error_response,
    create_not_found_response,
    create_conflict_response,
    create_rate_limit_response,
    
    # Flask integration utilities
    handle_flask_exception,
    json_response,
    register_error_handlers,
    
    # Convenience aliases
    success_response,
    error_response,
    validation_error,
    auth_error,
    permission_error,
    business_error,
    not_found,
    conflict_error,
    rate_limit_error,
    paginated_response,
)

# Application exception hierarchy
from .exceptions import (
    # Base exception class
    BaseApplicationError,
    
    # Specific exception types
    ValidationError,
    AuthenticationError,
    AuthorizationError,
    BusinessLogicError,
    DatabaseError,
    ExternalServiceError,
    CircuitBreakerError,
    SystemError,
    
    # Error classification enums
    ErrorCategory,
    ErrorSeverity,
    
    # Utility functions
    format_error_response,
    register_error_handlers as register_exception_handlers,
    create_error_context,
    safe_str,
)

# Enhanced JSON processing utilities
from .json_utils import (
    # Custom encoder/decoder classes
    EnterpriseJSONEncoder,
    EnterpriseJSONDecoder,
    JSONCache,
    
    # Core JSON functions
    dumps,
    loads,
    load,
    dump,
    
    # Utility functions
    pretty_print,
    minify,
    safe_loads,
    
    # JSON schema validation
    validate_json_schema as validate_json_schema_utils,
    create_validator,
    
    # Advanced JSON utilities
    extract_json_paths,
    merge_json,
    sanitize_for_json,
    
    # Caching utilities
    cached_loads,
    clear_json_cache,
    
    # Convenience aliases
    serialize,
    deserialize,
    parse as json_parse,
    stringify,
)


# Package version and metadata
__version__ = "1.0.0"
__author__ = "Enterprise Python Development Team"
__description__ = "Centralized utility functions for Flask application supporting enterprise-grade functionality"


# Utility function categories for documentation and IDE support
DATETIME_UTILS = [
    'DateTimeProcessor', 'parse', 'now', 'utc_now', 'to_iso', 'format_datetime',
    'add_time', 'subtract_time', 'diff', 'is_valid_date', 'validate_date_range',
    'get_business_days', 'convert_timezone', 'get_age', 'is_business_hour'
]

HTTP_UTILS = [
    'HTTPClientConfig', 'SyncHTTPClient', 'AsyncHTTPClient', 'HTTPClientFactory',
    'create_sync_client', 'create_async_client'
]

VALIDATION_UTILS = [
    'ValidationResult', 'validate_email_address', 'validate_password_strength',
    'validate_url', 'validate_phone_number', 'validate_uuid', 'validate_numeric_range',
    'validate_json_schema', 'validate_file_upload', 'sanitize_input'
]

SANITIZATION_UTILS = [
    'InputSanitizer', 'SanitizationResult', 'sanitize_html', 'sanitize_text',
    'sanitize_email', 'sanitize_url', 'sanitize_filename'
]

RESPONSE_UTILS = [
    'APIResponse', 'ErrorDetail', 'APIStatus', 'create_success_response',
    'create_error_response', 'create_paginated_response', 'json_response'
]

EXCEPTION_UTILS = [
    'BaseApplicationError', 'ValidationError', 'AuthenticationError',
    'BusinessLogicError', 'DatabaseError', 'ExternalServiceError',
    'ErrorCategory', 'ErrorSeverity'
]

JSON_UTILS = [
    'EnterpriseJSONEncoder', 'dumps', 'loads', 'pretty_print', 'minify',
    'safe_loads', 'merge_json', 'cached_loads'
]


def get_utility_categories():
    """
    Get categorized list of available utility functions for documentation.
    
    Returns:
        Dictionary mapping utility categories to available functions
    """
    return {
        'datetime': DATETIME_UTILS,
        'http': HTTP_UTILS,
        'validation': VALIDATION_UTILS,
        'sanitization': SANITIZATION_UTILS,
        'response': RESPONSE_UTILS,
        'exceptions': EXCEPTION_UTILS,
        'json': JSON_UTILS,
    }


def get_all_utilities():
    """
    Get complete list of all available utility functions.
    
    Returns:
        List of all utility function names available in the package
    """
    all_utils = []
    categories = get_utility_categories()
    for category_utils in categories.values():
        all_utils.extend(category_utils)
    return sorted(all_utils)


# Comprehensive __all__ export list for explicit public API
__all__ = [
    # Datetime utilities
    'DateTimeProcessor', 'DateTimeError', 'DateParseError', 'TimezoneError', 'DateValidationError',
    'parse', 'now', 'utc_now', 'to_iso', 'to_local_iso', 'format_datetime', 'to_timestamp',
    'add_time', 'subtract_time', 'diff', 'is_valid_date', 'validate_date_range',
    'get_business_days', 'get_quarter', 'get_week_of_year', 'is_leap_year', 'get_days_in_month',
    'create_date_range', 'get_available_timezones', 'convert_timezone', 'get_age',
    'is_business_hour', 'format_duration',
    
    # HTTP client utilities
    'HTTPClientConfig', 'SyncHTTPClient', 'AsyncHTTPClient', 'HTTPClientFactory',
    'create_sync_client', 'create_async_client',
    
    # Validation utilities
    'ValidationResult', 'validate_email_address', 'validate_password_strength', 'validate_url',
    'validate_phone_number', 'validate_uuid', 'validate_date_range_validator', 'validate_numeric_range',
    'validate_json_schema', 'validate_file_upload', 'sanitize_html_input', 'validate_sql_injection_risk',
    'sanitize_input', 'create_composite_validator', 'validate_required_string', 'validate_optional_string',
    'EMAIL_REGEX', 'URL_REGEX', 'PHONE_PATTERNS', 'PASSWORD_PATTERNS',
    
    # Sanitization utilities
    'InputSanitizer', 'SanitizationResult', 'SanitizationContext', 'SecurityViolationType',
    'HTMLSanitizationPolicy', 'SANITIZATION_POLICIES', 'sanitizer', 'sanitize_html',
    'sanitize_text', 'sanitize_email', 'sanitize_url', 'sanitize_filename',
    
    # Response utilities
    'APIResponse', 'ErrorDetail', 'APIStatus', 'create_success_response', 'create_paginated_response',
    'create_pagination_metadata', 'create_error_response', 'create_validation_error_response',
    'create_authentication_error_response', 'create_authorization_error_response',
    'create_business_error_response', 'create_database_error_response', 'create_external_service_error_response',
    'create_not_found_response', 'create_conflict_response', 'create_rate_limit_response',
    'handle_flask_exception', 'json_response', 'register_error_handlers',
    'success_response', 'error_response', 'validation_error', 'auth_error', 'permission_error',
    'business_error', 'not_found', 'conflict_error', 'rate_limit_error', 'paginated_response',
    
    # Exception utilities
    'BaseApplicationError', 'ValidationError', 'AuthenticationError', 'AuthorizationError',
    'BusinessLogicError', 'DatabaseError', 'ExternalServiceError', 'CircuitBreakerError',
    'SystemError', 'ErrorCategory', 'ErrorSeverity', 'format_error_response',
    'register_exception_handlers', 'create_error_context', 'safe_str',
    
    # JSON utilities
    'EnterpriseJSONEncoder', 'EnterpriseJSONDecoder', 'JSONCache', 'dumps', 'loads', 'load', 'dump',
    'pretty_print', 'minify', 'safe_loads', 'validate_json_schema_utils', 'create_validator',
    'extract_json_paths', 'merge_json', 'sanitize_for_json', 'cached_loads', 'clear_json_cache',
    'serialize', 'deserialize', 'json_parse', 'stringify',
    
    # Package metadata and utilities
    'get_utility_categories', 'get_all_utilities',
]