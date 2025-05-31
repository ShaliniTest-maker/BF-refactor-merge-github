"""
Utils Package - Centralized Utility Functions for Flask Application

This module serves as the central access point for all utility functions across the Flask 
application, providing comprehensive shared functionality supporting all application layers 
per Section 5.4.1 cross-cutting concerns and Section 0.1.2 technical scope.

The utils package implements enterprise-grade utility patterns replacing Node.js helper 
libraries with Python equivalents while maintaining functional parity and performance 
characteristics per Section 0.2.4 dependency decisions.

Core Functionality Areas:
- Date/Time processing using python-dateutil 2.8+ equivalent to Node.js moment
- HTTP client utilities with requests 2.31+ and httpx 0.24+ for external service communication
- Input validation and sanitization using marshmallow 3.20+, pydantic 2.3+, and bleach 6.0+
- HTML sanitization and XSS prevention for enterprise security compliance
- Standardized API response formatting maintaining Node.js compatibility

Module Organization:
- datetime_utils: Comprehensive date/time processing and timezone handling
- http: Enterprise-grade HTTP clients with circuit breaker patterns and retry logic
- validators: Input validation, schema validation, and security pattern validation  
- sanitizers: HTML sanitization, input sanitization, and security policy management
- response: Standardized API response formatting and error handling patterns

Integration Points:
- Flask application factory pattern integration
- Cross-cutting concerns support for monitoring and observability
- Business logic processing support with comprehensive error handling
- External service integration with resilience patterns
- Security-first design with enterprise compliance features

Performance Characteristics:
- Optimized for ≤10% variance from Node.js baseline per Section 0.1.1
- Connection pooling and resource management for scalability
- Caching patterns for frequently accessed utilities
- Monitoring integration for performance tracking

Author: Flask Migration System
Version: 1.0.0
License: Enterprise
"""

# Core imports for error handling and logging
import logging
from typing import Any, Dict, List, Optional, Union, Tuple, Type

# Configure module logger
logger = logging.getLogger(__name__)

# =============================================================================
# DATE/TIME UTILITIES
# =============================================================================
# Import core date/time processing functionality equivalent to Node.js moment

from .datetime_utils import (
    # Core processor class for advanced date operations
    DateTimeProcessor,
    
    # Exception classes for error handling
    DateTimeError,
    DateParseError,
    TimezoneError,
    DateValidationError,
    
    # Primary date/time functions for common operations
    parse as parse_datetime,
    now as datetime_now,
    utc_now,
    to_iso,
    to_local_iso,
    format_datetime,
    to_timestamp,
    add_time,
    subtract_time,
    diff as datetime_diff,
    
    # Validation and utility functions
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
    
    # Business logic utilities
    get_age,
    is_business_hour,
    format_duration
)

# =============================================================================
# HTTP CLIENT UTILITIES  
# =============================================================================
# Import HTTP client functionality for external service communication

from .http import (
    # Configuration and client classes
    HTTPClientConfig,
    SyncHTTPClient,
    AsyncHTTPClient,
    HTTPClientFactory,
    
    # Convenience factory functions
    create_sync_client,
    create_async_client,
    
    # Exception classes for error handling
    ExternalServiceError,
    CircuitBreakerError
)

# =============================================================================
# VALIDATION UTILITIES
# =============================================================================
# Import comprehensive validation functionality

from .validators import (
    # Core validation result container
    ValidationResult,
    
    # Primary validation functions
    validate_email_address,
    sanitize_html_input,
    validate_sql_injection_risk,
    validate_password_strength,
    validate_url,
    validate_phone_number,
    validate_uuid,
    validate_date_range as validate_date_range_validator,
    validate_numeric_range,
    validate_json_schema,
    validate_file_upload,
    
    # Composite validation and input sanitization
    create_composite_validator,
    sanitize_input,
    
    # Convenience validators
    validate_required_string,
    validate_optional_string,
    
    # Validation patterns and constants
    EMAIL_REGEX,
    URL_REGEX,
    PHONE_PATTERNS,
    PASSWORD_PATTERNS
)

# =============================================================================
# SANITIZATION UTILITIES
# =============================================================================
# Import HTML and input sanitization functionality

from .sanitizers import (
    # Core sanitization classes
    SecurityPolicyManager,
    HTMLSanitizer,
    InputSanitizer,
    EnterpriseSanitizationManager,
    
    # Exception classes
    SanitizationError,
    InvalidInputError,
    SecurityPolicyViolationError,
    ConfigurationError,
    
    # Convenience sanitization functions
    sanitize_html,
    sanitize_text,
    sanitize_email,
    sanitize_url,
    sanitize_filename
)

# =============================================================================
# RESPONSE FORMATTING UTILITIES
# =============================================================================
# Import standardized API response formatting functionality

from .response import (
    # Core response classes and enums
    ResponseFormatter,
    ResponseStatus,
    ErrorCode,
    
    # Primary response creation functions
    success_response,
    error_response,
    validation_error_response,
    not_found_response,
    unauthorized_response,
    forbidden_response,
    conflict_response,
    rate_limited_response,
    internal_error_response,
    
    # Specialized response functions
    paginated_response,
    created_response,
    no_content_response,
    partial_content_response,
    
    # Flask integration utilities
    make_json_response,
    make_response_headers,
    
    # Utility functions
    get_status_code_from_error_code,
    validate_response_structure
)

# =============================================================================
# CENTRALIZED UTILITY INTERFACES
# =============================================================================
# Provide convenient grouped access to related functionality

class DateTimeUtils:
    """
    Centralized interface for date/time utilities providing convenient access
    to all date/time processing functionality with enterprise-grade features.
    """
    
    # Core processor instance for advanced operations
    processor = DateTimeProcessor()
    
    # Static method shortcuts for common operations
    @staticmethod
    def parse(date_input, timezone_input=None, strict=False):
        """Parse date input with comprehensive format support."""
        return parse_datetime(date_input, timezone_input, strict)
    
    @staticmethod
    def now(timezone_input=None):
        """Get current datetime in specified timezone."""
        return datetime_now(timezone_input)
    
    @staticmethod
    def utc_now():
        """Get current UTC datetime."""
        return utc_now()
    
    @staticmethod
    def to_iso(dt, include_microseconds=False, timezone_input=None):
        """Format datetime as ISO 8601 string."""
        return to_iso(dt, include_microseconds, timezone_input)
    
    @staticmethod
    def format(dt, format_str, timezone_input=None):
        """Format datetime using custom format string."""
        return format_datetime(dt, format_str, timezone_input)
    
    @staticmethod
    def validate_range(start_date, end_date, allow_same=True):
        """Validate date range with business logic constraints."""
        return validate_date_range(start_date, end_date, allow_same)


class HttpUtils:
    """
    Centralized interface for HTTP client utilities providing convenient access
    to synchronous and asynchronous HTTP clients with enterprise resilience patterns.
    """
    
    @staticmethod
    def create_sync_client(service_name, base_url=None, config=None):
        """Create configured synchronous HTTP client."""
        return create_sync_client(service_name, base_url, config)
    
    @staticmethod
    def create_async_client(service_name, base_url=None, config=None):
        """Create configured asynchronous HTTP client.""" 
        return create_async_client(service_name, base_url, config)
    
    @staticmethod
    def get_default_config(**overrides):
        """Get default HTTP client configuration with optional overrides."""
        config = HTTPClientConfig()
        for key, value in overrides.items():
            if hasattr(config, key):
                setattr(config, key, value)
        return config


class ValidationUtils:
    """
    Centralized interface for validation utilities providing convenient access
    to all validation functionality with comprehensive security patterns.
    """
    
    @staticmethod
    def email(email, check_deliverability=True):
        """Validate email address with comprehensive checks."""
        return validate_email_address(email, check_deliverability)
    
    @staticmethod
    def url(url, require_https=False):
        """Validate URL format and security requirements."""
        return validate_url(url, require_https)
    
    @staticmethod
    def password(password, min_length=8, **requirements):
        """Validate password strength with configurable requirements."""
        return validate_password_strength(password, min_length, **requirements)
    
    @staticmethod
    def phone(phone, country_code='us', normalize=True):
        """Validate phone number with international support."""
        return validate_phone_number(phone, country_code, normalize)
    
    @staticmethod
    def uuid_string(uuid_string, version=4):
        """Validate UUID format and version requirements."""
        return validate_uuid(uuid_string, version)
    
    @staticmethod
    def numeric(value, min_value=None, max_value=None, allow_decimal=True):
        """Validate numeric values with range constraints."""
        return validate_numeric_range(value, min_value, max_value, allow_decimal)
    
    @staticmethod
    def sanitize_input_data(input_value, max_length=None, check_sql=True, sanitize_html=True):
        """Comprehensive input sanitization with security checks."""
        return sanitize_input(input_value, max_length, True, check_sql, sanitize_html)


class SanitizationUtils:
    """
    Centralized interface for sanitization utilities providing convenient access
    to HTML sanitization and input sanitization with enterprise security policies.
    """
    
    @staticmethod
    def html(html_content, policy='basic', strict_validation=True):
        """Sanitize HTML content with configurable security policy."""
        return sanitize_html(html_content, policy, strict_validation)
    
    @staticmethod
    def text(text_content, policy='form'):
        """Sanitize text content removing all HTML."""
        return sanitize_text(text_content, policy)
    
    @staticmethod
    def email_address(email, normalize=True):
        """Sanitize and validate email address."""
        return sanitize_email(email, normalize)
    
    @staticmethod
    def url_address(url, allow_private=False):
        """Sanitize and validate URL with security checks."""
        return sanitize_url(url, allow_private)
    
    @staticmethod
    def filename(filename, max_length=255):
        """Sanitize filename for safe file system usage."""
        return sanitize_filename(filename, max_length)


class ResponseUtils:
    """
    Centralized interface for response formatting utilities providing convenient access
    to standardized API response patterns with comprehensive error handling.
    """
    
    @staticmethod
    def success(data=None, message=None, meta=None, status_code=200, request=None):
        """Create standardized success response."""
        return success_response(data, message, meta, status_code, request)
    
    @staticmethod
    def error(message, error_code=None, errors=None, status_code=400, exception=None, request=None):
        """Create standardized error response."""
        return error_response(message, error_code, errors, status_code, exception, request)
    
    @staticmethod
    def validation_error(message="Validation failed", errors=None, field_errors=None, request=None):
        """Create standardized validation error response."""
        return validation_error_response(message, errors, field_errors, request)
    
    @staticmethod
    def not_found(resource="Resource", resource_id=None, request=None):
        """Create standardized not found error response."""
        return not_found_response(resource, resource_id, request)
    
    @staticmethod
    def paginated(data, page=1, page_size=None, total_count=None, message=None, request=None):
        """Create standardized paginated response."""
        return paginated_response(data, page, page_size, total_count, message, request)
    
    @staticmethod
    def created(data=None, resource_id=None, location=None, message=None, request=None):
        """Create standardized resource creation response."""
        return created_response(data, resource_id, location, message, request)


# =============================================================================
# PACKAGE METADATA AND EXPORTS
# =============================================================================

# Package version and metadata
__version__ = "1.0.0"
__author__ = "Flask Migration System"
__description__ = "Centralized utility functions for Flask application"

# Comprehensive export list for external imports
__all__ = [
    # =============================================================================
    # CENTRALIZED UTILITY INTERFACES
    # =============================================================================
    'DateTimeUtils',
    'HttpUtils', 
    'ValidationUtils',
    'SanitizationUtils',
    'ResponseUtils',
    
    # =============================================================================
    # DATE/TIME UTILITIES
    # =============================================================================
    # Core classes
    'DateTimeProcessor',
    
    # Exception classes
    'DateTimeError',
    'DateParseError',
    'TimezoneError', 
    'DateValidationError',
    
    # Primary functions
    'parse_datetime',
    'datetime_now',
    'utc_now',
    'to_iso',
    'to_local_iso',
    'format_datetime',
    'to_timestamp',
    'add_time',
    'subtract_time',
    'datetime_diff',
    
    # Validation and utility functions
    'is_valid_date',
    'validate_date_range',
    'get_business_days',
    'get_quarter',
    'get_week_of_year',
    'is_leap_year',
    'get_days_in_month',
    'create_date_range',
    'get_available_timezones',
    'convert_timezone',
    'get_age',
    'is_business_hour',
    'format_duration',
    
    # =============================================================================
    # HTTP CLIENT UTILITIES
    # =============================================================================
    # Core classes
    'HTTPClientConfig',
    'SyncHTTPClient',
    'AsyncHTTPClient',
    'HTTPClientFactory',
    
    # Factory functions
    'create_sync_client',
    'create_async_client',
    
    # Exception classes
    'ExternalServiceError',
    'CircuitBreakerError',
    
    # =============================================================================
    # VALIDATION UTILITIES
    # =============================================================================
    # Core classes
    'ValidationResult',
    
    # Primary validation functions
    'validate_email_address',
    'sanitize_html_input',
    'validate_sql_injection_risk',
    'validate_password_strength',
    'validate_url',
    'validate_phone_number',
    'validate_uuid',
    'validate_date_range_validator',
    'validate_numeric_range',
    'validate_json_schema',
    'validate_file_upload',
    
    # Composite validation
    'create_composite_validator',
    'sanitize_input',
    
    # Convenience validators
    'validate_required_string',
    'validate_optional_string',
    
    # Patterns and constants
    'EMAIL_REGEX',
    'URL_REGEX',
    'PHONE_PATTERNS',
    'PASSWORD_PATTERNS',
    
    # =============================================================================
    # SANITIZATION UTILITIES
    # =============================================================================
    # Core classes
    'SecurityPolicyManager',
    'HTMLSanitizer',
    'InputSanitizer',
    'EnterpriseSanitizationManager',
    
    # Exception classes
    'SanitizationError',
    'InvalidInputError',
    'SecurityPolicyViolationError',
    'ConfigurationError',
    
    # Convenience functions
    'sanitize_html',
    'sanitize_text',
    'sanitize_email',
    'sanitize_url',
    'sanitize_filename',
    
    # =============================================================================
    # RESPONSE FORMATTING UTILITIES
    # =============================================================================
    # Core classes and enums
    'ResponseFormatter',
    'ResponseStatus',
    'ErrorCode',
    
    # Primary response functions
    'success_response',
    'error_response',
    'validation_error_response',
    'not_found_response',
    'unauthorized_response',
    'forbidden_response',
    'conflict_response',
    'rate_limited_response',
    'internal_error_response',
    
    # Specialized responses
    'paginated_response',
    'created_response',
    'no_content_response',
    'partial_content_response',
    
    # Flask integration
    'make_json_response',
    'make_response_headers',
    
    # Utility functions
    'get_status_code_from_error_code',
    'validate_response_structure'
]

# =============================================================================
# PACKAGE INITIALIZATION AND LOGGING
# =============================================================================

def _initialize_package():
    """
    Initialize the utils package with logging and configuration validation.
    
    This function performs package-level initialization including:
    - Logger configuration for structured logging
    - Validation of critical dependencies
    - Performance monitoring setup
    - Enterprise integration checks
    """
    try:
        # Configure package logging
        logger.info(
            "Utils package initialized",
            version=__version__,
            modules_loaded=[
                'datetime_utils',
                'http',
                'validators', 
                'sanitizers',
                'response'
            ],
            enterprise_features_enabled=True
        )
        
        # Validate critical dependencies are available
        _validate_dependencies()
        
        # Log successful initialization
        logger.info(
            "Utils package ready for cross-cutting functionality",
            date_time_utils=True,
            http_clients=True,
            validation_utils=True,
            sanitization_utils=True,
            response_utils=True
        )
        
    except Exception as e:
        logger.error(
            "Utils package initialization failed",
            error=str(e),
            error_type=type(e).__name__
        )
        raise


def _validate_dependencies():
    """
    Validate that all critical dependencies are properly loaded and functional.
    
    Raises:
        ImportError: If critical dependencies are missing
        ConfigurationError: If dependency configuration is invalid
    """
    try:
        # Validate datetime utilities
        test_dt = datetime_now()
        assert test_dt is not None, "DateTime utilities not functional"
        
        # Validate HTTP client factory
        test_config = HTTPClientConfig()
        assert test_config is not None, "HTTP client configuration not functional"
        
        # Validate validation utilities
        test_result = ValidationResult(True, "test", [], "test")
        assert test_result.is_valid, "Validation utilities not functional"
        
        # Validate sanitization utilities
        test_sanitized = sanitize_text("test")
        assert test_sanitized == "test", "Sanitization utilities not functional"
        
        # Validate response utilities
        test_response, status_code = success_response("test")
        assert test_response['success'] is True, "Response utilities not functional"
        assert status_code == 200, "Response status codes not functional"
        
        logger.debug("All utility dependencies validated successfully")
        
    except Exception as e:
        logger.error(
            "Dependency validation failed",
            error=str(e),
            error_type=type(e).__name__
        )
        raise ImportError(f"Critical utils dependency validation failed: {str(e)}") from e


# Initialize the package when imported
_initialize_package()

# Log package ready state
logger.info(
    "Utils package initialization complete",
    description=__description__,
    total_exports=len(__all__),
    ready_for_application_use=True
)