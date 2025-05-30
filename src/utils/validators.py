"""
Comprehensive validation utilities providing standardized input validation, data sanitization,
and schema validation supporting marshmallow and pydantic integration.

This module implements enterprise-grade validation patterns replacing Node.js validators
with Python equivalents as specified in Section 0.2.4 dependency decisions and Section 3.2.2
input validation requirements.

Key Features:
- Email validation using email-validator 2.0+ replacing Node.js validators
- Comprehensive input validation and sanitization patterns
- XSS prevention and HTML sanitization using bleach 6.0+
- Integration with marshmallow 3.20+ and pydantic 2.3+ validation frameworks
- Enterprise validation error handling with structured reporting
- Cross-cutting validation utilities for business logic processing
- Type-safe validation with comprehensive error context
"""

import re
import uuid
from datetime import datetime, date
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional, Pattern, Union, Callable, Type
from urllib.parse import urlparse

import bleach
import structlog
from email_validator import validate_email, EmailNotValidError
from marshmallow import ValidationError as MarshmallowValidationError, Schema, fields
from pydantic import BaseModel, ValidationError as PydanticValidationError, validator
from pydantic.types import EmailStr

from .exceptions import ValidationError, ErrorCategory, ErrorSeverity

# Get structured logger
logger = structlog.get_logger(__name__)

# Validation constants and patterns
EMAIL_REGEX = re.compile(
    r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
    re.IGNORECASE
)

# Enhanced password strength regex patterns
PASSWORD_PATTERNS = {
    'min_length': re.compile(r'.{8,}'),
    'has_lowercase': re.compile(r'[a-z]'),
    'has_uppercase': re.compile(r'[A-Z]'),
    'has_digit': re.compile(r'\d'),
    'has_special': re.compile(r'[!@#$%^&*(),.?":{}|<>]'),
    'no_common_patterns': re.compile(r'^(?!.*(?:password|123456|qwerty|admin))', re.IGNORECASE)
}

# URL validation pattern
URL_REGEX = re.compile(
    r'^https?:\/\/'  # http:// or https://
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
    r'localhost|'  # localhost
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP
    r'(?::\d+)?'  # optional port
    r'(?:\/?|[/?]\S+)$',
    re.IGNORECASE
)

# Phone number patterns (international formats)
PHONE_PATTERNS = {
    'us': re.compile(r'^\+?1?[2-9]\d{2}[2-9]\d{2}\d{4}$'),
    'international': re.compile(r'^\+?[1-9]\d{1,14}$'),
    'general': re.compile(r'^[\+]?[(]?[\+]?\d{1,4}[)]?[-\s\.]?\d{1,4}[-\s\.]?\d{1,9}$')
}

# SQL injection patterns to detect
SQL_INJECTION_PATTERNS = [
    re.compile(r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b)", re.IGNORECASE),
    re.compile(r"('[^']*')|(\s*;\s*)|(\s*--[^\n]*)|(/\*.*?\*/)", re.IGNORECASE),
    re.compile(r"(\bOR\b.*=.*)|(\bAND\b.*=.*)", re.IGNORECASE)
]

# XSS patterns for additional protection beyond bleach
XSS_PATTERNS = [
    re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
    re.compile(r'javascript:', re.IGNORECASE),
    re.compile(r'on\w+\s*=', re.IGNORECASE),
    re.compile(r'expression\s*\(', re.IGNORECASE)
]

# Allowed HTML tags for bleach sanitization
ALLOWED_HTML_TAGS = [
    'p', 'br', 'strong', 'em', 'ul', 'ol', 'li', 'a', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'
]

ALLOWED_HTML_ATTRIBUTES = {
    'a': ['href', 'title'],
    '*': ['class']
}


class ValidationResult:
    """
    Standardized validation result container providing consistent validation outcomes
    with detailed error context and severity assessment.
    
    Supports both success and failure states with comprehensive error reporting
    per Section 5.4.2 error handling patterns.
    """
    
    def __init__(
        self,
        is_valid: bool,
        value: Any = None,
        errors: Optional[List[str]] = None,
        field_name: Optional[str] = None,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM
    ):
        self.is_valid = is_valid
        self.value = value
        self.errors = errors or []
        self.field_name = field_name
        self.severity = severity
        self.timestamp = datetime.utcnow()
    
    def add_error(self, error: str, severity: ErrorSeverity = ErrorSeverity.MEDIUM) -> None:
        """Add validation error with severity tracking."""
        self.errors.append(error)
        self.is_valid = False
        if severity.value > self.severity.value:
            self.severity = severity
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert validation result to dictionary format."""
        return {
            'is_valid': self.is_valid,
            'value': self.value,
            'errors': self.errors,
            'field_name': self.field_name,
            'severity': self.severity.value,
            'timestamp': self.timestamp.isoformat()
        }


def validate_email_address(
    email: Union[str, None],
    check_deliverability: bool = True,
    allow_smtputf8: bool = False
) -> ValidationResult:
    """
    Validate email address using email-validator 2.0+ replacing Node.js validators.
    
    Implements comprehensive email validation per Section 0.2.4 dependency decisions
    with enterprise-grade validation patterns and security checks.
    
    Args:
        email: Email address to validate
        check_deliverability: Whether to check email domain deliverability
        allow_smtputf8: Whether to allow international characters
    
    Returns:
        ValidationResult with validation outcome and normalized email
    
    Raises:
        ValidationError: For validation failures requiring error handler integration
    """
    if not email:
        result = ValidationResult(False, None, ["Email address is required"], "email")
        logger.warning("Email validation failed: missing email", field="email")
        return result
    
    if not isinstance(email, str):
        result = ValidationResult(False, None, ["Email must be a string"], "email")
        logger.warning("Email validation failed: invalid type", field="email", email_type=type(email).__name__)
        return result
    
    # Strip whitespace and convert to lowercase for validation
    email = email.strip().lower()
    
    # Basic format validation using regex
    if not EMAIL_REGEX.match(email):
        result = ValidationResult(False, None, ["Invalid email format"], "email")
        logger.warning("Email validation failed: invalid format", field="email", email_length=len(email))
        return result
    
    try:
        # Use email-validator for comprehensive validation
        validated_email = validate_email(
            email,
            check_deliverability=check_deliverability,
            allow_smtputf8=allow_smtputf8
        )
        
        # Extract normalized email address
        normalized_email = validated_email.email
        
        logger.info("Email validation successful", field="email", normalized_email=normalized_email)
        return ValidationResult(True, normalized_email, [], "email")
        
    except EmailNotValidError as e:
        error_msg = f"Invalid email address: {str(e)}"
        result = ValidationResult(False, None, [error_msg], "email")
        
        logger.warning(
            "Email validation failed",
            field="email",
            error=str(e),
            email_length=len(email)
        )
        
        # For critical applications, raise ValidationError for Flask error handler
        if check_deliverability:
            raise ValidationError(
                message=f"Email validation failed: {str(e)}",
                field_errors={"email": [error_msg]},
                details={"email": email, "validation_error": str(e)}
            )
        
        return result


def sanitize_html_input(
    html_input: Union[str, None],
    allowed_tags: Optional[List[str]] = None,
    allowed_attributes: Optional[Dict[str, List[str]]] = None,
    strip_tags: bool = False
) -> ValidationResult:
    """
    Sanitize HTML input using bleach 6.0+ for XSS prevention per Section 3.2.2.
    
    Provides comprehensive HTML sanitization with configurable security policies
    and enterprise-grade XSS protection patterns.
    
    Args:
        html_input: HTML content to sanitize
        allowed_tags: List of allowed HTML tags (defaults to safe subset)
        allowed_attributes: Dict of allowed attributes per tag
        strip_tags: Whether to strip all HTML tags
    
    Returns:
        ValidationResult with sanitized HTML content
    """
    if not html_input:
        return ValidationResult(True, "", [], "html_content")
    
    if not isinstance(html_input, str):
        result = ValidationResult(False, None, ["HTML input must be a string"], "html_content")
        logger.warning("HTML sanitization failed: invalid type", field="html_content", input_type=type(html_input).__name__)
        return result
    
    # Use default safe tags if none provided
    tags = allowed_tags if allowed_tags is not None else ([] if strip_tags else ALLOWED_HTML_TAGS)
    attributes = allowed_attributes if allowed_attributes is not None else ALLOWED_HTML_ATTRIBUTES
    
    try:
        # Additional XSS pattern detection before bleach processing
        for pattern in XSS_PATTERNS:
            if pattern.search(html_input):
                error_msg = "Potentially malicious content detected"
                result = ValidationResult(False, None, [error_msg], "html_content", ErrorSeverity.HIGH)
                
                logger.error(
                    "XSS pattern detected in HTML input",
                    field="html_content",
                    input_length=len(html_input),
                    security_risk="xss_attempt"
                )
                
                raise ValidationError(
                    message="HTML input contains potentially malicious content",
                    field_errors={"html_content": [error_msg]},
                    category=ErrorCategory.VALIDATION,
                    severity=ErrorSeverity.HIGH,
                    details={"security_risk": "xss_attempt", "input_length": len(html_input)}
                )
        
        # Sanitize using bleach
        sanitized_html = bleach.clean(
            html_input,
            tags=tags,
            attributes=attributes,
            strip=True,
            strip_comments=True
        )
        
        # Link processing for additional security
        if 'a' in tags:
            sanitized_html = bleach.linkify(
                sanitized_html,
                callbacks=[],
                skip_tags=['pre', 'code']
            )
        
        logger.info(
            "HTML sanitization successful",
            field="html_content",
            original_length=len(html_input),
            sanitized_length=len(sanitized_html),
            tags_allowed=len(tags)
        )
        
        return ValidationResult(True, sanitized_html, [], "html_content")
        
    except Exception as e:
        error_msg = f"HTML sanitization failed: {str(e)}"
        result = ValidationResult(False, None, [error_msg], "html_content", ErrorSeverity.HIGH)
        
        logger.error(
            "HTML sanitization error",
            field="html_content",
            error=str(e),
            input_length=len(html_input)
        )
        
        raise ValidationError(
            message="HTML input sanitization failed",
            field_errors={"html_content": [error_msg]},
            details={"sanitization_error": str(e), "input_length": len(html_input)}
        )


def validate_sql_injection_risk(input_value: Union[str, None]) -> ValidationResult:
    """
    Validate input for SQL injection patterns and security risks.
    
    Provides enterprise-grade SQL injection detection with pattern recognition
    and security risk assessment per Section 5.4.2 security validation.
    
    Args:
        input_value: Input string to validate for SQL injection risks
    
    Returns:
        ValidationResult with security risk assessment
    """
    if not input_value:
        return ValidationResult(True, input_value, [], "sql_input")
    
    if not isinstance(input_value, str):
        return ValidationResult(True, input_value, [], "sql_input")
    
    # Check for SQL injection patterns
    detected_patterns = []
    for pattern in SQL_INJECTION_PATTERNS:
        if pattern.search(input_value):
            detected_patterns.append(pattern.pattern)
    
    if detected_patterns:
        error_msg = "Potentially malicious SQL patterns detected"
        result = ValidationResult(
            False, 
            None, 
            [error_msg], 
            "sql_input", 
            ErrorSeverity.CRITICAL
        )
        
        logger.error(
            "SQL injection risk detected",
            field="sql_input",
            patterns_detected=detected_patterns,
            input_length=len(input_value),
            security_risk="sql_injection"
        )
        
        raise ValidationError(
            message="Input contains potentially malicious SQL patterns",
            field_errors={"sql_input": [error_msg]},
            category=ErrorCategory.VALIDATION,
            severity=ErrorSeverity.CRITICAL,
            details={
                "security_risk": "sql_injection",
                "patterns_detected": detected_patterns,
                "input_length": len(input_value)
            }
        )
    
    logger.debug("SQL injection validation passed", field="sql_input", input_length=len(input_value))
    return ValidationResult(True, input_value, [], "sql_input")


def validate_password_strength(
    password: Union[str, None],
    min_length: int = 8,
    require_uppercase: bool = True,
    require_lowercase: bool = True,
    require_digit: bool = True,
    require_special: bool = True,
    check_common_patterns: bool = True
) -> ValidationResult:
    """
    Validate password strength using comprehensive security criteria.
    
    Implements enterprise-grade password validation with configurable security
    requirements and strength assessment per security best practices.
    
    Args:
        password: Password to validate
        min_length: Minimum password length requirement
        require_uppercase: Whether uppercase letters are required
        require_lowercase: Whether lowercase letters are required
        require_digit: Whether digits are required
        require_special: Whether special characters are required
        check_common_patterns: Whether to check for common weak patterns
    
    Returns:
        ValidationResult with password strength assessment
    """
    if not password:
        result = ValidationResult(False, None, ["Password is required"], "password")
        logger.warning("Password validation failed: missing password", field="password")
        return result
    
    if not isinstance(password, str):
        result = ValidationResult(False, None, ["Password must be a string"], "password")
        logger.warning("Password validation failed: invalid type", field="password", password_type=type(password).__name__)
        return result
    
    errors = []
    
    # Check minimum length
    if len(password) < min_length:
        errors.append(f"Password must be at least {min_length} characters long")
    
    # Check character requirements
    if require_lowercase and not PASSWORD_PATTERNS['has_lowercase'].search(password):
        errors.append("Password must contain at least one lowercase letter")
    
    if require_uppercase and not PASSWORD_PATTERNS['has_uppercase'].search(password):
        errors.append("Password must contain at least one uppercase letter")
    
    if require_digit and not PASSWORD_PATTERNS['has_digit'].search(password):
        errors.append("Password must contain at least one digit")
    
    if require_special and not PASSWORD_PATTERNS['has_special'].search(password):
        errors.append("Password must contain at least one special character")
    
    # Check for common weak patterns
    if check_common_patterns and not PASSWORD_PATTERNS['no_common_patterns'].search(password):
        errors.append("Password contains common weak patterns")
    
    if errors:
        result = ValidationResult(False, None, errors, "password", ErrorSeverity.MEDIUM)
        logger.warning(
            "Password validation failed",
            field="password",
            errors=errors,
            password_length=len(password)
        )
        return result
    
    logger.info("Password validation successful", field="password", password_length=len(password))
    return ValidationResult(True, "***MASKED***", [], "password")


def validate_url(url: Union[str, None], require_https: bool = False) -> ValidationResult:
    """
    Validate URL format and security requirements.
    
    Provides URL validation with security checks and protocol requirements
    supporting external service integration patterns.
    
    Args:
        url: URL to validate
        require_https: Whether to require HTTPS protocol
    
    Returns:
        ValidationResult with URL validation outcome
    """
    if not url:
        result = ValidationResult(False, None, ["URL is required"], "url")
        logger.warning("URL validation failed: missing URL", field="url")
        return result
    
    if not isinstance(url, str):
        result = ValidationResult(False, None, ["URL must be a string"], "url")
        logger.warning("URL validation failed: invalid type", field="url", url_type=type(url).__name__)
        return result
    
    # Strip whitespace
    url = url.strip()
    
    # Basic URL format validation
    if not URL_REGEX.match(url):
        result = ValidationResult(False, None, ["Invalid URL format"], "url")
        logger.warning("URL validation failed: invalid format", field="url", url_length=len(url))
        return result
    
    try:
        # Parse URL for detailed validation
        parsed = urlparse(url)
        
        # Check for required HTTPS
        if require_https and parsed.scheme != 'https':
            error_msg = "HTTPS protocol is required"
            result = ValidationResult(False, None, [error_msg], "url")
            logger.warning("URL validation failed: HTTPS required", field="url", scheme=parsed.scheme)
            return result
        
        # Check for valid hostname
        if not parsed.netloc:
            error_msg = "URL must contain a valid hostname"
            result = ValidationResult(False, None, [error_msg], "url")
            logger.warning("URL validation failed: missing hostname", field="url")
            return result
        
        logger.info("URL validation successful", field="url", scheme=parsed.scheme, netloc=parsed.netloc)
        return ValidationResult(True, url, [], "url")
        
    except Exception as e:
        error_msg = f"URL parsing failed: {str(e)}"
        result = ValidationResult(False, None, [error_msg], "url")
        logger.error("URL validation error", field="url", error=str(e), url_length=len(url))
        return result


def validate_phone_number(
    phone: Union[str, None],
    country_code: str = 'us',
    normalize: bool = True
) -> ValidationResult:
    """
    Validate phone number format with international support.
    
    Provides comprehensive phone number validation supporting multiple formats
    and international number patterns with normalization capabilities.
    
    Args:
        phone: Phone number to validate
        country_code: Country code for format validation ('us', 'international', 'general')
        normalize: Whether to normalize the phone number format
    
    Returns:
        ValidationResult with phone validation outcome and normalized number
    """
    if not phone:
        result = ValidationResult(False, None, ["Phone number is required"], "phone")
        logger.warning("Phone validation failed: missing phone", field="phone")
        return result
    
    if not isinstance(phone, str):
        result = ValidationResult(False, None, ["Phone number must be a string"], "phone")
        logger.warning("Phone validation failed: invalid type", field="phone", phone_type=type(phone).__name__)
        return result
    
    # Remove common formatting characters
    cleaned_phone = re.sub(r'[^\d\+]', '', phone.strip())
    
    # Get appropriate pattern
    pattern = PHONE_PATTERNS.get(country_code, PHONE_PATTERNS['general'])
    
    if not pattern.match(cleaned_phone):
        error_msg = f"Invalid phone number format for {country_code}"
        result = ValidationResult(False, None, [error_msg], "phone")
        logger.warning(
            "Phone validation failed: invalid format",
            field="phone",
            country_code=country_code,
            cleaned_length=len(cleaned_phone)
        )
        return result
    
    # Normalize phone number if requested
    normalized_phone = cleaned_phone if normalize else phone
    
    logger.info(
        "Phone validation successful",
        field="phone",
        country_code=country_code,
        normalized_length=len(normalized_phone)
    )
    
    return ValidationResult(True, normalized_phone, [], "phone")


def validate_uuid(uuid_string: Union[str, None], version: int = 4) -> ValidationResult:
    """
    Validate UUID format and version requirements.
    
    Provides UUID validation supporting different UUID versions with
    format verification and type checking.
    
    Args:
        uuid_string: UUID string to validate
        version: Expected UUID version (1, 3, 4, or 5)
    
    Returns:
        ValidationResult with UUID validation outcome
    """
    if not uuid_string:
        result = ValidationResult(False, None, ["UUID is required"], "uuid")
        logger.warning("UUID validation failed: missing UUID", field="uuid")
        return result
    
    if not isinstance(uuid_string, str):
        result = ValidationResult(False, None, ["UUID must be a string"], "uuid")
        logger.warning("UUID validation failed: invalid type", field="uuid", uuid_type=type(uuid_string).__name__)
        return result
    
    try:
        parsed_uuid = uuid.UUID(uuid_string.strip())
        
        # Check UUID version if specified
        if version and parsed_uuid.version != version:
            error_msg = f"UUID must be version {version}, got version {parsed_uuid.version}"
            result = ValidationResult(False, None, [error_msg], "uuid")
            logger.warning(
                "UUID validation failed: version mismatch",
                field="uuid",
                expected_version=version,
                actual_version=parsed_uuid.version
            )
            return result
        
        logger.info("UUID validation successful", field="uuid", version=parsed_uuid.version)
        return ValidationResult(True, str(parsed_uuid), [], "uuid")
        
    except ValueError as e:
        error_msg = f"Invalid UUID format: {str(e)}"
        result = ValidationResult(False, None, [error_msg], "uuid")
        logger.warning("UUID validation failed: invalid format", field="uuid", error=str(e))
        return result


def validate_date_range(
    start_date: Union[str, datetime, date, None],
    end_date: Union[str, datetime, date, None],
    allow_same_date: bool = True,
    max_range_days: Optional[int] = None
) -> ValidationResult:
    """
    Validate date range with business logic constraints.
    
    Provides comprehensive date range validation supporting multiple input formats
    with business rule enforcement and constraint checking.
    
    Args:
        start_date: Start date (string, datetime, or date object)
        end_date: End date (string, datetime, or date object)
        allow_same_date: Whether start and end can be the same date
        max_range_days: Maximum allowed range in days
    
    Returns:
        ValidationResult with date range validation outcome
    """
    if not start_date or not end_date:
        result = ValidationResult(False, None, ["Both start and end dates are required"], "date_range")
        logger.warning("Date range validation failed: missing dates", field="date_range")
        return result
    
    try:
        # Parse dates to datetime objects
        def parse_date(date_input: Union[str, datetime, date]) -> datetime:
            if isinstance(date_input, str):
                # Try multiple date formats
                formats = ['%Y-%m-%d', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S', '%m/%d/%Y']
                for fmt in formats:
                    try:
                        return datetime.strptime(date_input, fmt)
                    except ValueError:
                        continue
                raise ValueError(f"Unable to parse date: {date_input}")
            elif isinstance(date_input, date) and not isinstance(date_input, datetime):
                return datetime.combine(date_input, datetime.min.time())
            elif isinstance(date_input, datetime):
                return date_input
            else:
                raise ValueError(f"Invalid date type: {type(date_input)}")
        
        parsed_start = parse_date(start_date)
        parsed_end = parse_date(end_date)
        
        # Validate date logic
        if parsed_start > parsed_end:
            error_msg = "Start date must be before or equal to end date"
            result = ValidationResult(False, None, [error_msg], "date_range")
            logger.warning(
                "Date range validation failed: start after end",
                field="date_range",
                start_date=parsed_start.isoformat(),
                end_date=parsed_end.isoformat()
            )
            return result
        
        # Check same date allowance
        if not allow_same_date and parsed_start.date() == parsed_end.date():
            error_msg = "Start and end dates cannot be the same"
            result = ValidationResult(False, None, [error_msg], "date_range")
            logger.warning(
                "Date range validation failed: same date not allowed",
                field="date_range",
                date=parsed_start.date().isoformat()
            )
            return result
        
        # Check maximum range constraint
        if max_range_days:
            range_days = (parsed_end - parsed_start).days
            if range_days > max_range_days:
                error_msg = f"Date range cannot exceed {max_range_days} days"
                result = ValidationResult(False, None, [error_msg], "date_range")
                logger.warning(
                    "Date range validation failed: range too large",
                    field="date_range",
                    range_days=range_days,
                    max_allowed=max_range_days
                )
                return result
        
        range_info = {
            'start_date': parsed_start.isoformat(),
            'end_date': parsed_end.isoformat(),
            'range_days': (parsed_end - parsed_start).days
        }
        
        logger.info("Date range validation successful", field="date_range", **range_info)
        return ValidationResult(True, range_info, [], "date_range")
        
    except Exception as e:
        error_msg = f"Date range validation failed: {str(e)}"
        result = ValidationResult(False, None, [error_msg], "date_range")
        logger.error("Date range validation error", field="date_range", error=str(e))
        return result


def validate_numeric_range(
    value: Union[str, int, float, Decimal, None],
    min_value: Optional[Union[int, float, Decimal]] = None,
    max_value: Optional[Union[int, float, Decimal]] = None,
    allow_decimal: bool = True,
    decimal_places: Optional[int] = None
) -> ValidationResult:
    """
    Validate numeric values with range constraints and precision requirements.
    
    Provides comprehensive numeric validation supporting integers, floats, and decimals
    with business logic constraints and precision control.
    
    Args:
        value: Numeric value to validate
        min_value: Minimum allowed value (inclusive)
        max_value: Maximum allowed value (inclusive)
        allow_decimal: Whether decimal values are allowed
        decimal_places: Maximum number of decimal places allowed
    
    Returns:
        ValidationResult with numeric validation outcome
    """
    if value is None:
        result = ValidationResult(False, None, ["Numeric value is required"], "numeric")
        logger.warning("Numeric validation failed: missing value", field="numeric")
        return result
    
    try:
        # Convert to appropriate numeric type
        if isinstance(value, str):
            value = value.strip()
            if not value:
                result = ValidationResult(False, None, ["Numeric value cannot be empty"], "numeric")
                return result
            
            # Try to parse as number
            if '.' in value and allow_decimal:
                parsed_value = Decimal(value)
            else:
                parsed_value = int(value) if not allow_decimal else float(value)
        elif isinstance(value, (int, float)):
            parsed_value = value
        elif isinstance(value, Decimal):
            parsed_value = value
        else:
            result = ValidationResult(False, None, ["Invalid numeric type"], "numeric")
            logger.warning("Numeric validation failed: invalid type", field="numeric", value_type=type(value).__name__)
            return result
        
        # Check decimal constraint
        if not allow_decimal and isinstance(parsed_value, (float, Decimal)) and parsed_value != int(parsed_value):
            error_msg = "Decimal values are not allowed"
            result = ValidationResult(False, None, [error_msg], "numeric")
            logger.warning("Numeric validation failed: decimal not allowed", field="numeric")
            return result
        
        # Check decimal places
        if decimal_places is not None and isinstance(parsed_value, (float, Decimal)):
            if isinstance(parsed_value, Decimal):
                places = abs(parsed_value.as_tuple().exponent)
            else:
                places = len(str(parsed_value).split('.')[1]) if '.' in str(parsed_value) else 0
            
            if places > decimal_places:
                error_msg = f"Number cannot have more than {decimal_places} decimal places"
                result = ValidationResult(False, None, [error_msg], "numeric")
                logger.warning(
                    "Numeric validation failed: too many decimal places",
                    field="numeric",
                    decimal_places=places,
                    max_allowed=decimal_places
                )
                return result
        
        # Check range constraints
        if min_value is not None and parsed_value < min_value:
            error_msg = f"Value must be at least {min_value}"
            result = ValidationResult(False, None, [error_msg], "numeric")
            logger.warning(
                "Numeric validation failed: below minimum",
                field="numeric",
                value=float(parsed_value),
                min_value=float(min_value)
            )
            return result
        
        if max_value is not None and parsed_value > max_value:
            error_msg = f"Value must be at most {max_value}"
            result = ValidationResult(False, None, [error_msg], "numeric")
            logger.warning(
                "Numeric validation failed: above maximum",
                field="numeric",
                value=float(parsed_value),
                max_value=float(max_value)
            )
            return result
        
        logger.info(
            "Numeric validation successful",
            field="numeric",
            value=float(parsed_value),
            value_type=type(parsed_value).__name__
        )
        
        return ValidationResult(True, parsed_value, [], "numeric")
        
    except (ValueError, InvalidOperation) as e:
        error_msg = f"Invalid numeric value: {str(e)}"
        result = ValidationResult(False, None, [error_msg], "numeric")
        logger.warning("Numeric validation failed: parsing error", field="numeric", error=str(e))
        return result


def validate_json_schema(
    data: Any,
    schema_validator: Union[Schema, Type[BaseModel], Callable],
    field_name: str = "data"
) -> ValidationResult:
    """
    Validate data against marshmallow or pydantic schema definitions.
    
    Provides unified validation interface supporting both marshmallow 3.20+ and pydantic 2.3+
    validation frameworks per Section 3.2.2 input validation requirements.
    
    Args:
        data: Data to validate against schema
        schema_validator: Marshmallow schema, Pydantic model, or custom validator
        field_name: Field name for error reporting
    
    Returns:
        ValidationResult with schema validation outcome and validated data
    """
    try:
        # Handle marshmallow schema validation
        if isinstance(schema_validator, Schema):
            try:
                validated_data = schema_validator.load(data)
                logger.info(
                    "Marshmallow schema validation successful",
                    field=field_name,
                    schema_type=schema_validator.__class__.__name__
                )
                return ValidationResult(True, validated_data, [], field_name)
                
            except MarshmallowValidationError as e:
                errors = []
                if hasattr(e, 'messages'):
                    if isinstance(e.messages, dict):
                        for field, field_errors in e.messages.items():
                            if isinstance(field_errors, list):
                                errors.extend([f"{field}: {err}" for err in field_errors])
                            else:
                                errors.append(f"{field}: {field_errors}")
                    else:
                        errors = e.messages if isinstance(e.messages, list) else [str(e.messages)]
                else:
                    errors = [str(e)]
                
                result = ValidationResult(False, None, errors, field_name)
                logger.warning(
                    "Marshmallow schema validation failed",
                    field=field_name,
                    errors=errors,
                    schema_type=schema_validator.__class__.__name__
                )
                return result
        
        # Handle pydantic model validation
        elif isinstance(schema_validator, type) and issubclass(schema_validator, BaseModel):
            try:
                validated_data = schema_validator.parse_obj(data)
                logger.info(
                    "Pydantic schema validation successful",
                    field=field_name,
                    schema_type=schema_validator.__name__
                )
                return ValidationResult(True, validated_data.dict(), [], field_name)
                
            except PydanticValidationError as e:
                errors = []
                for error in e.errors():
                    field_path = ".".join(str(loc) for loc in error['loc'])
                    error_msg = f"{field_path}: {error['msg']}"
                    errors.append(error_msg)
                
                result = ValidationResult(False, None, errors, field_name)
                logger.warning(
                    "Pydantic schema validation failed",
                    field=field_name,
                    errors=errors,
                    schema_type=schema_validator.__name__
                )
                return result
        
        # Handle custom callable validator
        elif callable(schema_validator):
            try:
                validated_data = schema_validator(data)
                logger.info(
                    "Custom validator successful",
                    field=field_name,
                    validator_type=schema_validator.__name__
                )
                return ValidationResult(True, validated_data, [], field_name)
                
            except Exception as e:
                error_msg = f"Custom validation failed: {str(e)}"
                result = ValidationResult(False, None, [error_msg], field_name)
                logger.warning(
                    "Custom validator failed",
                    field=field_name,
                    error=str(e),
                    validator_type=schema_validator.__name__
                )
                return result
        
        else:
            error_msg = "Invalid schema validator type"
            result = ValidationResult(False, None, [error_msg], field_name)
            logger.error(
                "Schema validation failed: invalid validator type",
                field=field_name,
                validator_type=type(schema_validator).__name__
            )
            return result
            
    except Exception as e:
        error_msg = f"Schema validation error: {str(e)}"
        result = ValidationResult(False, None, [error_msg], field_name)
        logger.error("Schema validation error", field=field_name, error=str(e))
        return result


def validate_file_upload(
    file_data: Any,
    allowed_extensions: Optional[List[str]] = None,
    max_size_mb: Optional[float] = None,
    required_mime_types: Optional[List[str]] = None
) -> ValidationResult:
    """
    Validate file upload data with security and size constraints.
    
    Provides comprehensive file upload validation supporting Flask file upload patterns
    with security checks and business logic constraints.
    
    Args:
        file_data: File data to validate (werkzeug FileStorage or file-like object)
        allowed_extensions: List of allowed file extensions
        max_size_mb: Maximum file size in megabytes
        required_mime_types: List of required MIME types
    
    Returns:
        ValidationResult with file validation outcome
    """
    if not file_data:
        result = ValidationResult(False, None, ["File upload is required"], "file_upload")
        logger.warning("File upload validation failed: missing file", field="file_upload")
        return result
    
    try:
        # Extract file information
        filename = getattr(file_data, 'filename', None)
        content_type = getattr(file_data, 'content_type', getattr(file_data, 'mimetype', None))
        
        # Check if file has a filename
        if not filename:
            error_msg = "File must have a filename"
            result = ValidationResult(False, None, [error_msg], "file_upload")
            logger.warning("File upload validation failed: missing filename", field="file_upload")
            return result
        
        # Validate file extension
        if allowed_extensions:
            file_ext = filename.lower().split('.')[-1] if '.' in filename else ''
            if file_ext not in [ext.lower().lstrip('.') for ext in allowed_extensions]:
                error_msg = f"File extension '{file_ext}' not allowed. Allowed: {', '.join(allowed_extensions)}"
                result = ValidationResult(False, None, [error_msg], "file_upload")
                logger.warning(
                    "File upload validation failed: invalid extension",
                    field="file_upload",
                    filename=filename,
                    extension=file_ext,
                    allowed_extensions=allowed_extensions
                )
                return result
        
        # Validate MIME type
        if required_mime_types and content_type:
            if content_type not in required_mime_types:
                error_msg = f"File type '{content_type}' not allowed. Allowed: {', '.join(required_mime_types)}"
                result = ValidationResult(False, None, [error_msg], "file_upload")
                logger.warning(
                    "File upload validation failed: invalid MIME type",
                    field="file_upload",
                    filename=filename,
                    content_type=content_type,
                    required_mime_types=required_mime_types
                )
                return result
        
        # Validate file size
        if max_size_mb and hasattr(file_data, 'seek') and hasattr(file_data, 'tell'):
            # Get file size
            file_data.seek(0, 2)  # Seek to end
            file_size = file_data.tell()
            file_data.seek(0)  # Reset to beginning
            
            max_size_bytes = max_size_mb * 1024 * 1024
            if file_size > max_size_bytes:
                error_msg = f"File size ({file_size / 1024 / 1024:.2f}MB) exceeds maximum ({max_size_mb}MB)"
                result = ValidationResult(False, None, [error_msg], "file_upload")
                logger.warning(
                    "File upload validation failed: file too large",
                    field="file_upload",
                    filename=filename,
                    file_size_mb=file_size / 1024 / 1024,
                    max_size_mb=max_size_mb
                )
                return result
        
        file_info = {
            'filename': filename,
            'content_type': content_type,
            'size_bytes': getattr(file_data, 'content_length', None)
        }
        
        logger.info(
            "File upload validation successful",
            field="file_upload",
            filename=filename,
            content_type=content_type
        )
        
        return ValidationResult(True, file_info, [], "file_upload")
        
    except Exception as e:
        error_msg = f"File upload validation failed: {str(e)}"
        result = ValidationResult(False, None, [error_msg], "file_upload")
        logger.error("File upload validation error", field="file_upload", error=str(e))
        return result


def create_composite_validator(*validators: Callable[[Any], ValidationResult]) -> Callable[[Any], ValidationResult]:
    """
    Create composite validator combining multiple validation functions.
    
    Provides validation composition pattern for complex validation requirements
    supporting enterprise-grade validation workflows and error aggregation.
    
    Args:
        *validators: Variable number of validation functions
    
    Returns:
        Composite validation function
    """
    def composite_validator(value: Any) -> ValidationResult:
        """Execute all validators and aggregate results."""
        all_errors = []
        highest_severity = ErrorSeverity.LOW
        final_value = value
        
        for validator in validators:
            try:
                result = validator(value)
                if not result.is_valid:
                    all_errors.extend(result.errors)
                    if result.severity.value > highest_severity.value:
                        highest_severity = result.severity
                else:
                    # Use the validated value from successful validators
                    if result.value is not None:
                        final_value = result.value
                        
            except Exception as e:
                all_errors.append(f"Validator error: {str(e)}")
                highest_severity = ErrorSeverity.HIGH
                logger.error(
                    "Composite validator error",
                    validator=validator.__name__,
                    error=str(e)
                )
        
        is_valid = len(all_errors) == 0
        
        logger.info(
            "Composite validation completed",
            validators_count=len(validators),
            is_valid=is_valid,
            errors_count=len(all_errors),
            severity=highest_severity.value
        )
        
        return ValidationResult(is_valid, final_value if is_valid else None, all_errors, "composite", highest_severity)
    
    return composite_validator


def sanitize_input(
    input_value: Any,
    max_length: Optional[int] = None,
    strip_whitespace: bool = True,
    check_sql_injection: bool = True,
    sanitize_html: bool = True
) -> ValidationResult:
    """
    Comprehensive input sanitization with security and business rule validation.
    
    Provides all-in-one input sanitization combining XSS prevention, SQL injection
    detection, and business logic constraints per Section 5.4.2 security patterns.
    
    Args:
        input_value: Input value to sanitize
        max_length: Maximum allowed length
        strip_whitespace: Whether to strip leading/trailing whitespace
        check_sql_injection: Whether to check for SQL injection patterns
        sanitize_html: Whether to sanitize HTML content
    
    Returns:
        ValidationResult with sanitized input value
    """
    if input_value is None:
        return ValidationResult(True, None, [], "input")
    
    # Convert to string for processing
    if not isinstance(input_value, str):
        input_value = str(input_value)
    
    original_value = input_value
    
    try:
        # Strip whitespace if requested
        if strip_whitespace:
            input_value = input_value.strip()
        
        # Check length constraint
        if max_length and len(input_value) > max_length:
            error_msg = f"Input length ({len(input_value)}) exceeds maximum ({max_length})"
            result = ValidationResult(False, None, [error_msg], "input")
            logger.warning(
                "Input sanitization failed: length exceeded",
                field="input",
                length=len(input_value),
                max_length=max_length
            )
            return result
        
        # Check for SQL injection if requested
        if check_sql_injection:
            sql_result = validate_sql_injection_risk(input_value)
            if not sql_result.is_valid:
                return sql_result
        
        # Sanitize HTML if requested
        if sanitize_html:
            html_result = sanitize_html_input(input_value, strip_tags=True)
            if not html_result.is_valid:
                return html_result
            input_value = html_result.value
        
        logger.info(
            "Input sanitization successful",
            field="input",
            original_length=len(original_value),
            sanitized_length=len(input_value),
            sql_check=check_sql_injection,
            html_sanitization=sanitize_html
        )
        
        return ValidationResult(True, input_value, [], "input")
        
    except Exception as e:
        error_msg = f"Input sanitization failed: {str(e)}"
        result = ValidationResult(False, None, [error_msg], "input")
        logger.error("Input sanitization error", field="input", error=str(e))
        return result


# Convenience validators for common patterns
def validate_required_string(value: Any, field_name: str = "string") -> ValidationResult:
    """Validate that value is a non-empty string."""
    if not value:
        return ValidationResult(False, None, [f"{field_name} is required"], field_name)
    
    if not isinstance(value, str):
        return ValidationResult(False, None, [f"{field_name} must be a string"], field_name)
    
    if not value.strip():
        return ValidationResult(False, None, [f"{field_name} cannot be empty"], field_name)
    
    return ValidationResult(True, value.strip(), [], field_name)


def validate_optional_string(value: Any, field_name: str = "string") -> ValidationResult:
    """Validate optional string field."""
    if not value:
        return ValidationResult(True, None, [], field_name)
    
    return validate_required_string(value, field_name)


# Export all validation functions and classes
__all__ = [
    'ValidationResult',
    'validate_email_address',
    'sanitize_html_input',
    'validate_sql_injection_risk',
    'validate_password_strength',
    'validate_url',
    'validate_phone_number',
    'validate_uuid',
    'validate_date_range',
    'validate_numeric_range',
    'validate_json_schema',
    'validate_file_upload',
    'create_composite_validator',
    'sanitize_input',
    'validate_required_string',
    'validate_optional_string',
    'EMAIL_REGEX',
    'URL_REGEX',
    'PHONE_PATTERNS',
    'PASSWORD_PATTERNS'
]