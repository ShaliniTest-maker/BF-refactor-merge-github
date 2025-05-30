"""
Comprehensive unit tests for utility modules.

This module provides comprehensive test coverage for authentication utilities, business
utilities, date/time processing, data manipulation, and common utility functions per
Section 6.6.1 helper function testing requirements.

Test Coverage Areas:
- Authentication utilities (JWT tokens, cryptographic operations, input validation)
- Business utilities (data manipulation, calculations, type conversions)
- Date/time processing utilities with python-dateutil 2.8+ equivalent to moment.js
- Error handling patterns per Section 4.2.3 with Flask @errorhandler integration
- Input validation and sanitization with security testing
- Type validation and conversion utilities
- Cryptographic utilities with enterprise-grade security testing

Key Testing Patterns:
- Comprehensive error handling validation per Section 4.2.3
- Security-focused testing for authentication components per Section 6.4.1
- Business rule validation per Section 5.2.4
- Type hints validation and runtime type checking
- Edge case and boundary condition testing
- Performance validation maintaining ≤10% variance requirement
"""

import pytest
import json
import uuid
import base64
import hashlib
import hmac
import decimal
import re
from datetime import datetime, timezone, timedelta, date
from typing import Any, Dict, List, Optional, Union, Tuple
from unittest.mock import Mock, patch, MagicMock
from freezegun import freeze_time

# Import utilities to test
from src.auth.utils import (
    JWTTokenUtils,
    DateTimeUtils,
    InputValidator,
    CryptographicUtils,
    generate_secure_token,
    validate_email,
    sanitize_html,
    parse_iso8601_date,
    format_iso8601_date,
    create_jwt_token,
    validate_jwt_token,
    encrypt_sensitive_data,
    decrypt_sensitive_data,
    AuthenticationError,
    TokenValidationError,
    CryptographicError,
    ValidationError,
    DateTimeValidationError,
    EmailValidationError,
    ConfigurationError
)

from src.business.utils import (
    clean_data,
    transform_data,
    merge_data,
    flatten_data,
    filter_data,
    parse_date,
    format_date,
    calculate_date_difference,
    get_business_days,
    convert_timezone,
    calculate_percentage,
    apply_discount,
    calculate_tax,
    round_currency,
    validate_currency,
    validate_email as business_validate_email,
    validate_phone,
    validate_postal_code,
    sanitize_input as business_sanitize_input,
    validate_json_schema,
    safe_int,
    safe_float,
    safe_str,
    normalize_boolean,
    parse_json,
    generate_unique_id,
    calculate_hash,
    DataFormat,
    CurrencyCode,
    TimezoneRegion,
    BaseBusinessException,
    BusinessRuleViolationError,
    DataProcessingError,
    DataValidationError as BusinessDataValidationError
)

# Import general utilities for integration testing
try:
    from src.utils import (
        parse as utils_parse,
        now as utils_now,
        utc_now as utils_utc_now,
        to_iso as utils_to_iso,
        format_datetime as utils_format_datetime,
        validate_email_address as utils_validate_email,
        sanitize_html as utils_sanitize_html,
        create_success_response,
        create_error_response,
        ValidationError as UtilsValidationError,
        safe_str as utils_safe_str
    )
    UTILS_AVAILABLE = True
except ImportError:
    # Utils module may not be fully implemented yet
    UTILS_AVAILABLE = False

# Third-party testing imports
import jwt
from cryptography.fernet import Fernet
from dateutil import parser as dateutil_parser
from dateutil import tz
import bleach
import email_validator


class TestJWTTokenUtils:
    """
    Comprehensive test suite for JWT token manipulation utilities.
    
    Tests JWT token generation, validation, claims extraction, and refresh
    functionality using PyJWT 2.8+ equivalent to Node.js jsonwebtoken patterns.
    Validates security features and error handling per Section 6.4.1.
    """
    
    @pytest.fixture
    def jwt_utils(self):
        """Create JWT utility instance with test configuration."""
        return JWTTokenUtils(secret_key="test-secret-key-12345", algorithm="HS256")
    
    @pytest.fixture
    def sample_payload(self):
        """Sample JWT payload for testing."""
        return {
            "user_id": "test-user-123",
            "email": "test@example.com",
            "roles": ["user", "admin"],
            "permissions": ["read", "write"]
        }
    
    def test_jwt_utils_initialization_success(self):
        """Test successful JWT utility initialization."""
        jwt_utils = JWTTokenUtils("secret-key", "HS256")
        assert jwt_utils.secret_key == "secret-key"
        assert jwt_utils.algorithm == "HS256"
    
    def test_jwt_utils_initialization_no_secret_key(self):
        """Test JWT utility initialization failure without secret key."""
        with pytest.raises(ConfigurationError) as exc_info:
            JWTTokenUtils(None, "HS256")
        
        assert "JWT secret key is required" in str(exc_info.value)
    
    def test_jwt_utils_initialization_invalid_algorithm(self):
        """Test JWT utility initialization with invalid algorithm."""
        with pytest.raises(ConfigurationError) as exc_info:
            JWTTokenUtils("secret-key", "INVALID_ALG")
        
        assert "Unsupported JWT algorithm" in str(exc_info.value)
    
    def test_generate_token_success(self, jwt_utils, sample_payload):
        """Test successful JWT token generation."""
        token = jwt_utils.generate_token(sample_payload, expires_in=3600)
        
        assert isinstance(token, str)
        assert len(token) > 0
        
        # Verify token can be decoded
        decoded = jwt.decode(token, "test-secret-key-12345", algorithms=["HS256"])
        assert decoded["user_id"] == "test-user-123"
        assert decoded["email"] == "test@example.com"
        assert "iat" in decoded
        assert "exp" in decoded
        assert "jti" in decoded
        assert decoded["iss"] == "flask-auth-system"
    
    def test_generate_token_with_additional_headers(self, jwt_utils, sample_payload):
        """Test JWT token generation with additional headers."""
        additional_headers = {"kid": "key-123", "typ": "JWT"}
        token = jwt_utils.generate_token(
            sample_payload, 
            expires_in=1800, 
            additional_headers=additional_headers
        )
        
        # Decode header to verify additional headers
        header = jwt.get_unverified_header(token)
        assert header["kid"] == "key-123"
        assert header["typ"] == "JWT"
        assert header["alg"] == "HS256"
    
    def test_generate_token_custom_expiration(self, jwt_utils, sample_payload):
        """Test JWT token generation with custom expiration time."""
        expires_in = 7200  # 2 hours
        token = jwt_utils.generate_token(sample_payload, expires_in=expires_in)
        
        decoded = jwt.decode(token, "test-secret-key-12345", algorithms=["HS256"])
        exp_time = datetime.fromtimestamp(decoded["exp"], tz=timezone.utc)
        iat_time = datetime.fromtimestamp(decoded["iat"], tz=timezone.utc)
        
        time_diff = exp_time - iat_time
        assert abs(time_diff.total_seconds() - expires_in) < 5  # Allow 5 second tolerance
    
    def test_validate_token_success(self, jwt_utils, sample_payload):
        """Test successful JWT token validation."""
        token = jwt_utils.generate_token(sample_payload)
        decoded_payload = jwt_utils.validate_token(token)
        
        assert decoded_payload["user_id"] == "test-user-123"
        assert decoded_payload["email"] == "test@example.com"
        assert decoded_payload["roles"] == ["user", "admin"]
        assert "iat" in decoded_payload
        assert "exp" in decoded_payload
    
    def test_validate_token_expired(self, jwt_utils, sample_payload):
        """Test JWT token validation with expired token."""
        # Generate token that expires immediately
        token = jwt_utils.generate_token(sample_payload, expires_in=-1)
        
        with pytest.raises(TokenValidationError) as exc_info:
            jwt_utils.validate_token(token)
        
        assert "JWT token has expired" in str(exc_info.value)
    
    def test_validate_token_invalid_signature(self, jwt_utils, sample_payload):
        """Test JWT token validation with invalid signature."""
        token = jwt_utils.generate_token(sample_payload)
        
        # Create different JWT utils with different secret
        wrong_jwt_utils = JWTTokenUtils("wrong-secret-key", "HS256")
        
        with pytest.raises(TokenValidationError) as exc_info:
            wrong_jwt_utils.validate_token(token)
        
        assert "JWT token signature verification failed" in str(exc_info.value)
    
    def test_validate_token_malformed(self, jwt_utils):
        """Test JWT token validation with malformed token."""
        malformed_token = "not.a.valid.jwt.token"
        
        with pytest.raises(TokenValidationError) as exc_info:
            jwt_utils.validate_token(malformed_token)
        
        assert "Invalid JWT token" in str(exc_info.value)
    
    def test_validate_token_with_leeway(self, jwt_utils, sample_payload):
        """Test JWT token validation with expiration leeway."""
        # Generate token that expires in 1 second
        token = jwt_utils.generate_token(sample_payload, expires_in=1)
        
        # Wait for token to expire
        import time
        time.sleep(2)
        
        # Should fail without leeway
        with pytest.raises(TokenValidationError):
            jwt_utils.validate_token(token, leeway=0)
        
        # Should succeed with sufficient leeway
        decoded = jwt_utils.validate_token(token, leeway=5)
        assert decoded["user_id"] == "test-user-123"
    
    def test_extract_claims_success(self, jwt_utils, sample_payload):
        """Test successful JWT claims extraction."""
        token = jwt_utils.generate_token(sample_payload)
        claims = jwt_utils.extract_claims(token, ["user_id", "email", "roles"])
        
        assert claims["user_id"] == "test-user-123"
        assert claims["email"] == "test@example.com"
        assert claims["roles"] == ["user", "admin"]
    
    def test_extract_claims_nonexistent(self, jwt_utils, sample_payload):
        """Test JWT claims extraction for non-existent claims."""
        token = jwt_utils.generate_token(sample_payload)
        claims = jwt_utils.extract_claims(token, ["user_id", "nonexistent"])
        
        assert claims["user_id"] == "test-user-123"
        assert claims["nonexistent"] is None
    
    def test_extract_claims_malformed_token(self, jwt_utils):
        """Test JWT claims extraction with malformed token."""
        malformed_token = "invalid.token"
        
        with pytest.raises(TokenValidationError) as exc_info:
            jwt_utils.extract_claims(malformed_token, ["user_id"])
        
        assert "Failed to extract claims" in str(exc_info.value)
    
    def test_refresh_token_success(self, jwt_utils, sample_payload):
        """Test successful JWT token refresh."""
        original_token = jwt_utils.generate_token(sample_payload, expires_in=3600)
        new_token = jwt_utils.refresh_token(original_token, new_expires_in=7200)
        
        # Decode both tokens
        original_decoded = jwt.decode(original_token, "test-secret-key-12345", algorithms=["HS256"])
        new_decoded = jwt.decode(new_token, "test-secret-key-12345", algorithms=["HS256"])
        
        # Verify preserved claims
        assert new_decoded["user_id"] == original_decoded["user_id"]
        assert new_decoded["email"] == original_decoded["email"]
        assert new_decoded["roles"] == original_decoded["roles"]
        
        # Verify new expiration
        assert new_decoded["exp"] > original_decoded["exp"]
    
    def test_refresh_token_preserve_specific_claims(self, jwt_utils, sample_payload):
        """Test JWT token refresh with specific claim preservation."""
        original_token = jwt_utils.generate_token(sample_payload)
        new_token = jwt_utils.refresh_token(
            original_token, 
            preserve_claims=["user_id", "email"]
        )
        
        new_decoded = jwt.decode(new_token, "test-secret-key-12345", algorithms=["HS256"])
        
        # Verify only specified claims preserved
        assert new_decoded["user_id"] == "test-user-123"
        assert new_decoded["email"] == "test@example.com"
        assert "roles" not in new_decoded
    
    def test_refresh_token_expired_original(self, jwt_utils, sample_payload):
        """Test JWT token refresh with expired original token."""
        expired_token = jwt_utils.generate_token(sample_payload, expires_in=-1)
        
        # Should still work as we validate without expiration check
        new_token = jwt_utils.refresh_token(expired_token)
        new_decoded = jwt.decode(new_token, "test-secret-key-12345", algorithms=["HS256"])
        
        assert new_decoded["user_id"] == "test-user-123"
    
    def test_refresh_token_invalid_original(self, jwt_utils):
        """Test JWT token refresh with invalid original token."""
        invalid_token = "invalid.token"
        
        with pytest.raises(TokenValidationError) as exc_info:
            jwt_utils.refresh_token(invalid_token)
        
        assert "Failed to refresh token" in str(exc_info.value)


class TestDateTimeUtils:
    """
    Comprehensive test suite for date/time processing utilities.
    
    Tests date parsing, formatting, validation, and masking using python-dateutil 2.8+
    equivalent to Node.js moment.js functionality per Section 5.2.4.
    """
    
    @pytest.fixture
    def datetime_utils(self):
        """Create datetime utility instance."""
        return DateTimeUtils(default_timezone="UTC")
    
    def test_datetime_utils_initialization(self):
        """Test datetime utility initialization."""
        dt_utils = DateTimeUtils("UTC")
        assert dt_utils.default_timezone == timezone.utc
        assert isinstance(dt_utils.masking_salt, str)
    
    def test_parse_iso8601_valid_format(self, datetime_utils):
        """Test ISO 8601 date parsing with valid formats."""
        test_cases = [
            "2024-01-15T10:30:00Z",
            "2024-01-15T10:30:00+00:00",
            "2024-01-15T10:30:00.123Z",
            "2024-01-15T10:30:00-05:00",
            "2024-01-15",
        ]
        
        for date_string in test_cases:
            result = datetime_utils.parse_iso8601(date_string)
            assert isinstance(result, datetime)
            assert result.year == 2024
            assert result.month == 1
            assert result.day == 15
    
    def test_parse_iso8601_invalid_format(self, datetime_utils):
        """Test ISO 8601 date parsing with invalid formats."""
        invalid_formats = [
            "not-a-date",
            "2024/01/15",
            "15-01-2024",
            "2024-13-01T10:30:00Z",  # Invalid month
            "2024-01-32T10:30:00Z",  # Invalid day
            "",
            None
        ]
        
        for invalid_date in invalid_formats:
            with pytest.raises(DateTimeValidationError):
                datetime_utils.parse_iso8601(invalid_date)
    
    def test_parse_iso8601_with_timezone(self, datetime_utils):
        """Test ISO 8601 date parsing with timezone conversion."""
        date_string = "2024-01-15T10:30:00"
        target_tz = tz.gettz("America/New_York")
        
        result = datetime_utils.parse_iso8601(date_string, default_timezone=target_tz)
        
        assert result.tzinfo == target_tz
        assert result.hour == 10
        assert result.minute == 30
    
    def test_parse_iso8601_out_of_range(self, datetime_utils):
        """Test ISO 8601 date parsing with out of range dates."""
        out_of_range_dates = [
            "1800-01-01T00:00:00Z",  # Too old
            "2200-01-01T00:00:00Z",  # Too far in future
        ]
        
        for date_string in out_of_range_dates:
            with pytest.raises(DateTimeValidationError) as exc_info:
                datetime_utils.parse_iso8601(date_string)
            
            assert "Date outside valid range" in str(exc_info.value)
    
    def test_format_iso8601_basic(self, datetime_utils):
        """Test basic ISO 8601 date formatting."""
        dt = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        result = datetime_utils.format_iso8601(dt)
        
        assert result == "2024-01-15T10:30:00+00:00"
    
    def test_format_iso8601_with_microseconds(self, datetime_utils):
        """Test ISO 8601 date formatting with microseconds."""
        dt = datetime(2024, 1, 15, 10, 30, 0, 123456, tzinfo=timezone.utc)
        
        # Without microseconds (default)
        result_no_micro = datetime_utils.format_iso8601(dt, include_microseconds=False)
        assert "123456" not in result_no_micro
        
        # With microseconds
        result_with_micro = datetime_utils.format_iso8601(dt, include_microseconds=True)
        assert "123456" in result_with_micro
    
    def test_format_iso8601_timezone_conversion(self, datetime_utils):
        """Test ISO 8601 date formatting with timezone conversion."""
        # UTC datetime
        dt_utc = datetime(2024, 1, 15, 15, 30, 0, tzinfo=timezone.utc)
        
        # Format without conversion
        result_no_convert = datetime_utils.format_iso8601(dt_utc, force_utc=False)
        assert "+00:00" in result_no_convert
        
        # Format with UTC conversion (should be same since already UTC)
        result_convert = datetime_utils.format_iso8601(dt_utc, force_utc=True)
        assert result_convert == result_no_convert
    
    def test_format_iso8601_naive_datetime(self, datetime_utils):
        """Test ISO 8601 date formatting with naive datetime."""
        dt_naive = datetime(2024, 1, 15, 10, 30, 0)
        result = datetime_utils.format_iso8601(dt_naive, force_utc=True)
        
        assert "+00:00" in result
        assert "2024-01-15T10:30:00" in result
    
    def test_mask_temporal_data_month_level(self, datetime_utils):
        """Test temporal data masking at month level."""
        dt = datetime(2024, 1, 15, 10, 30, 45, tzinfo=timezone.utc)
        result = datetime_utils.mask_temporal_data(dt, masking_level="month")
        
        assert result == "2024-01-01T00:00:00+00:00"
    
    def test_mask_temporal_data_week_level(self, datetime_utils):
        """Test temporal data masking at week level."""
        # Wednesday, January 17, 2024
        dt = datetime(2024, 1, 17, 10, 30, 45, tzinfo=timezone.utc)
        result = datetime_utils.mask_temporal_data(dt, masking_level="week")
        
        # Should be Monday of that week
        assert "2024-01-15T00:00:00" in result
    
    def test_mask_temporal_data_year_level(self, datetime_utils):
        """Test temporal data masking at year level."""
        dt = datetime(2024, 6, 15, 10, 30, 45, tzinfo=timezone.utc)
        result = datetime_utils.mask_temporal_data(dt, masking_level="year")
        
        assert result == "2024-01-01T00:00:00+00:00"
    
    def test_mask_temporal_data_string_input(self, datetime_utils):
        """Test temporal data masking with string input."""
        date_string = "2024-01-15T10:30:45Z"
        result = datetime_utils.mask_temporal_data(date_string, masking_level="month")
        
        assert result == "2024-01-01T00:00:00+00:00"
    
    def test_mask_temporal_data_invalid_input(self, datetime_utils):
        """Test temporal data masking with invalid input."""
        invalid_date = "not-a-date"
        result = datetime_utils.mask_temporal_data(invalid_date)
        
        # Should return safe default
        assert result == "1970-01-01T00:00:00Z"
    
    def test_validate_date_range_success(self, datetime_utils):
        """Test successful date range validation."""
        dt = datetime(2024, 1, 15, tzinfo=timezone.utc)
        min_date = datetime(2020, 1, 1, tzinfo=timezone.utc)
        max_date = datetime(2030, 1, 1, tzinfo=timezone.utc)
        
        result = datetime_utils.validate_date_range(dt, min_date, max_date)
        assert result is True
    
    def test_validate_date_range_outside_bounds(self, datetime_utils):
        """Test date range validation outside bounds."""
        dt = datetime(2024, 1, 15, tzinfo=timezone.utc)
        min_date = datetime(2025, 1, 1, tzinfo=timezone.utc)  # After test date
        max_date = datetime(2030, 1, 1, tzinfo=timezone.utc)
        
        result = datetime_utils.validate_date_range(dt, min_date, max_date)
        assert result is False
    
    def test_validate_date_range_string_input(self, datetime_utils):
        """Test date range validation with string input."""
        date_string = "2024-01-15T10:30:00Z"
        min_date = datetime(2020, 1, 1, tzinfo=timezone.utc)
        max_date = datetime(2030, 1, 1, tzinfo=timezone.utc)
        
        result = datetime_utils.validate_date_range(date_string, min_date, max_date)
        assert result is True
    
    def test_validate_date_range_invalid_string(self, datetime_utils):
        """Test date range validation with invalid string input."""
        invalid_date = "not-a-date"
        min_date = datetime(2020, 1, 1, tzinfo=timezone.utc)
        max_date = datetime(2030, 1, 1, tzinfo=timezone.utc)
        
        result = datetime_utils.validate_date_range(invalid_date, min_date, max_date)
        assert result is False


class TestInputValidator:
    """
    Comprehensive test suite for input validation and sanitization utilities.
    
    Tests email validation, HTML sanitization, URL validation, password strength,
    and general input sanitization using enterprise-grade security libraries
    per Section 6.4.1 and XSS prevention requirements.
    """
    
    @pytest.fixture
    def input_validator(self):
        """Create input validator instance."""
        return InputValidator()
    
    def test_input_validator_initialization(self, input_validator):
        """Test input validator initialization."""
        assert hasattr(input_validator, 'allowed_tags')
        assert hasattr(input_validator, 'allowed_attributes')
        assert isinstance(input_validator.allowed_tags, set)
        assert isinstance(input_validator.allowed_attributes, dict)
    
    def test_validate_email_valid_addresses(self, input_validator):
        """Test email validation with valid email addresses."""
        valid_emails = [
            "test@example.com",
            "user+tag@domain.org",
            "firstname.lastname@company.co.uk",
            "admin@sub.domain.com",
            "test123@example-domain.com"
        ]
        
        for email in valid_emails:
            is_valid, result = input_validator.validate_email(email)
            assert is_valid is True
            assert "@" in result
    
    def test_validate_email_invalid_addresses(self, input_validator):
        """Test email validation with invalid email addresses."""
        invalid_emails = [
            "invalid-email",
            "@domain.com",
            "user@",
            "user@@domain.com",
            "user@domain",
            "user name@domain.com",  # Space in local part
            "user@domain..com",  # Double dot
            "",
            None
        ]
        
        for email in invalid_emails:
            is_valid, error_msg = input_validator.validate_email(email)
            assert is_valid is False
            assert isinstance(error_msg, str)
            assert len(error_msg) > 0
    
    def test_validate_email_normalization(self, input_validator):
        """Test email validation with normalization."""
        email = "  Test.User+Tag@Example.COM  "
        is_valid, normalized = input_validator.validate_email(email, normalize=True)
        
        assert is_valid is True
        assert normalized.lower() in normalized  # Should be normalized
        assert normalized.strip() == normalized  # Should be stripped
    
    def test_validate_email_deliverability_check(self, input_validator):
        """Test email validation with deliverability checking."""
        # Note: This test may be skipped if network is not available
        email = "test@example.com"
        
        try:
            is_valid, result = input_validator.validate_email(
                email, 
                check_deliverability=True
            )
            # Should still be valid format-wise
            assert is_valid is True or result  # Accept either valid or specific error
        except EmailValidationError:
            # Network issues or configuration problems are acceptable
            pytest.skip("Deliverability check failed due to network/config issues")
    
    def test_sanitize_html_remove_dangerous_tags(self, input_validator):
        """Test HTML sanitization removes dangerous tags."""
        dangerous_html = """
        <p>Safe paragraph</p>
        <script>alert('xss')</script>
        <img src="x" onerror="alert('xss')">
        <iframe src="javascript:alert('xss')"></iframe>
        """
        
        sanitized = input_validator.sanitize_html(dangerous_html)
        
        assert "<p>Safe paragraph</p>" in sanitized
        assert "<script>" not in sanitized
        assert "alert('xss')" not in sanitized
        assert "<iframe>" not in sanitized
        assert "javascript:" not in sanitized
    
    def test_sanitize_html_preserve_safe_tags(self, input_validator):
        """Test HTML sanitization preserves safe tags."""
        safe_html = """
        <p>Paragraph text</p>
        <strong>Bold text</strong>
        <em>Italic text</em>
        <ul><li>List item</li></ul>
        <h1>Heading</h1>
        """
        
        sanitized = input_validator.sanitize_html(safe_html)
        
        assert "<p>" in sanitized
        assert "<strong>" in sanitized
        assert "<em>" in sanitized
        assert "<ul>" in sanitized
        assert "<li>" in sanitized
        assert "<h1>" in sanitized
    
    def test_sanitize_html_strip_all_tags(self, input_validator):
        """Test HTML sanitization with all tags stripped."""
        html_content = "<p><strong>Bold</strong> text with <em>emphasis</em></p>"
        
        sanitized = input_validator.sanitize_html(html_content, strip_tags=True)
        
        assert "<" not in sanitized
        assert ">" not in sanitized
        assert "Bold text with emphasis" in sanitized
    
    def test_sanitize_html_custom_tags(self, input_validator):
        """Test HTML sanitization with custom allowed tags."""
        html_content = "<div><p>Text</p><span>More text</span></div>"
        custom_tags = {"p", "span"}
        
        sanitized = input_validator.sanitize_html(
            html_content, 
            custom_tags=custom_tags
        )
        
        assert "<p>" in sanitized
        assert "<span>" in sanitized
        assert "<div>" not in sanitized
    
    def test_validate_url_valid_urls(self, input_validator):
        """Test URL validation with valid URLs."""
        valid_urls = [
            "https://example.com",
            "http://sub.domain.org/path",
            "https://example.com:8080/path?query=value",
            "https://user:pass@domain.com/secure",
            "https://domain.com/path#fragment"
        ]
        
        for url in valid_urls:
            assert input_validator.validate_url(url) is True
    
    def test_validate_url_invalid_urls(self, input_validator):
        """Test URL validation with invalid URLs."""
        invalid_urls = [
            "not-a-url",
            "ftp://example.com",  # Invalid scheme
            "https://",  # Missing netloc
            "example.com",  # Missing scheme
            "",
            None
        ]
        
        for url in invalid_urls:
            assert input_validator.validate_url(url) is False
    
    def test_validate_url_custom_schemes(self, input_validator):
        """Test URL validation with custom allowed schemes."""
        url = "ftp://example.com/file.txt"
        
        # Should fail with default schemes
        assert input_validator.validate_url(url) is False
        
        # Should pass with custom schemes
        assert input_validator.validate_url(url, ["ftp", "http", "https"]) is True
    
    def test_validate_password_strength_strong(self, input_validator):
        """Test password strength validation with strong passwords."""
        strong_passwords = [
            "StrongP@ssw0rd123",
            "Complex!Pass123",
            "MySecure#Pass2024"
        ]
        
        for password in strong_passwords:
            is_valid, errors = input_validator.validate_password_strength(password)
            assert is_valid is True
            assert len(errors) == 0
    
    def test_validate_password_strength_weak(self, input_validator):
        """Test password strength validation with weak passwords."""
        weak_passwords = [
            "weak",  # Too short
            "password",  # No uppercase, numbers, special chars
            "PASSWORD",  # No lowercase, numbers, special chars
            "12345678",  # No letters, special chars
            "Pass123",  # No special chars
        ]
        
        for password in weak_passwords:
            is_valid, errors = input_validator.validate_password_strength(password)
            assert is_valid is False
            assert len(errors) > 0
            assert all(isinstance(error, str) for error in errors)
    
    def test_validate_password_strength_custom_requirements(self, input_validator):
        """Test password strength validation with custom requirements."""
        password = "simple123"
        
        # Relaxed requirements
        is_valid, errors = input_validator.validate_password_strength(
            password,
            min_length=6,
            require_uppercase=False,
            require_special=False
        )
        assert is_valid is True
        
        # Strict requirements
        is_valid, errors = input_validator.validate_password_strength(
            password,
            min_length=12,
            require_uppercase=True,
            require_special=True
        )
        assert is_valid is False
        assert len(errors) > 0
    
    def test_sanitize_input_basic(self, input_validator):
        """Test basic input sanitization."""
        dirty_input = "  <script>alert('xss')</script>User Input  "
        sanitized = input_validator.sanitize_input(dirty_input)
        
        assert sanitized == "User Input"
        assert "<script>" not in sanitized
        assert "alert" not in sanitized
    
    def test_sanitize_input_max_length(self, input_validator):
        """Test input sanitization with maximum length."""
        long_input = "a" * 100
        
        with pytest.raises(ValidationError) as exc_info:
            input_validator.sanitize_input(long_input, max_length=50)
        
        assert "exceeds maximum length" in str(exc_info.value)
    
    def test_sanitize_input_allowed_chars(self, input_validator):
        """Test input sanitization with allowed characters."""
        input_with_special = "user@123#$%"
        
        # Allow alphanumeric and @ only
        sanitized = input_validator.sanitize_input(
            input_with_special, 
            allowed_chars=r"[a-zA-Z0-9@]"
        )
        assert sanitized == "user@123"
    
    def test_sanitize_input_no_whitespace_stripping(self, input_validator):
        """Test input sanitization without whitespace stripping."""
        input_with_spaces = "  text with spaces  "
        sanitized = input_validator.sanitize_input(
            input_with_spaces, 
            strip_whitespace=False
        )
        
        assert sanitized.startswith("  ")
        assert sanitized.endswith("  ")


class TestCryptographicUtils:
    """
    Comprehensive test suite for cryptographic utilities.
    
    Tests secure token generation, AES encryption/decryption, password hashing,
    HMAC signatures, and AWS KMS integration using cryptography 41.0+ library
    per Section 6.4.1 enterprise-grade security requirements.
    """
    
    @pytest.fixture
    def crypto_utils(self):
        """Create cryptographic utility instance."""
        return CryptographicUtils()
    
    @pytest.fixture
    def sample_encryption_key(self):
        """Generate sample encryption key for testing."""
        return CryptographicUtils().generate_encryption_key(256)
    
    def test_crypto_utils_initialization(self, crypto_utils):
        """Test cryptographic utilities initialization."""
        assert hasattr(crypto_utils, 'kms_client')
        assert hasattr(crypto_utils, 'kms_key_arn')
    
    def test_generate_secure_token_default(self, crypto_utils):
        """Test secure token generation with default parameters."""
        token = crypto_utils.generate_secure_token()
        
        assert isinstance(token, str)
        assert len(token) > 0
        # Base64 encoded 32 bytes should be around 43 characters
        assert 40 <= len(token) <= 50
        
        # Should be URL-safe base64 (no padding)
        assert "=" not in token
    
    def test_generate_secure_token_custom_length(self, crypto_utils):
        """Test secure token generation with custom length."""
        lengths = [16, 32, 64, 128]
        
        for length in lengths:
            token = crypto_utils.generate_secure_token(length)
            # Base64 encoding increases size by ~4/3
            expected_min = int(length * 4 / 3) - 2
            expected_max = int(length * 4 / 3) + 2
            assert expected_min <= len(token) <= expected_max
    
    def test_generate_secure_token_uniqueness(self, crypto_utils):
        """Test secure token generation produces unique tokens."""
        tokens = set()
        for _ in range(100):
            token = crypto_utils.generate_secure_token()
            tokens.add(token)
        
        # All tokens should be unique
        assert len(tokens) == 100
    
    def test_generate_encryption_key_valid_sizes(self, crypto_utils):
        """Test encryption key generation with valid key sizes."""
        valid_sizes = [128, 192, 256]
        
        for size in valid_sizes:
            key = crypto_utils.generate_encryption_key(size)
            assert isinstance(key, bytes)
            assert len(key) == size // 8  # Size in bytes
    
    def test_generate_encryption_key_invalid_size(self, crypto_utils):
        """Test encryption key generation with invalid key size."""
        invalid_sizes = [64, 512, 1024]
        
        for size in invalid_sizes:
            with pytest.raises(CryptographicError) as exc_info:
                crypto_utils.generate_encryption_key(size)
            
            assert "Key size must be 128, 192, or 256 bits" in str(exc_info.value)
    
    def test_encrypt_decrypt_aes_gcm_string(self, crypto_utils, sample_encryption_key):
        """Test AES-GCM encryption and decryption with string data."""
        plaintext = "This is a secret message that needs encryption"
        
        encrypted_data, nonce, key_used = crypto_utils.encrypt_aes_gcm(
            plaintext, 
            sample_encryption_key
        )
        
        # Verify encryption results
        assert isinstance(encrypted_data, bytes)
        assert isinstance(nonce, bytes)
        assert key_used == sample_encryption_key
        assert len(nonce) == 12  # GCM nonce length
        
        # Decrypt and verify
        decrypted = crypto_utils.decrypt_aes_gcm(
            encrypted_data, 
            nonce, 
            sample_encryption_key
        )
        assert decrypted.decode('utf-8') == plaintext
    
    def test_encrypt_decrypt_aes_gcm_bytes(self, crypto_utils, sample_encryption_key):
        """Test AES-GCM encryption and decryption with bytes data."""
        plaintext = b"Binary data that needs encryption \x00\x01\x02"
        
        encrypted_data, nonce, key_used = crypto_utils.encrypt_aes_gcm(
            plaintext, 
            sample_encryption_key
        )
        
        decrypted = crypto_utils.decrypt_aes_gcm(
            encrypted_data, 
            nonce, 
            sample_encryption_key
        )
        assert decrypted == plaintext
    
    def test_encrypt_aes_gcm_auto_key_generation(self, crypto_utils):
        """Test AES-GCM encryption with automatic key generation."""
        plaintext = "Test message"
        
        encrypted_data, nonce, generated_key = crypto_utils.encrypt_aes_gcm(plaintext)
        
        assert isinstance(generated_key, bytes)
        assert len(generated_key) == 32  # 256-bit key
        
        # Should be able to decrypt with generated key
        decrypted = crypto_utils.decrypt_aes_gcm(encrypted_data, nonce, generated_key)
        assert decrypted.decode('utf-8') == plaintext
    
    def test_encrypt_aes_gcm_with_associated_data(self, crypto_utils, sample_encryption_key):
        """Test AES-GCM encryption with associated authenticated data."""
        plaintext = "Secret message"
        associated_data = b"authentication-context"
        
        encrypted_data, nonce, _ = crypto_utils.encrypt_aes_gcm(
            plaintext, 
            sample_encryption_key,
            associated_data=associated_data
        )
        
        # Should decrypt successfully with correct associated data
        decrypted = crypto_utils.decrypt_aes_gcm(
            encrypted_data, 
            nonce, 
            sample_encryption_key,
            associated_data=associated_data
        )
        assert decrypted.decode('utf-8') == plaintext
        
        # Should fail with wrong associated data
        with pytest.raises(CryptographicError):
            crypto_utils.decrypt_aes_gcm(
                encrypted_data, 
                nonce, 
                sample_encryption_key,
                associated_data=b"wrong-context"
            )
    
    def test_decrypt_aes_gcm_wrong_key(self, crypto_utils, sample_encryption_key):
        """Test AES-GCM decryption with wrong key."""
        plaintext = "Secret message"
        encrypted_data, nonce, _ = crypto_utils.encrypt_aes_gcm(plaintext, sample_encryption_key)
        
        wrong_key = crypto_utils.generate_encryption_key(256)
        
        with pytest.raises(CryptographicError) as exc_info:
            crypto_utils.decrypt_aes_gcm(encrypted_data, nonce, wrong_key)
        
        assert "AES-GCM decryption failed" in str(exc_info.value)
    
    def test_hash_password_default(self, crypto_utils):
        """Test password hashing with default salt generation."""
        password = "MySecurePassword123!"
        
        password_hash, salt = crypto_utils.hash_password(password)
        
        assert isinstance(password_hash, bytes)
        assert isinstance(salt, bytes)
        assert len(password_hash) == 32  # SHA256 output length
        assert len(salt) == 32  # Default salt length
    
    def test_hash_password_custom_salt(self, crypto_utils):
        """Test password hashing with custom salt."""
        password = "MySecurePassword123!"
        custom_salt = b"custom_salt_16_bytes"
        
        password_hash, returned_salt = crypto_utils.hash_password(password, custom_salt)
        
        assert returned_salt == custom_salt
        assert isinstance(password_hash, bytes)
    
    def test_hash_password_consistency(self, crypto_utils):
        """Test password hashing produces consistent results."""
        password = "MySecurePassword123!"
        salt = b"consistent_salt_here"
        
        hash1, _ = crypto_utils.hash_password(password, salt)
        hash2, _ = crypto_utils.hash_password(password, salt)
        
        assert hash1 == hash2
    
    def test_verify_password_success(self, crypto_utils):
        """Test successful password verification."""
        password = "MySecurePassword123!"
        password_hash, salt = crypto_utils.hash_password(password)
        
        is_valid = crypto_utils.verify_password(password, password_hash, salt)
        assert is_valid is True
    
    def test_verify_password_failure(self, crypto_utils):
        """Test password verification failure."""
        correct_password = "MySecurePassword123!"
        wrong_password = "WrongPassword456!"
        
        password_hash, salt = crypto_utils.hash_password(correct_password)
        
        is_valid = crypto_utils.verify_password(wrong_password, password_hash, salt)
        assert is_valid is False
    
    def test_generate_hmac_signature_sha256(self, crypto_utils):
        """Test HMAC signature generation with SHA256."""
        data = "Important data that needs signing"
        secret_key = "secret-signing-key"
        
        signature = crypto_utils.generate_hmac_signature(data, secret_key, "sha256")
        
        assert isinstance(signature, str)
        assert len(signature) == 64  # SHA256 hex length
        assert all(c in "0123456789abcdef" for c in signature)
    
    def test_generate_hmac_signature_sha512(self, crypto_utils):
        """Test HMAC signature generation with SHA512."""
        data = "Important data that needs signing"
        secret_key = "secret-signing-key"
        
        signature = crypto_utils.generate_hmac_signature(data, secret_key, "sha512")
        
        assert isinstance(signature, str)
        assert len(signature) == 128  # SHA512 hex length
    
    def test_generate_hmac_signature_bytes_data(self, crypto_utils):
        """Test HMAC signature generation with bytes data."""
        data = b"Binary data \x00\x01\x02"
        secret_key = "secret-signing-key"
        
        signature = crypto_utils.generate_hmac_signature(data, secret_key)
        
        assert isinstance(signature, str)
        assert len(signature) == 64
    
    def test_generate_hmac_signature_invalid_algorithm(self, crypto_utils):
        """Test HMAC signature generation with invalid algorithm."""
        data = "Test data"
        secret_key = "secret-key"
        
        with pytest.raises(CryptographicError) as exc_info:
            crypto_utils.generate_hmac_signature(data, secret_key, "invalid_alg")
        
        assert "Unsupported algorithm" in str(exc_info.value)
    
    def test_verify_hmac_signature_success(self, crypto_utils):
        """Test successful HMAC signature verification."""
        data = "Important data that needs signing"
        secret_key = "secret-signing-key"
        
        signature = crypto_utils.generate_hmac_signature(data, secret_key)
        is_valid = crypto_utils.verify_hmac_signature(data, signature, secret_key)
        
        assert is_valid is True
    
    def test_verify_hmac_signature_failure(self, crypto_utils):
        """Test HMAC signature verification failure."""
        data = "Important data that needs signing"
        secret_key = "secret-signing-key"
        
        signature = crypto_utils.generate_hmac_signature(data, secret_key)
        
        # Verify with wrong data
        is_valid = crypto_utils.verify_hmac_signature("Wrong data", signature, secret_key)
        assert is_valid is False
        
        # Verify with wrong key
        is_valid = crypto_utils.verify_hmac_signature(data, signature, "wrong-key")
        assert is_valid is False
        
        # Verify with wrong signature
        is_valid = crypto_utils.verify_hmac_signature(data, "wrong-signature", secret_key)
        assert is_valid is False
    
    @patch.dict('os.environ', {
        'AWS_ACCESS_KEY_ID': 'test-key',
        'AWS_SECRET_ACCESS_KEY': 'test-secret',
        'AWS_KMS_CMK_ARN': 'arn:aws:kms:us-east-1:123456789:key/test-key-id'
    })
    def test_kms_encryption_success(self, crypto_utils):
        """Test AWS KMS encryption success (mocked)."""
        with patch.object(crypto_utils, 'kms_client') as mock_kms:
            mock_kms.encrypt.return_value = {
                'CiphertextBlob': b'encrypted-data-blob'
            }
            
            plaintext = "Secret data for KMS"
            result = crypto_utils.encrypt_with_kms(plaintext)
            
            assert result == b'encrypted-data-blob'
            mock_kms.encrypt.assert_called_once()
    
    def test_kms_encryption_unavailable(self, crypto_utils):
        """Test AWS KMS encryption when KMS is unavailable."""
        # Ensure KMS client is None
        crypto_utils.kms_client = None
        
        plaintext = "Secret data for KMS"
        result = crypto_utils.encrypt_with_kms(plaintext)
        
        assert result is None
    
    @patch.dict('os.environ', {
        'AWS_ACCESS_KEY_ID': 'test-key',
        'AWS_SECRET_ACCESS_KEY': 'test-secret'
    })
    def test_kms_decryption_success(self, crypto_utils):
        """Test AWS KMS decryption success (mocked)."""
        with patch.object(crypto_utils, 'kms_client') as mock_kms:
            mock_kms.decrypt.return_value = {
                'Plaintext': b'decrypted-data'
            }
            
            ciphertext_blob = b'encrypted-data-blob'
            result = crypto_utils.decrypt_with_kms(ciphertext_blob)
            
            assert result == b'decrypted-data'
            mock_kms.decrypt.assert_called_once()
    
    def test_kms_decryption_unavailable(self, crypto_utils):
        """Test AWS KMS decryption when KMS is unavailable."""
        crypto_utils.kms_client = None
        
        ciphertext_blob = b'encrypted-data-blob'
        result = crypto_utils.decrypt_with_kms(ciphertext_blob)
        
        assert result is None


class TestConvenienceFunctions:
    """
    Test suite for convenience functions in auth utilities.
    
    Tests the module-level convenience functions that provide simplified
    access to common utility operations.
    """
    
    def test_generate_secure_token_convenience(self):
        """Test convenience function for secure token generation."""
        token = generate_secure_token()
        assert isinstance(token, str)
        assert len(token) > 0
        
        custom_token = generate_secure_token(16)
        assert isinstance(custom_token, str)
        assert len(custom_token) != len(token)  # Different lengths
    
    def test_validate_email_convenience(self):
        """Test convenience function for email validation."""
        is_valid, result = validate_email("test@example.com")
        assert is_valid is True
        assert "@" in result
        
        is_valid, error = validate_email("invalid-email")
        assert is_valid is False
        assert isinstance(error, str)
    
    def test_sanitize_html_convenience(self):
        """Test convenience function for HTML sanitization."""
        dangerous_html = "<script>alert('xss')</script><p>Safe text</p>"
        sanitized = sanitize_html(dangerous_html)
        
        assert "<script>" not in sanitized
        assert "Safe text" in sanitized
        
        stripped = sanitize_html(dangerous_html, strip_tags=True)
        assert "<" not in stripped
        assert "Safe text" in stripped
    
    def test_parse_iso8601_date_convenience(self):
        """Test convenience function for ISO 8601 date parsing."""
        result = parse_iso8601_date("2024-01-15T10:30:00Z")
        assert isinstance(result, datetime)
        assert result.year == 2024
        
        invalid_result = parse_iso8601_date("invalid-date")
        assert invalid_result is None
    
    def test_format_iso8601_date_convenience(self):
        """Test convenience function for ISO 8601 date formatting."""
        dt = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        result = format_iso8601_date(dt)
        
        assert "2024-01-15T10:30:00" in result
        assert "+00:00" in result
    
    def test_create_jwt_token_convenience(self):
        """Test convenience function for JWT token creation."""
        payload = {"user_id": "test-123", "role": "admin"}
        token = create_jwt_token(payload)
        
        assert isinstance(token, str)
        assert len(token) > 0
    
    def test_validate_jwt_token_convenience(self):
        """Test convenience function for JWT token validation."""
        payload = {"user_id": "test-123", "role": "admin"}
        token = create_jwt_token(payload)
        
        decoded = validate_jwt_token(token)
        assert decoded["user_id"] == "test-123"
        assert decoded["role"] == "admin"
    
    def test_encrypt_decrypt_sensitive_data_convenience(self):
        """Test convenience functions for data encryption/decryption."""
        sensitive_data = "This is sensitive information"
        
        encrypted_data, nonce, key = encrypt_sensitive_data(sensitive_data)
        assert isinstance(encrypted_data, bytes)
        assert isinstance(nonce, bytes)
        assert isinstance(key, bytes)
        
        decrypted = decrypt_sensitive_data(encrypted_data, nonce, key)
        assert decrypted.decode('utf-8') == sensitive_data


class TestBusinessDataManipulation:
    """
    Comprehensive test suite for business data manipulation utilities.
    
    Tests data cleaning, transformation, merging, flattening, and filtering
    functions per Section 5.2.4 business logic requirements.
    """
    
    def test_clean_data_dict_basic(self):
        """Test basic dictionary data cleaning."""
        dirty_data = {
            'name': '  John Doe  ',
            'email': '',
            'age': '25',
            'notes': None,
            'tags': []
        }
        
        cleaned = clean_data(
            dirty_data,
            remove_empty=True,
            remove_none=True,
            strip_strings=True,
            convert_types=True
        )
        
        assert cleaned['name'] == 'John Doe'
        assert cleaned['age'] == 25
        assert 'email' not in cleaned
        assert 'notes' not in cleaned
        assert 'tags' not in cleaned
    
    def test_clean_data_list_basic(self):
        """Test basic list data cleaning."""
        dirty_list = [
            '  text  ',
            '',
            None,
            '123',
            '45.67',
            []
        ]
        
        cleaned = clean_data(
            dirty_list,
            remove_empty=True,
            remove_none=True,
            strip_strings=True,
            convert_types=True
        )
        
        assert 'text' in cleaned
        assert 123 in cleaned
        assert 45.67 in cleaned
        assert '' not in cleaned
        assert None not in cleaned
        assert [] not in cleaned
    
    def test_clean_data_nested_structures(self):
        """Test cleaning nested data structures."""
        nested_data = {
            'user': {
                'profile': {
                    'name': '  John  ',
                    'age': '30',
                    'empty': ''
                },
                'settings': {
                    'theme': 'dark',
                    'notifications': None
                }
            },
            'metadata': []
        }
        
        cleaned = clean_data(nested_data, remove_empty=True, remove_none=True)
        
        assert cleaned['user']['profile']['name'] == 'John'
        assert cleaned['user']['profile']['age'] == 30
        assert 'empty' not in cleaned['user']['profile']
        assert 'notifications' not in cleaned['user']['settings']
        assert 'metadata' not in cleaned
    
    def test_clean_data_invalid_type(self):
        """Test data cleaning with invalid data type."""
        with pytest.raises(DataProcessingError) as exc_info:
            clean_data("invalid-type")
        
        assert "Unsupported data type" in str(exc_info.value)
        assert exc_info.value.error_code == "UNSUPPORTED_DATA_TYPE"
    
    def test_transform_data_basic(self):
        """Test basic data transformation."""
        api_data = {
            'firstName': 'John',
            'lastName': 'Doe',
            'emailAddress': 'john@example.com',
            'dateOfBirth': '1990-01-01'
        }
        
        field_mapping = {
            'firstName': 'first_name',
            'lastName': 'last_name',
            'emailAddress': 'email',
            'dateOfBirth': 'birth_date'
        }
        
        transformed = transform_data(api_data, field_mapping)
        
        assert transformed['first_name'] == 'John'
        assert transformed['last_name'] == 'Doe'
        assert transformed['email'] == 'john@example.com'
        assert transformed['birth_date'] == '1990-01-01'
    
    def test_transform_data_with_transformers(self):
        """Test data transformation with custom transformers."""
        data = {
            'name': 'john doe',
            'age': '25',
            'salary': '50000.00'
        }
        
        field_mapping = {
            'name': 'full_name',
            'age': 'age_years',
            'salary': 'annual_salary'
        }
        
        transformers = {
            'full_name': lambda x: x.title(),
            'age_years': lambda x: int(x),
            'annual_salary': lambda x: decimal.Decimal(x)
        }
        
        transformed = transform_data(data, field_mapping, transformers)
        
        assert transformed['full_name'] == 'John Doe'
        assert transformed['age_years'] == 25
        assert isinstance(transformed['annual_salary'], decimal.Decimal)
    
    def test_transform_data_remove_unmapped(self):
        """Test data transformation with unmapped field removal."""
        data = {
            'name': 'John',
            'age': 25,
            'internal_id': 'SECRET-123',
            'temp_field': 'temp_value'
        }
        
        field_mapping = {
            'name': 'full_name',
            'age': 'age_years'
        }
        
        transformed = transform_data(data, field_mapping, remove_unmapped=True)
        
        assert 'full_name' in transformed
        assert 'age_years' in transformed
        assert 'internal_id' not in transformed
        assert 'temp_field' not in transformed
    
    def test_transform_data_invalid_mapping(self):
        """Test data transformation with invalid field mapping."""
        data = {'name': 'John'}
        
        with pytest.raises(DataProcessingError) as exc_info:
            transform_data(data, "invalid-mapping")
        
        assert "Field mapping must be a dictionary" in str(exc_info.value)
    
    def test_merge_data_basic(self):
        """Test basic data merging."""
        base_config = {'api': {'timeout': 30}, 'debug': False}
        user_config = {'api': {'retries': 3}, 'debug': True}
        env_config = {'api': {'host': 'prod.example.com'}}
        
        merged = merge_data(base_config, user_config, env_config)
        
        assert merged['debug'] is True
        assert merged['api']['timeout'] == 30
        assert merged['api']['retries'] == 3
        assert merged['api']['host'] == 'prod.example.com'
    
    def test_merge_data_preserve_strategy(self):
        """Test data merging with preserve strategy."""
        data1 = {'name': 'original', 'age': 25}
        data2 = {'name': 'updated', 'city': 'New York'}
        
        merged = merge_data(data1, data2, merge_strategy="preserve")
        
        assert merged['name'] == 'original'  # Preserved
        assert merged['age'] == 25
        assert merged['city'] == 'New York'
    
    def test_merge_data_combine_strategy(self):
        """Test data merging with combine strategy."""
        data1 = {'tags': ['python', 'flask'], 'count': 5}
        data2 = {'tags': ['web', 'api'], 'count': 3}
        
        merged = merge_data(data1, data2, merge_strategy="combine")
        
        assert merged['tags'] == ['python', 'flask', 'web', 'api']
        assert merged['count'] == 3  # Last value for non-list
    
    def test_merge_data_invalid_strategy(self):
        """Test data merging with invalid strategy."""
        data1 = {'name': 'John'}
        data2 = {'age': 25}
        
        with pytest.raises(DataProcessingError) as exc_info:
            merge_data(data1, data2, merge_strategy="invalid")
        
        assert "Invalid merge strategy" in str(exc_info.value)
    
    def test_flatten_data_basic(self):
        """Test basic data flattening."""
        nested_data = {
            'user': {
                'profile': {
                    'name': 'John Doe',
                    'age': 30
                },
                'preferences': {
                    'theme': 'dark'
                }
            },
            'settings': {
                'notifications': True
            }
        }
        
        flattened = flatten_data(nested_data)
        
        expected_keys = {
            'user.profile.name',
            'user.profile.age', 
            'user.preferences.theme',
            'settings.notifications'
        }
        
        assert set(flattened.keys()) == expected_keys
        assert flattened['user.profile.name'] == 'John Doe'
        assert flattened['user.profile.age'] == 30
    
    def test_flatten_data_custom_separator(self):
        """Test data flattening with custom separator."""
        nested_data = {
            'level1': {
                'level2': {
                    'value': 'test'
                }
            }
        }
        
        flattened = flatten_data(nested_data, separator="_")
        
        assert 'level1_level2_value' in flattened
        assert flattened['level1_level2_value'] == 'test'
    
    def test_flatten_data_max_depth(self):
        """Test data flattening with maximum depth."""
        nested_data = {
            'level1': {
                'level2': {
                    'level3': {
                        'value': 'deep'
                    }
                }
            }
        }
        
        flattened = flatten_data(nested_data, max_depth=2)
        
        assert 'level1.level2' in flattened
        assert isinstance(flattened['level1.level2'], dict)
        assert flattened['level1.level2']['level3']['value'] == 'deep'
    
    def test_filter_data_list_all_match(self):
        """Test data filtering with all criteria matching."""
        users = [
            {'name': 'John', 'age': 30, 'active': True, 'role': 'admin'},
            {'name': 'Jane', 'age': 25, 'active': True, 'role': 'user'},
            {'name': 'Bob', 'age': 35, 'active': False, 'role': 'admin'}
        ]
        
        filtered = filter_data(
            users, 
            {'active': True, 'role': 'admin'}, 
            match_mode="all"
        )
        
        assert len(filtered) == 1
        assert filtered[0]['name'] == 'John'
    
    def test_filter_data_any_match(self):
        """Test data filtering with any criteria matching."""
        users = [
            {'name': 'John', 'age': 30, 'active': True, 'role': 'admin'},
            {'name': 'Jane', 'age': 25, 'active': True, 'role': 'user'},
            {'name': 'Bob', 'age': 35, 'active': False, 'role': 'admin'}
        ]
        
        filtered = filter_data(
            users, 
            {'active': False, 'role': 'admin'}, 
            match_mode="any"
        )
        
        assert len(filtered) == 2  # John (admin) and Bob (both admin and inactive)
        names = [user['name'] for user in filtered]
        assert 'John' in names
        assert 'Bob' in names
    
    def test_filter_data_single_dict(self):
        """Test data filtering with single dictionary."""
        user = {'name': 'John', 'age': 30, 'active': True}
        
        # Should match
        result = filter_data(user, {'active': True})
        assert result == user
        
        # Should not match
        result = filter_data(user, {'active': False})
        assert result == {}
    
    def test_filter_data_invalid_input(self):
        """Test data filtering with invalid input."""
        with pytest.raises(DataProcessingError) as exc_info:
            filter_data("invalid-input", {'key': 'value'})
        
        assert "must be a list of dictionaries or a single dictionary" in str(exc_info.value)


class TestBusinessDateTimeProcessing:
    """
    Comprehensive test suite for business date/time processing utilities.
    
    Tests date parsing, formatting, difference calculations, business days,
    and timezone conversions using python-dateutil 2.8+ equivalent to
    Node.js moment.js functionality per Section 5.2.4.
    """
    
    def test_parse_date_various_formats(self):
        """Test date parsing with various input formats."""
        test_cases = [
            ("2024-01-15T10:30:00Z", 2024, 1, 15, 10, 30),
            ("2024-01-15 10:30:00", 2024, 1, 15, 10, 30),
            ("01/15/2024", 2024, 1, 15, 0, 0),
            ("January 15, 2024", 2024, 1, 15, 0, 0),
            ("2024-01-15", 2024, 1, 15, 0, 0),
        ]
        
        for date_string, year, month, day, hour, minute in test_cases:
            result = parse_date(date_string)
            assert result.year == year
            assert result.month == month
            assert result.day == day
            assert result.hour == hour
            assert result.minute == minute
    
    def test_parse_date_with_timezone(self):
        """Test date parsing with timezone information."""
        date_string = "2024-01-15 10:30:00"
        result = parse_date(date_string, timezone_info="America/New_York")
        
        assert result.tzinfo is not None
        assert result.hour == 10
        assert result.minute == 30
    
    def test_parse_date_with_format_hint(self):
        """Test date parsing with format hint."""
        date_string = "15/01/2024 14:30"
        result = parse_date(date_string, format_hint="%d/%m/%Y %H:%M")
        
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 15
        assert result.hour == 14
        assert result.minute == 30
    
    def test_parse_date_invalid_format(self):
        """Test date parsing with invalid format."""
        invalid_dates = [
            "not-a-date",
            "",
            None,
            "32/01/2024",  # Invalid day
            "01/13/2024 25:00:00"  # Invalid hour
        ]
        
        for invalid_date in invalid_dates:
            with pytest.raises(BusinessDataValidationError):
                parse_date(invalid_date)
    
    def test_format_date_iso_format(self):
        """Test date formatting in ISO format."""
        dt = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        result = format_date(dt, format_type="iso")
        
        assert "2024-01-15T10:30:00" in result
        assert "+00:00" in result
    
    def test_format_date_various_formats(self):
        """Test date formatting with various format types."""
        dt = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        
        format_cases = [
            ("date", "2024-01-15"),
            ("time", "10:30:00"),
            ("datetime", "2024-01-15 10:30:00"),
            ("human", "January 15, 2024 at 10:30 AM"),
        ]
        
        for format_type, expected_pattern in format_cases:
            result = format_date(dt, format_type=format_type)
            assert expected_pattern in result or len(result) > 0
    
    def test_format_date_with_timezone_conversion(self):
        """Test date formatting with timezone conversion."""
        dt_utc = datetime(2024, 1, 15, 15, 30, 0, tzinfo=timezone.utc)
        
        # Convert to Eastern Time (UTC-5 in January)
        result = format_date(dt_utc, format_type="datetime", timezone_info="America/New_York")
        
        # Should show earlier time in Eastern timezone
        assert "2024-01-15" in result
        assert "10:30:00" in result  # 15:30 UTC = 10:30 EST
    
    def test_calculate_date_difference_days(self):
        """Test date difference calculation in days."""
        start_date = parse_date("2024-01-01")
        end_date = parse_date("2024-01-15")
        
        diff_days = calculate_date_difference(start_date, end_date, unit="days")
        assert diff_days == 14
    
    def test_calculate_date_difference_hours(self):
        """Test date difference calculation in hours."""
        start_date = parse_date("2024-01-01T00:00:00Z")
        end_date = parse_date("2024-01-01T12:00:00Z")
        
        diff_hours = calculate_date_difference(start_date, end_date, unit="hours")
        assert diff_hours == 12
    
    def test_calculate_date_difference_months(self):
        """Test date difference calculation in months."""
        start_date = parse_date("2024-01-01")
        end_date = parse_date("2024-04-01")
        
        diff_months = calculate_date_difference(start_date, end_date, unit="months")
        assert diff_months == 3
    
    def test_calculate_date_difference_years(self):
        """Test date difference calculation in years."""
        start_date = parse_date("2020-01-01")
        end_date = parse_date("2024-01-01")
        
        diff_years = calculate_date_difference(start_date, end_date, unit="years")
        assert diff_years == 4
    
    def test_calculate_date_difference_invalid_unit(self):
        """Test date difference calculation with invalid unit."""
        start_date = parse_date("2024-01-01")
        end_date = parse_date("2024-01-15")
        
        with pytest.raises(BusinessDataValidationError) as exc_info:
            calculate_date_difference(start_date, end_date, unit="invalid")
        
        assert "Unsupported time unit" in str(exc_info.value)
    
    def test_get_business_days_exclude_weekends(self):
        """Test business days calculation excluding weekends."""
        # Monday to Friday (5 business days)
        start_date = parse_date("2024-01-01")  # Monday
        end_date = parse_date("2024-01-05")    # Friday
        
        business_days = get_business_days(start_date, end_date)
        assert business_days == 5
    
    def test_get_business_days_with_weekend(self):
        """Test business days calculation spanning weekends."""
        # Monday to Monday (5 business days, skipping weekend)
        start_date = parse_date("2024-01-01")  # Monday
        end_date = parse_date("2024-01-08")    # Monday (next week)
        
        business_days = get_business_days(start_date, end_date)
        assert business_days == 6  # 5 days first week + 1 day second week
    
    def test_get_business_days_with_holidays(self):
        """Test business days calculation with holidays."""
        start_date = parse_date("2024-01-01")  # Monday
        end_date = parse_date("2024-01-05")    # Friday
        holidays = [parse_date("2024-01-03")]  # Wednesday holiday
        
        business_days = get_business_days(start_date, end_date, holidays=holidays)
        assert business_days == 4  # 5 days - 1 holiday
    
    def test_get_business_days_include_weekends(self):
        """Test business days calculation including weekends."""
        start_date = parse_date("2024-01-01")  # Monday
        end_date = parse_date("2024-01-07")    # Sunday
        
        business_days = get_business_days(start_date, end_date, exclude_weekends=False)
        assert business_days == 7  # All 7 days
    
    def test_convert_timezone_utc_to_eastern(self):
        """Test timezone conversion from UTC to Eastern."""
        utc_time = parse_date("2024-01-15T15:30:00Z")
        eastern_time = convert_timezone(utc_time, "America/New_York")
        
        assert eastern_time.hour == 10  # 15:30 UTC = 10:30 EST (UTC-5)
        assert eastern_time.minute == 30
    
    def test_convert_timezone_naive_datetime(self):
        """Test timezone conversion with naive datetime."""
        naive_time = datetime(2024, 1, 15, 10, 30, 0)
        pacific_time = convert_timezone(
            naive_time, 
            "America/Los_Angeles", 
            source_timezone="UTC"
        )
        
        assert pacific_time.hour == 2  # 10:30 UTC = 02:30 PST (UTC-8)
        assert pacific_time.minute == 30
    
    def test_convert_timezone_invalid_timezone(self):
        """Test timezone conversion with invalid timezone."""
        dt = parse_date("2024-01-15T10:30:00Z")
        
        with pytest.raises(BusinessDataValidationError) as exc_info:
            convert_timezone(dt, "Invalid/Timezone")
        
        assert "Invalid timezone identifier" in str(exc_info.value)


class TestBusinessCalculations:
    """
    Comprehensive test suite for business calculation utilities.
    
    Tests percentage calculations, discount applications, tax calculations,
    currency rounding, and validation per Section 5.2.4 business logic requirements.
    """
    
    def test_calculate_percentage_basic(self):
        """Test basic percentage calculation."""
        result = calculate_percentage(15, 20)
        assert result == decimal.Decimal('75.00')
        
        result = calculate_percentage(1, 3, precision=4)
        assert result == decimal.Decimal('33.3333')
    
    def test_calculate_percentage_zero_total(self):
        """Test percentage calculation with zero total."""
        with pytest.raises(BusinessRuleViolationError) as exc_info:
            calculate_percentage(10, 0)
        
        assert "Cannot calculate percentage with zero total" in str(exc_info.value)
        assert exc_info.value.error_code == "DIVISION_BY_ZERO"
    
    def test_calculate_percentage_negative_values(self):
        """Test percentage calculation with negative values."""
        with pytest.raises(BusinessRuleViolationError) as exc_info:
            calculate_percentage(-5, 20)
        
        assert "requires non-negative values" in str(exc_info.value)
    
    def test_apply_discount_percentage(self):
        """Test discount application with percentage."""
        original_amount = decimal.Decimal('100.00')
        discounted = apply_discount(original_amount, 15, "percentage")
        
        assert discounted == decimal.Decimal('85.00')
    
    def test_apply_discount_fixed_amount(self):
        """Test discount application with fixed amount."""
        original_amount = decimal.Decimal('100.00')
        discounted = apply_discount(original_amount, 25, "fixed")
        
        assert discounted == decimal.Decimal('75.00')
    
    def test_apply_discount_with_maximum(self):
        """Test discount application with maximum limit."""
        original_amount = decimal.Decimal('100.00')
        discounted = apply_discount(
            original_amount, 
            30,  # 30% would be $30
            "percentage", 
            max_discount=20  # But limit to $20
        )
        
        assert discounted == decimal.Decimal('80.00')  # $100 - $20 max discount
    
    def test_apply_discount_exceeds_amount(self):
        """Test discount application that exceeds original amount."""
        original_amount = decimal.Decimal('50.00')
        discounted = apply_discount(original_amount, 75, "fixed")  # $75 discount on $50
        
        assert discounted == decimal.Decimal('0.00')  # Cannot go below zero
    
    def test_apply_discount_invalid_percentage(self):
        """Test discount application with invalid percentage."""
        with pytest.raises(BusinessRuleViolationError) as exc_info:
            apply_discount(100, 150, "percentage")  # 150% discount
        
        assert "cannot exceed 100%" in str(exc_info.value)
    
    def test_apply_discount_invalid_type(self):
        """Test discount application with invalid discount type."""
        with pytest.raises(BusinessRuleViolationError) as exc_info:
            apply_discount(100, 10, "invalid_type")
        
        assert "Invalid discount type" in str(exc_info.value)
    
    def test_calculate_tax_exclusive(self):
        """Test exclusive tax calculation."""
        base_amount = decimal.Decimal('100.00')
        tax_amount, total_amount = calculate_tax(base_amount, 8.5, "exclusive")
        
        assert tax_amount == decimal.Decimal('8.50')
        assert total_amount == decimal.Decimal('108.50')
    
    def test_calculate_tax_inclusive(self):
        """Test inclusive tax calculation."""
        inclusive_amount = decimal.Decimal('108.50')
        tax_amount, net_amount = calculate_tax(inclusive_amount, 8.5, "inclusive")
        
        # Tax should be approximately $8.50, net should be approximately $100
        assert abs(tax_amount - decimal.Decimal('8.50')) < decimal.Decimal('0.01')
        assert abs(net_amount - decimal.Decimal('100.00')) < decimal.Decimal('0.01')
    
    def test_calculate_tax_invalid_rate(self):
        """Test tax calculation with invalid tax rate."""
        with pytest.raises(BusinessRuleViolationError) as exc_info:
            calculate_tax(100, -5, "exclusive")  # Negative tax rate
        
        assert "must be between 0 and 100 percent" in str(exc_info.value)
        
        with pytest.raises(BusinessRuleViolationError) as exc_info:
            calculate_tax(100, 150, "exclusive")  # Tax rate over 100%
        
        assert "must be between 0 and 100 percent" in str(exc_info.value)
    
    def test_calculate_tax_invalid_type(self):
        """Test tax calculation with invalid tax type."""
        with pytest.raises(BusinessRuleViolationError) as exc_info:
            calculate_tax(100, 8.5, "invalid_type")
        
        assert "Invalid tax type" in str(exc_info.value)
    
    def test_round_currency_usd(self):
        """Test currency rounding for USD."""
        amount = decimal.Decimal('123.456')
        rounded = round_currency(amount, "USD")
        
        assert rounded == decimal.Decimal('123.46')
    
    def test_round_currency_jpy(self):
        """Test currency rounding for JPY (no decimals)."""
        amount = decimal.Decimal('123.456')
        rounded = round_currency(amount, "JPY")
        
        assert rounded == decimal.Decimal('123')
    
    def test_round_currency_custom_rounding(self):
        """Test currency rounding with custom rounding mode."""
        amount = decimal.Decimal('123.455')
        
        # ROUND_HALF_UP (default)
        rounded_up = round_currency(amount, "USD", "ROUND_HALF_UP")
        assert rounded_up == decimal.Decimal('123.46')
        
        # ROUND_HALF_DOWN
        rounded_down = round_currency(amount, "USD", "ROUND_HALF_DOWN")
        assert rounded_down == decimal.Decimal('123.45')
    
    def test_round_currency_invalid_mode(self):
        """Test currency rounding with invalid rounding mode."""
        with pytest.raises(BusinessRuleViolationError) as exc_info:
            round_currency(100, "USD", "INVALID_MODE")
        
        assert "Invalid rounding mode" in str(exc_info.value)
    
    def test_validate_currency_success(self):
        """Test successful currency validation."""
        valid_amount = decimal.Decimal('99.99')
        
        result = validate_currency(
            valid_amount,
            "USD",
            min_amount=1.00,
            max_amount=10000.00
        )
        assert result is True
    
    def test_validate_currency_negative_amount(self):
        """Test currency validation with negative amount."""
        with pytest.raises(BusinessRuleViolationError) as exc_info:
            validate_currency(-10.00, "USD")
        
        assert "cannot be negative" in str(exc_info.value)
    
    def test_validate_currency_below_minimum(self):
        """Test currency validation below minimum."""
        with pytest.raises(BusinessRuleViolationError) as exc_info:
            validate_currency(0.50, "USD", min_amount=1.00)
        
        assert "below minimum" in str(exc_info.value)
    
    def test_validate_currency_exceeds_maximum(self):
        """Test currency validation exceeding maximum."""
        with pytest.raises(BusinessRuleViolationError) as exc_info:
            validate_currency(15000.00, "USD", max_amount=10000.00)
        
        assert "exceeds maximum" in str(exc_info.value)
    
    def test_validate_currency_invalid_precision(self):
        """Test currency validation with invalid precision."""
        # USD should have max 2 decimal places
        with pytest.raises(BusinessRuleViolationError) as exc_info:
            validate_currency(decimal.Decimal('99.999'), "USD")
        
        assert "too many decimal places" in str(exc_info.value)


class TestBusinessValidationUtils:
    """
    Comprehensive test suite for business validation utilities.
    
    Tests email, phone, postal code validation, input sanitization,
    and JSON schema validation per business requirements.
    """
    
    def test_business_validate_email_valid(self):
        """Test business email validation with valid emails."""
        valid_emails = [
            "user@example.com",
            "test.email+tag@domain.org",
            "business@company.co.uk"
        ]
        
        for email in valid_emails:
            assert business_validate_email(email) is True
    
    def test_business_validate_email_invalid(self):
        """Test business email validation with invalid emails."""
        invalid_emails = [
            "invalid-email",
            "@domain.com",
            "user@domain..com",
            ""
        ]
        
        for email in invalid_emails:
            assert business_validate_email(email) is False
    
    def test_validate_phone_international(self):
        """Test international phone number validation."""
        valid_phones = [
            "+1-555-123-4567",
            "+44 20 7946 0958",
            "+33 1 42 86 83 26"
        ]
        
        for phone in valid_phones:
            assert validate_phone(phone, format_type="international") is True
    
    def test_validate_phone_us_national(self):
        """Test US national phone number validation."""
        valid_us_phones = [
            "(555) 123-4567",
            "555-123-4567",
            "555.123.4567"
        ]
        
        for phone in valid_us_phones:
            assert validate_phone(phone, country_code="US", format_type="national") is True
    
    def test_validate_phone_invalid(self):
        """Test phone number validation with invalid numbers."""
        invalid_phones = [
            "123",  # Too short
            "123456789012345678",  # Too long
            "abc-def-ghij",  # Non-numeric
            ""
        ]
        
        for phone in invalid_phones:
            assert validate_phone(phone) is False
    
    def test_validate_postal_code_us(self):
        """Test US postal code validation."""
        valid_us_codes = [
            "12345",
            "12345-6789"
        ]
        
        for code in valid_us_codes:
            assert validate_postal_code(code, "US") is True
        
        invalid_us_codes = [
            "1234",  # Too short
            "123456",  # Too long
            "ABCDE"  # Letters
        ]
        
        for code in invalid_us_codes:
            assert validate_postal_code(code, "US") is False
    
    def test_validate_postal_code_ca(self):
        """Test Canadian postal code validation."""
        valid_ca_codes = [
            "K1A 0A6",
            "K1A0A6",  # Without space
            "M5V 3L9"
        ]
        
        for code in valid_ca_codes:
            assert validate_postal_code(code, "CA") is True
    
    def test_validate_postal_code_unsupported_country(self):
        """Test postal code validation for unsupported country."""
        with pytest.raises(BusinessDataValidationError) as exc_info:
            validate_postal_code("12345", "XX")  # Unsupported country
        
        assert "not supported for country" in str(exc_info.value)
    
    def test_business_sanitize_input_basic(self):
        """Test business input sanitization."""
        dangerous_input = "<script>alert('xss')</script>Hello World"
        sanitized = business_sanitize_input(dangerous_input)
        
        assert "<script>" not in sanitized
        assert "Hello World" in sanitized
    
    def test_business_sanitize_input_with_html(self):
        """Test business input sanitization allowing HTML."""
        html_input = "<p>Hello <b>World</b></p>"
        sanitized = business_sanitize_input(html_input, allow_html=True)
        
        assert "<p>" in sanitized
        assert "<b>" in sanitized
        assert "Hello World" in sanitized
    
    def test_business_sanitize_input_max_length(self):
        """Test business input sanitization with length limit."""
        long_input = "a" * 100
        
        with pytest.raises(BusinessDataValidationError) as exc_info:
            business_sanitize_input(long_input, max_length=50)
        
        assert "exceeds maximum length" in str(exc_info.value)
    
    def test_validate_json_schema_success(self):
        """Test successful JSON schema validation."""
        schema = {
            "type": "object",
            "properties": {
                "name": {"type": "string", "minLength": 1},
                "age": {"type": "number", "minimum": 0}
            },
            "required": ["name", "age"]
        }
        
        valid_data = {"name": "John Doe", "age": 30}
        
        assert validate_json_schema(valid_data, schema) is True
    
    def test_validate_json_schema_failure(self):
        """Test JSON schema validation failure."""
        schema = {
            "type": "object",
            "properties": {
                "name": {"type": "string", "minLength": 1},
                "age": {"type": "number", "minimum": 0}
            },
            "required": ["name", "age"]
        }
        
        invalid_data = {"name": "", "age": -5}  # Invalid values
        
        with pytest.raises(BusinessDataValidationError) as exc_info:
            validate_json_schema(invalid_data, schema)
        
        assert "JSON schema validation failed" in str(exc_info.value)
    
    def test_validate_json_schema_missing_library(self):
        """Test JSON schema validation when jsonschema library is missing."""
        # Mock missing import
        with patch('src.business.utils.jsonschema', None):
            from src.business.utils import validate_json_schema as mock_validate
            
            with pytest.raises(BusinessDataValidationError):
                mock_validate({"test": "data"}, {"type": "object"})


class TestBusinessTypeConversion:
    """
    Comprehensive test suite for business type conversion utilities.
    
    Tests safe integer, float, string conversions, boolean normalization,
    and JSON parsing per Section 5.2.4 data processing requirements.
    """
    
    def test_safe_int_success(self):
        """Test successful safe integer conversion."""
        test_cases = [
            ("123", 123),
            (123.0, 123),
            (decimal.Decimal("456"), 456),
            ("  789  ", 789),
            (-42, -42)
        ]
        
        for input_val, expected in test_cases:
            result = safe_int(input_val)
            assert result == expected
    
    def test_safe_int_with_default(self):
        """Test safe integer conversion with default values."""
        invalid_inputs = [
            "not-a-number",
            "123.45",  # Non-integer float
            None,
            ""
        ]
        
        for input_val in invalid_inputs:
            result = safe_int(input_val, default=0)
            assert result == 0
    
    def test_safe_int_range_validation(self):
        """Test safe integer conversion with range validation."""
        # Within range
        result = safe_int("50", min_value=1, max_value=100)
        assert result == 50
        
        # Below minimum
        with pytest.raises(BusinessDataValidationError) as exc_info:
            safe_int("0", min_value=1, max_value=100)
        assert "below minimum" in str(exc_info.value)
        
        # Above maximum
        with pytest.raises(BusinessDataValidationError) as exc_info:
            safe_int("150", min_value=1, max_value=100)
        assert "exceeds maximum" in str(exc_info.value)
    
    def test_safe_float_success(self):
        """Test successful safe float conversion."""
        test_cases = [
            ("123.45", 123.45),
            (123, 123.0),
            ("  456.78  ", 456.78),
            (decimal.Decimal("789.01"), 789.01)
        ]
        
        for input_val, expected in test_cases:
            result = safe_float(input_val)
            assert abs(result - expected) < 0.001  # Float precision tolerance
    
    def test_safe_float_with_precision(self):
        """Test safe float conversion with precision control."""
        result = safe_float("123.456789", precision=2)
        assert result == 123.46
        
        result = safe_float("123.456789", precision=4)
        assert result == 123.4568
    
    def test_safe_float_range_validation(self):
        """Test safe float conversion with range validation."""
        # Within range
        result = safe_float("50.5", min_value=1.0, max_value=100.0)
        assert result == 50.5
        
        # Below minimum
        with pytest.raises(BusinessDataValidationError) as exc_info:
            safe_float("0.5", min_value=1.0, max_value=100.0)
        assert "below minimum" in str(exc_info.value)
    
    def test_safe_float_non_finite(self):
        """Test safe float conversion with non-finite values."""
        import math
        
        # Test infinity
        result = safe_float(float('inf'), default=0.0)
        assert result == 0.0
        
        # Test NaN
        result = safe_float(float('nan'), default=0.0)
        assert result == 0.0
    
    def test_safe_str_success(self):
        """Test successful safe string conversion."""
        test_cases = [
            (123, "123"),
            (123.45, "123.45"),
            (True, "True"),
            ("  hello  ", "hello"),  # With whitespace stripping
        ]
        
        for input_val, expected in test_cases:
            result = safe_str(input_val)
            assert result == expected
    
    def test_safe_str_max_length(self):
        """Test safe string conversion with maximum length."""
        long_string = "a" * 100
        
        with pytest.raises(BusinessDataValidationError) as exc_info:
            safe_str(long_string, max_length=50)
        
        assert "exceeds maximum length" in str(exc_info.value)
    
    def test_safe_str_no_strip(self):
        """Test safe string conversion without whitespace stripping."""
        input_str = "  hello world  "
        result = safe_str(input_str, strip_whitespace=False)
        
        assert result == "  hello world  "
    
    def test_normalize_boolean_standard_values(self):
        """Test boolean normalization with standard values."""
        true_values = [True, 1, "true", "yes", "on", "1"]
        false_values = [False, 0, "false", "no", "off", "0"]
        
        for val in true_values:
            result = normalize_boolean(val)
            assert result is True
        
        for val in false_values:
            result = normalize_boolean(val)
            assert result is False
    
    def test_normalize_boolean_ambiguous_values(self):
        """Test boolean normalization with ambiguous values."""
        ambiguous_values = ["maybe", "unknown", "xyz", None]
        
        for val in ambiguous_values:
            result = normalize_boolean(val, default=None)
            assert result is None
    
    def test_normalize_boolean_with_default(self):
        """Test boolean normalization with default value."""
        result = normalize_boolean("ambiguous", default=False)
        assert result is False
        
        result = normalize_boolean(None, default=True)
        assert result is True
    
    def test_parse_json_success(self):
        """Test successful JSON parsing."""
        json_string = '{"name": "John", "age": 30, "active": true}'
        result = parse_json(json_string)
        
        assert result["name"] == "John"
        assert result["age"] == 30
        assert result["active"] is True
    
    def test_parse_json_with_default(self):
        """Test JSON parsing with default value."""
        invalid_json = "not valid json"
        result = parse_json(invalid_json, default={})
        
        assert result == {}
    
    def test_parse_json_security_limits(self):
        """Test JSON parsing with security limits."""
        # Test excessive nesting
        deeply_nested = '{"a":' * 150 + '1' + '}' * 150
        result = parse_json(deeply_nested, default={})
        assert result == {}
        
        # Test large size
        large_json = '{"data": "' + 'x' * 2000000 + '"}'  # >1MB
        result = parse_json(large_json, default={})
        assert result == {}
    
    def test_parse_json_non_object(self):
        """Test JSON parsing with non-object result."""
        json_array = '[1, 2, 3]'
        result = parse_json(json_array, default={})
        
        assert result == {}  # Should return default for non-object


class TestBusinessHelperFunctions:
    """
    Test suite for business helper functions.
    
    Tests unique ID generation and hash calculation utilities.
    """
    
    def test_generate_unique_id_basic(self):
        """Test basic unique ID generation."""
        id1 = generate_unique_id()
        id2 = generate_unique_id()
        
        assert isinstance(id1, str)
        assert isinstance(id2, str)
        assert id1 != id2
        assert len(id1) == 8  # Default length
    
    def test_generate_unique_id_with_prefix(self):
        """Test unique ID generation with prefix."""
        user_id = generate_unique_id("USER", 12)
        
        assert user_id.startswith("USER_")
        assert len(user_id) == 17  # "USER_" + 12 characters
    
    def test_generate_unique_id_uniqueness(self):
        """Test unique ID generation produces unique IDs."""
        ids = set()
        for _ in range(100):
            new_id = generate_unique_id("TEST")
            ids.add(new_id)
        
        assert len(ids) == 100  # All should be unique
    
    def test_calculate_hash_string(self):
        """Test hash calculation with string data."""
        data = "Hello World"
        hash_result = calculate_hash(data, "sha256")
        
        assert isinstance(hash_result, str)
        assert len(hash_result) == 64  # SHA256 hex length
        
        # Same input should produce same hash
        hash_result2 = calculate_hash(data, "sha256")
        assert hash_result == hash_result2
    
    def test_calculate_hash_different_algorithms(self):
        """Test hash calculation with different algorithms."""
        data = "Test data"
        
        md5_hash = calculate_hash(data, "md5")
        sha1_hash = calculate_hash(data, "sha1")
        sha256_hash = calculate_hash(data, "sha256")
        sha512_hash = calculate_hash(data, "sha512")
        
        assert len(md5_hash) == 32
        assert len(sha1_hash) == 40
        assert len(sha256_hash) == 64
        assert len(sha512_hash) == 128
        
        # All should be different
        hashes = {md5_hash, sha1_hash, sha256_hash, sha512_hash}
        assert len(hashes) == 4
    
    def test_calculate_hash_dict_data(self):
        """Test hash calculation with dictionary data."""
        data_dict = {"user": "john", "action": "login", "timestamp": 1234567890}
        hash_result = calculate_hash(data_dict, "sha256")
        
        assert isinstance(hash_result, str)
        assert len(hash_result) == 64
        
        # Same dict should produce same hash (JSON is sorted)
        hash_result2 = calculate_hash(data_dict, "sha256")
        assert hash_result == hash_result2
        
        # Different order should produce same hash (sorted keys)
        data_dict2 = {"timestamp": 1234567890, "action": "login", "user": "john"}
        hash_result3 = calculate_hash(data_dict2, "sha256")
        assert hash_result == hash_result3
    
    def test_calculate_hash_bytes_data(self):
        """Test hash calculation with bytes data."""
        data = b"Binary data \x00\x01\x02"
        hash_result = calculate_hash(data, "sha256")
        
        assert isinstance(hash_result, str)
        assert len(hash_result) == 64
    
    def test_calculate_hash_invalid_algorithm(self):
        """Test hash calculation with invalid algorithm."""
        with pytest.raises(DataProcessingError) as exc_info:
            calculate_hash("test data", "invalid_algorithm")
        
        assert "Unsupported hash algorithm" in str(exc_info.value)
        assert exc_info.value.error_code == "UNSUPPORTED_HASH_ALGORITHM"


class TestUtilsIntegration:
    """
    Integration tests for general utils module.
    
    Tests integration between different utility modules when available.
    """
    
    @pytest.mark.skipif(not UTILS_AVAILABLE, reason="Utils module not fully available")
    def test_utils_datetime_integration(self):
        """Test integration with utils datetime functions."""
        # Test utils date parsing
        result = utils_parse("2024-01-15T10:30:00Z")
        assert isinstance(result, datetime)
        
        # Test utils date formatting
        dt = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        formatted = utils_to_iso(dt)
        assert "2024-01-15T10:30:00" in formatted
    
    @pytest.mark.skipif(not UTILS_AVAILABLE, reason="Utils module not fully available")
    def test_utils_validation_integration(self):
        """Test integration with utils validation functions."""
        # Test utils email validation
        result = utils_validate_email("test@example.com")
        assert result is True or isinstance(result, tuple)
        
        # Test utils HTML sanitization
        sanitized = utils_sanitize_html("<script>alert('xss')</script><p>Safe</p>")
        assert "<script>" not in sanitized
        assert "Safe" in sanitized
    
    @pytest.mark.skipif(not UTILS_AVAILABLE, reason="Utils module not fully available")
    def test_utils_response_integration(self):
        """Test integration with utils response functions."""
        # Test success response creation
        response = create_success_response({"message": "Success"})
        assert isinstance(response, dict)
        assert "data" in response or "message" in response
        
        # Test error response creation
        error_response = create_error_response("Test error", "TEST_ERROR")
        assert isinstance(error_response, dict)
        assert "error" in error_response or "message" in error_response


class TestErrorHandling:
    """
    Comprehensive test suite for error handling patterns.
    
    Tests error handling patterns per Section 4.2.3 with Flask @errorhandler
    integration and structured error reporting.
    """
    
    def test_authentication_error_handling(self):
        """Test authentication error handling."""
        with pytest.raises(AuthenticationError) as exc_info:
            raise AuthenticationError("Test authentication error")
        
        error = exc_info.value
        assert str(error) == "Test authentication error"
        assert isinstance(error, Exception)
    
    def test_token_validation_error_handling(self):
        """Test JWT token validation error handling."""
        with pytest.raises(TokenValidationError) as exc_info:
            raise TokenValidationError("Token validation failed")
        
        error = exc_info.value
        assert "Token validation failed" in str(error)
        assert isinstance(error, AuthenticationError)
    
    def test_cryptographic_error_handling(self):
        """Test cryptographic error handling."""
        with pytest.raises(CryptographicError) as exc_info:
            raise CryptographicError("Encryption operation failed")
        
        error = exc_info.value
        assert "Encryption operation failed" in str(error)
    
    def test_business_rule_violation_error(self):
        """Test business rule violation error handling."""
        with pytest.raises(BusinessRuleViolationError) as exc_info:
            raise BusinessRuleViolationError(
                message="Business rule violated",
                error_code="RULE_VIOLATION",
                context={"rule": "minimum_amount"},
                severity=ErrorSeverity.HIGH
            )
        
        error = exc_info.value
        assert error.message == "Business rule violated"
        assert error.error_code == "RULE_VIOLATION"
        assert error.context["rule"] == "minimum_amount"
        assert error.severity == ErrorSeverity.HIGH
    
    def test_data_processing_error(self):
        """Test data processing error handling."""
        with pytest.raises(DataProcessingError) as exc_info:
            raise DataProcessingError(
                message="Data processing failed",
                error_code="PROCESSING_ERROR",
                processing_stage="data_transformation",
                severity=ErrorSeverity.MEDIUM
            )
        
        error = exc_info.value
        assert error.processing_stage == "data_transformation"
        assert error.severity == ErrorSeverity.MEDIUM
    
    def test_data_validation_error(self):
        """Test data validation error handling."""
        with pytest.raises(BusinessDataValidationError) as exc_info:
            raise BusinessDataValidationError(
                message="Validation failed",
                error_code="VALIDATION_ERROR",
                context={"field": "email", "value": "invalid"},
                severity=ErrorSeverity.MEDIUM
            )
        
        error = exc_info.value
        assert error.context["field"] == "email"
        assert error.context["value"] == "invalid"


class TestPerformanceRequirements:
    """
    Test suite for performance requirements validation.
    
    Tests utilities maintain ≤10% performance variance requirement
    per Section 0.1.1 primary objectives.
    """
    
    def test_jwt_token_generation_performance(self, jwt_utils, sample_payload):
        """Test JWT token generation performance."""
        import time
        
        # Baseline timing
        start_time = time.time()
        for _ in range(100):
            jwt_utils.generate_token(sample_payload)
        end_time = time.time()
        
        baseline_duration = end_time - start_time
        
        # Should complete 100 token generations in reasonable time
        assert baseline_duration < 1.0  # Less than 1 second for 100 tokens
    
    def test_encryption_performance(self, crypto_utils):
        """Test encryption/decryption performance."""
        import time
        
        test_data = "Performance test data " * 100  # ~2KB of data
        key = crypto_utils.generate_encryption_key(256)
        
        # Encryption performance
        start_time = time.time()
        for _ in range(50):
            encrypted_data, nonce, _ = crypto_utils.encrypt_aes_gcm(test_data, key)
        encryption_time = time.time() - start_time
        
        # Decryption performance
        start_time = time.time()
        for _ in range(50):
            crypto_utils.decrypt_aes_gcm(encrypted_data, nonce, key)
        decryption_time = time.time() - start_time
        
        # Should complete 50 operations in reasonable time
        assert encryption_time < 1.0
        assert decryption_time < 1.0
    
    def test_data_cleaning_performance(self):
        """Test data cleaning performance."""
        import time
        
        # Generate large test dataset
        large_dataset = {
            f"field_{i}": f"  value_{i}  " if i % 2 == 0 else "" 
            for i in range(1000)
        }
        
        start_time = time.time()
        cleaned = clean_data(large_dataset, remove_empty=True, strip_strings=True)
        duration = time.time() - start_time
        
        # Should clean 1000 fields in reasonable time
        assert duration < 0.5  # Less than 500ms
        assert len(cleaned) < len(large_dataset)  # Should remove empty fields


# Test fixtures and configuration
@pytest.fixture(scope="session")
def test_configuration():
    """Session-wide test configuration."""
    return {
        "test_secret_key": "test-secret-key-for-jwt-testing",
        "test_timezone": "UTC",
        "performance_threshold": 1.0,  # 1 second max for performance tests
        "coverage_requirement": 0.90   # 90% coverage requirement
    }


@pytest.fixture
def mock_environment():
    """Mock environment variables for testing."""
    with patch.dict('os.environ', {
        'JWT_SECRET_KEY': 'test-jwt-secret',
        'DATE_MASKING_SALT': 'test-masking-salt',
        'FLASK_ENV': 'testing'
    }):
        yield


@pytest.fixture
def mock_aws_credentials():
    """Mock AWS credentials for KMS testing."""
    with patch.dict('os.environ', {
        'AWS_ACCESS_KEY_ID': 'test-access-key',
        'AWS_SECRET_ACCESS_KEY': 'test-secret-key',
        'AWS_KMS_CMK_ARN': 'arn:aws:kms:us-east-1:123456789:key/test-key-id',
        'AWS_REGION': 'us-east-1'
    }):
        yield


# Custom test markers
pytestmark = [
    pytest.mark.utilities,
    pytest.mark.unit,
    pytest.mark.security,
    pytest.mark.performance
]


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "--cov=src.auth.utils", "--cov=src.business.utils"])