"""
Comprehensive Unit Tests for Utility Functions

This module provides comprehensive unit testing for all utility functions across the Flask
application, covering authentication utilities, business utilities, date/time processing,
data manipulation, and common utility functions. Tests ensure comprehensive coverage of
helper functions with type validation and error handling patterns per Section 6.6.1.

Test Coverage Areas:
- Authentication utilities: JWT token manipulation, session management, decorators
- Business utilities: Data transformation, validation, calculations, type conversion
- Date/time processing: python-dateutil 2.8+ functionality equivalent to Node.js moment
- Data manipulation: Cleaning, transformation, merging, filtering operations
- Security utilities: Encryption, sanitization, validation patterns
- Error handling: Comprehensive edge case and exception testing
- Performance validation: Ensuring ≤10% variance from baseline requirements

Testing Framework:
- pytest 7.4+ with extensive plugin support per Section 6.6.1
- Flask application testing with pytest-flask integration
- Authentication testing fixtures for JWT and session validation
- Security testing patterns for input validation and sanitization
- Performance testing with baseline comparison validation
- Comprehensive mock integration for external dependencies

Author: Flask Migration Team
Version: 1.0.0
Compliance: SOC 2, ISO 27001, OWASP Top 10 testing standards
Coverage Target: 95% minimum per Section 6.6.3 quality metrics
"""

import pytest
import json
import base64
import hashlib
import secrets
import time
import decimal
from datetime import datetime, timezone, timedelta, date
from typing import Any, Dict, List, Optional, Union, Tuple
from unittest.mock import Mock, patch, MagicMock, call
from freezegun import freeze_time
import structlog

# Flask testing imports
from flask import Flask, g, request, session
from flask.testing import FlaskClient
from flask_login import current_user, login_user

# Cryptographic and security imports
import jwt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from dateutil import parser as dateutil_parser
from dateutil.relativedelta import relativedelta
import redis
import bleach

# Import utilities under test
from src.auth.utils import (
    JWTTokenManager, DateTimeUtilities, InputValidator, CryptographicUtilities,
    jwt_manager, datetime_utils, input_validator, crypto_utils,
    require_valid_token, get_current_user_id, get_current_user_permissions,
    log_security_event
)

from src.business.utils import (
    clean_data, transform_data, merge_data, flatten_data, filter_data,
    parse_date, format_date, calculate_date_difference, get_business_days,
    convert_timezone, calculate_percentage, apply_discount, calculate_tax,
    round_currency, validate_currency, validate_email, validate_phone,
    validate_postal_code, sanitize_input, validate_json_schema,
    safe_int, safe_float, safe_str, normalize_boolean, parse_json,
    generate_unique_id, calculate_hash
)

from src.utils import (
    DateTimeUtils, HttpUtils, ValidationUtils, SanitizationUtils, ResponseUtils
)

# Import test fixtures and exceptions
from src.auth.exceptions import (
    JWTException, AuthenticationException, ValidationException, SecurityException
)
from src.business.exceptions import (
    BaseBusinessException, BusinessRuleViolationError, DataProcessingError,
    DataValidationError, ConfigurationError
)

# Configure test logging
logger = structlog.get_logger("tests.unit.test_utilities")


class TestJWTTokenManager:
    """
    Comprehensive tests for JWT token management functionality.
    
    Tests JWT token creation, validation, refresh, and revocation operations
    with comprehensive security validation and error handling per Section 6.4.1
    authentication framework requirements.
    """
    
    @pytest.fixture
    def jwt_manager(self, mock_redis_cache):
        """Create JWT token manager instance for testing."""
        with patch('src.auth.utils.get_redis_client', return_value=mock_redis_cache):
            manager = JWTTokenManager(
                secret_key="test-secret-key-do-not-use-in-production",
                algorithm="HS256",
                issuer="test-issuer",
                audience="test-audience"
            )
            return manager
    
    def test_create_access_token_success(self, jwt_manager, mock_redis_cache):
        """Test successful access token creation with comprehensive claims."""
        user_id = "test-user-123"
        permissions = ["read:documents", "write:documents"]
        additional_claims = {"organization_id": "org-456"}
        
        token = jwt_manager.create_access_token(
            user_id=user_id,
            permissions=permissions,
            additional_claims=additional_claims
        )
        
        # Validate token structure
        assert isinstance(token, str)
        assert len(token) > 100  # JWT tokens are typically long
        
        # Decode and validate claims
        decoded = jwt.decode(
            token, 
            jwt_manager.secret_key, 
            algorithms=[jwt_manager.algorithm],
            audience=jwt_manager.audience,
            issuer=jwt_manager.issuer
        )
        
        assert decoded['sub'] == user_id
        assert decoded['iss'] == jwt_manager.issuer
        assert decoded['aud'] == jwt_manager.audience
        assert decoded['type'] == 'access_token'
        assert decoded['permissions'] == permissions
        assert decoded['organization_id'] == "org-456"
        assert 'jti' in decoded
        assert 'iat' in decoded
        assert 'exp' in decoded
        
        # Validate Redis caching
        mock_redis_cache.setex.assert_called()
        cache_call = mock_redis_cache.setex.call_args
        assert cache_call[0][0].startswith("token_meta:")
        
        logger.info("JWT access token creation test passed", 
                   user_id=user_id, permissions_count=len(permissions))
    
    def test_create_access_token_minimal(self, jwt_manager):
        """Test access token creation with minimal required parameters."""
        user_id = "minimal-user"
        
        token = jwt_manager.create_access_token(user_id=user_id)
        
        decoded = jwt.decode(
            token,
            jwt_manager.secret_key,
            algorithms=[jwt_manager.algorithm],
            audience=jwt_manager.audience,
            issuer=jwt_manager.issuer
        )
        
        assert decoded['sub'] == user_id
        assert decoded['type'] == 'access_token'
        assert 'permissions' not in decoded or decoded['permissions'] == []
    
    def test_create_refresh_token_success(self, jwt_manager):
        """Test successful refresh token creation with access token binding."""
        user_id = "refresh-user"
        access_token_jti = "access-token-jti-123"
        
        refresh_token = jwt_manager.create_refresh_token(
            user_id=user_id,
            access_token_jti=access_token_jti
        )
        
        decoded = jwt.decode(
            refresh_token,
            jwt_manager.secret_key,
            algorithms=[jwt_manager.algorithm],
            audience=jwt_manager.audience,
            issuer=jwt_manager.issuer
        )
        
        assert decoded['sub'] == user_id
        assert decoded['type'] == 'refresh_token'
        assert decoded['access_token_jti'] == access_token_jti
        assert 'jti' in decoded
    
    def test_validate_token_success(self, jwt_manager):
        """Test successful token validation with comprehensive checks."""
        user_id = "validate-user"
        permissions = ["admin:users"]
        
        token = jwt_manager.create_access_token(
            user_id=user_id,
            permissions=permissions
        )
        
        claims = jwt_manager.validate_token(
            token=token,
            required_claims=['sub', 'permissions']
        )
        
        assert claims['sub'] == user_id
        assert claims['permissions'] == permissions
        assert claims['type'] == 'access_token'
    
    def test_validate_token_expired(self, jwt_manager):
        """Test token validation with expired token."""
        user_id = "expired-user"
        
        # Create token with very short expiry
        with freeze_time("2024-01-01 12:00:00"):
            token = jwt_manager.create_access_token(
                user_id=user_id,
                expires_delta=timedelta(seconds=1)
            )
        
        # Validate after expiry
        with freeze_time("2024-01-01 12:00:02"):
            with pytest.raises(JWTException) as exc_info:
                jwt_manager.validate_token(token)
            
            assert "expired" in str(exc_info.value).lower()
    
    def test_validate_token_invalid_signature(self, jwt_manager):
        """Test token validation with invalid signature."""
        # Create token with different secret
        invalid_manager = JWTTokenManager(
            secret_key="different-secret-key",
            algorithm="HS256"
        )
        token = invalid_manager.create_access_token("test-user")
        
        with pytest.raises(JWTException) as exc_info:
            jwt_manager.validate_token(token)
        
        assert "signature" in str(exc_info.value).lower()
    
    def test_validate_token_missing_required_claims(self, jwt_manager):
        """Test token validation with missing required claims."""
        token = jwt_manager.create_access_token("test-user")
        
        with pytest.raises(JWTException) as exc_info:
            jwt_manager.validate_token(
                token,
                required_claims=['missing_claim']
            )
        
        assert "missing required claims" in str(exc_info.value).lower()
    
    def test_revoke_token_success(self, jwt_manager, mock_redis_cache):
        """Test successful token revocation with blacklist management."""
        user_id = "revoke-user"
        token = jwt_manager.create_access_token(user_id)
        
        result = jwt_manager.revoke_token(token, reason="user_logout")
        
        assert result is True
        mock_redis_cache.setex.assert_called()
        
        # Verify blacklist key creation
        blacklist_calls = [call for call in mock_redis_cache.setex.call_args_list 
                          if call[0][0].startswith("blacklist:")]
        assert len(blacklist_calls) > 0
    
    def test_refresh_access_token_success(self, jwt_manager):
        """Test successful token refresh with rotation."""
        user_id = "refresh-test-user"
        
        # Create initial access token
        access_token = jwt_manager.create_access_token(user_id)
        access_claims = jwt_manager.validate_token(access_token)
        
        # Create refresh token
        refresh_token = jwt_manager.create_refresh_token(
            user_id=user_id,
            access_token_jti=access_claims['jti']
        )
        
        # Refresh tokens
        new_access_token, new_refresh_token = jwt_manager.refresh_access_token(refresh_token)
        
        # Validate new tokens
        new_access_claims = jwt_manager.validate_token(new_access_token)
        new_refresh_claims = jwt_manager.validate_token(new_refresh_token)
        
        assert new_access_claims['sub'] == user_id
        assert new_refresh_claims['sub'] == user_id
        assert new_access_claims['jti'] != access_claims['jti']  # Different token ID
    
    def test_refresh_access_token_invalid_type(self, jwt_manager):
        """Test token refresh with invalid token type."""
        user_id = "invalid-refresh-user"
        access_token = jwt_manager.create_access_token(user_id)
        
        # Try to refresh with access token instead of refresh token
        with pytest.raises(JWTException) as exc_info:
            jwt_manager.refresh_access_token(access_token)
        
        assert "invalid token type" in str(exc_info.value).lower()
    
    def test_get_token_claims_without_validation(self, jwt_manager):
        """Test token claims extraction without validation for debugging."""
        user_id = "claims-user"
        permissions = ["debug:access"]
        
        token = jwt_manager.create_access_token(
            user_id=user_id,
            permissions=permissions
        )
        
        claims = jwt_manager.get_token_claims(token)
        
        assert claims is not None
        assert claims['sub'] == user_id
        assert claims['permissions'] == permissions
    
    def test_get_token_claims_malformed_token(self, jwt_manager):
        """Test token claims extraction with malformed token."""
        malformed_token = "invalid.jwt.token"
        
        claims = jwt_manager.get_token_claims(malformed_token)
        
        assert claims is None
    
    @patch('src.auth.utils.logger')
    def test_token_creation_logging(self, mock_logger, jwt_manager):
        """Test security logging for token creation operations."""
        user_id = "logging-user"
        permissions = ["test:permission"]
        
        jwt_manager.create_access_token(
            user_id=user_id,
            permissions=permissions
        )
        
        mock_logger.info.assert_called()
        log_call = mock_logger.info.call_args[0][0]
        assert "access token created" in log_call.lower()


class TestDateTimeUtilities:
    """
    Comprehensive tests for date/time processing utilities.
    
    Tests date/time parsing, validation, manipulation, and formatting operations
    using python-dateutil 2.8+ equivalent to Node.js moment functionality
    per Section 5.2.4 business logic requirements.
    """
    
    @pytest.fixture
    def dt_utils(self):
        """Create DateTimeUtilities instance for testing."""
        return DateTimeUtilities()
    
    def test_parse_iso8601_safely_valid_utc(self, dt_utils):
        """Test safe ISO 8601 parsing with valid UTC datetime."""
        date_string = "2024-01-15T10:30:00Z"
        
        result = dt_utils.parse_iso8601_safely(date_string)
        
        assert result is not None
        assert isinstance(result, datetime)
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 15
        assert result.hour == 10
        assert result.minute == 30
        assert result.second == 0
        assert result.tzinfo == timezone.utc
        
        logger.debug("ISO 8601 UTC parsing test passed", parsed_date=result.isoformat())
    
    def test_parse_iso8601_safely_with_timezone(self, dt_utils):
        """Test ISO 8601 parsing with timezone offset."""
        date_string = "2024-01-15T10:30:00+05:00"
        
        result = dt_utils.parse_iso8601_safely(date_string)
        
        assert result is not None
        assert result.tzinfo is not None
        assert result.utcoffset() == timedelta(hours=5)
    
    def test_parse_iso8601_safely_naive_datetime(self, dt_utils):
        """Test ISO 8601 parsing with naive datetime."""
        date_string = "2024-01-15T10:30:00"
        
        result = dt_utils.parse_iso8601_safely(
            date_string,
            default_timezone=timezone.utc
        )
        
        assert result is not None
        assert result.tzinfo == timezone.utc
    
    def test_parse_iso8601_safely_invalid_format(self, dt_utils):
        """Test ISO 8601 parsing with invalid format."""
        invalid_strings = [
            "not-a-date",
            "2024/01/15",  # Wrong format
            "2024-13-45",  # Invalid month/day
            "24-01-15",    # Wrong year format
            "",
            None
        ]
        
        for invalid_string in invalid_strings:
            with pytest.raises(ValidationException):
                dt_utils.parse_iso8601_safely(invalid_string)
    
    def test_parse_iso8601_safely_too_long(self, dt_utils):
        """Test ISO 8601 parsing with overly long string."""
        long_string = "2024-01-15T10:30:00Z" + "x" * 100
        
        with pytest.raises(ValidationException) as exc_info:
            dt_utils.parse_iso8601_safely(long_string)
        
        assert "too long" in str(exc_info.value).lower()
    
    def test_parse_iso8601_safely_out_of_range(self, dt_utils):
        """Test ISO 8601 parsing with dates outside business range."""
        out_of_range_dates = [
            "1800-01-01T00:00:00Z",  # Before min business date
            "2200-01-01T00:00:00Z"   # After max business date
        ]
        
        for date_string in out_of_range_dates:
            with pytest.raises(ValidationException):
                dt_utils.parse_iso8601_safely(date_string)
    
    def test_mask_temporal_data_month_level(self, dt_utils):
        """Test temporal data masking at month level."""
        original_date = "2024-01-15T14:30:45Z"
        
        masked = dt_utils.mask_temporal_data(original_date, masking_level="month")
        
        assert masked == "2024-01-01T00:00:00+00:00"
    
    def test_mask_temporal_data_week_level(self, dt_utils):
        """Test temporal data masking at week level."""
        # Test with Wednesday (2024-01-17)
        original_date = "2024-01-17T14:30:45Z"
        
        masked = dt_utils.mask_temporal_data(original_date, masking_level="week")
        
        # Should round to Monday (2024-01-15)
        expected = datetime(2024, 1, 15, 0, 0, 0, tzinfo=timezone.utc)
        assert masked == expected.isoformat()
    
    def test_mask_temporal_data_quarter_level(self, dt_utils):
        """Test temporal data masking at quarter level."""
        original_date = "2024-07-15T14:30:45Z"  # Q3
        
        masked = dt_utils.mask_temporal_data(original_date, masking_level="quarter")
        
        assert masked == "2024-07-01T00:00:00+00:00"  # Start of Q3
    
    def test_mask_temporal_data_year_level(self, dt_utils):
        """Test temporal data masking at year level."""
        original_date = "2024-07-15T14:30:45Z"
        
        masked = dt_utils.mask_temporal_data(original_date, masking_level="year")
        
        assert masked == "2024-01-01T00:00:00+00:00"
    
    def test_mask_temporal_data_datetime_object(self, dt_utils):
        """Test temporal data masking with datetime object input."""
        original_date = datetime(2024, 1, 15, 14, 30, 45, tzinfo=timezone.utc)
        
        masked = dt_utils.mask_temporal_data(original_date, masking_level="month")
        
        assert masked == "2024-01-01T00:00:00+00:00"
    
    def test_mask_temporal_data_invalid_input(self, dt_utils):
        """Test temporal data masking with invalid input."""
        invalid_inputs = ["invalid-date", None, 12345]
        
        for invalid_input in invalid_inputs:
            result = dt_utils.mask_temporal_data(invalid_input)
            assert result == "1970-01-01T00:00:00Z"  # Safe default
    
    def test_format_for_api_response_iso8601(self, dt_utils):
        """Test API response formatting in ISO 8601 format."""
        dt = datetime(2024, 1, 15, 10, 30, 45, tzinfo=timezone.utc)
        
        result = dt_utils.format_for_api_response(dt, format_type="iso8601")
        
        assert result == "2024-01-15T10:30:45+00:00"
    
    def test_format_for_api_response_timestamp(self, dt_utils):
        """Test API response formatting as timestamp."""
        dt = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        
        result = dt_utils.format_for_api_response(dt, format_type="timestamp")
        
        assert result == "1704067200"  # Unix timestamp for 2024-01-01
    
    def test_format_for_api_response_date_only(self, dt_utils):
        """Test API response formatting as date only."""
        dt = datetime(2024, 1, 15, 10, 30, 45, tzinfo=timezone.utc)
        
        result = dt_utils.format_for_api_response(dt, format_type="date_only")
        
        assert result == "2024-01-15"
    
    def test_format_for_api_response_naive_datetime(self, dt_utils):
        """Test API response formatting with naive datetime."""
        dt = datetime(2024, 1, 15, 10, 30, 45)  # No timezone
        
        result = dt_utils.format_for_api_response(dt, include_timezone=True)
        
        assert "+00:00" in result  # UTC timezone added
    
    def test_format_for_api_response_invalid_input(self, dt_utils):
        """Test API response formatting with invalid input."""
        invalid_inputs = ["not-a-datetime", None, 12345]
        
        for invalid_input in invalid_inputs:
            result = dt_utils.format_for_api_response(invalid_input)
            assert result == ""
    
    def test_calculate_age_securely_valid(self, dt_utils):
        """Test secure age calculation with valid birth date."""
        birth_date = "1990-05-15T00:00:00Z"
        reference_date = datetime(2024, 5, 15, tzinfo=timezone.utc)
        
        age = dt_utils.calculate_age_securely(birth_date, reference_date)
        
        assert age == 34
    
    def test_calculate_age_securely_datetime_object(self, dt_utils):
        """Test secure age calculation with datetime object."""
        birth_date = datetime(1990, 5, 15, tzinfo=timezone.utc)
        reference_date = datetime(2024, 5, 16, tzinfo=timezone.utc)  # Day after birthday
        
        age = dt_utils.calculate_age_securely(birth_date, reference_date)
        
        assert age == 34
    
    def test_calculate_age_securely_future_birth_date(self, dt_utils):
        """Test secure age calculation with future birth date."""
        birth_date = "2030-01-01T00:00:00Z"
        reference_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
        
        age = dt_utils.calculate_age_securely(birth_date, reference_date)
        
        assert age is None  # Invalid: birth date in future
    
    def test_calculate_age_securely_unreasonable_age(self, dt_utils):
        """Test secure age calculation with unreasonable age."""
        birth_date = "1800-01-01T00:00:00Z"  # Would be 224 years old
        reference_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
        
        age = dt_utils.calculate_age_securely(birth_date, reference_date)
        
        assert age is None  # Invalid: unreasonable age
    
    def test_calculate_age_securely_invalid_date(self, dt_utils):
        """Test secure age calculation with invalid date."""
        invalid_dates = ["invalid-date", None, ""]
        reference_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
        
        for invalid_date in invalid_dates:
            age = dt_utils.calculate_age_securely(invalid_date, reference_date)
            assert age is None


class TestInputValidator:
    """
    Comprehensive tests for input validation and sanitization utilities.
    
    Tests email validation, HTML sanitization, URL validation, phone validation,
    and comprehensive input sanitization with security patterns per Section 6.4.2
    authorization system requirements.
    """
    
    @pytest.fixture
    def validator(self, mock_redis_cache):
        """Create InputValidator instance for testing."""
        with patch('src.auth.utils.get_redis_client', return_value=mock_redis_cache):
            return InputValidator()
    
    def test_validate_and_sanitize_email_valid(self, validator):
        """Test email validation with valid email addresses."""
        valid_emails = [
            "user@example.com",
            "test.user+tag@domain.co.uk",
            "admin@subdomain.example.org",
            "  USER@EXAMPLE.COM  ",  # Case and whitespace handling
        ]
        
        for email in valid_emails:
            result = validator.validate_and_sanitize_email(email)
            assert result is not None
            assert "@" in result
            assert result == result.lower().strip()
            
            logger.debug("Email validation passed", email=email, sanitized=result)
    
    def test_validate_and_sanitize_email_invalid(self, validator):
        """Test email validation with invalid email addresses."""
        invalid_emails = [
            "",
            "not-an-email",
            "@example.com",
            "user@",
            "user..double.dot@example.com",
            "user@.example.com",
            "x" * 300 + "@example.com",  # Too long
        ]
        
        for email in invalid_emails:
            with pytest.raises(ValidationException):
                validator.validate_and_sanitize_email(email)
    
    def test_validate_and_sanitize_email_with_deliverability(self, validator):
        """Test email validation with deliverability checking."""
        email = "test@example.com"
        
        # Mock successful deliverability check
        with patch('email_validator.validate_email') as mock_validate:
            mock_validate.return_value.email = email.lower()
            
            result = validator.validate_and_sanitize_email(
                email, 
                check_deliverability=True
            )
            
            assert result == email.lower()
            mock_validate.assert_called_once()
    
    def test_sanitize_html_content_safe_tags(self, validator):
        """Test HTML sanitization with safe tags."""
        html_content = "<p>Hello <b>World</b>! <em>Test</em> content.</p>"
        
        result = validator.sanitize_html_content(html_content)
        
        assert "<p>" in result
        assert "<b>" in result
        assert "<em>" in result
        assert "Hello World! Test content." in result
    
    def test_sanitize_html_content_dangerous_tags(self, validator):
        """Test HTML sanitization removes dangerous tags."""
        dangerous_html = """
        <script>alert('xss')</script>
        <p>Safe content</p>
        <iframe src="evil.com"></iframe>
        <img src="x" onerror="alert('xss')">
        """
        
        result = validator.sanitize_html_content(dangerous_html)
        
        assert "<script>" not in result
        assert "<iframe>" not in result
        assert "onerror" not in result
        assert "alert" not in result
        assert "Safe content" in result
    
    def test_sanitize_html_content_suspicious_patterns(self, validator):
        """Test HTML sanitization detects suspicious patterns."""
        suspicious_content = """
        <p onclick="eval('malicious code')">Click me</p>
        <div onload="javascript:alert('xss')">Content</div>
        """
        
        with pytest.raises(ValidationException) as exc_info:
            validator.sanitize_html_content(suspicious_content)
        
        assert "suspicious patterns" in str(exc_info.value).lower()
    
    def test_sanitize_html_content_empty_and_none(self, validator):
        """Test HTML sanitization with empty and None input."""
        assert validator.sanitize_html_content("") == ""
        assert validator.sanitize_html_content(None) == ""
    
    def test_validate_url_valid_urls(self, validator):
        """Test URL validation with valid URLs."""
        valid_urls = [
            "https://example.com",
            "http://subdomain.example.org/path",
            "https://example.com:8080/api/v1",
            "http://localhost:3000/test",
        ]
        
        for url in valid_urls:
            result = validator.validate_url(url)
            assert result == url
    
    def test_validate_url_invalid_schemes(self, validator):
        """Test URL validation rejects invalid schemes."""
        invalid_urls = [
            "ftp://example.com",
            "file:///etc/passwd",
            "javascript:alert('xss')",
            "data:text/html,<script>alert('xss')</script>",
        ]
        
        for url in invalid_urls:
            with pytest.raises(ValidationException):
                validator.validate_url(url)
    
    def test_validate_url_security_checks(self, validator):
        """Test URL validation with security domain checking."""
        # Test production environment restrictions
        with patch.dict('os.environ', {'FLASK_ENV': 'production'}):
            blocked_urls = [
                "http://localhost:8080",
                "https://127.0.0.1:3000",
                "http://0.0.0.0:5000",
            ]
            
            for url in blocked_urls:
                with pytest.raises(ValidationException):
                    validator.validate_url(url, check_domain_security=True)
    
    def test_validate_phone_number_valid(self, validator):
        """Test phone number validation with valid formats."""
        valid_phones = [
            "+1-555-123-4567",
            "+14155552671",
            "5551234567",
            "(555) 123-4567",
            "+44 20 7946 0958",  # UK format
        ]
        
        for phone in valid_phones:
            result = validator.validate_phone_number(phone)
            assert result is not None
            assert result.isdigit() or result.startswith('+')
    
    def test_validate_phone_number_us_format(self, validator):
        """Test phone number validation with US-specific format."""
        us_phone = "(555) 123-4567"
        
        result = validator.validate_phone_number(
            us_phone, 
            country_code="US"
        )
        
        assert result is not None
        digits_only = ''.join(filter(str.isdigit, result))
        assert len(digits_only) == 10  # US phone numbers have 10 digits
    
    def test_validate_phone_number_invalid(self, validator):
        """Test phone number validation with invalid formats."""
        invalid_phones = [
            "",
            "123",  # Too short
            "123456789012345678901",  # Too long
            "abc-def-ghij",  # Non-numeric
            "555-CALL-NOW",  # Mixed format
        ]
        
        for phone in invalid_phones:
            with pytest.raises(ValidationException):
                validator.validate_phone_number(phone)
    
    def test_validate_username_valid(self, validator):
        """Test username validation with valid usernames."""
        valid_usernames = [
            "john_doe",
            "admin123",
            "user_2024",
            "testuser",
            "a" * 30,  # Maximum length
        ]
        
        for username in valid_usernames:
            result = validator.validate_username(username)
            assert result == username
    
    def test_validate_username_invalid_format(self, validator):
        """Test username validation with invalid formats."""
        invalid_usernames = [
            "",
            "ab",  # Too short
            "a" * 31,  # Too long
            "user@domain",  # Invalid characters
            "user-name",  # Hyphen not allowed
            "user name",  # Space not allowed
        ]
        
        for username in invalid_usernames:
            with pytest.raises(ValidationException):
                validator.validate_username(username)
    
    def test_validate_username_reserved(self, validator):
        """Test username validation rejects reserved usernames."""
        reserved_usernames = [
            "admin",
            "administrator",
            "root",
            "system",
            "support",
        ]
        
        for username in reserved_usernames:
            with pytest.raises(ValidationException):
                validator.validate_username(username)


class TestCryptographicUtilities:
    """
    Comprehensive tests for cryptographic utility functions.
    
    Tests secure token generation, data encryption/decryption, password hashing,
    and digital signature operations with comprehensive security validation
    per Section 6.4.3 data protection requirements.
    """
    
    @pytest.fixture
    def crypto_utils(self):
        """Create CryptographicUtilities instance for testing."""
        test_key = Fernet.generate_key()
        return CryptographicUtilities(master_key=test_key[:32])
    
    def test_generate_secure_token_default(self, crypto_utils):
        """Test secure token generation with default parameters."""
        token = crypto_utils.generate_secure_token()
        
        assert isinstance(token, str)
        assert len(token) > 40  # Base64 encoded 32 bytes should be longer
        
        # Test token uniqueness
        token2 = crypto_utils.generate_secure_token()
        assert token != token2
    
    def test_generate_secure_token_custom_length(self, crypto_utils):
        """Test secure token generation with custom length."""
        lengths = [16, 32, 64, 128]
        
        for length in lengths:
            token = crypto_utils.generate_secure_token(length=length)
            assert isinstance(token, str)
            
            # Decode to verify actual byte length
            decoded = base64.urlsafe_b64decode(token.encode('ascii'))
            assert len(decoded) == length
    
    def test_generate_secure_token_invalid_length(self, crypto_utils):
        """Test secure token generation with invalid lengths."""
        invalid_lengths = [0, 10, 256]  # Too small or too large
        
        for length in invalid_lengths:
            with pytest.raises(SecurityException):
                crypto_utils.generate_secure_token(length=length)
    
    def test_encrypt_decrypt_session_data_success(self, crypto_utils):
        """Test successful session data encryption and decryption."""
        test_data = {
            'user_id': 'test-user-123',
            'permissions': ['read', 'write'],
            'organization_id': 'org-456',
            'session_start': '2024-01-15T10:30:00Z'
        }
        
        # Encrypt data
        encrypted = crypto_utils.encrypt_session_data(test_data)
        assert isinstance(encrypted, str)
        assert len(encrypted) > 100  # Encrypted data should be substantial
        
        # Decrypt data
        decrypted = crypto_utils.decrypt_session_data(encrypted)
        
        assert decrypted['user_id'] == test_data['user_id']
        assert decrypted['permissions'] == test_data['permissions']
        assert decrypted['organization_id'] == test_data['organization_id']
        assert decrypted['session_start'] == test_data['session_start']
        
        # Encryption timestamp should be removed
        assert '_encrypted_at' not in decrypted
    
    def test_encrypt_session_data_with_timestamp(self, crypto_utils):
        """Test session data encryption includes timestamp."""
        test_data = {'user_id': 'timestamp-test'}
        
        with freeze_time("2024-01-15 10:30:00"):
            encrypted = crypto_utils.encrypt_session_data(
                test_data, 
                include_timestamp=True
            )
            
            # Decrypt to verify timestamp inclusion
            decrypted = crypto_utils.decrypt_session_data(encrypted)
            
            # Timestamp should have been included during encryption
            # but removed during decryption
            assert 'user_id' in decrypted
    
    def test_decrypt_session_data_expired(self, crypto_utils):
        """Test session data decryption with expired data."""
        test_data = {'user_id': 'expired-test'}
        
        # Encrypt data in the past
        with freeze_time("2024-01-15 10:00:00"):
            encrypted = crypto_utils.encrypt_session_data(test_data)
        
        # Try to decrypt after expiry (1 second max age)
        with freeze_time("2024-01-15 10:00:02"):
            with pytest.raises(SecurityException):
                crypto_utils.decrypt_session_data(encrypted, max_age_seconds=1)
    
    def test_decrypt_session_data_invalid(self, crypto_utils):
        """Test session data decryption with invalid encrypted data."""
        invalid_data = [
            "invalid-base64-data",
            "",
            "validbase64butnotencrypted==",
        ]
        
        for invalid in invalid_data:
            with pytest.raises(SecurityException):
                crypto_utils.decrypt_session_data(invalid)
    
    def test_hash_password_securely_success(self, crypto_utils):
        """Test secure password hashing with salt generation."""
        password = "test-password-123!"
        
        hashed_password, salt = crypto_utils.hash_password_securely(password)
        
        assert isinstance(hashed_password, str)
        assert isinstance(salt, str)
        assert len(hashed_password) > 40  # Base64 encoded hash
        assert len(salt) > 40  # Base64 encoded salt
        
        # Test uniqueness with same password
        hashed2, salt2 = crypto_utils.hash_password_securely(password)
        assert hashed_password != hashed2  # Different due to random salt
        assert salt != salt2
    
    def test_hash_password_securely_custom_salt(self, crypto_utils):
        """Test secure password hashing with custom salt."""
        password = "test-password"
        custom_salt = secrets.token_bytes(32)
        
        hashed_password, returned_salt = crypto_utils.hash_password_securely(
            password, 
            salt=custom_salt
        )
        
        # Should return the same salt that was provided
        decoded_salt = base64.urlsafe_b64decode(returned_salt.encode('ascii'))
        assert decoded_salt == custom_salt
    
    def test_verify_password_hash_success(self, crypto_utils):
        """Test successful password hash verification."""
        password = "verification-test-password"
        
        hashed_password, salt = crypto_utils.hash_password_securely(password)
        
        # Verify correct password
        result = crypto_utils.verify_password_hash(password, hashed_password, salt)
        assert result is True
    
    def test_verify_password_hash_failure(self, crypto_utils):
        """Test password hash verification with wrong password."""
        correct_password = "correct-password"
        wrong_password = "wrong-password"
        
        hashed_password, salt = crypto_utils.hash_password_securely(correct_password)
        
        # Verify wrong password
        result = crypto_utils.verify_password_hash(wrong_password, hashed_password, salt)
        assert result is False
    
    def test_verify_password_hash_invalid_data(self, crypto_utils):
        """Test password hash verification with invalid hash data."""
        password = "test-password"
        
        # Test with invalid base64 data
        result = crypto_utils.verify_password_hash(
            password, 
            "invalid-hash", 
            "invalid-salt"
        )
        assert result is False
    
    def test_create_verify_digital_signature_success(self, crypto_utils):
        """Test digital signature creation and verification."""
        test_data = "important data to sign"
        
        # Create signature
        signature = crypto_utils.create_digital_signature(test_data)
        assert isinstance(signature, str)
        assert len(signature) > 40
        
        # Verify signature
        is_valid = crypto_utils.verify_digital_signature(test_data, signature)
        assert is_valid is True
    
    def test_create_verify_digital_signature_bytes(self, crypto_utils):
        """Test digital signature with bytes input."""
        test_data = b"binary data to sign"
        
        signature = crypto_utils.create_digital_signature(test_data)
        is_valid = crypto_utils.verify_digital_signature(test_data, signature)
        
        assert is_valid is True
    
    def test_verify_digital_signature_tampered_data(self, crypto_utils):
        """Test digital signature verification with tampered data."""
        original_data = "original data"
        tampered_data = "tampered data"
        
        signature = crypto_utils.create_digital_signature(original_data)
        is_valid = crypto_utils.verify_digital_signature(tampered_data, signature)
        
        assert is_valid is False
    
    def test_verify_digital_signature_invalid_signature(self, crypto_utils):
        """Test digital signature verification with invalid signature."""
        test_data = "test data"
        invalid_signature = "invalid-signature-data"
        
        is_valid = crypto_utils.verify_digital_signature(test_data, invalid_signature)
        assert is_valid is False


class TestBusinessDataManipulation:
    """
    Comprehensive tests for business data manipulation utilities.
    
    Tests data cleaning, transformation, merging, flattening, and filtering
    operations with comprehensive error handling and edge case validation
    per Section 5.2.4 business logic requirements.
    """
    
    def test_clean_data_dict_comprehensive(self):
        """Test comprehensive data cleaning for dictionary structures."""
        dirty_data = {
            'name': '  John Doe  ',
            'email': '',
            'age': '25',
            'notes': None,
            'tags': [],
            'active': 'true',
            'score': '89.5',
            'nested': {
                'address': '  123 Main St  ',
                'city': '',
                'phone': None
            }
        }
        
        cleaned = clean_data(
            dirty_data,
            remove_empty=True,
            remove_none=True,
            strip_strings=True,
            convert_types=True
        )
        
        # Verify string processing
        assert cleaned['name'] == 'John Doe'
        assert 'email' not in cleaned  # Empty string removed
        assert 'notes' not in cleaned  # None removed
        assert 'tags' not in cleaned  # Empty list removed
        
        # Verify type conversion
        assert cleaned['age'] == 25
        assert isinstance(cleaned['age'], int)
        assert cleaned['score'] == 89.5
        assert isinstance(cleaned['score'], float)
        
        # Verify nested cleaning
        assert cleaned['nested']['address'] == '123 Main St'
        assert 'city' not in cleaned['nested']
        assert 'phone' not in cleaned['nested']
    
    def test_clean_data_list_processing(self):
        """Test data cleaning for list structures."""
        dirty_list = [
            '  item1  ',
            '',
            None,
            '42',
            '3.14',
            {
                'key': '  value  ',
                'empty': '',
                'number': '100'
            }
        ]
        
        cleaned = clean_data(
            dirty_list,
            remove_empty=True,
            remove_none=True,
            strip_strings=True,
            convert_types=True
        )
        
        assert cleaned[0] == 'item1'
        assert cleaned[1] == 42
        assert cleaned[2] == 3.14
        assert cleaned[3]['key'] == 'value'
        assert 'empty' not in cleaned[3]
        assert cleaned[3]['number'] == 100
    
    def test_clean_data_preserve_options(self):
        """Test data cleaning with preservation options."""
        test_data = {
            'name': '  preserve  ',
            'empty': '',
            'none_value': None
        }
        
        # Test preserving empty and None values
        preserved = clean_data(
            test_data,
            remove_empty=False,
            remove_none=False,
            strip_strings=False,
            convert_types=False
        )
        
        assert preserved['name'] == '  preserve  '  # Not stripped
        assert preserved['empty'] == ''  # Empty preserved
        assert preserved['none_value'] is None  # None preserved
    
    def test_clean_data_invalid_type(self):
        """Test data cleaning with invalid input type."""
        invalid_inputs = [
            "string",
            123,
            None,
            set([1, 2, 3])
        ]
        
        for invalid_input in invalid_inputs:
            with pytest.raises(DataProcessingError):
                clean_data(invalid_input)
    
    def test_transform_data_field_mapping(self):
        """Test data transformation with field mapping."""
        source_data = {
            'firstName': 'John',
            'lastName': 'Doe',
            'emailAddress': 'john@example.com',
            'birthYear': '1990'
        }
        
        field_mapping = {
            'firstName': 'first_name',
            'lastName': 'last_name',
            'emailAddress': 'email',
            'birthYear': 'birth_year'
        }
        
        transformed = transform_data(source_data, field_mapping)
        
        assert transformed['first_name'] == 'John'
        assert transformed['last_name'] == 'Doe'
        assert transformed['email'] == 'john@example.com'
        assert transformed['birth_year'] == '1990'
        
        # Original keys should not exist
        assert 'firstName' not in transformed
        assert 'lastName' not in transformed
    
    def test_transform_data_with_transformers(self):
        """Test data transformation with custom transformer functions."""
        source_data = {
            'name': 'john doe',
            'age': '30',
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
        
        transformed = transform_data(
            source_data, 
            field_mapping, 
            transformers=transformers
        )
        
        assert transformed['full_name'] == 'John Doe'
        assert transformed['age_years'] == 30
        assert isinstance(transformed['age_years'], int)
        assert transformed['annual_salary'] == decimal.Decimal('50000.00')
    
    def test_transform_data_transformer_error(self):
        """Test data transformation with transformer function error."""
        source_data = {'number': 'not-a-number'}
        field_mapping = {'number': 'converted_number'}
        transformers = {'converted_number': lambda x: int(x)}  # Will fail
        
        with pytest.raises(DataProcessingError) as exc_info:
            transform_data(source_data, field_mapping, transformers=transformers)
        
        assert "transformation failed" in str(exc_info.value).lower()
    
    def test_merge_data_override_strategy(self):
        """Test data merging with override strategy."""
        base_data = {
            'name': 'John',
            'age': 25,
            'config': {
                'theme': 'light',
                'lang': 'en'
            }
        }
        
        update_data = {
            'age': 26,
            'city': 'New York',
            'config': {
                'theme': 'dark',
                'notifications': True
            }
        }
        
        merged = merge_data(
            base_data, 
            update_data, 
            merge_strategy="override",
            deep_merge=True
        )
        
        assert merged['name'] == 'John'  # From base
        assert merged['age'] == 26  # Overridden
        assert merged['city'] == 'New York'  # Added
        assert merged['config']['theme'] == 'dark'  # Overridden
        assert merged['config']['lang'] == 'en'  # Preserved from base
        assert merged['config']['notifications'] is True  # Added
    
    def test_merge_data_preserve_strategy(self):
        """Test data merging with preserve strategy."""
        base_data = {'name': 'John', 'age': 25}
        update_data = {'name': 'Jane', 'city': 'Boston'}
        
        merged = merge_data(
            base_data, 
            update_data, 
            merge_strategy="preserve"
        )
        
        assert merged['name'] == 'John'  # Preserved from base
        assert merged['age'] == 25
        assert merged['city'] == 'Boston'  # Added from update
    
    def test_merge_data_combine_strategy(self):
        """Test data merging with combine strategy."""
        base_data = {
            'tags': ['python', 'flask'],
            'config': {'debug': True}
        }
        
        update_data = {
            'tags': ['testing', 'pytest'],
            'config': {'verbose': True}
        }
        
        merged = merge_data(
            base_data, 
            update_data, 
            merge_strategy="combine"
        )
        
        assert merged['tags'] == ['python', 'flask', 'testing', 'pytest']
        assert merged['config']['debug'] is True
        assert merged['config']['verbose'] is True
    
    def test_flatten_data_nested_structure(self):
        """Test data flattening with deeply nested structures."""
        nested_data = {
            'user': {
                'profile': {
                    'personal': {
                        'name': 'John Doe',
                        'age': 30
                    },
                    'contact': {
                        'email': 'john@example.com'
                    }
                },
                'preferences': {
                    'theme': 'dark',
                    'notifications': True
                }
            },
            'metadata': {
                'created': '2024-01-15',
                'version': '1.0'
            }
        }
        
        flattened = flatten_data(nested_data)
        
        assert flattened['user.profile.personal.name'] == 'John Doe'
        assert flattened['user.profile.personal.age'] == 30
        assert flattened['user.profile.contact.email'] == 'john@example.com'
        assert flattened['user.preferences.theme'] == 'dark'
        assert flattened['user.preferences.notifications'] is True
        assert flattened['metadata.created'] == '2024-01-15'
        assert flattened['metadata.version'] == '1.0'
    
    def test_flatten_data_custom_separator(self):
        """Test data flattening with custom separator."""
        nested_data = {
            'level1': {
                'level2': {
                    'value': 'test'
                }
            }
        }
        
        flattened = flatten_data(nested_data, separator="__")
        
        assert flattened['level1__level2__value'] == 'test'
    
    def test_flatten_data_max_depth(self):
        """Test data flattening with maximum depth limit."""
        deep_data = {
            'a': {
                'b': {
                    'c': {
                        'd': {
                            'value': 'deep'
                        }
                    }
                }
            }
        }
        
        flattened = flatten_data(deep_data, max_depth=2)
        
        # Should flatten only 2 levels deep
        assert 'a.b.c' in flattened
        assert isinstance(flattened['a.b.c'], dict)
        assert flattened['a.b.c']['d']['value'] == 'deep'
    
    def test_filter_data_list_all_mode(self):
        """Test data filtering on list with 'all' match mode."""
        users = [
            {'name': 'John', 'age': 30, 'active': True, 'role': 'admin'},
            {'name': 'Jane', 'age': 25, 'active': True, 'role': 'user'},
            {'name': 'Bob', 'age': 35, 'active': False, 'role': 'admin'},
            {'name': 'Alice', 'age': 28, 'active': True, 'role': 'admin'}
        ]
        
        # Filter for active admin users
        filtered = filter_data(
            users,
            criteria={'active': True, 'role': 'admin'},
            match_mode="all"
        )
        
        assert len(filtered) == 2
        assert all(user['active'] is True for user in filtered)
        assert all(user['role'] == 'admin' for user in filtered)
        assert filtered[0]['name'] == 'John'
        assert filtered[1]['name'] == 'Alice'
    
    def test_filter_data_list_any_mode(self):
        """Test data filtering on list with 'any' match mode."""
        items = [
            {'category': 'tech', 'priority': 'high', 'status': 'active'},
            {'category': 'business', 'priority': 'low', 'status': 'active'},
            {'category': 'tech', 'priority': 'medium', 'status': 'inactive'},
            {'category': 'design', 'priority': 'high', 'status': 'pending'}
        ]
        
        # Filter for items that are either high priority OR tech category
        filtered = filter_data(
            items,
            criteria={'category': 'tech', 'priority': 'high'},
            match_mode="any"
        )
        
        assert len(filtered) == 3  # 2 tech items + 1 high priority design item
    
    def test_filter_data_string_matching(self):
        """Test data filtering with string pattern matching."""
        products = [
            {'name': 'iPhone 15 Pro', 'brand': 'Apple'},
            {'name': 'Galaxy S24', 'brand': 'Samsung'},
            {'name': 'iPhone 14', 'brand': 'Apple'},
            {'name': 'Pixel 8', 'brand': 'Google'}
        ]
        
        # Filter for products with 'iPhone' in name
        filtered = filter_data(
            products,
            criteria={'name': 'iPhone'},
            match_mode="all"
        )
        
        assert len(filtered) == 2
        assert all('iPhone' in product['name'] for product in filtered)
    
    def test_filter_data_single_dict(self):
        """Test data filtering on single dictionary."""
        user_data = {'name': 'John', 'age': 30, 'active': True}
        
        # Matching criteria
        result = filter_data(
            user_data,
            criteria={'active': True},
            match_mode="all"
        )
        
        assert result == user_data
        
        # Non-matching criteria
        result = filter_data(
            user_data,
            criteria={'active': False},
            match_mode="all"
        )
        
        assert result == {}


class TestBusinessDateTimeProcessing:
    """
    Comprehensive tests for business date/time processing utilities.
    
    Tests date parsing, formatting, calculations, and business day operations
    using python-dateutil 2.8+ equivalent to Node.js moment functionality
    per Section 5.2.4 business logic requirements.
    """
    
    def test_parse_date_iso_format(self):
        """Test date parsing with ISO 8601 formats."""
        iso_dates = [
            "2024-01-15T10:30:00Z",
            "2024-01-15T10:30:00+05:00",
            "2024-01-15T10:30:00.123Z",
            "2024-01-15"
        ]
        
        for date_string in iso_dates:
            result = parse_date(date_string)
            assert isinstance(result, datetime)
            assert result.year == 2024
            assert result.month == 1
            assert result.day == 15
    
    def test_parse_date_with_timezone_conversion(self):
        """Test date parsing with timezone conversion."""
        date_string = "2024-01-15T10:30:00"
        target_timezone = "America/New_York"
        
        result = parse_date(date_string, timezone_info=target_timezone)
        
        assert isinstance(result, datetime)
        assert result.tzinfo is not None
        assert str(result.tzinfo) != "UTC"
    
    def test_parse_date_with_format_hint(self):
        """Test date parsing with specific format hint."""
        date_string = "15/01/2024"
        format_hint = "%d/%m/%Y"
        
        result = parse_date(date_string, format_hint=format_hint)
        
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 15
    
    def test_parse_date_invalid_format(self):
        """Test date parsing with invalid formats."""
        invalid_dates = [
            "not-a-date",
            "2024/13/45",
            "",
            None
        ]
        
        for invalid_date in invalid_dates:
            with pytest.raises(DataValidationError):
                parse_date(invalid_date)
    
    def test_format_date_iso_output(self):
        """Test date formatting to ISO 8601 format."""
        dt = datetime(2024, 1, 15, 10, 30, 45, tzinfo=timezone.utc)
        
        result = format_date(dt, format_type="iso")
        
        assert result == "2024-01-15T10:30:45+00:00"
    
    def test_format_date_various_formats(self):
        """Test date formatting with various output formats."""
        dt = datetime(2024, 1, 15, 10, 30, 45, tzinfo=timezone.utc)
        
        formats_expected = {
            "date": "2024-01-15",
            "time": "10:30:45",
            "datetime": "2024-01-15 10:30:45",
            "timestamp": "1705316645",
            "human": "January 15, 2024 at 10:30 AM"
        }
        
        for format_type, expected in formats_expected.items():
            result = format_date(dt, format_type=format_type)
            assert result == expected
    
    def test_format_date_with_timezone_conversion(self):
        """Test date formatting with timezone conversion."""
        dt = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        
        # Convert to Eastern Time (UTC-5 in winter)
        result = format_date(
            dt, 
            format_type="datetime", 
            timezone_info="America/New_York"
        )
        
        # Should show 05:30 (10:30 UTC - 5 hours)
        assert "05:30" in result
    
    def test_calculate_date_difference_days(self):
        """Test date difference calculation in days."""
        start_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
        end_date = datetime(2024, 1, 15, tzinfo=timezone.utc)
        
        difference = calculate_date_difference(start_date, end_date, unit="days")
        
        assert difference == 14.0
    
    def test_calculate_date_difference_various_units(self):
        """Test date difference calculation in various units."""
        start_date = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        end_date = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)  # 12 hours later
        
        units_expected = {
            "seconds": 43200.0,  # 12 * 60 * 60
            "minutes": 720.0,    # 12 * 60
            "hours": 12.0,
            "days": 0.5
        }
        
        for unit, expected in units_expected.items():
            result = calculate_date_difference(start_date, end_date, unit=unit)
            assert abs(result - expected) < 0.001  # Allow for small floating point differences
    
    def test_calculate_date_difference_months_years(self):
        """Test date difference calculation in months and years."""
        start_date = datetime(2022, 1, 15, tzinfo=timezone.utc)
        end_date = datetime(2024, 1, 15, tzinfo=timezone.utc)  # Exactly 2 years
        
        years_diff = calculate_date_difference(start_date, end_date, unit="years")
        months_diff = calculate_date_difference(start_date, end_date, unit="months")
        
        assert abs(years_diff - 2.0) < 0.1
        assert abs(months_diff - 24.0) < 1.0
    
    def test_get_business_days_exclude_weekends(self):
        """Test business days calculation excluding weekends."""
        # Start on Monday, end on Friday (same week)
        start_date = datetime(2024, 1, 15, tzinfo=timezone.utc)  # Monday
        end_date = datetime(2024, 1, 19, tzinfo=timezone.utc)    # Friday
        
        business_days = get_business_days(
            start_date, 
            end_date, 
            exclude_weekends=True
        )
        
        assert business_days == 5  # Monday through Friday
    
    def test_get_business_days_with_holidays(self):
        """Test business days calculation with holidays."""
        start_date = datetime(2024, 1, 15, tzinfo=timezone.utc)  # Monday
        end_date = datetime(2024, 1, 19, tzinfo=timezone.utc)    # Friday
        
        # Add holiday on Wednesday
        holidays = [datetime(2024, 1, 17, tzinfo=timezone.utc)]
        
        business_days = get_business_days(
            start_date, 
            end_date, 
            exclude_weekends=True,
            holidays=holidays
        )
        
        assert business_days == 4  # Monday, Tuesday, Thursday, Friday
    
    def test_get_business_days_include_weekends(self):
        """Test business days calculation including weekends."""
        start_date = datetime(2024, 1, 15, tzinfo=timezone.utc)  # Monday
        end_date = datetime(2024, 1, 21, tzinfo=timezone.utc)    # Sunday
        
        business_days = get_business_days(
            start_date, 
            end_date, 
            exclude_weekends=False
        )
        
        assert business_days == 7  # All 7 days counted
    
    def test_convert_timezone_utc_to_local(self):
        """Test timezone conversion from UTC to local timezone."""
        utc_time = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        target_timezone = "America/New_York"
        
        converted = convert_timezone(utc_time, target_timezone)
        
        assert converted.hour == 7  # UTC-5 in winter
        assert converted.tzinfo is not None
    
    def test_convert_timezone_naive_datetime(self):
        """Test timezone conversion with naive datetime."""
        naive_time = datetime(2024, 1, 15, 12, 0, 0)
        target_timezone = "America/Los_Angeles"
        source_timezone = "UTC"
        
        converted = convert_timezone(
            naive_time, 
            target_timezone,
            source_timezone=source_timezone
        )
        
        assert converted.hour == 4  # UTC-8 in winter
        assert converted.tzinfo is not None


class TestBusinessCalculations:
    """
    Comprehensive tests for business calculation utilities.
    
    Tests percentage calculations, discount applications, tax calculations,
    currency rounding, and validation with proper decimal precision handling
    per Section 5.2.4 business logic requirements.
    """
    
    def test_calculate_percentage_basic(self):
        """Test basic percentage calculation."""
        result = calculate_percentage(25, 100)
        
        assert result == decimal.Decimal('25.00')
        assert isinstance(result, decimal.Decimal)
    
    def test_calculate_percentage_precision(self):
        """Test percentage calculation with custom precision."""
        result = calculate_percentage(1, 3, precision=4)
        
        expected = decimal.Decimal('33.3333')
        assert result == expected
    
    def test_calculate_percentage_zero_total(self):
        """Test percentage calculation with zero total."""
        with pytest.raises(BusinessRuleViolationError) as exc_info:
            calculate_percentage(50, 0)
        
        assert "division by zero" in str(exc_info.value).lower()
    
    def test_calculate_percentage_negative_values(self):
        """Test percentage calculation with negative values."""
        with pytest.raises(BusinessRuleViolationError):
            calculate_percentage(-10, 100)
        
        with pytest.raises(BusinessRuleViolationError):
            calculate_percentage(10, -100)
    
    def test_apply_discount_percentage(self):
        """Test discount application with percentage discount."""
        original_amount = decimal.Decimal('100.00')
        discount_rate = 15  # 15%
        
        result = apply_discount(original_amount, discount_rate, "percentage")
        
        expected = decimal.Decimal('85.00')
        assert result == expected
    
    def test_apply_discount_fixed_amount(self):
        """Test discount application with fixed amount discount."""
        original_amount = decimal.Decimal('100.00')
        discount_amount = decimal.Decimal('25.00')
        
        result = apply_discount(original_amount, discount_amount, "fixed")
        
        expected = decimal.Decimal('75.00')
        assert result == expected
    
    def test_apply_discount_with_maximum(self):
        """Test discount application with maximum discount limit."""
        original_amount = decimal.Decimal('100.00')
        discount_rate = 30  # 30% = $30
        max_discount = decimal.Decimal('20.00')
        
        result = apply_discount(
            original_amount, 
            discount_rate, 
            "percentage",
            max_discount=max_discount
        )
        
        expected = decimal.Decimal('80.00')  # $100 - $20 (capped)
        assert result == expected
    
    def test_apply_discount_exceeds_amount(self):
        """Test discount application that exceeds original amount."""
        original_amount = decimal.Decimal('50.00')
        discount_amount = decimal.Decimal('75.00')  # More than original
        
        result = apply_discount(original_amount, discount_amount, "fixed")
        
        assert result == decimal.Decimal('0.00')  # Cannot be negative
    
    def test_apply_discount_invalid_percentage(self):
        """Test discount application with invalid percentage."""
        original_amount = decimal.Decimal('100.00')
        
        with pytest.raises(BusinessRuleViolationError):
            apply_discount(original_amount, 150, "percentage")  # >100%
    
    def test_calculate_tax_exclusive(self):
        """Test tax calculation with exclusive tax."""
        amount = decimal.Decimal('100.00')
        tax_rate = decimal.Decimal('8.5')  # 8.5%
        
        tax_amount, total_amount = calculate_tax(amount, tax_rate, "exclusive")
        
        assert tax_amount == decimal.Decimal('8.50')
        assert total_amount == decimal.Decimal('108.50')
    
    def test_calculate_tax_inclusive(self):
        """Test tax calculation with inclusive tax."""
        amount = decimal.Decimal('108.50')  # Includes tax
        tax_rate = decimal.Decimal('8.5')   # 8.5%
        
        tax_amount, net_amount = calculate_tax(amount, tax_rate, "inclusive")
        
        # Tax amount should be approximately 8.50
        assert abs(tax_amount - decimal.Decimal('8.50')) < decimal.Decimal('0.01')
        # Net amount should be approximately 100.00
        assert abs(net_amount - decimal.Decimal('100.00')) < decimal.Decimal('0.01')
    
    def test_calculate_tax_zero_rate(self):
        """Test tax calculation with zero tax rate."""
        amount = decimal.Decimal('100.00')
        
        tax_amount, total_amount = calculate_tax(amount, 0, "exclusive")
        
        assert tax_amount == decimal.Decimal('0.00')
        assert total_amount == decimal.Decimal('100.00')
    
    def test_calculate_tax_invalid_rate(self):
        """Test tax calculation with invalid tax rate."""
        amount = decimal.Decimal('100.00')
        
        with pytest.raises(BusinessRuleViolationError):
            calculate_tax(amount, -5, "exclusive")  # Negative rate
        
        with pytest.raises(BusinessRuleViolationError):
            calculate_tax(amount, 150, "exclusive")  # >100% rate
    
    def test_round_currency_usd(self):
        """Test currency rounding for USD (2 decimal places)."""
        amount = decimal.Decimal('123.456')
        
        result = round_currency(amount, "USD")
        
        assert result == decimal.Decimal('123.46')
    
    def test_round_currency_jpy(self):
        """Test currency rounding for JPY (no decimal places)."""
        amount = decimal.Decimal('123.456')
        
        result = round_currency(amount, "JPY")
        
        assert result == decimal.Decimal('123')
    
    def test_round_currency_bhd(self):
        """Test currency rounding for BHD (3 decimal places)."""
        amount = decimal.Decimal('123.4567')
        
        result = round_currency(amount, "BHD")
        
        assert result == decimal.Decimal('123.457')
    
    def test_round_currency_custom_rounding(self):
        """Test currency rounding with custom rounding mode."""
        amount = decimal.Decimal('123.455')
        
        # Test different rounding modes
        result_up = round_currency(amount, "USD", "ROUND_UP")
        result_down = round_currency(amount, "USD", "ROUND_DOWN")
        
        assert result_up == decimal.Decimal('123.46')
        assert result_down == decimal.Decimal('123.45')
    
    def test_validate_currency_valid_amounts(self):
        """Test currency validation with valid amounts."""
        valid_amounts = [
            decimal.Decimal('99.99'),
            decimal.Decimal('0.01'),
            decimal.Decimal('1000.00')
        ]
        
        for amount in valid_amounts:
            result = validate_currency(amount, "USD")
            assert result is True
    
    def test_validate_currency_with_range(self):
        """Test currency validation with amount range."""
        amount = decimal.Decimal('50.00')
        
        # Valid range
        result = validate_currency(
            amount, 
            "USD",
            min_amount=decimal.Decimal('1.00'),
            max_amount=decimal.Decimal('100.00')
        )
        assert result is True
        
        # Below minimum
        with pytest.raises(BusinessRuleViolationError):
            validate_currency(
                decimal.Decimal('0.50'),
                "USD", 
                min_amount=decimal.Decimal('1.00')
            )
        
        # Above maximum
        with pytest.raises(BusinessRuleViolationError):
            validate_currency(
                decimal.Decimal('150.00'),
                "USD",
                max_amount=decimal.Decimal('100.00')
            )
    
    def test_validate_currency_precision(self):
        """Test currency validation with precision checking."""
        # Valid precision for USD (2 decimal places)
        valid_amount = decimal.Decimal('99.99')
        result = validate_currency(valid_amount, "USD")
        assert result is True
        
        # Invalid precision for USD (3 decimal places)
        with pytest.raises(BusinessRuleViolationError):
            validate_currency(decimal.Decimal('99.999'), "USD")
        
        # Valid precision for JPY (no decimal places)
        valid_jpy = decimal.Decimal('1000')
        result = validate_currency(valid_jpy, "JPY")
        assert result is True
        
        # Invalid precision for JPY (with decimal places)
        with pytest.raises(BusinessRuleViolationError):
            validate_currency(decimal.Decimal('1000.50'), "JPY")
    
    def test_validate_currency_negative_amount(self):
        """Test currency validation with negative amounts."""
        with pytest.raises(BusinessRuleViolationError):
            validate_currency(decimal.Decimal('-50.00'), "USD")


class TestTypeConversionUtilities:
    """
    Comprehensive tests for type conversion utilities.
    
    Tests safe type conversions for integers, floats, strings, booleans,
    and JSON parsing with comprehensive error handling and validation
    per Section 5.2.4 business logic requirements.
    """
    
    def test_safe_int_valid_conversions(self):
        """Test safe integer conversion with valid inputs."""
        test_cases = [
            ("123", 123),
            (123, 123),
            (123.0, 123),
            ("  456  ", 456),
            (decimal.Decimal('789'), 789)
        ]
        
        for input_value, expected in test_cases:
            result = safe_int(input_value)
            assert result == expected
            assert isinstance(result, int)
    
    def test_safe_int_with_range_validation(self):
        """Test safe integer conversion with range validation."""
        # Valid range
        result = safe_int("50", min_value=1, max_value=100)
        assert result == 50
        
        # Below minimum
        with pytest.raises(DataValidationError):
            safe_int("0", min_value=1, max_value=100)
        
        # Above maximum
        with pytest.raises(DataValidationError):
            safe_int("150", min_value=1, max_value=100)
    
    def test_safe_int_invalid_with_default(self):
        """Test safe integer conversion with invalid input and default."""
        invalid_inputs = [
            "not-a-number",
            "",
            None,
            "123.45",  # Float string
            []
        ]
        
        for invalid_input in invalid_inputs:
            result = safe_int(invalid_input, default=0)
            assert result == 0
    
    def test_safe_int_invalid_without_default(self):
        """Test safe integer conversion with invalid input and no default."""
        with pytest.raises(DataValidationError):
            safe_int("not-a-number")
    
    def test_safe_float_valid_conversions(self):
        """Test safe float conversion with valid inputs."""
        test_cases = [
            ("123.45", 123.45),
            (123.45, 123.45),
            (123, 123.0),
            ("  456.78  ", 456.78),
            (decimal.Decimal('789.12'), 789.12)
        ]
        
        for input_value, expected in test_cases:
            result = safe_float(input_value)
            assert abs(result - expected) < 0.0001
            assert isinstance(result, float)
    
    def test_safe_float_with_precision(self):
        """Test safe float conversion with precision control."""
        result = safe_float("123.456789", precision=2)
        assert result == 123.46
    
    def test_safe_float_with_range_validation(self):
        """Test safe float conversion with range validation."""
        # Valid range
        result = safe_float("50.5", min_value=1.0, max_value=100.0)
        assert result == 50.5
        
        # Below minimum
        with pytest.raises(DataValidationError):
            safe_float("0.5", min_value=1.0)
        
        # Above maximum  
        with pytest.raises(DataValidationError):
            safe_float("150.5", max_value=100.0)
    
    def test_safe_float_infinity_and_nan(self):
        """Test safe float conversion with infinity and NaN."""
        # Test infinity
        result = safe_float("inf", default=0.0)
        assert result == 0.0  # Should return default for non-finite
        
        # Test NaN
        result = safe_float("nan", default=0.0)
        assert result == 0.0  # Should return default for non-finite
    
    def test_safe_str_valid_conversions(self):
        """Test safe string conversion with valid inputs."""
        test_cases = [
            ("hello", "hello"),
            (123, "123"),
            (123.45, "123.45"),
            (True, "True"),
            ("  spaces  ", "spaces")  # With strip
        ]
        
        for input_value, expected in test_cases:
            result = safe_str(input_value, strip_whitespace=True)
            assert result == expected
            assert isinstance(result, str)
    
    def test_safe_str_with_length_limit(self):
        """Test safe string conversion with length validation."""
        # Valid length
        result = safe_str("hello", max_length=10)
        assert result == "hello"
        
        # Exceeds length
        with pytest.raises(DataValidationError):
            safe_str("very long string", max_length=5)
    
    def test_safe_str_whitespace_handling(self):
        """Test safe string conversion with whitespace handling."""
        # With stripping
        result = safe_str("  hello world  ", strip_whitespace=True)
        assert result == "hello world"
        
        # Without stripping
        result = safe_str("  hello world  ", strip_whitespace=False)
        assert result == "  hello world  "
    
    def test_safe_str_none_with_default(self):
        """Test safe string conversion with None input and default."""
        result = safe_str(None, default="default_value")
        assert result == "default_value"
    
    def test_normalize_boolean_true_values(self):
        """Test boolean normalization with true values."""
        true_values = [
            True,
            "true",
            "TRUE",
            "yes",
            "y",
            "on",
            "1",
            1,
            "enable",
            "enabled",
            "active"
        ]
        
        for value in true_values:
            result = normalize_boolean(value)
            assert result is True
    
    def test_normalize_boolean_false_values(self):
        """Test boolean normalization with false values."""
        false_values = [
            False,
            "false",
            "FALSE",
            "no",
            "n",
            "off",
            "0",
            0,
            "disable",
            "disabled",
            "inactive"
        ]
        
        for value in false_values:
            result = normalize_boolean(value)
            assert result is False
    
    def test_normalize_boolean_ambiguous_with_default(self):
        """Test boolean normalization with ambiguous values."""
        ambiguous_values = [
            "maybe",
            "unknown",
            "",
            "random_string"
        ]
        
        for value in ambiguous_values:
            result = normalize_boolean(value, default=None)
            assert result is None
    
    def test_normalize_boolean_numeric_values(self):
        """Test boolean normalization with numeric values."""
        assert normalize_boolean(1) is True
        assert normalize_boolean(0) is False
        assert normalize_boolean(42) is True  # Non-zero
        assert normalize_boolean(-1) is True  # Non-zero
    
    def test_parse_json_valid(self):
        """Test JSON parsing with valid JSON strings."""
        test_cases = [
            ('{"name": "John", "age": 30}', {"name": "John", "age": 30}),
            ('{"items": [1, 2, 3]}', {"items": [1, 2, 3]}),
            ('{}', {}),
            ('{"nested": {"key": "value"}}', {"nested": {"key": "value"}})
        ]
        
        for json_string, expected in test_cases:
            result = parse_json(json_string)
            assert result == expected
    
    def test_parse_json_invalid_with_default(self):
        """Test JSON parsing with invalid JSON and default."""
        invalid_json = [
            "not json",
            "{invalid: json}",
            "",
            "{'single': 'quotes'}"  # Python dict format, not JSON
        ]
        
        for invalid in invalid_json:
            result = parse_json(invalid, default={})
            assert result == {}
    
    def test_parse_json_invalid_without_default(self):
        """Test JSON parsing with invalid JSON and no default."""
        with pytest.raises(DataValidationError):
            parse_json("invalid json")
    
    def test_parse_json_security_limits(self):
        """Test JSON parsing with security limits."""
        # Test excessive nesting
        deeply_nested = '{"a": ' * 150 + '{}' + '}' * 150
        result = parse_json(deeply_nested, default={})
        assert result == {}
        
        # Test large size
        large_json = '{"data": "' + 'x' * 2000000 + '"}'  # > 1MB
        result = parse_json(large_json, default={})
        assert result == {}
    
    def test_parse_json_non_object_with_default(self):
        """Test JSON parsing with non-object JSON and default."""
        non_object_json = [
            '[1, 2, 3]',  # Array
            '"string"',   # String
            '123',        # Number
            'true'        # Boolean
        ]
        
        for json_string in non_object_json:
            result = parse_json(json_string, default={})
            assert result == {}  # Should return default for non-objects


class TestUtilityHelperFunctions:
    """
    Comprehensive tests for utility helper functions.
    
    Tests unique ID generation, hash calculation, and other common
    utility functions with comprehensive validation and error handling
    per Section 5.2.4 business logic requirements.
    """
    
    def test_generate_unique_id_default(self):
        """Test unique ID generation with default parameters."""
        id1 = generate_unique_id()
        id2 = generate_unique_id()
        
        assert isinstance(id1, str)
        assert isinstance(id2, str)
        assert len(id1) == 8  # Default length
        assert id1 != id2  # Should be unique
        assert id1.isalnum()  # Should be alphanumeric
    
    def test_generate_unique_id_with_prefix(self):
        """Test unique ID generation with prefix."""
        prefix = "TXN"
        id_with_prefix = generate_unique_id(prefix=prefix)
        
        assert id_with_prefix.startswith(f"{prefix}_")
        assert len(id_with_prefix) > len(prefix) + 1
    
    def test_generate_unique_id_custom_length(self):
        """Test unique ID generation with custom length."""
        lengths = [4, 12, 16, 32]
        
        for length in lengths:
            unique_id = generate_unique_id(length=length)
            assert len(unique_id) == length
            assert unique_id.isalnum()
    
    def test_generate_unique_id_with_prefix_and_length(self):
        """Test unique ID generation with both prefix and custom length."""
        prefix = "USER"
        length = 12
        
        unique_id = generate_unique_id(prefix=prefix, length=length)
        
        assert unique_id.startswith(f"{prefix}_")
        # Total length should be prefix + underscore + length
        assert len(unique_id) == len(prefix) + 1 + length
    
    def test_calculate_hash_string_data(self):
        """Test hash calculation with string data."""
        test_string = "Hello, World!"
        
        # Test different algorithms
        algorithms = ["md5", "sha1", "sha256", "sha512"]
        
        for algorithm in algorithms:
            hash_value = calculate_hash(test_string, algorithm=algorithm)
            assert isinstance(hash_value, str)
            assert len(hash_value) > 0
            assert all(c in '0123456789abcdef' for c in hash_value)  # Hex characters
            
            # Same input should produce same hash
            hash_value2 = calculate_hash(test_string, algorithm=algorithm)
            assert hash_value == hash_value2
    
    def test_calculate_hash_bytes_data(self):
        """Test hash calculation with bytes data."""
        test_bytes = b"Binary data for hashing"
        
        hash_value = calculate_hash(test_bytes, algorithm="sha256")
        
        assert isinstance(hash_value, str)
        assert len(hash_value) == 64  # SHA256 produces 64 hex characters
    
    def test_calculate_hash_dict_data(self):
        """Test hash calculation with dictionary data."""
        test_dict = {
            "user_id": "123",
            "action": "login",
            "timestamp": "2024-01-15T10:30:00Z"
        }
        
        hash_value = calculate_hash(test_dict, algorithm="sha256")
        
        assert isinstance(hash_value, str)
        assert len(hash_value) == 64
        
        # Same dict should produce same hash (deterministic JSON serialization)
        hash_value2 = calculate_hash(test_dict, algorithm="sha256")
        assert hash_value == hash_value2
        
        # Different dict should produce different hash
        different_dict = test_dict.copy()
        different_dict["user_id"] = "456"
        hash_value3 = calculate_hash(different_dict, algorithm="sha256")
        assert hash_value != hash_value3
    
    def test_calculate_hash_unsupported_algorithm(self):
        """Test hash calculation with unsupported algorithm."""
        test_data = "test data"
        
        with pytest.raises(DataProcessingError):
            calculate_hash(test_data, algorithm="unsupported_algorithm")
    
    def test_calculate_hash_algorithm_specific_lengths(self):
        """Test hash calculation produces correct lengths for algorithms."""
        test_data = "test data"
        
        expected_lengths = {
            "md5": 32,
            "sha1": 40,
            "sha256": 64,
            "sha512": 128
        }
        
        for algorithm, expected_length in expected_lengths.items():
            hash_value = calculate_hash(test_data, algorithm=algorithm)
            assert len(hash_value) == expected_length


class TestCentralizedUtilityInterfaces:
    """
    Comprehensive tests for centralized utility interfaces.
    
    Tests the centralized utility classes (DateTimeUtils, HttpUtils, etc.)
    that provide convenient access to utility functionality with comprehensive
    validation per Section 5.4.1 cross-cutting concerns.
    """
    
    def test_datetime_utils_static_methods(self):
        """Test DateTimeUtils static method access."""
        # Test parse method
        date_string = "2024-01-15T10:30:00Z"
        result = DateTimeUtils.parse(date_string)
        
        assert isinstance(result, datetime)
        assert result.year == 2024
        
        # Test now method
        now = DateTimeUtils.now()
        assert isinstance(now, datetime)
        assert now.tzinfo is not None
        
        # Test utc_now method
        utc_now = DateTimeUtils.utc_now()
        assert isinstance(utc_now, datetime)
        assert utc_now.tzinfo == timezone.utc
        
        # Test to_iso method
        dt = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        iso_string = DateTimeUtils.to_iso(dt)
        assert iso_string == "2024-01-15T10:30:00+00:00"
        
        # Test format method
        formatted = DateTimeUtils.format(dt, "%Y-%m-%d")
        assert formatted == "2024-01-15"
        
        # Test validate_range method
        start_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
        end_date = datetime(2024, 1, 15, tzinfo=timezone.utc)
        
        is_valid = DateTimeUtils.validate_range(start_date, end_date)
        assert is_valid is True
    
    def test_http_utils_client_creation(self):
        """Test HttpUtils client creation methods."""
        # Test sync client creation
        sync_client = HttpUtils.create_sync_client(
            service_name="test-service",
            base_url="https://api.example.com"
        )
        assert sync_client is not None
        
        # Test async client creation
        async_client = HttpUtils.create_async_client(
            service_name="test-async-service",
            base_url="https://api.example.com"
        )
        assert async_client is not None
        
        # Test default config creation
        config = HttpUtils.get_default_config(timeout=30, retries=5)
        assert hasattr(config, 'timeout')
        assert hasattr(config, 'retries')
    
    def test_validation_utils_methods(self):
        """Test ValidationUtils convenience methods."""
        # Test email validation
        result = ValidationUtils.email("test@example.com")
        assert result is not None
        
        # Test URL validation
        result = ValidationUtils.url("https://example.com")
        assert result is not None
        
        # Test phone validation
        result = ValidationUtils.phone("+1-555-123-4567")
        assert result is not None
        
        # Test UUID validation
        test_uuid = "123e4567-e89b-12d3-a456-426614174000"
        result = ValidationUtils.uuid_string(test_uuid)
        assert result is not None
        
        # Test numeric validation
        result = ValidationUtils.numeric(42, min_value=0, max_value=100)
        assert result is True
        
        # Test input sanitization
        result = ValidationUtils.sanitize_input_data("<script>alert('xss')</script>Safe text")
        assert "script" not in result.lower()
        assert "safe text" in result.lower()
    
    def test_sanitization_utils_methods(self):
        """Test SanitizationUtils convenience methods."""
        # Test HTML sanitization
        html_content = "<p>Safe content</p><script>alert('xss')</script>"
        result = SanitizationUtils.html(html_content)
        assert "<p>Safe content</p>" in result
        assert "script" not in result
        
        # Test text sanitization
        text_content = "<b>Bold text</b> with HTML"
        result = SanitizationUtils.text(text_content)
        assert "Bold text with HTML" in result
        assert "<b>" not in result
        
        # Test email sanitization
        result = SanitizationUtils.email_address("  USER@EXAMPLE.COM  ")
        assert result == "user@example.com"
        
        # Test URL sanitization
        result = SanitizationUtils.url_address("https://example.com/path")
        assert result == "https://example.com/path"
        
        # Test filename sanitization
        result = SanitizationUtils.filename("test file!@#$%^&*().txt")
        assert "test" in result
        assert ".txt" in result
        assert "!@#$%^&*()" not in result
    
    def test_response_utils_methods(self):
        """Test ResponseUtils convenience methods."""
        # Test success response
        response, status_code = ResponseUtils.success(
            data={"message": "Success"},
            message="Operation completed"
        )
        assert response['success'] is True
        assert status_code == 200
        assert response['data']['message'] == "Success"
        
        # Test error response
        response, status_code = ResponseUtils.error(
            message="Something went wrong",
            error_code="VALIDATION_ERROR"
        )
        assert response['success'] is False
        assert status_code == 400
        assert response['message'] == "Something went wrong"
        
        # Test validation error response
        response, status_code = ResponseUtils.validation_error(
            errors=["Field is required", "Invalid format"]
        )
        assert response['success'] is False
        assert status_code == 400
        assert len(response['errors']) == 2
        
        # Test not found response
        response, status_code = ResponseUtils.not_found(
            resource="User",
            resource_id="123"
        )
        assert response['success'] is False
        assert status_code == 404
        
        # Test paginated response
        test_data = [{"id": 1}, {"id": 2}, {"id": 3}]
        response, status_code = ResponseUtils.paginated(
            data=test_data,
            page=1,
            page_size=10,
            total_count=3
        )
        assert response['success'] is True
        assert status_code == 200
        assert len(response['data']) == 3
        assert response['pagination']['page'] == 1
        
        # Test created response
        response, status_code = ResponseUtils.created(
            data={"id": "new-resource-123"},
            resource_id="new-resource-123"
        )
        assert response['success'] is True
        assert status_code == 201
        assert response['data']['id'] == "new-resource-123"


class TestAuthenticationDecorators:
    """
    Comprehensive tests for authentication decorators and middleware.
    
    Tests JWT token validation decorators, permission checking, and user
    context management with Flask integration per Section 6.4.1 authentication
    framework requirements.
    """
    
    @pytest.fixture
    def app_with_auth(self, app):
        """Create Flask app with authentication configuration."""
        with app.app_context():
            # Mock JWT manager
            with patch('src.auth.utils.jwt_manager') as mock_jwt_manager:
                mock_jwt_manager.validate_token.return_value = {
                    'sub': 'test-user-123',
                    'permissions': ['read:documents', 'write:documents'],
                    'type': 'access_token',
                    'jti': 'token-id-123'
                }
                yield app, mock_jwt_manager
    
    def test_require_valid_token_success(self, app_with_auth):
        """Test successful JWT token validation decorator."""
        app, mock_jwt_manager = app_with_auth
        
        @require_valid_token(['read:documents'])
        def protected_endpoint():
            return {"message": "Success", "user_id": get_current_user_id()}
        
        with app.test_request_context(
            '/', 
            headers={'Authorization': 'Bearer valid-jwt-token'}
        ):
            result = protected_endpoint()
            
            assert result['message'] == "Success"
            assert result['user_id'] == 'test-user-123'
            
            # Verify JWT validation was called
            mock_jwt_manager.validate_token.assert_called_once_with('valid-jwt-token')
    
    def test_require_valid_token_missing_header(self, app_with_auth):
        """Test JWT token decorator with missing Authorization header."""
        app, mock_jwt_manager = app_with_auth
        
        @require_valid_token()
        def protected_endpoint():
            return {"message": "Success"}
        
        with app.test_request_context('/'):
            response = protected_endpoint()
            
            assert response[1] == 401  # Unauthorized
            assert 'authorization header' in response[0].get_json()['error'].lower()
    
    def test_require_valid_token_invalid_header_format(self, app_with_auth):
        """Test JWT token decorator with invalid header format."""
        app, mock_jwt_manager = app_with_auth
        
        @require_valid_token()
        def protected_endpoint():
            return {"message": "Success"}
        
        with app.test_request_context(
            '/', 
            headers={'Authorization': 'Invalid header-format'}
        ):
            response = protected_endpoint()
            
            assert response[1] == 401  # Unauthorized
    
    def test_require_valid_token_insufficient_permissions(self, app_with_auth):
        """Test JWT token decorator with insufficient permissions."""
        app, mock_jwt_manager = app_with_auth
        
        # User has 'read:documents' but endpoint requires 'admin:users'
        @require_valid_token(['admin:users'])
        def admin_endpoint():
            return {"message": "Admin access"}
        
        with app.test_request_context(
            '/', 
            headers={'Authorization': 'Bearer valid-jwt-token'}
        ):
            response = admin_endpoint()
            
            assert response[1] == 403  # Forbidden
            assert 'insufficient permissions' in response[0].get_json()['error'].lower()
    
    def test_require_valid_token_jwt_exception(self, app_with_auth):
        """Test JWT token decorator with JWT validation exception."""
        app, mock_jwt_manager = app_with_auth
        
        # Mock JWT validation failure
        mock_jwt_manager.validate_token.side_effect = JWTException("Token expired")
        
        @require_valid_token()
        def protected_endpoint():
            return {"message": "Success"}
        
        with app.test_request_context(
            '/', 
            headers={'Authorization': 'Bearer expired-token'}
        ):
            with pytest.raises(JWTException):
                protected_endpoint()
    
    def test_get_current_user_context(self, app_with_auth):
        """Test user context access functions."""
        app, mock_jwt_manager = app_with_auth
        
        @require_valid_token(['read:documents'])
        def context_endpoint():
            return {
                "user_id": get_current_user_id(),
                "permissions": get_current_user_permissions()
            }
        
        with app.test_request_context(
            '/', 
            headers={'Authorization': 'Bearer valid-jwt-token'}
        ):
            result = context_endpoint()
            
            assert result['user_id'] == 'test-user-123'
            assert 'read:documents' in result['permissions']
            assert 'write:documents' in result['permissions']
    
    def test_get_current_user_no_context(self, app):
        """Test user context access without authentication."""
        with app.app_context():
            user_id = get_current_user_id()
            permissions = get_current_user_permissions()
            
            assert user_id is None
            assert permissions == []
    
    @patch('src.auth.utils.logger')
    def test_log_security_event(self, mock_logger, app):
        """Test security event logging functionality."""
        with app.test_request_context(
            '/api/test', 
            method='POST',
            headers={'User-Agent': 'Test-Agent/1.0'},
            environ_base={'REMOTE_ADDR': '192.168.1.100'}
        ):
            log_security_event(
                event_type="authentication_failed",
                user_id="test-user",
                metadata={
                    "reason": "invalid_token",
                    "attempts": 3
                }
            )
            
            # Verify logging was called
            mock_logger.info.assert_called_once()
            log_call_args = mock_logger.info.call_args[1]
            
            assert log_call_args['event_type'] == "authentication_failed"
            assert log_call_args['user_id'] == "test-user"
            assert log_call_args['ip_address'] == "192.168.1.100"
            assert log_call_args['user_agent'] == "Test-Agent/1.0"
            assert log_call_args['endpoint'] == "test"
            assert log_call_args['method'] == "POST"
            assert log_call_args['reason'] == "invalid_token"
            assert log_call_args['attempts'] == 3


class TestPerformanceAndBaseline:
    """
    Performance validation tests ensuring ≤10% variance requirement.
    
    Tests utility function performance against baseline measurements to ensure
    compliance with migration performance requirements per Section 6.6.3
    quality metrics and Section 0.1.1 performance characteristics.
    """
    
    @pytest.fixture
    def performance_baseline(self):
        """Performance baseline measurements for comparison."""
        return {
            'jwt_token_creation_ms': 5.0,
            'jwt_token_validation_ms': 3.0,
            'data_cleaning_ms': 2.0,
            'date_parsing_ms': 1.0,
            'hash_calculation_ms': 1.5,
            'encryption_ms': 4.0,
            'decryption_ms': 4.0
        }
    
    @pytest.fixture
    def performance_threshold(self):
        """Performance variance threshold (10%)."""
        return 0.10
    
    def test_jwt_token_creation_performance(self, jwt_manager, performance_baseline, performance_threshold):
        """Test JWT token creation performance against baseline."""
        import time
        
        # Measure token creation performance
        start_time = time.perf_counter()
        
        for _ in range(100):
            jwt_manager.create_access_token(
                user_id="perf-test-user",
                permissions=["read", "write"]
            )
        
        end_time = time.perf_counter()
        avg_time_ms = ((end_time - start_time) / 100) * 1000
        
        baseline_ms = performance_baseline['jwt_token_creation_ms']
        variance = abs(avg_time_ms - baseline_ms) / baseline_ms
        
        assert variance <= performance_threshold, (
            f"JWT token creation performance variance {variance:.2%} exceeds "
            f"threshold {performance_threshold:.2%}. "
            f"Average: {avg_time_ms:.2f}ms, Baseline: {baseline_ms:.2f}ms"
        )
        
        logger.info("JWT token creation performance validated", 
                   avg_time_ms=avg_time_ms, 
                   baseline_ms=baseline_ms,
                   variance_pct=variance * 100)
    
    def test_jwt_token_validation_performance(self, jwt_manager, performance_baseline, performance_threshold):
        """Test JWT token validation performance against baseline."""
        import time
        
        # Create test token
        test_token = jwt_manager.create_access_token("perf-user")
        
        # Measure validation performance
        start_time = time.perf_counter()
        
        for _ in range(100):
            jwt_manager.validate_token(test_token)
        
        end_time = time.perf_counter()
        avg_time_ms = ((end_time - start_time) / 100) * 1000
        
        baseline_ms = performance_baseline['jwt_token_validation_ms']
        variance = abs(avg_time_ms - baseline_ms) / baseline_ms
        
        assert variance <= performance_threshold, (
            f"JWT token validation performance variance {variance:.2%} exceeds threshold"
        )
    
    def test_data_cleaning_performance(self, performance_baseline, performance_threshold):
        """Test data cleaning performance against baseline."""
        import time
        
        test_data = {
            'field1': '  value1  ',
            'field2': '',
            'field3': None,
            'field4': '123',
            'field5': '45.67',
            'nested': {
                'sub1': '  nested_value  ',
                'sub2': '',
                'sub3': '789'
            }
        }
        
        # Measure cleaning performance
        start_time = time.perf_counter()
        
        for _ in range(1000):
            clean_data(
                test_data,
                remove_empty=True,
                remove_none=True,
                strip_strings=True,
                convert_types=True
            )
        
        end_time = time.perf_counter()
        avg_time_ms = ((end_time - start_time) / 1000) * 1000
        
        baseline_ms = performance_baseline['data_cleaning_ms']
        variance = abs(avg_time_ms - baseline_ms) / baseline_ms
        
        assert variance <= performance_threshold, (
            f"Data cleaning performance variance {variance:.2%} exceeds threshold"
        )
    
    def test_date_parsing_performance(self, performance_baseline, performance_threshold):
        """Test date parsing performance against baseline."""
        import time
        
        test_dates = [
            "2024-01-15T10:30:00Z",
            "2024-01-15T10:30:00+05:00",
            "2024-01-15T10:30:00.123Z",
            "2024-01-15"
        ]
        
        # Measure parsing performance
        start_time = time.perf_counter()
        
        for _ in range(250):  # 250 * 4 dates = 1000 total
            for date_string in test_dates:
                parse_date(date_string)
        
        end_time = time.perf_counter()
        avg_time_ms = ((end_time - start_time) / 1000) * 1000
        
        baseline_ms = performance_baseline['date_parsing_ms']
        variance = abs(avg_time_ms - baseline_ms) / baseline_ms
        
        assert variance <= performance_threshold, (
            f"Date parsing performance variance {variance:.2%} exceeds threshold"
        )
    
    def test_hash_calculation_performance(self, performance_baseline, performance_threshold):
        """Test hash calculation performance against baseline."""
        import time
        
        test_data = "Performance test data for hash calculation" * 10
        
        # Measure hashing performance
        start_time = time.perf_counter()
        
        for _ in range(1000):
            calculate_hash(test_data, algorithm="sha256")
        
        end_time = time.perf_counter()
        avg_time_ms = ((end_time - start_time) / 1000) * 1000
        
        baseline_ms = performance_baseline['hash_calculation_ms']
        variance = abs(avg_time_ms - baseline_ms) / baseline_ms
        
        assert variance <= performance_threshold, (
            f"Hash calculation performance variance {variance:.2%} exceeds threshold"
        )
    
    def test_encryption_decryption_performance(self, crypto_utils, performance_baseline, performance_threshold):
        """Test encryption/decryption performance against baseline."""
        import time
        
        test_data = {
            'user_id': 'performance-test-user',
            'permissions': ['read', 'write', 'admin'],
            'metadata': {'session': 'test', 'ip': '192.168.1.1'}
        }
        
        # Measure encryption performance
        start_time = time.perf_counter()
        
        encrypted_data = []
        for _ in range(100):
            encrypted = crypto_utils.encrypt_session_data(test_data)
            encrypted_data.append(encrypted)
        
        end_time = time.perf_counter()
        encryption_avg_ms = ((end_time - start_time) / 100) * 1000
        
        # Measure decryption performance
        start_time = time.perf_counter()
        
        for encrypted in encrypted_data:
            crypto_utils.decrypt_session_data(encrypted)
        
        end_time = time.perf_counter()
        decryption_avg_ms = ((end_time - start_time) / 100) * 1000
        
        # Validate encryption performance
        encryption_baseline = performance_baseline['encryption_ms']
        encryption_variance = abs(encryption_avg_ms - encryption_baseline) / encryption_baseline
        
        assert encryption_variance <= performance_threshold, (
            f"Encryption performance variance {encryption_variance:.2%} exceeds threshold"
        )
        
        # Validate decryption performance
        decryption_baseline = performance_baseline['decryption_ms']
        decryption_variance = abs(decryption_avg_ms - decryption_baseline) / decryption_baseline
        
        assert decryption_variance <= performance_threshold, (
            f"Decryption performance variance {decryption_variance:.2%} exceeds threshold"
        )
        
        logger.info("Encryption/decryption performance validated",
                   encryption_ms=encryption_avg_ms,
                   decryption_ms=decryption_avg_ms,
                   encryption_variance_pct=encryption_variance * 100,
                   decryption_variance_pct=decryption_variance * 100)


# Performance monitoring and logging
logger.info("Utility tests module loaded successfully",
           test_classes=11,
           test_methods=150,
           coverage_target="95%",
           performance_validation=True)