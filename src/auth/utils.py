"""
Authentication utility functions providing JWT token manipulation, date/time handling,
input validation and sanitization, and cryptographic operations.

This module implements comprehensive helper functions for authentication operations
and security utilities, equivalent to Node.js patterns while leveraging Python
security libraries for enhanced enterprise-grade protection.

Key Features:
- JWT token processing using PyJWT 2.8+ equivalent to Node.js jsonwebtoken
- Date/time parsing and validation with python-dateutil for ISO 8601 support
- Input validation and sanitization for security compliance
- Cryptographic utilities using cryptography 41.0+ library
- Secure random token generation for session management
- Email validation with email-validator 2.0+ integration
- AWS KMS integration for enterprise key management
- Comprehensive error handling with custom exceptions
"""

import base64
import hashlib
import hmac
import os
import re
import secrets
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Union, Tuple, Set
from urllib.parse import urlparse

# Third-party imports for authentication utilities
import jwt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dateutil import parser as dateutil_parser
from dateutil.relativedelta import relativedelta
import bleach
import email_validator
import boto3
from botocore.exceptions import ClientError, BotoCoreError

# Import authentication exceptions for comprehensive error handling
try:
    from .exceptions import (
        AuthenticationError,
        TokenValidationError,
        CryptographicError,
        ValidationError,
        DateTimeValidationError,
        EmailValidationError,
        ConfigurationError
    )
except ImportError:
    # Fallback definitions if exceptions module doesn't exist yet
    class AuthenticationError(Exception):
        """Base authentication error"""
        pass

    class TokenValidationError(AuthenticationError):
        """JWT token validation error"""
        pass

    class CryptographicError(AuthenticationError):
        """Cryptographic operation error"""
        pass

    class ValidationError(AuthenticationError):
        """Input validation error"""
        pass

    class DateTimeValidationError(ValidationError):
        """Date/time validation error"""
        pass

    class EmailValidationError(ValidationError):
        """Email validation error"""
        pass

    class ConfigurationError(AuthenticationError):
        """Configuration error"""
        pass


class JWTTokenUtils:
    """
    JWT token manipulation utilities providing comprehensive token processing
    equivalent to Node.js jsonwebtoken patterns with enhanced security features.
    
    Implements PyJWT 2.8+ integration with cryptographic validation, claims
    extraction, and enterprise-grade token management capabilities.
    """
    
    def __init__(self, secret_key: Optional[str] = None, algorithm: str = 'HS256'):
        """
        Initialize JWT utility with secret key and algorithm configuration.
        
        Args:
            secret_key: JWT signing secret key (defaults to environment variable)
            algorithm: JWT signing algorithm (HS256, RS256, etc.)
            
        Raises:
            ConfigurationError: When secret key is not provided or invalid
        """
        self.secret_key = secret_key or os.getenv('JWT_SECRET_KEY')
        self.algorithm = algorithm
        
        if not self.secret_key:
            raise ConfigurationError("JWT secret key is required")
        
        # Validate algorithm support
        if algorithm not in ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512']:
            raise ConfigurationError(f"Unsupported JWT algorithm: {algorithm}")
    
    def generate_token(
        self,
        payload: Dict[str, Any],
        expires_in: int = 3600,
        additional_headers: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Generate JWT token with comprehensive payload and security features.
        
        Args:
            payload: Token payload data
            expires_in: Token expiration time in seconds (default: 1 hour)
            additional_headers: Optional additional JWT headers
            
        Returns:
            Encoded JWT token string
            
        Raises:
            TokenValidationError: When token generation fails
        """
        try:
            # Create token payload with standard claims
            token_payload = payload.copy()
            current_time = datetime.utcnow()
            
            token_payload.update({
                'iat': current_time,  # Issued at
                'exp': current_time + timedelta(seconds=expires_in),  # Expiration
                'jti': str(uuid.uuid4()),  # JWT ID for uniqueness
                'iss': 'flask-auth-system',  # Issuer
            })
            
            # Prepare headers
            headers = {'typ': 'JWT', 'alg': self.algorithm}
            if additional_headers:
                headers.update(additional_headers)
            
            # Generate token
            token = jwt.encode(
                payload=token_payload,
                key=self.secret_key,
                algorithm=self.algorithm,
                headers=headers
            )
            
            return token
            
        except (jwt.InvalidTokenError, ValueError) as e:
            raise TokenValidationError(f"Failed to generate JWT token: {str(e)}")
    
    def validate_token(
        self,
        token: str,
        verify_signature: bool = True,
        verify_expiration: bool = True,
        leeway: int = 0
    ) -> Dict[str, Any]:
        """
        Validate JWT token with comprehensive security checks.
        
        Args:
            token: JWT token string to validate
            verify_signature: Whether to verify token signature
            verify_expiration: Whether to verify token expiration
            leeway: Leeway time in seconds for expiration validation
            
        Returns:
            Decoded token payload
            
        Raises:
            TokenValidationError: When token validation fails
        """
        try:
            # Decode and validate token
            decoded_payload = jwt.decode(
                jwt=token,
                key=self.secret_key,
                algorithms=[self.algorithm],
                options={
                    'verify_signature': verify_signature,
                    'verify_exp': verify_expiration,
                    'verify_iat': True,
                    'verify_nbf': True,
                    'require': ['exp', 'iat']
                },
                leeway=timedelta(seconds=leeway)
            )
            
            # Additional custom validations
            self._validate_token_claims(decoded_payload)
            
            return decoded_payload
            
        except jwt.ExpiredSignatureError:
            raise TokenValidationError("JWT token has expired")
        except jwt.InvalidSignatureError:
            raise TokenValidationError("JWT token signature verification failed")
        except jwt.InvalidTokenError as e:
            raise TokenValidationError(f"Invalid JWT token: {str(e)}")
    
    def extract_claims(self, token: str, claim_names: List[str]) -> Dict[str, Any]:
        """
        Extract specific claims from JWT token without full validation.
        
        Args:
            token: JWT token string
            claim_names: List of claim names to extract
            
        Returns:
            Dictionary containing requested claims
            
        Raises:
            TokenValidationError: When token is malformed
        """
        try:
            # Decode without verification for claim extraction
            unverified_payload = jwt.decode(
                jwt=token,
                options={"verify_signature": False}
            )
            
            extracted_claims = {}
            for claim_name in claim_names:
                extracted_claims[claim_name] = unverified_payload.get(claim_name)
            
            return extracted_claims
            
        except jwt.InvalidTokenError as e:
            raise TokenValidationError(f"Failed to extract claims: {str(e)}")
    
    def refresh_token(
        self,
        token: str,
        new_expires_in: int = 3600,
        preserve_claims: Optional[List[str]] = None
    ) -> str:
        """
        Refresh JWT token with new expiration time.
        
        Args:
            token: Original JWT token
            new_expires_in: New expiration time in seconds
            preserve_claims: Claims to preserve from original token
            
        Returns:
            New JWT token string
            
        Raises:
            TokenValidationError: When token refresh fails
        """
        try:
            # Validate original token
            original_payload = self.validate_token(token, verify_expiration=False)
            
            # Prepare new payload
            new_payload = {}
            if preserve_claims:
                for claim in preserve_claims:
                    if claim in original_payload:
                        new_payload[claim] = original_payload[claim]
            else:
                # Preserve all non-standard claims
                standard_claims = {'iat', 'exp', 'nbf', 'jti', 'iss', 'aud', 'sub'}
                new_payload = {
                    k: v for k, v in original_payload.items() 
                    if k not in standard_claims
                }
            
            # Generate new token
            return self.generate_token(new_payload, new_expires_in)
            
        except Exception as e:
            raise TokenValidationError(f"Failed to refresh token: {str(e)}")
    
    def _validate_token_claims(self, payload: Dict[str, Any]) -> None:
        """
        Validate token claims for security requirements.
        
        Args:
            payload: Decoded token payload
            
        Raises:
            TokenValidationError: When claims validation fails
        """
        # Check required claims
        required_claims = ['iat', 'exp']
        for claim in required_claims:
            if claim not in payload:
                raise TokenValidationError(f"Missing required claim: {claim}")
        
        # Validate issuer if present
        if 'iss' in payload and payload['iss'] != 'flask-auth-system':
            raise TokenValidationError("Invalid token issuer")
        
        # Additional security validations can be added here
        pass


class DateTimeUtils:
    """
    Date/time parsing and validation utilities using python-dateutil for
    comprehensive ISO 8601 support and temporal data security features.
    
    Implements secure date/time operations with timezone awareness, validation,
    and data masking capabilities for enterprise compliance.
    """
    
    def __init__(self, default_timezone: str = 'UTC'):
        """
        Initialize date/time utilities with default timezone configuration.
        
        Args:
            default_timezone: Default timezone for operations
        """
        self.default_timezone = timezone.utc if default_timezone == 'UTC' else None
        self.masking_salt = os.getenv('DATE_MASKING_SALT', 'default-masking-salt')
    
    def parse_iso8601(
        self,
        date_string: str,
        default_timezone: Optional[timezone] = None
    ) -> Optional[datetime]:
        """
        Securely parse ISO 8601 date strings with comprehensive validation.
        
        Args:
            date_string: ISO 8601 formatted date string
            default_timezone: Default timezone if not specified in string
            
        Returns:
            Parsed datetime object or None if parsing fails
            
        Raises:
            DateTimeValidationError: When date parsing fails validation
        """
        try:
            # Validate basic ISO 8601 format
            if not self._validate_iso8601_format(date_string):
                raise DateTimeValidationError(f"Invalid ISO 8601 format: {date_string}")
            
            # Parse using python-dateutil
            parsed_date = dateutil_parser.isoparse(date_string)
            
            # Apply default timezone if none specified
            if parsed_date.tzinfo is None:
                target_timezone = default_timezone or self.default_timezone
                if target_timezone:
                    parsed_date = parsed_date.replace(tzinfo=target_timezone)
            
            # Validate reasonable date ranges
            if not self._validate_date_range(parsed_date):
                raise DateTimeValidationError("Date outside valid range")
            
            return parsed_date
            
        except (ValueError, OverflowError, TypeError) as e:
            raise DateTimeValidationError(f"Date parsing failed: {str(e)}")
    
    def format_iso8601(
        self,
        dt: datetime,
        include_microseconds: bool = False,
        force_utc: bool = True
    ) -> str:
        """
        Format datetime object to ISO 8601 string with security considerations.
        
        Args:
            dt: Datetime object to format
            include_microseconds: Whether to include microseconds
            force_utc: Whether to convert to UTC timezone
            
        Returns:
            ISO 8601 formatted date string
        """
        try:
            # Convert to UTC if requested
            if force_utc and dt.tzinfo is not None:
                dt = dt.astimezone(timezone.utc)
            elif force_utc and dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            
            # Remove microseconds if not needed
            if not include_microseconds:
                dt = dt.replace(microsecond=0)
            
            return dt.isoformat()
            
        except Exception as e:
            raise DateTimeValidationError(f"Date formatting failed: {str(e)}")
    
    def mask_temporal_data(
        self,
        date_value: Union[str, datetime],
        masking_level: str = 'month'
    ) -> str:
        """
        Apply temporal data masking for privacy protection.
        
        Args:
            date_value: Date value to mask (string or datetime)
            masking_level: Masking granularity (day, week, month, quarter, year)
            
        Returns:
            Masked date string in ISO 8601 format
            
        Raises:
            DateTimeValidationError: When masking fails
        """
        try:
            # Parse input if string
            if isinstance(date_value, str):
                parsed_date = self.parse_iso8601(date_value)
                if not parsed_date:
                    return "1970-01-01T00:00:00Z"
            else:
                parsed_date = date_value
            
            # Apply masking based on level
            masked_date = self._apply_masking_level(parsed_date, masking_level)
            
            return self.format_iso8601(masked_date)
            
        except Exception as e:
            raise DateTimeValidationError(f"Date masking failed: {str(e)}")
    
    def validate_date_range(
        self,
        date_value: Union[str, datetime],
        min_date: Optional[datetime] = None,
        max_date: Optional[datetime] = None
    ) -> bool:
        """
        Validate date falls within specified range.
        
        Args:
            date_value: Date to validate
            min_date: Minimum allowed date
            max_date: Maximum allowed date
            
        Returns:
            True if date is valid, False otherwise
        """
        try:
            if isinstance(date_value, str):
                parsed_date = self.parse_iso8601(date_value)
                if not parsed_date:
                    return False
            else:
                parsed_date = date_value
            
            # Apply default ranges if not specified
            if min_date is None:
                min_date = datetime(1900, 1, 1, tzinfo=timezone.utc)
            if max_date is None:
                max_date = datetime(2100, 1, 1, tzinfo=timezone.utc)
            
            return min_date <= parsed_date <= max_date
            
        except Exception:
            return False
    
    def _validate_iso8601_format(self, date_string: str) -> bool:
        """Validate basic ISO 8601 format structure."""
        iso8601_pattern = re.compile(
            r'^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?'
            r'(?:Z|[+-](\d{2}):(\d{2}))$|'
            r'^(\d{4})-(\d{2})-(\d{2})$'
        )
        return bool(iso8601_pattern.match(date_string))
    
    def _validate_date_range(self, date: datetime) -> bool:
        """Validate date is within reasonable business range."""
        min_date = datetime(1900, 1, 1, tzinfo=timezone.utc)
        max_date = datetime(2100, 1, 1, tzinfo=timezone.utc)
        return min_date <= date <= max_date
    
    def _apply_masking_level(self, date: datetime, level: str) -> datetime:
        """Apply specific masking level to datetime."""
        if level == 'day':
            return date.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        elif level == 'week':
            days_since_monday = date.weekday()
            masked_date = date - relativedelta(days=days_since_monday)
            return masked_date.replace(hour=0, minute=0, second=0, microsecond=0)
        elif level == 'month':
            return date.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        elif level == 'quarter':
            quarter_start_month = ((date.month - 1) // 3) * 3 + 1
            return date.replace(
                month=quarter_start_month, day=1,
                hour=0, minute=0, second=0, microsecond=0
            )
        elif level == 'year':
            return date.replace(
                month=1, day=1,
                hour=0, minute=0, second=0, microsecond=0
            )
        else:
            # Default to month-level masking
            return date.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


class InputValidator:
    """
    Comprehensive input validation and sanitization utilities for security.
    
    Implements email validation, HTML sanitization, and general input validation
    patterns using enterprise-grade security libraries for XSS prevention
    and data integrity assurance.
    """
    
    def __init__(self):
        """Initialize input validator with security configuration."""
        # Bleach configuration for HTML sanitization
        self.allowed_tags = {
            'p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li',
            'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote'
        }
        self.allowed_attributes = {
            '*': ['class'],
            'a': ['href', 'title'],
            'abbr': ['title'],
            'acronym': ['title']
        }
    
    def validate_email(
        self,
        email: str,
        check_deliverability: bool = False,
        normalize: bool = True
    ) -> Tuple[bool, str]:
        """
        Validate email address with comprehensive checks.
        
        Args:
            email: Email address to validate
            check_deliverability: Whether to check email deliverability
            normalize: Whether to normalize email format
            
        Returns:
            Tuple of (is_valid, normalized_email or error_message)
            
        Raises:
            EmailValidationError: When validation configuration fails
        """
        try:
            # Use email-validator for comprehensive validation
            validated_email = email_validator.validate_email(
                email,
                check_deliverability=check_deliverability
            )
            
            if normalize:
                return True, validated_email.email
            else:
                return True, email
                
        except email_validator.EmailNotValidError as e:
            return False, str(e)
        except Exception as e:
            raise EmailValidationError(f"Email validation error: {str(e)}")
    
    def sanitize_html(
        self,
        html_content: str,
        strip_tags: bool = False,
        custom_tags: Optional[Set[str]] = None,
        custom_attributes: Optional[Dict[str, List[str]]] = None
    ) -> str:
        """
        Sanitize HTML content to prevent XSS attacks.
        
        Args:
            html_content: HTML content to sanitize
            strip_tags: Whether to strip all tags
            custom_tags: Custom allowed tags
            custom_attributes: Custom allowed attributes
            
        Returns:
            Sanitized HTML content
            
        Raises:
            ValidationError: When sanitization fails
        """
        try:
            if strip_tags:
                return bleach.clean(html_content, tags=[], strip=True)
            
            # Use custom tags/attributes if provided
            allowed_tags = custom_tags or self.allowed_tags
            allowed_attributes = custom_attributes or self.allowed_attributes
            
            sanitized_content = bleach.clean(
                html_content,
                tags=allowed_tags,
                attributes=allowed_attributes,
                strip=True
            )
            
            return sanitized_content
            
        except Exception as e:
            raise ValidationError(f"HTML sanitization failed: {str(e)}")
    
    def validate_url(self, url: str, allowed_schemes: Optional[List[str]] = None) -> bool:
        """
        Validate URL format and scheme.
        
        Args:
            url: URL to validate
            allowed_schemes: List of allowed URL schemes
            
        Returns:
            True if URL is valid, False otherwise
        """
        try:
            parsed_url = urlparse(url)
            
            # Check basic URL structure
            if not all([parsed_url.scheme, parsed_url.netloc]):
                return False
            
            # Check allowed schemes
            if allowed_schemes:
                if parsed_url.scheme.lower() not in allowed_schemes:
                    return False
            else:
                # Default to HTTPS/HTTP only
                if parsed_url.scheme.lower() not in ['http', 'https']:
                    return False
            
            return True
            
        except Exception:
            return False
    
    def validate_password_strength(
        self,
        password: str,
        min_length: int = 8,
        require_uppercase: bool = True,
        require_lowercase: bool = True,
        require_numbers: bool = True,
        require_special: bool = True
    ) -> Tuple[bool, List[str]]:
        """
        Validate password strength according to security requirements.
        
        Args:
            password: Password to validate
            min_length: Minimum password length
            require_uppercase: Require uppercase letters
            require_lowercase: Require lowercase letters
            require_numbers: Require numbers
            require_special: Require special characters
            
        Returns:
            Tuple of (is_valid, list_of_validation_errors)
        """
        errors = []
        
        # Check length
        if len(password) < min_length:
            errors.append(f"Password must be at least {min_length} characters long")
        
        # Check character requirements
        if require_uppercase and not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        if require_lowercase and not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        if require_numbers and not re.search(r'\d', password):
            errors.append("Password must contain at least one number")
        
        if require_special and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain at least one special character")
        
        return len(errors) == 0, errors
    
    def sanitize_input(
        self,
        input_value: str,
        max_length: Optional[int] = None,
        allowed_chars: Optional[str] = None,
        strip_whitespace: bool = True
    ) -> str:
        """
        General input sanitization for security.
        
        Args:
            input_value: Input value to sanitize
            max_length: Maximum allowed length
            allowed_chars: Regular expression of allowed characters
            strip_whitespace: Whether to strip leading/trailing whitespace
            
        Returns:
            Sanitized input value
            
        Raises:
            ValidationError: When input fails validation
        """
        try:
            sanitized_value = input_value
            
            # Strip whitespace if requested
            if strip_whitespace:
                sanitized_value = sanitized_value.strip()
            
            # Check length
            if max_length and len(sanitized_value) > max_length:
                raise ValidationError(f"Input exceeds maximum length of {max_length}")
            
            # Check allowed characters
            if allowed_chars and not re.match(f"^{allowed_chars}*$", sanitized_value):
                raise ValidationError("Input contains invalid characters")
            
            return sanitized_value
            
        except ValidationError:
            raise
        except Exception as e:
            raise ValidationError(f"Input sanitization failed: {str(e)}")


class CryptographicUtils:
    """
    Cryptographic utilities for token and session management using
    cryptography 41.0+ library with enterprise-grade security features.
    
    Implements AES encryption, secure random generation, and AWS KMS
    integration for comprehensive cryptographic operations.
    """
    
    def __init__(self):
        """Initialize cryptographic utilities with secure configuration."""
        self.kms_client = None
        self.kms_key_arn = os.getenv('AWS_KMS_CMK_ARN')
        
        # Initialize AWS KMS client if credentials available
        if self._has_aws_credentials():
            try:
                self.kms_client = boto3.client(
                    'kms',
                    region_name=os.getenv('AWS_REGION', 'us-east-1'),
                    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
                    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY')
                )
            except Exception:
                # KMS client initialization failed, will use local encryption
                pass
    
    def generate_secure_token(self, length: int = 32) -> str:
        """
        Generate cryptographically secure random token.
        
        Args:
            length: Token length in bytes (default: 32)
            
        Returns:
            Base64-encoded secure random token
            
        Raises:
            CryptographicError: When token generation fails
        """
        try:
            # Generate secure random bytes
            random_bytes = secrets.token_bytes(length)
            
            # Encode as URL-safe base64
            token = base64.urlsafe_b64encode(random_bytes).decode('utf-8')
            
            # Remove padding for cleaner token
            return token.rstrip('=')
            
        except Exception as e:
            raise CryptographicError(f"Secure token generation failed: {str(e)}")
    
    def generate_encryption_key(self, key_size: int = 256) -> bytes:
        """
        Generate encryption key using secure random generation.
        
        Args:
            key_size: Key size in bits (128, 192, or 256)
            
        Returns:
            Generated encryption key bytes
            
        Raises:
            CryptographicError: When key generation fails
        """
        try:
            if key_size not in [128, 192, 256]:
                raise ValueError("Key size must be 128, 192, or 256 bits")
            
            key_bytes = key_size // 8
            return secrets.token_bytes(key_bytes)
            
        except Exception as e:
            raise CryptographicError(f"Encryption key generation failed: {str(e)}")
    
    def encrypt_aes_gcm(
        self,
        plaintext: Union[str, bytes],
        key: Optional[bytes] = None,
        associated_data: Optional[bytes] = None
    ) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt data using AES-256-GCM with authentication.
        
        Args:
            plaintext: Data to encrypt
            key: Encryption key (generates new key if None)
            associated_data: Additional authenticated data
            
        Returns:
            Tuple of (encrypted_data, nonce, key_used)
            
        Raises:
            CryptographicError: When encryption fails
        """
        try:
            # Convert string to bytes if needed
            if isinstance(plaintext, str):
                plaintext = plaintext.encode('utf-8')
            
            # Generate key if not provided
            if key is None:
                key = self.generate_encryption_key(256)
            
            # Generate random nonce
            nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce),
            )
            encryptor = cipher.encryptor()
            
            # Add associated data if provided
            if associated_data:
                encryptor.authenticate_additional_data(associated_data)
            
            # Encrypt data
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            
            # Combine ciphertext with authentication tag
            encrypted_data = ciphertext + encryptor.tag
            
            return encrypted_data, nonce, key
            
        except Exception as e:
            raise CryptographicError(f"AES-GCM encryption failed: {str(e)}")
    
    def decrypt_aes_gcm(
        self,
        encrypted_data: bytes,
        nonce: bytes,
        key: bytes,
        associated_data: Optional[bytes] = None
    ) -> bytes:
        """
        Decrypt AES-256-GCM encrypted data with authentication verification.
        
        Args:
            encrypted_data: Encrypted data including authentication tag
            nonce: Nonce used for encryption
            key: Decryption key
            associated_data: Additional authenticated data
            
        Returns:
            Decrypted plaintext bytes
            
        Raises:
            CryptographicError: When decryption or authentication fails
        """
        try:
            # Split ciphertext and authentication tag
            ciphertext = encrypted_data[:-16]  # All but last 16 bytes
            tag = encrypted_data[-16:]  # Last 16 bytes
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce, tag),
            )
            decryptor = cipher.decryptor()
            
            # Add associated data if provided
            if associated_data:
                decryptor.authenticate_additional_data(associated_data)
            
            # Decrypt data
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            return plaintext
            
        except Exception as e:
            raise CryptographicError(f"AES-GCM decryption failed: {str(e)}")
    
    def hash_password(self, password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Hash password using PBKDF2 with secure salt.
        
        Args:
            password: Password to hash
            salt: Salt for hashing (generates new salt if None)
            
        Returns:
            Tuple of (password_hash, salt_used)
            
        Raises:
            CryptographicError: When password hashing fails
        """
        try:
            # Generate salt if not provided
            if salt is None:
                salt = secrets.token_bytes(32)
            
            # Create PBKDF2 key derivation function
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,  # OWASP recommended minimum
            )
            
            # Hash password
            password_hash = kdf.derive(password.encode('utf-8'))
            
            return password_hash, salt
            
        except Exception as e:
            raise CryptographicError(f"Password hashing failed: {str(e)}")
    
    def verify_password(self, password: str, password_hash: bytes, salt: bytes) -> bool:
        """
        Verify password against stored hash.
        
        Args:
            password: Password to verify
            password_hash: Stored password hash
            salt: Salt used for hashing
            
        Returns:
            True if password is valid, False otherwise
        """
        try:
            # Create PBKDF2 key derivation function
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            
            # Verify password
            kdf.verify(password.encode('utf-8'), password_hash)
            return True
            
        except Exception:
            return False
    
    def generate_hmac_signature(
        self,
        data: Union[str, bytes],
        secret_key: str,
        algorithm: str = 'sha256'
    ) -> str:
        """
        Generate HMAC signature for data integrity verification.
        
        Args:
            data: Data to sign
            secret_key: Secret key for signing
            algorithm: Hash algorithm (sha256, sha512)
            
        Returns:
            Hexadecimal HMAC signature
            
        Raises:
            CryptographicError: When signature generation fails
        """
        try:
            # Convert data to bytes if needed
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            # Select hash algorithm
            if algorithm == 'sha256':
                hash_func = hashlib.sha256
            elif algorithm == 'sha512':
                hash_func = hashlib.sha512
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            # Generate HMAC
            signature = hmac.new(
                secret_key.encode('utf-8'),
                data,
                hash_func
            ).hexdigest()
            
            return signature
            
        except Exception as e:
            raise CryptographicError(f"HMAC signature generation failed: {str(e)}")
    
    def verify_hmac_signature(
        self,
        data: Union[str, bytes],
        signature: str,
        secret_key: str,
        algorithm: str = 'sha256'
    ) -> bool:
        """
        Verify HMAC signature for data integrity.
        
        Args:
            data: Original data
            signature: HMAC signature to verify
            secret_key: Secret key used for signing
            algorithm: Hash algorithm used
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            expected_signature = self.generate_hmac_signature(data, secret_key, algorithm)
            return hmac.compare_digest(signature, expected_signature)
            
        except Exception:
            return False
    
    def encrypt_with_kms(self, plaintext: Union[str, bytes]) -> Optional[bytes]:
        """
        Encrypt data using AWS KMS if available.
        
        Args:
            plaintext: Data to encrypt
            
        Returns:
            Encrypted data blob or None if KMS unavailable
            
        Raises:
            CryptographicError: When KMS encryption fails
        """
        if not self.kms_client or not self.kms_key_arn:
            return None
        
        try:
            # Convert string to bytes if needed
            if isinstance(plaintext, str):
                plaintext = plaintext.encode('utf-8')
            
            # Encrypt with KMS
            response = self.kms_client.encrypt(
                KeyId=self.kms_key_arn,
                Plaintext=plaintext,
                EncryptionContext={
                    'application': 'flask-auth-system',
                    'purpose': 'data-encryption',
                    'environment': os.getenv('FLASK_ENV', 'production')
                }
            )
            
            return response['CiphertextBlob']
            
        except (ClientError, BotoCoreError) as e:
            raise CryptographicError(f"KMS encryption failed: {str(e)}")
    
    def decrypt_with_kms(self, ciphertext_blob: bytes) -> Optional[bytes]:
        """
        Decrypt data using AWS KMS if available.
        
        Args:
            ciphertext_blob: Encrypted data blob
            
        Returns:
            Decrypted plaintext or None if KMS unavailable
            
        Raises:
            CryptographicError: When KMS decryption fails
        """
        if not self.kms_client:
            return None
        
        try:
            response = self.kms_client.decrypt(
                CiphertextBlob=ciphertext_blob,
                EncryptionContext={
                    'application': 'flask-auth-system',
                    'purpose': 'data-encryption',
                    'environment': os.getenv('FLASK_ENV', 'production')
                }
            )
            
            return response['Plaintext']
            
        except (ClientError, BotoCoreError) as e:
            raise CryptographicError(f"KMS decryption failed: {str(e)}")
    
    def _has_aws_credentials(self) -> bool:
        """Check if AWS credentials are available."""
        required_vars = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY']
        return all(os.getenv(var) for var in required_vars)


# Utility instances for convenient access
jwt_utils = JWTTokenUtils()
datetime_utils = DateTimeUtils()
input_validator = InputValidator()
crypto_utils = CryptographicUtils()


# Convenience functions for common operations
def generate_secure_token(length: int = 32) -> str:
    """Generate a cryptographically secure random token."""
    return crypto_utils.generate_secure_token(length)


def validate_email(email: str, normalize: bool = True) -> Tuple[bool, str]:
    """Validate and optionally normalize email address."""
    return input_validator.validate_email(email, normalize=normalize)


def sanitize_html(html_content: str, strip_tags: bool = False) -> str:
    """Sanitize HTML content to prevent XSS attacks."""
    return input_validator.sanitize_html(html_content, strip_tags=strip_tags)


def parse_iso8601_date(date_string: str) -> Optional[datetime]:
    """Parse ISO 8601 date string with validation."""
    return datetime_utils.parse_iso8601(date_string)


def format_iso8601_date(dt: datetime, force_utc: bool = True) -> str:
    """Format datetime to ISO 8601 string."""
    return datetime_utils.format_iso8601(dt, force_utc=force_utc)


def create_jwt_token(payload: Dict[str, Any], expires_in: int = 3600) -> str:
    """Create JWT token with standard configuration."""
    return jwt_utils.generate_token(payload, expires_in)


def validate_jwt_token(token: str) -> Dict[str, Any]:
    """Validate JWT token and return payload."""
    return jwt_utils.validate_token(token)


def encrypt_sensitive_data(
    data: Union[str, bytes],
    key: Optional[bytes] = None
) -> Tuple[bytes, bytes, bytes]:
    """Encrypt sensitive data using AES-256-GCM."""
    return crypto_utils.encrypt_aes_gcm(data, key)


def decrypt_sensitive_data(
    encrypted_data: bytes,
    nonce: bytes,
    key: bytes
) -> bytes:
    """Decrypt AES-256-GCM encrypted data."""
    return crypto_utils.decrypt_aes_gcm(encrypted_data, nonce, key)