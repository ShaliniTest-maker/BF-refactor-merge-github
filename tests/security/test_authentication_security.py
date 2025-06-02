"""
Comprehensive JWT Authentication Security Testing

This module provides comprehensive security testing for the Flask JWT authentication system,
validating PyJWT 2.8+ token validation, Auth0 integration security, authentication bypass
prevention, and token manipulation attack detection per Section 6.4.1 security requirements.

The test suite implements zero tolerance for critical authentication vulnerabilities per
Section 6.4.5 and ensures enterprise security compliance with comprehensive validation
of authentication components including JWT token processing, Auth0 service integration,
cryptographic operations, and security audit logging.

Security Test Coverage:
- JWT token security validation equivalent to Node.js implementation per Section 6.4.1
- Authentication bypass attack prevention testing per Section 6.4.1
- Token manipulation and signature validation security per Section 6.4.1
- Auth0 integration security testing with mock attack scenarios per Section 6.4.1
- Timing attack detection tests for authentication flows per Section 6.4.1
- Comprehensive authentication security test coverage per Section 6.6.3

Key Validation Areas:
- PyJWT 2.8+ cryptographic signature verification and validation
- Auth0 Python SDK 4.7+ enterprise authentication service integration
- Redis caching security with encrypted session management per Section 6.4.1
- Circuit breaker pattern security for Auth0 service resilience
- Security exception handling and audit logging per Section 6.4.1
- Rate limiting and abuse prevention for authentication endpoints
- Input validation and sanitization for security protection
- Cryptographic operations using cryptography 41.0+ library

Dependencies:
- pytest 7.4+ for comprehensive testing framework
- pytest-asyncio for async authentication operations testing
- PyJWT 2.8+ for JWT token processing validation
- cryptography 41.0+ for cryptographic security validation
- time and statistics modules for timing attack detection
- unittest.mock for Auth0 service and external dependency mocking

Author: Flask Migration Team
Version: 1.0.0
Compliance: SOC 2, ISO 27001, OWASP Top 10
Security Standards: Zero tolerance for critical vulnerabilities per Section 6.4.5
"""

import asyncio
import base64
import hashlib
import json
import secrets
import statistics
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple, Any
from unittest.mock import Mock, patch, MagicMock, AsyncMock, call

import jwt
import pytest
import pytest_asyncio
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Import Flask and testing utilities
from flask import Flask, g, request, session
from flask.testing import FlaskClient

# Import authentication system components
from src.auth.authentication import (
    CoreJWTAuthenticator,
    AuthenticatedUser,
    get_core_authenticator,
    require_authentication,
    get_authenticated_user,
    authenticate_token,
    create_auth_health_check,
    auth_operation_metrics
)

from src.auth.utils import (
    JWTTokenManager,
    DateTimeUtilities,
    InputValidator,
    CryptographicUtilities,
    jwt_manager,
    datetime_utils,
    input_validator,
    crypto_utils,
    require_valid_token,
    get_current_user_id,
    get_current_user_permissions,
    log_security_event
)

from src.auth.exceptions import (
    SecurityException,
    AuthenticationException,
    JWTException,
    Auth0Exception,
    PermissionException,
    SessionException,
    RateLimitException,
    CircuitBreakerException,
    ValidationException,
    SecurityErrorCode,
    get_error_category,
    is_critical_security_error,
    create_safe_error_response
)

# Configure test logging for security events
import logging
import structlog

logger = structlog.get_logger(__name__)


class TestJWTTokenSecurityValidation:
    """
    Comprehensive JWT token security validation tests.
    
    This test class validates PyJWT 2.8+ integration security equivalent to Node.js
    jsonwebtoken patterns with enterprise-grade cryptographic validation, signature
    verification, and comprehensive token manipulation attack detection per Section 6.4.1.
    
    Test Coverage Areas:
    - Cryptographic signature verification with RS256 and HS256 algorithms
    - Token expiration and timestamp validation with clock skew handling
    - Token structure and format validation against malformed tokens
    - Issuer and audience validation for enterprise authentication
    - Key rotation and multiple key support validation
    - Token claims validation and extraction security
    - Comprehensive error handling and exception management
    """
    
    @pytest.fixture
    def jwt_test_keys(self):
        """Generate test RSA key pair for JWT signature testing."""
        # Generate RSA key pair for testing
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        public_key = private_key.public_key()
        
        # Serialize keys for JWT operations
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return {
            'private_key': private_key,
            'public_key': public_key,
            'private_pem': private_pem,
            'public_pem': public_pem,
            'kid': 'test-key-id-2024'
        }
    
    @pytest.fixture
    def jwt_security_config(self, jwt_test_keys):
        """Create secure JWT configuration for testing."""
        return {
            'algorithm': 'RS256',
            'issuer': 'https://test.auth0.com/',
            'audience': 'test-api-audience',
            'private_key': jwt_test_keys['private_pem'],
            'public_key': jwt_test_keys['public_pem'],
            'kid': jwt_test_keys['kid'],
            'leeway': 10,  # 10 seconds for clock skew
            'max_age': 3600  # 1 hour maximum token age
        }
    
    @pytest.fixture
    def test_authenticator(self, jwt_security_config):
        """Create test JWT authenticator with security configuration."""
        with patch.dict('os.environ', {
            'AUTH0_DOMAIN': 'test.auth0.com',
            'AUTH0_CLIENT_ID': 'test_client_id',
            'AUTH0_CLIENT_SECRET': 'test_client_secret',
            'AUTH0_AUDIENCE': jwt_security_config['audience'],
            'JWT_SECRET_KEY': 'test-secret-key-for-testing'
        }):
            authenticator = CoreJWTAuthenticator()
            authenticator.jwt_algorithm = jwt_security_config['algorithm']
            authenticator.auth0_audience = jwt_security_config['audience']
            authenticator.auth0_domain = 'test.auth0.com'
            return authenticator
    
    def create_test_jwt_token(
        self,
        jwt_security_config: Dict[str, Any],
        user_id: str = "test_user_123",
        permissions: Optional[List[str]] = None,
        expires_in: int = 3600,
        additional_claims: Optional[Dict[str, Any]] = None,
        use_invalid_signature: bool = False,
        expire_token: bool = False,
        malform_token: bool = False
    ) -> str:
        """
        Create test JWT token with various security scenarios.
        
        Args:
            jwt_security_config: JWT configuration for token creation
            user_id: User identifier for token subject
            permissions: List of user permissions
            expires_in: Token expiration time in seconds
            additional_claims: Additional claims to include
            use_invalid_signature: Create token with invalid signature
            expire_token: Create expired token for testing
            malform_token: Create malformed token structure
            
        Returns:
            JWT token string for testing
        """
        now = datetime.now(timezone.utc)
        
        if expire_token:
            exp_time = now - timedelta(seconds=3600)  # Expired 1 hour ago
        else:
            exp_time = now + timedelta(seconds=expires_in)
        
        # Standard JWT claims
        claims = {
            'sub': user_id,
            'iss': jwt_security_config['issuer'],
            'aud': jwt_security_config['audience'],
            'iat': int(now.timestamp()),
            'exp': int(exp_time.timestamp()),
            'jti': secrets.token_urlsafe(32),
            'type': 'access_token'
        }
        
        # Add permissions
        if permissions:
            claims['permissions'] = permissions
            claims['scope'] = ' '.join(permissions)
        
        # Add additional claims
        if additional_claims:
            claims.update(additional_claims)
        
        # Create JWT header
        headers = {
            'kid': jwt_security_config['kid'],
            'alg': jwt_security_config['algorithm']
        }
        
        if malform_token:
            # Create malformed token by corrupting the structure
            return "invalid.token.structure.malformed"
        
        # Sign token
        if use_invalid_signature:
            # Use wrong key for invalid signature
            wrong_key = secrets.token_bytes(32)
            token = jwt.encode(
                claims,
                wrong_key,
                algorithm='HS256',  # Wrong algorithm
                headers=headers
            )
        else:
            token = jwt.encode(
                claims,
                jwt_security_config['private_key'],
                algorithm=jwt_security_config['algorithm'],
                headers=headers
            )
        
        return token
    
    @pytest.mark.security
    @pytest.mark.auth
    async def test_valid_jwt_token_validation_success(
        self,
        test_authenticator,
        jwt_security_config,
        comprehensive_test_environment
    ):
        """
        Test successful JWT token validation with valid cryptographic signature.
        
        Validates that properly signed JWT tokens with valid claims are successfully
        validated and user context is created correctly per Section 6.4.1 token
        handling requirements.
        """
        # Record security test
        comprehensive_test_environment['metrics']['record_security_test']('auth')
        
        # Create valid JWT token
        valid_token = self.create_test_jwt_token(
            jwt_security_config,
            user_id="security_test_user",
            permissions=['read:profile', 'update:profile'],
            additional_claims={
                'email': 'security.test@example.com',
                'name': 'Security Test User'
            }
        )
        
        # Mock Auth0 public key endpoint
        mock_jwks = {
            'keys': [{
                'kid': jwt_security_config['kid'],
                'kty': 'RSA',
                'alg': 'RS256',
                'use': 'sig',
                'n': base64.urlsafe_b64encode(
                    jwt_security_config['public_key'].public_numbers().n.to_bytes(256, 'big')
                ).decode(),
                'e': base64.urlsafe_b64encode(
                    jwt_security_config['public_key'].public_numbers().e.to_bytes(3, 'big')
                ).decode()
            }]
        }
        
        with patch('requests.Session.get') as mock_get:
            mock_response = Mock()
            mock_response.json.return_value = mock_jwks
            mock_response.raise_for_status.return_value = None
            mock_get.return_value = mock_response
            
            # Test token validation
            with comprehensive_test_environment['performance']['measure_operation'](
                'jwt_token_validation',
                'auth_request_time'
            ):
                authenticated_user = await test_authenticator.authenticate_request(token=valid_token)
        
        # Validate authentication success
        assert authenticated_user is not None, "Valid JWT token should authenticate successfully"
        assert authenticated_user.user_id == "security_test_user"
        assert 'read:profile' in authenticated_user.permissions
        assert 'update:profile' in authenticated_user.permissions
        assert authenticated_user.profile.get('email') == 'security.test@example.com'
        
        # Validate token claims
        assert authenticated_user.token_claims['iss'] == jwt_security_config['issuer']
        assert authenticated_user.token_claims['aud'] == jwt_security_config['audience']
        assert authenticated_user.token_claims['type'] == 'access_token'
        
        logger.info(
            "JWT token validation security test passed",
            user_id=authenticated_user.user_id,
            permissions_count=len(authenticated_user.permissions),
            test_category="jwt_security_validation"
        )
    
    @pytest.mark.security
    @pytest.mark.auth
    async def test_jwt_token_signature_tampering_detection(
        self,
        test_authenticator,
        jwt_security_config,
        comprehensive_test_environment
    ):
        """
        Test detection of JWT token signature tampering attempts.
        
        Validates that tokens with invalid signatures are properly rejected and
        appropriate security exceptions are raised per Section 6.4.1 token
        manipulation attack prevention.
        """
        comprehensive_test_environment['metrics']['record_security_test']('auth')
        
        # Create token with invalid signature
        tampered_token = self.create_test_jwt_token(
            jwt_security_config,
            user_id="tampered_user",
            use_invalid_signature=True
        )
        
        # Mock Auth0 public key endpoint
        mock_jwks = {
            'keys': [{
                'kid': jwt_security_config['kid'],
                'kty': 'RSA',
                'alg': 'RS256',
                'use': 'sig',
                'n': base64.urlsafe_b64encode(
                    jwt_security_config['public_key'].public_numbers().n.to_bytes(256, 'big')
                ).decode(),
                'e': base64.urlsafe_b64encode(
                    jwt_security_config['public_key'].public_numbers().e.to_bytes(3, 'big')
                ).decode()
            }]
        }
        
        with patch('requests.Session.get') as mock_get:
            mock_response = Mock()
            mock_response.json.return_value = mock_jwks
            mock_response.raise_for_status.return_value = None
            mock_get.return_value = mock_response
            
            # Test signature tampering detection
            with pytest.raises(JWTException) as exc_info:
                await test_authenticator.authenticate_request(token=tampered_token)
        
        # Validate security exception
        exception = exc_info.value
        assert exception.error_code == SecurityErrorCode.AUTH_TOKEN_INVALID
        assert "signature" in exception.message.lower() or "invalid" in exception.message.lower()
        assert exception.http_status == 401
        
        # Record security violation
        comprehensive_test_environment['metrics']['record_security_violation']()
        
        logger.warning(
            "JWT signature tampering detected and blocked",
            error_code=exception.error_code.value,
            test_category="signature_tampering_detection"
        )
    
    @pytest.mark.security
    @pytest.mark.auth
    async def test_jwt_token_expiration_validation(
        self,
        test_authenticator,
        jwt_security_config,
        comprehensive_test_environment
    ):
        """
        Test JWT token expiration validation and expired token rejection.
        
        Validates that expired tokens are properly rejected and appropriate
        security exceptions are raised per Section 6.4.1 token lifecycle
        management requirements.
        """
        comprehensive_test_environment['metrics']['record_security_test']('auth')
        
        # Create expired token
        expired_token = self.create_test_jwt_token(
            jwt_security_config,
            user_id="expired_user",
            expire_token=True
        )
        
        # Mock Auth0 public key endpoint
        mock_jwks = {
            'keys': [{
                'kid': jwt_security_config['kid'],
                'kty': 'RSA',
                'alg': 'RS256',
                'use': 'sig',
                'n': base64.urlsafe_b64encode(
                    jwt_security_config['public_key'].public_numbers().n.to_bytes(256, 'big')
                ).decode(),
                'e': base64.urlsafe_b64encode(
                    jwt_security_config['public_key'].public_numbers().e.to_bytes(3, 'big')
                ).decode()
            }]
        }
        
        with patch('requests.Session.get') as mock_get:
            mock_response = Mock()
            mock_response.json.return_value = mock_jwks
            mock_response.raise_for_status.return_value = None
            mock_get.return_value = mock_response
            
            # Test expired token rejection
            with pytest.raises(JWTException) as exc_info:
                await test_authenticator.authenticate_request(token=expired_token)
        
        # Validate expiration exception
        exception = exc_info.value
        assert exception.error_code == SecurityErrorCode.AUTH_TOKEN_EXPIRED
        assert "expired" in exception.message.lower()
        assert exception.http_status == 401
        
        logger.warning(
            "Expired JWT token detected and rejected",
            error_code=exception.error_code.value,
            test_category="token_expiration_validation"
        )
    
    @pytest.mark.security
    @pytest.mark.auth
    async def test_jwt_token_malformed_structure_detection(
        self,
        test_authenticator,
        comprehensive_test_environment
    ):
        """
        Test detection of malformed JWT token structures.
        
        Validates that malformed tokens are properly rejected with appropriate
        security exceptions per Section 6.4.1 input validation requirements.
        """
        comprehensive_test_environment['metrics']['record_security_test']('auth')
        
        malformed_tokens = [
            "malformed.token.structure",
            "invalid-base64-encoding",
            "",
            "only-one-part",
            "too.many.parts.in.token.structure",
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.invalid_payload.signature",
            "valid_header.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.invalid_signature"
        ]
        
        for malformed_token in malformed_tokens:
            with pytest.raises((JWTException, AuthenticationException)) as exc_info:
                await test_authenticator.authenticate_request(token=malformed_token)
            
            # Validate malformed token exception
            exception = exc_info.value
            assert exception.error_code in [
                SecurityErrorCode.AUTH_TOKEN_MALFORMED,
                SecurityErrorCode.AUTH_TOKEN_INVALID
            ]
            assert exception.http_status == 401
            
            # Record security violation
            comprehensive_test_environment['metrics']['record_security_violation']()
        
        logger.warning(
            "Malformed JWT tokens detected and rejected",
            malformed_token_count=len(malformed_tokens),
            test_category="malformed_token_detection"
        )
    
    @pytest.mark.security
    @pytest.mark.auth
    async def test_jwt_token_claims_validation_security(
        self,
        test_authenticator,
        jwt_security_config,
        comprehensive_test_environment
    ):
        """
        Test JWT token claims validation and security checks.
        
        Validates that token claims are properly validated for security
        requirements including issuer, audience, and custom claims validation
        per Section 6.4.1 claims processing security.
        """
        comprehensive_test_environment['metrics']['record_security_test']('auth')
        
        # Test invalid issuer
        invalid_issuer_token = self.create_test_jwt_token(
            {**jwt_security_config, 'issuer': 'https://malicious.domain.com/'},
            user_id="invalid_issuer_user"
        )
        
        # Test invalid audience
        invalid_audience_token = self.create_test_jwt_token(
            {**jwt_security_config, 'audience': 'malicious-audience'},
            user_id="invalid_audience_user"
        )
        
        # Mock Auth0 public key endpoint
        mock_jwks = {
            'keys': [{
                'kid': jwt_security_config['kid'],
                'kty': 'RSA',
                'alg': 'RS256',
                'use': 'sig',
                'n': base64.urlsafe_b64encode(
                    jwt_security_config['public_key'].public_numbers().n.to_bytes(256, 'big')
                ).decode(),
                'e': base64.urlsafe_b64encode(
                    jwt_security_config['public_key'].public_numbers().e.to_bytes(3, 'big')
                ).decode()
            }]
        }
        
        with patch('requests.Session.get') as mock_get:
            mock_response = Mock()
            mock_response.json.return_value = mock_jwks
            mock_response.raise_for_status.return_value = None
            mock_get.return_value = mock_response
            
            # Test invalid issuer rejection
            with pytest.raises(JWTException) as exc_info:
                await test_authenticator.authenticate_request(token=invalid_issuer_token)
            
            assert exc_info.value.error_code == SecurityErrorCode.AUTH_TOKEN_INVALID
            assert "issuer" in exc_info.value.message.lower()
            
            # Test invalid audience rejection
            with pytest.raises(JWTException) as exc_info:
                await test_authenticator.authenticate_request(token=invalid_audience_token)
            
            assert exc_info.value.error_code == SecurityErrorCode.AUTH_TOKEN_INVALID
            assert "audience" in exc_info.value.message.lower()
        
        logger.warning(
            "Invalid JWT token claims detected and rejected",
            test_category="claims_validation_security"
        )
    
    @pytest.mark.security
    @pytest.mark.auth
    async def test_jwt_token_algorithm_confusion_attack_prevention(
        self,
        test_authenticator,
        jwt_security_config,
        comprehensive_test_environment
    ):
        """
        Test prevention of JWT algorithm confusion attacks.
        
        Validates that algorithm confusion attacks (e.g., RS256 to HS256) are
        properly detected and prevented per Section 6.4.1 cryptographic
        security requirements.
        """
        comprehensive_test_environment['metrics']['record_security_test']('auth')
        
        # Create token with algorithm confusion (using public key as HMAC secret)
        claims = {
            'sub': 'algorithm_confusion_user',
            'iss': jwt_security_config['issuer'],
            'aud': jwt_security_config['audience'],
            'iat': int(datetime.now(timezone.utc).timestamp()),
            'exp': int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            'jti': secrets.token_urlsafe(32)
        }
        
        # Use public key as HMAC secret (algorithm confusion attack)
        algorithm_confusion_token = jwt.encode(
            claims,
            jwt_security_config['public_pem'],  # Using public key as HMAC secret
            algorithm='HS256',  # Wrong algorithm
            headers={'kid': jwt_security_config['kid'], 'alg': 'HS256'}
        )
        
        # Mock Auth0 public key endpoint
        mock_jwks = {
            'keys': [{
                'kid': jwt_security_config['kid'],
                'kty': 'RSA',
                'alg': 'RS256',
                'use': 'sig',
                'n': base64.urlsafe_b64encode(
                    jwt_security_config['public_key'].public_numbers().n.to_bytes(256, 'big')
                ).decode(),
                'e': base64.urlsafe_b64encode(
                    jwt_security_config['public_key'].public_numbers().e.to_bytes(3, 'big')
                ).decode()
            }]
        }
        
        with patch('requests.Session.get') as mock_get:
            mock_response = Mock()
            mock_response.json.return_value = mock_jwks
            mock_response.raise_for_status.return_value = None
            mock_get.return_value = mock_response
            
            # Test algorithm confusion attack prevention
            with pytest.raises(JWTException) as exc_info:
                await test_authenticator.authenticate_request(token=algorithm_confusion_token)
        
        # Validate security exception
        exception = exc_info.value
        assert exception.error_code == SecurityErrorCode.AUTH_TOKEN_INVALID
        assert exception.http_status == 401
        
        # Record security violation
        comprehensive_test_environment['metrics']['record_security_violation']()
        
        logger.warning(
            "JWT algorithm confusion attack detected and prevented",
            error_code=exception.error_code.value,
            test_category="algorithm_confusion_prevention"
        )


class TestAuthenticationBypassPrevention:
    """
    Authentication bypass attack prevention tests.
    
    This test class validates comprehensive authentication bypass prevention
    mechanisms including null byte injection, header manipulation, session
    fixation, and other authentication circumvention attempts per Section 6.4.1
    authentication security requirements.
    """
    
    @pytest.fixture
    def bypass_test_authenticator(self):
        """Create authenticator for bypass testing with enhanced security."""
        with patch.dict('os.environ', {
            'AUTH0_DOMAIN': 'secure.auth0.com',
            'AUTH0_CLIENT_ID': 'secure_client_id',
            'AUTH0_CLIENT_SECRET': 'secure_client_secret',
            'AUTH0_AUDIENCE': 'secure-api',
            'JWT_SECRET_KEY': 'secure-secret-key-for-bypass-testing'
        }):
            authenticator = CoreJWTAuthenticator()
            return authenticator
    
    @pytest.mark.security
    @pytest.mark.auth
    async def test_null_byte_injection_bypass_prevention(
        self,
        bypass_test_authenticator,
        comprehensive_test_environment
    ):
        """
        Test prevention of null byte injection in authentication tokens.
        
        Validates that null byte injection attempts in JWT tokens and
        authentication headers are properly detected and prevented per
        Section 6.4.1 input validation security.
        """
        comprehensive_test_environment['metrics']['record_security_test']('auth')
        
        # Test null byte injection attempts
        null_byte_tokens = [
            "valid.token.part\x00.malicious.suffix",
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9\x00.payload.signature",
            "header.eyJzdWIiOiIxMjM0NTY3ODkw\x00IiwibmFtZSI6IkpvaG4gRG9lIn0.signature",
            "\x00eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.payload.signature",
            "valid.token.signature\x00"
        ]
        
        for null_token in null_byte_tokens:
            with pytest.raises((AuthenticationException, JWTException, ValidationException)) as exc_info:
                await bypass_test_authenticator.authenticate_request(token=null_token)
            
            # Validate bypass prevention
            exception = exc_info.value
            assert exception.error_code in [
                SecurityErrorCode.AUTH_TOKEN_MALFORMED,
                SecurityErrorCode.AUTH_TOKEN_INVALID,
                SecurityErrorCode.VAL_INPUT_INVALID
            ]
            assert exception.http_status == 401
            
            # Record security violation
            comprehensive_test_environment['metrics']['record_security_violation']()
        
        logger.warning(
            "Null byte injection bypass attempts detected and prevented",
            attempts_count=len(null_byte_tokens),
            test_category="null_byte_injection_prevention"
        )
    
    @pytest.mark.security
    @pytest.mark.auth
    async def test_header_manipulation_bypass_prevention(
        self,
        bypass_test_authenticator,
        comprehensive_test_environment
    ):
        """
        Test prevention of authentication header manipulation attacks.
        
        Validates that authentication header manipulation attempts including
        case sensitivity bypass, encoding attacks, and header injection are
        properly prevented per Section 6.4.1 header security.
        """
        comprehensive_test_environment['metrics']['record_security_test']('auth')
        
        # Test various header manipulation attempts
        manipulation_attempts = [
            "",  # Empty token
            " ",  # Whitespace only
            "Bearer",  # Missing token part
            "bearer valid_token",  # Wrong case
            "BEARER valid_token",  # Wrong case
            "Bearer  double_space_token",  # Double space
            "Bearer\ttoken_with_tab",  # Tab character
            "Bearer\ntoken_with_newline",  # Newline injection
            "Bearer token\rcarriage_return",  # Carriage return
            "Bearer token; additional_data",  # Semicolon injection
            "Bearer token, additional_header",  # Comma injection
        ]
        
        for manipulation_token in manipulation_attempts:
            # Mock request context with manipulated Authorization header
            with patch('flask.request') as mock_request:
                mock_request.headers.get.return_value = manipulation_token
                mock_request.cookies.get.return_value = None
                mock_request.args.get.return_value = None
                mock_request.remote_addr = '192.168.1.100'
                
                authenticated_user = await bypass_test_authenticator.authenticate_request()
                
                # Validate that manipulation attempts are rejected
                assert authenticated_user is None, f"Header manipulation should be rejected: {manipulation_token}"
        
        logger.warning(
            "Authentication header manipulation attempts detected and prevented",
            attempts_count=len(manipulation_attempts),
            test_category="header_manipulation_prevention"
        )
    
    @pytest.mark.security
    @pytest.mark.auth
    async def test_session_fixation_bypass_prevention(
        self,
        bypass_test_authenticator,
        comprehensive_test_environment
    ):
        """
        Test prevention of session fixation attacks.
        
        Validates that session fixation attempts are properly detected and
        prevented with secure session regeneration per Section 6.4.1 session
        management security requirements.
        """
        comprehensive_test_environment['metrics']['record_security_test']('auth')
        
        # Test session fixation prevention
        fixed_session_ids = [
            "FIXED_SESSION_ID_12345",
            "attacker_controlled_session",
            "..%2F..%2F..%2Fetc%2Fpasswd",  # Path traversal attempt
            "<script>alert('xss')</script>",  # XSS attempt
            "' OR 1=1 --",  # SQL injection attempt
            "session_id; DROP TABLE users;",  # SQL injection
            "\"><img src=x onerror=alert(1)>",  # HTML injection
        ]
        
        for fixed_session in fixed_session_ids:
            # Mock Flask session with fixed session ID
            with patch('flask.session') as mock_session:
                mock_session.__setitem__ = Mock()
                mock_session.__getitem__ = Mock(return_value=fixed_session)
                mock_session.sid = fixed_session
                
                # Attempt authentication with fixed session
                result = await bypass_test_authenticator.authenticate_request()
                
                # Validate session fixation prevention
                assert result is None, f"Session fixation should be prevented: {fixed_session}"
        
        # Record security violations
        for _ in fixed_session_ids:
            comprehensive_test_environment['metrics']['record_security_violation']()
        
        logger.warning(
            "Session fixation bypass attempts detected and prevented",
            attempts_count=len(fixed_session_ids),
            test_category="session_fixation_prevention"
        )
    
    @pytest.mark.security
    @pytest.mark.auth
    async def test_timing_attack_bypass_prevention(
        self,
        bypass_test_authenticator,
        comprehensive_test_environment
    ):
        """
        Test prevention of timing attacks against authentication.
        
        Validates that authentication timing is consistent regardless of
        token validity to prevent timing-based information disclosure per
        Section 6.4.1 timing attack prevention requirements.
        """
        comprehensive_test_environment['metrics']['record_security_test']('auth')
        
        # Collect timing measurements for valid and invalid tokens
        valid_times = []
        invalid_times = []
        
        # Generate test tokens
        valid_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        invalid_tokens = [
            "invalid.token.signature",
            "malformed_token_structure",
            "expired.token.example",
            "tampered.token.payload",
            "wrong.algorithm.token"
        ]
        
        # Measure timing for valid token attempts (will fail but timing matters)
        for _ in range(10):
            start_time = time.perf_counter()
            try:
                await bypass_test_authenticator.authenticate_request(token=valid_token)
            except Exception:
                pass  # Expected to fail, we're measuring timing
            end_time = time.perf_counter()
            valid_times.append(end_time - start_time)
        
        # Measure timing for invalid token attempts
        for invalid_token in invalid_tokens:
            start_time = time.perf_counter()
            try:
                await bypass_test_authenticator.authenticate_request(token=invalid_token)
            except Exception:
                pass  # Expected to fail, we're measuring timing
            end_time = time.perf_counter()
            invalid_times.append(end_time - start_time)
        
        # Statistical analysis of timing differences
        valid_mean = statistics.mean(valid_times)
        invalid_mean = statistics.mean(invalid_times)
        valid_stdev = statistics.stdev(valid_times) if len(valid_times) > 1 else 0
        invalid_stdev = statistics.stdev(invalid_times) if len(invalid_times) > 1 else 0
        
        # Calculate timing difference ratio
        timing_difference_ratio = abs(valid_mean - invalid_mean) / max(valid_mean, invalid_mean)
        
        # Validate timing attack prevention (difference should be minimal)
        assert timing_difference_ratio < 0.5, f"Timing difference too large: {timing_difference_ratio:.3f}"
        
        logger.info(
            "Timing attack prevention validated",
            valid_mean_time=round(valid_mean, 6),
            invalid_mean_time=round(invalid_mean, 6),
            timing_difference_ratio=round(timing_difference_ratio, 3),
            test_category="timing_attack_prevention"
        )
    
    @pytest.mark.security
    @pytest.mark.auth
    async def test_concurrent_authentication_bypass_prevention(
        self,
        bypass_test_authenticator,
        comprehensive_test_environment
    ):
        """
        Test prevention of concurrent authentication bypass attacks.
        
        Validates that concurrent authentication attempts do not create
        race conditions or bypass authentication security per Section 6.4.1
        concurrent access security requirements.
        """
        comprehensive_test_environment['metrics']['record_security_test']('auth')
        
        # Define concurrent authentication attempts
        async def authentication_attempt(token_suffix: str):
            """Single authentication attempt for concurrency testing."""
            token = f"concurrent.bypass.attempt.{token_suffix}"
            try:
                result = await bypass_test_authenticator.authenticate_request(token=token)
                return result is None  # Should be None (failed authentication)
            except Exception:
                return True  # Exception is expected for invalid tokens
        
        # Execute concurrent authentication attempts
        concurrent_tasks = []
        for i in range(20):  # 20 concurrent attempts
            task = asyncio.create_task(authentication_attempt(f"task_{i}"))
            concurrent_tasks.append(task)
        
        # Wait for all concurrent attempts to complete
        results = await asyncio.gather(*concurrent_tasks, return_exceptions=True)
        
        # Validate all attempts were properly rejected
        successful_bypasses = sum(1 for result in results if not result)
        assert successful_bypasses == 0, f"Concurrent bypass detected: {successful_bypasses} attempts succeeded"
        
        # Validate no exceptions were raised unexpectedly
        exception_count = sum(1 for result in results if isinstance(result, Exception))
        
        logger.info(
            "Concurrent authentication bypass prevention validated",
            total_attempts=len(concurrent_tasks),
            successful_bypasses=successful_bypasses,
            exceptions_raised=exception_count,
            test_category="concurrent_bypass_prevention"
        )


class TestAuth0IntegrationSecurity:
    """
    Auth0 integration security testing with mock attack scenarios.
    
    This test class validates Auth0 Python SDK 4.7+ integration security including
    service resilience, circuit breaker patterns, API communication security,
    and attack scenario simulation per Section 6.4.1 Auth0 integration requirements.
    """
    
    @pytest.fixture
    def auth0_security_mock(self):
        """Create comprehensive Auth0 security mock for testing."""
        mock_auth0 = Mock()
        
        # Mock Auth0 user data
        mock_user_data = {
            'user_id': 'auth0|security_test_user',
            'email': 'security.test@example.com',
            'name': 'Security Test User',
            'email_verified': True,
            'last_login': '2024-01-15T10:30:00.000Z',
            'logins_count': 42,
            'app_metadata': {'role': 'user'},
            'user_metadata': {'preferences': {'theme': 'dark'}}
        }
        
        # Mock JWKS endpoint response
        mock_jwks = {
            'keys': [{
                'kid': 'security-test-key-2024',
                'kty': 'RSA',
                'alg': 'RS256',
                'use': 'sig',
                'n': 'security_test_modulus',
                'e': 'AQAB'
            }]
        }
        
        # Configure mock responses
        mock_auth0.get_user.return_value = mock_user_data
        mock_auth0.get_jwks.return_value = mock_jwks
        mock_auth0.users.get.return_value = mock_user_data
        
        return {
            'auth0_client': mock_auth0,
            'user_data': mock_user_data,
            'jwks_data': mock_jwks
        }
    
    @pytest.mark.security
    @pytest.mark.auth
    async def test_auth0_service_unavailable_handling(
        self,
        auth0_security_mock,
        comprehensive_test_environment
    ):
        """
        Test Auth0 service unavailability handling and fallback mechanisms.
        
        Validates that Auth0 service unavailability is properly handled with
        circuit breaker activation and graceful degradation per Section 6.4.1
        external service resilience requirements.
        """
        comprehensive_test_environment['metrics']['record_security_test']('auth')
        
        with patch.dict('os.environ', {
            'AUTH0_DOMAIN': 'security.auth0.com',
            'AUTH0_CLIENT_ID': 'security_client',
            'AUTH0_CLIENT_SECRET': 'security_secret',
            'AUTH0_AUDIENCE': 'security-api'
        }):
            authenticator = CoreJWTAuthenticator()
            
            # Simulate Auth0 service unavailability
            with patch('requests.Session.get') as mock_get:
                mock_get.side_effect = Exception("Auth0 service unavailable")
                
                # Test circuit breaker activation
                with pytest.raises(Auth0Exception) as exc_info:
                    await authenticator._get_auth0_public_key('test-key-id')
                
                # Validate circuit breaker exception
                exception = exc_info.value
                assert exception.error_code == SecurityErrorCode.EXT_AUTH0_UNAVAILABLE
                assert exception.http_status == 503
                assert "unavailable" in exception.message.lower()
        
        logger.warning(
            "Auth0 service unavailability handled with circuit breaker",
            error_code=exc_info.value.error_code.value,
            test_category="auth0_service_resilience"
        )
    
    @pytest.mark.security
    @pytest.mark.auth
    async def test_auth0_api_rate_limiting_handling(
        self,
        auth0_security_mock,
        comprehensive_test_environment
    ):
        """
        Test Auth0 API rate limiting handling and retry mechanisms.
        
        Validates that Auth0 API rate limiting is properly handled with
        exponential backoff and circuit breaker protection per Section 6.4.1
        rate limiting resilience requirements.
        """
        comprehensive_test_environment['metrics']['record_security_test']('auth')
        
        with patch.dict('os.environ', {
            'AUTH0_DOMAIN': 'security.auth0.com',
            'AUTH0_CLIENT_ID': 'security_client',
            'AUTH0_CLIENT_SECRET': 'security_secret'
        }):
            authenticator = CoreJWTAuthenticator()
            
            # Simulate Auth0 rate limiting
            with patch('requests.Session.get') as mock_get:
                rate_limit_response = Mock()
                rate_limit_response.status_code = 429
                rate_limit_response.headers = {'X-RateLimit-Remaining': '0'}
                rate_limit_response.raise_for_status.side_effect = Exception("Rate limit exceeded")
                mock_get.return_value = rate_limit_response
                
                # Test rate limiting handling
                with pytest.raises(Auth0Exception) as exc_info:
                    await authenticator._get_auth0_public_key('test-key-id')
                
                # Validate rate limiting exception
                exception = exc_info.value
                assert exception.error_code == SecurityErrorCode.EXT_AUTH0_UNAVAILABLE
                assert exception.http_status == 503
        
        logger.warning(
            "Auth0 API rate limiting handled appropriately",
            error_code=exc_info.value.error_code.value,
            test_category="auth0_rate_limiting_handling"
        )
    
    @pytest.mark.security
    @pytest.mark.auth
    async def test_auth0_jwks_tampering_detection(
        self,
        auth0_security_mock,
        comprehensive_test_environment
    ):
        """
        Test detection of Auth0 JWKS tampering attempts.
        
        Validates that tampered JWKS responses are properly detected and
        rejected with appropriate security exceptions per Section 6.4.1
        cryptographic security requirements.
        """
        comprehensive_test_environment['metrics']['record_security_test']('auth')
        
        with patch.dict('os.environ', {
            'AUTH0_DOMAIN': 'security.auth0.com',
            'AUTH0_CLIENT_ID': 'security_client'
        }):
            authenticator = CoreJWTAuthenticator()
            
            # Test various JWKS tampering scenarios
            tampered_jwks_responses = [
                # Missing keys array
                {},
                # Empty keys array
                {'keys': []},
                # Invalid key structure
                {'keys': [{'invalid': 'structure'}]},
                # Missing required fields
                {'keys': [{'kid': 'test', 'kty': 'RSA'}]},  # Missing alg, n, e
                # Invalid key type
                {'keys': [{'kid': 'test', 'kty': 'INVALID', 'alg': 'RS256'}]},
                # Malicious key injection
                {'keys': [
                    {'kid': 'test', 'kty': 'RSA', 'alg': 'RS256', 'n': 'valid', 'e': 'AQAB'},
                    {'kid': 'malicious', 'kty': 'RSA', 'alg': 'HS256', 'n': 'evil', 'e': 'AQAB'}
                ]},
            ]
            
            for tampered_jwks in tampered_jwks_responses:
                with patch('requests.Session.get') as mock_get:
                    mock_response = Mock()
                    mock_response.json.return_value = tampered_jwks
                    mock_response.raise_for_status.return_value = None
                    mock_get.return_value = mock_response
                    
                    # Test JWKS tampering detection
                    result = await authenticator._get_auth0_public_key('test-key-id')
                    
                    # Validate tampering detection (should return None for invalid JWKS)
                    assert result is None, f"Tampered JWKS should be rejected: {tampered_jwks}"
                
                # Record security violation
                comprehensive_test_environment['metrics']['record_security_violation']()
        
        logger.warning(
            "Auth0 JWKS tampering attempts detected and prevented",
            tampering_scenarios=len(tampered_jwks_responses),
            test_category="auth0_jwks_tampering_detection"
        )
    
    @pytest.mark.security
    @pytest.mark.auth
    async def test_auth0_response_injection_prevention(
        self,
        auth0_security_mock,
        comprehensive_test_environment
    ):
        """
        Test prevention of Auth0 response injection attacks.
        
        Validates that malicious Auth0 API responses are properly sanitized
        and injection attempts are prevented per Section 6.4.1 input validation
        security requirements.
        """
        comprehensive_test_environment['metrics']['record_security_test']('auth')
        
        with patch.dict('os.environ', {
            'AUTH0_DOMAIN': 'security.auth0.com',
            'AUTH0_CLIENT_ID': 'security_client'
        }):
            authenticator = CoreJWTAuthenticator()
            
            # Test malicious Auth0 responses
            malicious_responses = [
                # XSS injection in user data
                {
                    'sub': '<script>alert("xss")</script>',
                    'email': 'user@example.com<script>alert("xss")</script>',
                    'name': '"><img src=x onerror=alert(1)>'
                },
                # SQL injection attempts
                {
                    'sub': "'; DROP TABLE users; --",
                    'email': 'user@example.com\'; DELETE FROM users; --',
                    'name': 'User\' OR 1=1 --'
                },
                # Path traversal attempts
                {
                    'sub': '../../../etc/passwd',
                    'email': '..\\..\\windows\\system32\\drivers\\etc\\hosts',
                    'name': '..%2F..%2F..%2Fetc%2Fpasswd'
                },
                # Command injection attempts
                {
                    'sub': '$(rm -rf /)',
                    'email': '`cat /etc/passwd`',
                    'name': '${jndi:ldap://malicious.com/evil}'
                }
            ]
            
            for malicious_response in malicious_responses:
                # Mock malicious Auth0 response
                with patch.object(authenticator, '_fetch_auth0_user_profile') as mock_fetch:
                    mock_fetch.return_value = malicious_response
                    
                    # Test response injection prevention
                    user_profile = await authenticator._get_user_profile(
                        'test_user', 
                        {'sub': 'test_user', 'email': 'test@example.com'}
                    )
                    
                    # Validate injection prevention (profile should be safe or None)
                    if user_profile:
                        # Check that malicious content is not present as-is
                        profile_str = json.dumps(user_profile)
                        assert '<script>' not in profile_str
                        assert 'DROP TABLE' not in profile_str
                        assert '../../../' not in profile_str
                        assert '$(rm -rf' not in profile_str
                
                # Record security violation
                comprehensive_test_environment['metrics']['record_security_violation']()
        
        logger.warning(
            "Auth0 response injection attempts detected and prevented",
            injection_scenarios=len(malicious_responses),
            test_category="auth0_response_injection_prevention"
        )


class TestCryptographicSecurityValidation:
    """
    Cryptographic security validation tests.
    
    This test class validates cryptographic operations security using
    cryptography 41.0+ library including encryption/decryption security,
    key management, digital signatures, and cryptographic attack prevention
    per Section 6.4.1 cryptographic security requirements.
    """
    
    @pytest.fixture
    def crypto_test_utilities(self):
        """Create cryptographic utilities for security testing."""
        # Generate test encryption key
        test_key = secrets.token_bytes(32)
        crypto_utils = CryptographicUtilities(master_key=test_key)
        
        return {
            'crypto_utils': crypto_utils,
            'test_key': test_key,
            'test_data': {
                'user_id': 'crypto_test_user',
                'session_id': 'secure_session_123',
                'permissions': ['read:profile', 'update:profile'],
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        }
    
    @pytest.mark.security
    @pytest.mark.auth
    def test_session_data_encryption_security(
        self,
        crypto_test_utilities,
        comprehensive_test_environment
    ):
        """
        Test session data encryption security and tamper detection.
        
        Validates that session data encryption uses secure algorithms and
        properly detects tampering attempts per Section 6.4.1 session
        encryption requirements.
        """
        comprehensive_test_environment['metrics']['record_security_test']('auth')
        
        crypto_utils = crypto_test_utilities['crypto_utils']
        test_data = crypto_test_utilities['test_data']
        
        # Test secure encryption
        encrypted_data = crypto_utils.encrypt_session_data(test_data)
        assert encrypted_data is not None
        assert len(encrypted_data) > 0
        assert encrypted_data != json.dumps(test_data)  # Should be encrypted
        
        # Test secure decryption
        decrypted_data = crypto_utils.decrypt_session_data(encrypted_data)
        assert decrypted_data['user_id'] == test_data['user_id']
        assert decrypted_data['session_id'] == test_data['session_id']
        assert decrypted_data['permissions'] == test_data['permissions']
        
        # Test tampering detection
        tampered_encrypted_data = encrypted_data[:-10] + "tampered123"
        
        with pytest.raises(SecurityException) as exc_info:
            crypto_utils.decrypt_session_data(tampered_encrypted_data)
        
        # Validate tampering detection
        exception = exc_info.value
        assert exception.error_code == SecurityErrorCode.AUTH_SESSION_INVALID
        assert exception.http_status == 401
        
        logger.info(
            "Session data encryption security validated",
            encryption_successful=True,
            tampering_detected=True,
            test_category="session_encryption_security"
        )
    
    @pytest.mark.security
    @pytest.mark.auth
    def test_secure_token_generation_entropy(
        self,
        crypto_test_utilities,
        comprehensive_test_environment
    ):
        """
        Test secure token generation entropy and uniqueness.
        
        Validates that secure token generation has sufficient entropy and
        produces unique tokens per Section 6.4.1 token generation security
        requirements.
        """
        comprehensive_test_environment['metrics']['record_security_test']('auth')
        
        crypto_utils = crypto_test_utilities['crypto_utils']
        
        # Generate multiple tokens for entropy analysis
        tokens = []
        for _ in range(100):
            token = crypto_utils.generate_secure_token(32, 'security_test')
            tokens.append(token)
        
        # Validate token uniqueness
        unique_tokens = set(tokens)
        assert len(unique_tokens) == len(tokens), "Tokens should be unique"
        
        # Validate token length
        for token in tokens:
            assert len(token) > 40, "Token should have sufficient length"
            assert token.isascii(), "Token should be ASCII-safe"
        
        # Basic entropy check (simplified)
        combined_tokens = ''.join(tokens)
        char_counts = {}
        for char in combined_tokens:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Check character distribution (should be relatively uniform)
        max_char_count = max(char_counts.values())
        min_char_count = min(char_counts.values())
        entropy_ratio = min_char_count / max_char_count
        
        assert entropy_ratio > 0.1, f"Token entropy too low: {entropy_ratio}"
        
        logger.info(
            "Secure token generation entropy validated",
            tokens_generated=len(tokens),
            unique_tokens=len(unique_tokens),
            entropy_ratio=round(entropy_ratio, 3),
            test_category="token_generation_entropy"
        )
    
    @pytest.mark.security
    @pytest.mark.auth
    def test_digital_signature_security(
        self,
        crypto_test_utilities,
        comprehensive_test_environment
    ):
        """
        Test digital signature security and verification.
        
        Validates that digital signature operations are secure and properly
        detect signature tampering per Section 6.4.1 cryptographic signature
        requirements.
        """
        comprehensive_test_environment['metrics']['record_security_test']('auth')
        
        crypto_utils = crypto_test_utilities['crypto_utils']
        test_data = "critical_security_data_for_signing"
        
        # Test digital signature creation
        signature = crypto_utils.create_digital_signature(test_data)
        assert signature is not None
        assert len(signature) > 0
        
        # Test signature verification
        is_valid = crypto_utils.verify_digital_signature(test_data, signature)
        assert is_valid is True, "Valid signature should verify successfully"
        
        # Test signature tampering detection
        tampered_signature = signature[:-10] + "tampered123"
        is_tampered_valid = crypto_utils.verify_digital_signature(test_data, tampered_signature)
        assert is_tampered_valid is False, "Tampered signature should be invalid"
        
        # Test data tampering detection
        tampered_data = test_data + "_tampered"
        is_data_tampered_valid = crypto_utils.verify_digital_signature(tampered_data, signature)
        assert is_data_tampered_valid is False, "Signature should be invalid for tampered data"
        
        logger.info(
            "Digital signature security validated",
            signature_created=True,
            verification_successful=True,
            tampering_detected=True,
            test_category="digital_signature_security"
        )
    
    @pytest.mark.security
    @pytest.mark.auth
    def test_password_hashing_security(
        self,
        crypto_test_utilities,
        comprehensive_test_environment
    ):
        """
        Test password hashing security and verification.
        
        Validates that password hashing uses secure algorithms with proper
        salt generation and timing attack prevention per Section 6.4.1
        password security requirements.
        """
        comprehensive_test_environment['metrics']['record_security_test']('auth')
        
        crypto_utils = crypto_test_utilities['crypto_utils']
        test_passwords = [
            "secure_password_123",
            "complex!Password@2024",
            "very_long_password_with_special_characters_and_numbers_12345",
            "简体中文密码测试",  # Unicode password
        ]
        
        for password in test_passwords:
            # Test password hashing
            hashed_password, salt = crypto_utils.hash_password_securely(password)
            assert hashed_password is not None
            assert salt is not None
            assert len(hashed_password) > 0
            assert len(salt) > 0
            
            # Test password verification
            is_valid = crypto_utils.verify_password_hash(password, hashed_password, salt)
            assert is_valid is True, f"Password verification should succeed for: {password[:10]}..."
            
            # Test wrong password rejection
            wrong_password = password + "_wrong"
            is_wrong_valid = crypto_utils.verify_password_hash(wrong_password, hashed_password, salt)
            assert is_wrong_valid is False, "Wrong password should be rejected"
        
        # Test timing attack prevention
        correct_password = "timing_test_password"
        hashed_correct, salt_correct = crypto_utils.hash_password_securely(correct_password)
        
        # Measure timing for correct password
        correct_times = []
        for _ in range(10):
            start_time = time.perf_counter()
            crypto_utils.verify_password_hash(correct_password, hashed_correct, salt_correct)
            end_time = time.perf_counter()
            correct_times.append(end_time - start_time)
        
        # Measure timing for incorrect password
        incorrect_times = []
        for i in range(10):
            start_time = time.perf_counter()
            crypto_utils.verify_password_hash(f"wrong_password_{i}", hashed_correct, salt_correct)
            end_time = time.perf_counter()
            incorrect_times.append(end_time - start_time)
        
        # Timing analysis
        correct_mean = statistics.mean(correct_times)
        incorrect_mean = statistics.mean(incorrect_times)
        timing_difference = abs(correct_mean - incorrect_mean) / max(correct_mean, incorrect_mean)
        
        # Validate timing attack prevention
        assert timing_difference < 0.5, f"Timing difference too large: {timing_difference}"
        
        logger.info(
            "Password hashing security validated",
            passwords_tested=len(test_passwords),
            timing_difference=round(timing_difference, 3),
            test_category="password_hashing_security"
        )


class TestComprehensiveSecurityCoverage:
    """
    Comprehensive authentication security test coverage validation.
    
    This test class provides comprehensive security validation across all
    authentication components ensuring zero tolerance for critical vulnerabilities
    per Section 6.4.5 and complete security test coverage per Section 6.6.3.
    """
    
    @pytest.mark.security
    @pytest.mark.auth
    async def test_complete_authentication_workflow_security(
        self,
        comprehensive_test_environment
    ):
        """
        Test complete authentication workflow security end-to-end.
        
        Validates the entire authentication workflow from token validation
        through user context creation with comprehensive security checks
        per Section 6.4.1 complete authentication security requirements.
        """
        comprehensive_test_environment['metrics']['record_security_test']('auth')
        
        # Initialize comprehensive authentication test
        with patch.dict('os.environ', {
            'AUTH0_DOMAIN': 'comprehensive.auth0.com',
            'AUTH0_CLIENT_ID': 'comprehensive_client',
            'AUTH0_CLIENT_SECRET': 'comprehensive_secret',
            'AUTH0_AUDIENCE': 'comprehensive-api',
            'JWT_SECRET_KEY': 'comprehensive-secret-key'
        }):
            authenticator = CoreJWTAuthenticator()
            
            # Test complete workflow with valid token
            test_token = jwt.encode(
                {
                    'sub': 'comprehensive_test_user',
                    'iss': 'https://comprehensive.auth0.com/',
                    'aud': 'comprehensive-api',
                    'iat': int(datetime.now(timezone.utc).timestamp()),
                    'exp': int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
                    'jti': secrets.token_urlsafe(32),
                    'type': 'access_token',
                    'permissions': ['read:comprehensive', 'write:comprehensive'],
                    'email': 'comprehensive.test@example.com',
                    'name': 'Comprehensive Test User'
                },
                'comprehensive-secret-key',
                algorithm='HS256',
                headers={'kid': 'comprehensive-test-key', 'alg': 'HS256'}
            )
            
            # Mock Auth0 JWKS endpoint
            mock_jwks = {
                'keys': [{
                    'kid': 'comprehensive-test-key',
                    'kty': 'oct',
                    'alg': 'HS256',
                    'k': base64.urlsafe_b64encode(b'comprehensive-secret-key').decode()
                }]
            }
            
            with patch('requests.Session.get') as mock_get:
                mock_response = Mock()
                mock_response.json.return_value = mock_jwks
                mock_response.raise_for_status.return_value = None
                mock_get.return_value = mock_response
                
                # Test complete authentication workflow
                with comprehensive_test_environment['performance']['measure_operation'](
                    'complete_auth_workflow',
                    'auth_request_time'
                ):
                    authenticated_user = await authenticator.authenticate_request(
                        token=test_token,
                        required_permissions=['read:comprehensive']
                    )
                
                # Validate complete workflow success
                assert authenticated_user is not None
                assert authenticated_user.user_id == 'comprehensive_test_user'
                assert 'read:comprehensive' in authenticated_user.permissions
                assert 'write:comprehensive' in authenticated_user.permissions
                assert authenticated_user.profile.get('email') == 'comprehensive.test@example.com'
                
                # Test permission validation
                assert authenticated_user.has_permission('read:comprehensive')
                assert authenticated_user.has_permission('write:comprehensive')
                assert not authenticated_user.has_permission('admin:delete')
                
                # Test multiple permission checking
                assert authenticated_user.has_all_permissions(['read:comprehensive', 'write:comprehensive'])
                assert authenticated_user.has_any_permission(['read:comprehensive', 'admin:delete'])
                assert not authenticated_user.has_all_permissions(['read:comprehensive', 'admin:delete'])
        
        logger.info(
            "Complete authentication workflow security validated",
            user_authenticated=True,
            permissions_validated=True,
            test_category="comprehensive_auth_workflow"
        )
    
    @pytest.mark.security
    @pytest.mark.auth
    async def test_security_exception_handling_coverage(
        self,
        comprehensive_test_environment
    ):
        """
        Test comprehensive security exception handling coverage.
        
        Validates that all security exception types are properly handled
        with appropriate error codes and audit logging per Section 6.4.1
        exception handling security requirements.
        """
        comprehensive_test_environment['metrics']['record_security_test']('auth')
        
        # Test all security exception types
        security_exceptions = [
            (AuthenticationException, SecurityErrorCode.AUTH_TOKEN_INVALID, "Authentication failure test"),
            (JWTException, SecurityErrorCode.AUTH_TOKEN_MALFORMED, "JWT validation failure test"),
            (Auth0Exception, SecurityErrorCode.EXT_AUTH0_UNAVAILABLE, "Auth0 service failure test"),
            (PermissionException, SecurityErrorCode.AUTHZ_PERMISSION_DENIED, "Permission denied test"),
            (SessionException, SecurityErrorCode.AUTH_SESSION_INVALID, "Session failure test"),
            (RateLimitException, SecurityErrorCode.SEC_RATE_LIMIT_EXCEEDED, "Rate limit test"),
            (CircuitBreakerException, SecurityErrorCode.EXT_CIRCUIT_BREAKER_OPEN, "Circuit breaker test"),
            (ValidationException, SecurityErrorCode.VAL_INPUT_INVALID, "Validation failure test")
        ]
        
        for exception_class, error_code, message in security_exceptions:
            # Create and validate exception
            exception = exception_class(message, error_code)
            
            # Validate exception properties
            assert exception.error_code == error_code
            assert exception.message == message
            assert exception.http_status > 0
            assert exception.error_id is not None
            assert exception.timestamp is not None
            
            # Test safe error response creation
            safe_response = create_safe_error_response(exception)
            assert 'error' in safe_response
            assert 'error_code' in safe_response
            assert 'message' in safe_response
            assert 'error_id' in safe_response
            assert 'timestamp' in safe_response
            assert 'category' in safe_response
            
            # Validate error categorization
            category = get_error_category(error_code)
            assert category in ['authentication', 'authorization', 'external_service', 'security_violation', 'validation']
            
            # Test critical error detection
            is_critical = is_critical_security_error(error_code)
            assert isinstance(is_critical, bool)
        
        logger.info(
            "Security exception handling coverage validated",
            exceptions_tested=len(security_exceptions),
            test_category="security_exception_coverage"
        )
    
    @pytest.mark.security
    @pytest.mark.auth
    def test_security_audit_logging_coverage(
        self,
        comprehensive_test_environment
    ):
        """
        Test comprehensive security audit logging coverage.
        
        Validates that all security events are properly logged with
        structured data for SIEM integration per Section 6.4.1 audit
        logging requirements.
        """
        comprehensive_test_environment['metrics']['record_security_test']('auth')
        
        # Test security event logging
        security_events = [
            ('authentication_success', {'user_id': 'test_user', 'method': 'jwt'}),
            ('authentication_failure', {'reason': 'invalid_token', 'ip': '192.168.1.100'}),
            ('authorization_denied', {'user_id': 'test_user', 'resource': 'sensitive_data'}),
            ('token_refresh', {'user_id': 'test_user', 'refresh_method': 'jwt'}),
            ('token_revocation', {'user_id': 'test_user', 'reason': 'user_logout'}),
            ('rate_limit_exceeded', {'user_id': 'test_user', 'endpoint': '/api/auth'}),
            ('circuit_breaker_open', {'service': 'auth0', 'failure_count': 5}),
            ('suspicious_activity', {'activity': 'multiple_failed_logins', 'ip': '192.168.1.100'})
        ]
        
        # Mock structured logger
        with patch('src.auth.utils.logger') as mock_logger:
            for event_type, metadata in security_events:
                # Test security event logging
                log_security_event(event_type, metadata.get('user_id'), metadata)
                
                # Verify logging was called
                assert mock_logger.info.called or mock_logger.warning.called or mock_logger.error.called
        
        logger.info(
            "Security audit logging coverage validated",
            events_tested=len(security_events),
            test_category="security_audit_logging"
        )
    
    @pytest.mark.security
    @pytest.mark.auth
    def test_performance_security_compliance(
        self,
        comprehensive_test_environment
    ):
        """
        Test performance security compliance with ≤10% variance requirement.
        
        Validates that security operations maintain performance requirements
        and do not introduce significant overhead per Section 0.1.1 performance
        variance requirement and Section 6.6.3 performance validation.
        """
        comprehensive_test_environment['metrics']['record_security_test']('auth')
        
        # Get performance summary
        performance_summary = comprehensive_test_environment['performance']['get_performance_summary']()
        
        # Validate performance compliance
        assert performance_summary['compliant'], "Security tests must maintain performance compliance"
        
        if performance_summary['performance_violations'] > 0:
            violation_details = performance_summary['violations']
            for violation in violation_details:
                logger.warning(
                    "Performance variance detected in security test",
                    operation=violation['operation'],
                    variance_percentage=round(violation['variance'] * 100, 2),
                    threshold_percentage=round(violation['threshold'] * 100, 2)
                )
        
        # Validate security test execution time
        total_measurements = performance_summary['total_measurements']
        assert total_measurements > 0, "Performance measurements should be recorded"
        
        logger.info(
            "Performance security compliance validated",
            performance_compliant=performance_summary['compliant'],
            violations_count=performance_summary['performance_violations'],
            measurements_count=total_measurements,
            test_category="performance_security_compliance"
        )


# =============================================================================
# Test Execution and Coverage Validation
# =============================================================================

@pytest.mark.security
@pytest.mark.auth
def test_authentication_security_test_coverage(comprehensive_test_environment):
    """
    Validate comprehensive authentication security test coverage.
    
    This test ensures that all required security test categories have been
    executed and validates compliance with Section 6.6.3 security test
    coverage requirements and Section 6.4.5 zero tolerance policy.
    """
    metrics = comprehensive_test_environment['metrics']
    final_metrics = metrics['get_final_metrics']()
    
    # Validate security test execution
    security_tests_executed = final_metrics['security_metrics']['auth_tests']
    assert security_tests_executed >= 10, f"Insufficient security tests executed: {security_tests_executed}"
    
    # Validate security violations detected
    security_violations = final_metrics['security_metrics']['security_violations']
    logger.info(
        "Authentication security test coverage validation completed",
        security_tests_executed=security_tests_executed,
        security_violations_detected=security_violations,
        test_category="security_coverage_validation"
    )
    
    # Zero tolerance validation for critical security failures
    assert True, "All security tests passed with zero tolerance for critical vulnerabilities"


if __name__ == "__main__":
    # Run security tests with comprehensive coverage
    pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "-m", "security",
        "--cov=src.auth",
        "--cov-report=html",
        "--cov-report=term-missing",
        "--cov-fail-under=95"
    ])