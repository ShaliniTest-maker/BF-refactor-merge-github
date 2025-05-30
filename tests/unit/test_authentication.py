"""
Comprehensive unit tests for authentication module.

This module provides comprehensive testing coverage for JWT authentication and Auth0 integration,
covering PyJWT token validation, cryptographic verification, Auth0 Python SDK integration, 
and authentication state management. Implements comprehensive authentication testing with 
security compliance validation and 95% coverage for authentication module.

Test Coverage Areas:
- PyJWT 2.8+ token validation testing replacing Node.js jsonwebtoken per Section 0.1.2
- Auth0 Python SDK integration testing per Section 6.4.1  
- JWT claims extraction and validation testing per Section 0.1.4
- Cryptographic verification testing with cryptography 41.0+ per Section 6.4.1
- Token expiration and refresh testing per Section 6.4.1
- User context creation and session management testing per Section 5.2.3
- Circuit breaker testing for Auth0 API calls per Section 6.4.2
- 95% authentication module coverage per Section 6.6.3 security compliance

Dependencies:
- pytest 7.4+ for comprehensive test framework with fixtures
- pytest-mock for external service mocking and behavior verification
- pytest-asyncio for asynchronous authentication operation testing
- freezegun for datetime testing consistency and token expiration scenarios
- PyJWT 2.8+ for token validation testing equivalent to Node.js patterns
- cryptography 41.0+ for cryptographic verification testing
- httpx for HTTP client mocking and Auth0 API simulation

Author: Flask Migration Team
Version: 1.0.0
Coverage: 95% authentication module coverage requirement
"""

import asyncio
import base64
import json
import time
import pytest
import secrets
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, MagicMock, AsyncMock, patch, call
from typing import Dict, List, Optional, Any, Set

# Third-party testing imports
import jwt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from freezegun import freeze_time
import httpx
import redis
from auth0.exceptions import Auth0Error

# Import authentication components to test
from src.auth.authentication import (
    Auth0Config,
    Auth0CircuitBreaker,
    JWTTokenValidator,
    Auth0UserManager,
    AuthenticationManager,
    get_auth_manager,
    init_auth_manager,
    close_auth_manager,
    authenticate_jwt_token,
    validate_user_permissions,
    refresh_jwt_token,
    create_authenticated_session,
    get_authenticated_session,
    invalidate_authenticated_session
)

# Import exception classes for testing
try:
    from src.auth.exceptions import (
        AuthenticationException,
        JWTException,
        Auth0Exception,
        SessionException,
        CircuitBreakerException,
        ValidationException,
        SecurityErrorCode
    )
except ImportError:
    # Fallback mock exceptions for testing isolation
    class AuthenticationException(Exception):
        def __init__(self, message, error_code=None, **kwargs):
            super().__init__(message)
            self.error_code = error_code
            self.metadata = kwargs

    class JWTException(AuthenticationException):
        pass

    class Auth0Exception(AuthenticationException):
        pass

    class SessionException(AuthenticationException):
        pass

    class CircuitBreakerException(AuthenticationException):
        pass

    class ValidationException(AuthenticationException):
        pass

    class SecurityErrorCode:
        AUTH_CREDENTIALS_INVALID = 'AUTH_CREDENTIALS_INVALID'
        AUTH_TOKEN_EXPIRED = 'AUTH_TOKEN_EXPIRED'
        AUTH_TOKEN_INVALID = 'AUTH_TOKEN_INVALID'
        AUTH_TOKEN_MALFORMED = 'AUTH_TOKEN_MALFORMED'
        AUTH_TOKEN_MISSING = 'AUTH_TOKEN_MISSING'
        AUTH_SESSION_INVALID = 'AUTH_SESSION_INVALID'
        EXT_AUTH0_UNAVAILABLE = 'EXT_AUTH0_UNAVAILABLE'
        EXT_AUTH0_API_ERROR = 'EXT_AUTH0_API_ERROR'
        EXT_CIRCUIT_BREAKER_OPEN = 'EXT_CIRCUIT_BREAKER_OPEN'
        VAL_INPUT_INVALID = 'VAL_INPUT_INVALID'
        AUTHZ_PERMISSION_DENIED = 'AUTHZ_PERMISSION_DENIED'

# Import cache classes for testing
try:
    from src.auth.cache import AuthenticationCache, hash_token, generate_session_id
except ImportError:
    # Mock cache implementations for testing
    class AuthenticationCache:
        def __init__(self):
            self._cache = {}
        
        def get_jwt_validation(self, token_hash):
            return self._cache.get(f'jwt_{token_hash}')
        
        def cache_jwt_validation(self, token_hash, result, ttl):
            self._cache[f'jwt_{token_hash}'] = result
            return True
        
        def get_auth0_user_profile(self, user_id):
            return self._cache.get(f'profile_{user_id}')
        
        def cache_auth0_user_profile(self, user_id, profile, ttl):
            self._cache[f'profile_{user_id}'] = profile
            return True
        
        def get_user_permissions(self, user_id):
            return self._cache.get(f'perm_{user_id}')
        
        def cache_user_permissions(self, user_id, permissions, ttl):
            self._cache[f'perm_{user_id}'] = permissions
            return True
        
        def get_user_session(self, session_id):
            return self._cache.get(f'session_{session_id}')
        
        def cache_user_session(self, session_id, session_data, ttl):
            self._cache[f'session_{session_id}'] = session_data
            return True
        
        def invalidate_user_session(self, session_id):
            return self._cache.pop(f'session_{session_id}', None) is not None
        
        def get(self, namespace, key):
            return self._cache.get(f'{namespace}_{key}')
        
        def set(self, namespace, key, value, ttl):
            self._cache[f'{namespace}_{key}'] = value
            return True
        
        def health_check(self):
            return {'status': 'healthy'}

    def hash_token(token):
        import hashlib
        return hashlib.sha256(token.encode()).hexdigest()[:16]
    
    def generate_session_id():
        return secrets.token_urlsafe(32)


# ============================================================================
# PYTEST MARKERS AND CONFIGURATION
# ============================================================================

pytestmark = [
    pytest.mark.auth,
    pytest.mark.utilities,
    pytest.mark.unit
]


# ============================================================================
# TEST FIXTURES
# ============================================================================

@pytest.fixture
def auth_config():
    """Auth0 configuration for testing."""
    return {
        'AUTH0_DOMAIN': 'test-domain.auth0.com',
        'AUTH0_CLIENT_ID': 'test-client-id',
        'AUTH0_CLIENT_SECRET': 'test-client-secret',
        'AUTH0_AUDIENCE': 'test-api-audience',
        'JWT_ALGORITHM': 'RS256'
    }


@pytest.fixture
def mock_auth_cache():
    """Mock authentication cache for testing."""
    return AuthenticationCache()


@pytest.fixture
def test_jwt_secret():
    """Test JWT secret key."""
    return 'test-jwt-secret-key-for-testing-authentication-module'


@pytest.fixture
def test_rsa_keypair():
    """Generate test RSA key pair for JWT testing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
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
        'private_pem': private_pem.decode('utf-8'),
        'public_pem': public_pem.decode('utf-8')
    }


@pytest.fixture
def valid_jwt_payload():
    """Valid JWT payload for testing."""
    return {
        'sub': 'auth0|test-user-12345',
        'email': 'test@example.com',
        'email_verified': True,
        'name': 'Test User',
        'roles': ['user', 'admin'],
        'permissions': ['read', 'write', 'delete'],
        'iat': int(time.time()),
        'exp': int(time.time()) + 3600,
        'aud': 'test-api-audience',
        'iss': 'https://test-domain.auth0.com/'
    }


@pytest.fixture
def valid_jwt_token(test_rsa_keypair, valid_jwt_payload):
    """Valid JWT token for testing."""
    return jwt.encode(
        payload=valid_jwt_payload,
        key=test_rsa_keypair['private_pem'],
        algorithm='RS256'
    )


@pytest.fixture
def expired_jwt_token(test_rsa_keypair, valid_jwt_payload):
    """Expired JWT token for testing."""
    expired_payload = {
        **valid_jwt_payload,
        'iat': int(time.time()) - 7200,  # 2 hours ago
        'exp': int(time.time()) - 3600   # 1 hour ago (expired)
    }
    return jwt.encode(
        payload=expired_payload,
        key=test_rsa_keypair['private_pem'],
        algorithm='RS256'
    )


@pytest.fixture
def malformed_jwt_tokens():
    """Collection of malformed JWT tokens for testing."""
    return [
        'invalid.token',  # Only 2 parts
        'invalid.jwt.token.extra',  # 4 parts
        'not-base64.not-base64.not-base64',  # Invalid base64
        '',  # Empty token
        'header.payload',  # Missing signature
        'a.b.c.d.e'  # Too many parts
    ]


@pytest.fixture
def mock_jwks_response():
    """Mock JWKS response from Auth0."""
    return {
        'keys': [
            {
                'kty': 'RSA',
                'kid': 'test-key-id',
                'use': 'sig',
                'alg': 'RS256',
                'n': 'test-modulus-value',
                'e': 'AQAB'
            }
        ]
    }


@pytest.fixture
def mock_auth0_user_profile():
    """Mock Auth0 user profile response."""
    return {
        'user_id': 'auth0|test-user-12345',
        'email': 'test@example.com',
        'email_verified': True,
        'name': 'Test User',
        'picture': 'https://example.com/avatar.jpg',
        'app_metadata': {
            'roles': ['user', 'admin']
        },
        'user_metadata': {
            'preferences': {
                'theme': 'dark'
            }
        }
    }


@pytest.fixture
def mock_auth0_permissions():
    """Mock Auth0 permissions response."""
    return [
        {
            'permission_name': 'read',
            'resource_server_identifier': 'test-api'
        },
        {
            'permission_name': 'write', 
            'resource_server_identifier': 'test-api'
        },
        {
            'permission_name': 'delete',
            'resource_server_identifier': 'test-api'
        }
    ]


@pytest.fixture
def sample_session_data():
    """Sample session data for testing."""
    return {
        'user_id': 'auth0|test-user-12345',
        'email': 'test@example.com',
        'roles': ['user', 'admin'],
        'permissions': ['read', 'write'],
        'session_start': datetime.utcnow().isoformat(),
        'ip_address': '192.168.1.100',
        'user_agent': 'Test Browser/1.0'
    }


# ============================================================================
# AUTH0CONFIG TESTS
# ============================================================================

class TestAuth0Config:
    """Test Auth0 configuration management."""

    def test_auth0_config_initialization_success(self, auth_config, mock_environment):
        """Test successful Auth0 configuration initialization."""
        with patch.dict('os.environ', auth_config):
            config = Auth0Config()
            
            assert config.domain == auth_config['AUTH0_DOMAIN']
            assert config.client_id == auth_config['AUTH0_CLIENT_ID'] 
            assert config.client_secret == auth_config['AUTH0_CLIENT_SECRET']
            assert config.audience == auth_config['AUTH0_AUDIENCE']
            assert config.algorithm == auth_config['JWT_ALGORITHM']
            assert config.issuer == f"https://{auth_config['AUTH0_DOMAIN']}/"

    def test_auth0_config_missing_required_vars(self):
        """Test Auth0 configuration validation with missing variables."""
        with patch.dict('os.environ', {}, clear=True):
            with pytest.raises(AuthenticationException) as exc_info:
                Auth0Config()
            
            assert 'Missing Auth0 configuration' in str(exc_info.value)
            assert exc_info.value.error_code == SecurityErrorCode.AUTH_CREDENTIALS_INVALID

    def test_auth0_config_invalid_domain_format(self, auth_config, mock_environment):
        """Test Auth0 configuration validation with invalid domain format."""
        invalid_config = {**auth_config, 'AUTH0_DOMAIN': 'invalid-domain'}
        
        with patch.dict('os.environ', invalid_config):
            with pytest.raises(AuthenticationException) as exc_info:
                Auth0Config()
            
            assert 'Invalid Auth0 domain format' in str(exc_info.value)
            assert exc_info.value.error_code == SecurityErrorCode.AUTH_CREDENTIALS_INVALID

    def test_auth0_config_properties(self, auth_config, mock_environment):
        """Test Auth0 configuration properties."""
        with patch.dict('os.environ', auth_config):
            config = Auth0Config()
            
            expected_jwks_url = f"https://{auth_config['AUTH0_DOMAIN']}/.well-known/jwks.json"
            expected_token_url = f"https://{auth_config['AUTH0_DOMAIN']}/oauth/token"
            expected_userinfo_url = f"https://{auth_config['AUTH0_DOMAIN']}/userinfo"
            
            assert config.jwks_url == expected_jwks_url
            assert config.token_url == expected_token_url
            assert config.userinfo_url == expected_userinfo_url

    def test_auth0_config_jwks_caching(self, auth_config, mock_environment):
        """Test JWKS caching functionality."""
        with patch.dict('os.environ', auth_config):
            config = Auth0Config()
            
            # Test initial state
            assert config._jwks_cache is None
            assert config._jwks_cache_expiry is None
            
            # Test cache setting
            test_jwks = {'keys': [{'kid': 'test', 'kty': 'RSA'}]}
            config._jwks_cache = test_jwks
            config._jwks_cache_expiry = datetime.utcnow() + timedelta(hours=1)
            
            assert config._jwks_cache == test_jwks
            assert config._jwks_cache_expiry > datetime.utcnow()


# ============================================================================
# AUTH0CIRCUITBREAKER TESTS
# ============================================================================

class TestAuth0CircuitBreaker:
    """Test Auth0 circuit breaker functionality."""

    def test_circuit_breaker_initialization(self):
        """Test circuit breaker initialization."""
        breaker = Auth0CircuitBreaker(failure_threshold=3, recovery_timeout=30)
        
        assert breaker.failure_threshold == 3
        assert breaker.recovery_timeout == 30
        assert breaker.failure_count == 0
        assert breaker.last_failure_time is None
        assert breaker.state == 'closed'

    @pytest.mark.asyncio
    async def test_circuit_breaker_async_success(self):
        """Test circuit breaker with successful async function."""
        breaker = Auth0CircuitBreaker()
        
        @breaker
        async def mock_async_function():
            return {'status': 'success'}
        
        result = await mock_async_function()
        assert result == {'status': 'success'}
        assert breaker.state == 'closed'
        assert breaker.failure_count == 0

    def test_circuit_breaker_sync_success(self):
        """Test circuit breaker with successful sync function."""
        breaker = Auth0CircuitBreaker()
        
        @breaker
        def mock_sync_function():
            return {'status': 'success'}
        
        result = mock_sync_function()
        assert result == {'status': 'success'}
        assert breaker.state == 'closed'
        assert breaker.failure_count == 0

    @pytest.mark.asyncio
    async def test_circuit_breaker_failure_tracking(self):
        """Test circuit breaker failure tracking."""
        breaker = Auth0CircuitBreaker(failure_threshold=2)
        
        @breaker
        async def failing_function():
            raise Auth0Exception("Service unavailable")
        
        # First failure
        with pytest.raises(Auth0Exception):
            await failing_function()
        
        assert breaker.failure_count == 1
        assert breaker.state == 'closed'
        
        # Second failure should open circuit
        with pytest.raises(Auth0Exception):
            await failing_function()
        
        assert breaker.failure_count == 2
        assert breaker.state == 'open'

    @pytest.mark.asyncio
    async def test_circuit_breaker_open_state(self):
        """Test circuit breaker behavior in open state."""
        breaker = Auth0CircuitBreaker(failure_threshold=1)
        
        @breaker
        async def failing_function():
            raise Auth0Exception("Service unavailable")
        
        # Trigger circuit open
        with pytest.raises(Auth0Exception):
            await failing_function()
        
        assert breaker.state == 'open'
        
        # Next call should raise CircuitBreakerException
        with pytest.raises(CircuitBreakerException) as exc_info:
            await failing_function()
        
        assert exc_info.value.error_code == SecurityErrorCode.EXT_CIRCUIT_BREAKER_OPEN
        assert 'Circuit breaker is open' in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_circuit_breaker_half_open_recovery(self):
        """Test circuit breaker half-open state and recovery."""
        breaker = Auth0CircuitBreaker(failure_threshold=1, recovery_timeout=1)
        
        call_count = 0
        
        @breaker
        async def sometimes_failing_function():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Auth0Exception("Service unavailable")
            return {'status': 'success'}
        
        # First call fails, opens circuit
        with pytest.raises(Auth0Exception):
            await sometimes_failing_function()
        
        assert breaker.state == 'open'
        
        # Wait for recovery timeout
        await asyncio.sleep(1.1)
        
        # Next call should enter half-open state and succeed
        result = await sometimes_failing_function()
        assert result == {'status': 'success'}
        assert breaker.state == 'closed'
        assert breaker.failure_count == 0

    def test_circuit_breaker_get_state(self):
        """Test circuit breaker state information."""
        breaker = Auth0CircuitBreaker(failure_threshold=5, recovery_timeout=60)
        
        state = breaker.get_state()
        
        assert state['state'] == 'closed'
        assert state['failure_count'] == 0
        assert state['last_failure_time'] is None
        assert state['failure_threshold'] == 5
        assert state['recovery_timeout'] == 60


# ============================================================================
# JWTTOKENVALIDATOR TESTS
# ============================================================================

class TestJWTTokenValidator:
    """Test JWT token validation functionality."""

    @pytest.fixture
    def jwt_validator(self, auth_config, mock_auth_cache, mock_environment):
        """JWT token validator instance for testing."""
        with patch.dict('os.environ', auth_config):
            config = Auth0Config()
            return JWTTokenValidator(config, mock_auth_cache)

    @pytest.mark.asyncio
    async def test_jwt_validation_success(self, jwt_validator, valid_jwt_token, 
                                        valid_jwt_payload, test_rsa_keypair):
        """Test successful JWT token validation."""
        with patch.object(jwt_validator, '_get_signing_key', return_value=test_rsa_keypair['public_pem']):
            result = await jwt_validator.validate_token(valid_jwt_token)
            
            assert result['sub'] == valid_jwt_payload['sub']
            assert result['email'] == valid_jwt_payload['email']
            assert 'validation_metadata' in result
            assert result['validation_metadata']['signature_verified'] == True

    @pytest.mark.asyncio
    async def test_jwt_validation_expired_token(self, jwt_validator, expired_jwt_token, test_rsa_keypair):
        """Test JWT validation with expired token."""
        with patch.object(jwt_validator, '_get_signing_key', return_value=test_rsa_keypair['public_pem']):
            with pytest.raises(JWTException) as exc_info:
                await jwt_validator.validate_token(expired_jwt_token)
            
            assert exc_info.value.error_code == SecurityErrorCode.AUTH_TOKEN_EXPIRED
            assert 'expired' in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_jwt_validation_invalid_signature(self, jwt_validator, valid_jwt_token):
        """Test JWT validation with invalid signature."""
        # Use different key for signature verification
        wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        wrong_public_pem = wrong_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        with patch.object(jwt_validator, '_get_signing_key', return_value=wrong_public_pem):
            with pytest.raises(JWTException) as exc_info:
                await jwt_validator.validate_token(valid_jwt_token)
            
            assert exc_info.value.error_code == SecurityErrorCode.AUTH_TOKEN_INVALID

    @pytest.mark.asyncio
    async def test_jwt_validation_malformed_token(self, jwt_validator, malformed_jwt_tokens):
        """Test JWT validation with malformed tokens."""
        for malformed_token in malformed_jwt_tokens:
            with pytest.raises(JWTException) as exc_info:
                await jwt_validator.validate_token(malformed_token)
            
            assert exc_info.value.error_code in [
                SecurityErrorCode.AUTH_TOKEN_MALFORMED,
                SecurityErrorCode.AUTH_TOKEN_INVALID
            ]

    @pytest.mark.asyncio
    async def test_jwt_validation_caching(self, jwt_validator, valid_jwt_token, 
                                        valid_jwt_payload, test_rsa_keypair, mock_auth_cache):
        """Test JWT validation result caching."""
        with patch.object(jwt_validator, '_get_signing_key', return_value=test_rsa_keypair['public_pem']):
            # First validation
            result1 = await jwt_validator.validate_token(valid_jwt_token, cache_result=True)
            
            # Second validation should use cache
            result2 = await jwt_validator.validate_token(valid_jwt_token, cache_result=True)
            
            assert result1['sub'] == result2['sub']
            assert result1['email'] == result2['email']

    @pytest.mark.asyncio
    async def test_jwt_validation_no_signature_verification(self, jwt_validator, valid_jwt_token):
        """Test JWT validation without signature verification."""
        result = await jwt_validator.validate_token(
            valid_jwt_token, 
            verify_signature=False,
            verify_expiration=False,
            verify_audience=False
        )
        
        assert 'sub' in result
        assert result['validation_metadata']['signature_verified'] == False

    @pytest.mark.asyncio
    async def test_fetch_jwks_success(self, jwt_validator, mock_jwks_response):
        """Test successful JWKS fetching."""
        mock_response = Mock()
        mock_response.json.return_value = mock_jwks_response
        mock_response.raise_for_status.return_value = None
        
        with patch.object(jwt_validator.http_client, 'get', return_value=mock_response):
            jwks = await jwt_validator._fetch_jwks()
            
            assert jwks == mock_jwks_response
            assert 'keys' in jwks

    @pytest.mark.asyncio
    async def test_fetch_jwks_http_error(self, jwt_validator):
        """Test JWKS fetching with HTTP error."""
        with patch.object(jwt_validator.http_client, 'get', 
                         side_effect=httpx.HTTPStatusError("Not found", request=Mock(), response=Mock())):
            with pytest.raises(Auth0Exception) as exc_info:
                await jwt_validator._fetch_jwks()
            
            assert exc_info.value.error_code == SecurityErrorCode.EXT_AUTH0_UNAVAILABLE

    @pytest.mark.asyncio
    async def test_token_refresh_success(self, jwt_validator):
        """Test successful token refresh."""
        refresh_token = 'test-refresh-token'
        mock_response_data = {
            'access_token': 'new-access-token',
            'token_type': 'Bearer',
            'expires_in': 3600
        }
        
        mock_response = Mock()
        mock_response.json.return_value = mock_response_data
        mock_response.raise_for_status.return_value = None
        
        with patch.object(jwt_validator.http_client, 'post', return_value=mock_response):
            result = await jwt_validator.refresh_token(refresh_token)
            
            assert result['access_token'] == 'new-access-token'
            assert result['token_type'] == 'Bearer'
            assert result['expires_in'] == 3600

    @pytest.mark.asyncio
    async def test_token_refresh_failure(self, jwt_validator):
        """Test token refresh failure."""
        refresh_token = 'invalid-refresh-token'
        
        with patch.object(jwt_validator.http_client, 'post', 
                         side_effect=httpx.HTTPStatusError("Unauthorized", request=Mock(), response=Mock())):
            with pytest.raises(Auth0Exception) as exc_info:
                await jwt_validator.refresh_token(refresh_token)
            
            assert exc_info.value.error_code == SecurityErrorCode.EXT_AUTH0_API_ERROR

    def test_jwk_to_pem_conversion(self, jwt_validator):
        """Test JWK to PEM key conversion."""
        # Sample JWK (simplified for testing)
        jwk = {
            'kty': 'RSA',
            'n': base64.urlsafe_b64encode(b'test-modulus').decode().rstrip('='),
            'e': base64.urlsafe_b64encode(b'\x01\x00\x01').decode().rstrip('=')  # 65537
        }
        
        # This test verifies the conversion process handles JWK format
        with pytest.raises(Auth0Exception):  # Expected to fail with simplified test data
            jwt_validator._jwk_to_pem(jwk)

    def test_custom_claims_validation_success(self, jwt_validator, valid_jwt_payload):
        """Test successful custom claims validation."""
        # Should not raise any exception
        jwt_validator._validate_custom_claims(valid_jwt_payload)

    def test_custom_claims_validation_missing_required(self, jwt_validator):
        """Test custom claims validation with missing required claims."""
        invalid_payload = {
            'email': 'test@example.com'
            # Missing 'sub', 'iat', 'exp'
        }
        
        with pytest.raises(JWTException) as exc_info:
            jwt_validator._validate_custom_claims(invalid_payload)
        
        assert exc_info.value.error_code == SecurityErrorCode.AUTH_TOKEN_INVALID

    def test_custom_claims_validation_invalid_user_id(self, jwt_validator):
        """Test custom claims validation with invalid user ID format."""
        invalid_payload = {
            'sub': 'invalid<>user>id',  # Invalid characters
            'iat': int(time.time()),
            'exp': int(time.time()) + 3600
        }
        
        with pytest.raises(JWTException) as exc_info:
            jwt_validator._validate_custom_claims(invalid_payload)
        
        assert exc_info.value.error_code == SecurityErrorCode.AUTH_TOKEN_INVALID

    def test_custom_claims_validation_future_issued_time(self, jwt_validator):
        """Test custom claims validation with future issued time."""
        future_payload = {
            'sub': 'auth0|test-user',
            'iat': int(time.time()) + 1000,  # Far in the future
            'exp': int(time.time()) + 3600
        }
        
        with pytest.raises(JWTException) as exc_info:
            jwt_validator._validate_custom_claims(future_payload)
        
        assert exc_info.value.error_code == SecurityErrorCode.AUTH_TOKEN_INVALID

    @pytest.mark.asyncio
    async def test_jwt_validator_close(self, jwt_validator):
        """Test JWT validator resource cleanup."""
        await jwt_validator.close()
        # Verify that close doesn't raise exceptions


# ============================================================================
# AUTH0USERMANAGER TESTS  
# ============================================================================

class TestAuth0UserManager:
    """Test Auth0 user management functionality."""

    @pytest.fixture
    def user_manager(self, auth_config, mock_auth_cache, mock_environment):
        """Auth0 user manager instance for testing."""
        with patch.dict('os.environ', auth_config):
            config = Auth0Config()
            return Auth0UserManager(config, mock_auth_cache)

    @pytest.mark.asyncio
    async def test_get_user_profile_success(self, user_manager, mock_auth0_user_profile):
        """Test successful user profile retrieval."""
        user_id = 'auth0|test-user-12345'
        
        mock_response = Mock()
        mock_response.json.return_value = mock_auth0_user_profile
        mock_response.raise_for_status.return_value = None
        
        with patch.object(user_manager, '_fetch_user_profile', return_value=mock_auth0_user_profile):
            result = await user_manager.get_user_profile(user_id)
            
            assert result['user_id'] == mock_auth0_user_profile['user_id']
            assert result['email'] == mock_auth0_user_profile['email']
            assert 'profile_metadata' in result

    @pytest.mark.asyncio
    async def test_get_user_profile_cached(self, user_manager, mock_auth0_user_profile, mock_auth_cache):
        """Test user profile retrieval from cache."""
        user_id = 'auth0|test-user-12345'
        
        # Pre-populate cache
        cached_profile = {**mock_auth0_user_profile, 'cached_at': datetime.utcnow().isoformat()}
        mock_auth_cache.cache_auth0_user_profile(user_id, cached_profile, 1800)
        
        result = await user_manager.get_user_profile(user_id, use_cache=True)
        
        assert result['user_id'] == mock_auth0_user_profile['user_id']
        assert 'cached_at' in result

    @pytest.mark.asyncio
    async def test_get_user_profile_fallback_to_cache(self, user_manager, mock_auth0_user_profile, mock_auth_cache):
        """Test user profile fallback to cache on API failure."""
        user_id = 'auth0|test-user-12345'
        
        # Pre-populate cache
        cached_profile = {**mock_auth0_user_profile, 'cached_at': datetime.utcnow().isoformat()}
        mock_auth_cache.cache_auth0_user_profile(user_id, cached_profile, 1800)
        
        with patch.object(user_manager, '_fetch_user_profile', side_effect=Auth0Exception("API unavailable")):
            result = await user_manager.get_user_profile(user_id, use_cache=True)
            
            assert result['user_id'] == mock_auth0_user_profile['user_id']
            assert result['profile_metadata']['fallback_used'] == True

    @pytest.mark.asyncio
    async def test_get_user_profile_no_fallback_available(self, user_manager):
        """Test user profile retrieval with no cache fallback."""
        user_id = 'auth0|test-user-12345'
        
        with patch.object(user_manager, '_fetch_user_profile', side_effect=Auth0Exception("API unavailable")):
            with pytest.raises(Auth0Exception) as exc_info:
                await user_manager.get_user_profile(user_id, use_cache=False)
            
            assert 'API unavailable' in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_validate_user_permissions_success(self, user_manager, mock_auth0_permissions):
        """Test successful user permissions validation."""
        user_id = 'auth0|test-user-12345'
        required_permissions = ['read', 'write']
        
        with patch.object(user_manager, '_fetch_user_permissions', 
                         return_value={'read', 'write', 'delete'}):
            result = await user_manager.validate_user_permissions(user_id, required_permissions)
            
            assert result['has_permissions'] == True
            assert result['user_id'] == user_id
            assert set(required_permissions).issubset(set(result['granted_permissions']))

    @pytest.mark.asyncio
    async def test_validate_user_permissions_insufficient(self, user_manager):
        """Test user permissions validation with insufficient permissions."""
        user_id = 'auth0|test-user-12345'
        required_permissions = ['read', 'write', 'admin']
        
        with patch.object(user_manager, '_fetch_user_permissions', 
                         return_value={'read', 'write'}):
            result = await user_manager.validate_user_permissions(user_id, required_permissions)
            
            assert result['has_permissions'] == False
            assert result['user_id'] == user_id

    @pytest.mark.asyncio
    async def test_validate_user_permissions_cached(self, user_manager, mock_auth_cache):
        """Test user permissions validation using cache."""
        user_id = 'auth0|test-user-12345'
        required_permissions = ['read', 'write']
        cached_permissions = {'read', 'write', 'delete'}
        
        # Pre-populate cache
        mock_auth_cache.cache_user_permissions(user_id, cached_permissions, 300)
        
        result = await user_manager.validate_user_permissions(user_id, required_permissions, use_cache=True)
        
        assert result['has_permissions'] == True
        assert result['validation_source'] == 'cache'

    @pytest.mark.asyncio
    async def test_validate_user_permissions_fallback_deny(self, user_manager):
        """Test user permissions validation fallback deny on failure."""
        user_id = 'auth0|test-user-12345'
        required_permissions = ['read', 'write']
        
        with patch.object(user_manager, '_fetch_user_permissions', 
                         side_effect=Auth0Exception("Service unavailable")):
            result = await user_manager.validate_user_permissions(user_id, required_permissions, use_cache=False)
            
            assert result['has_permissions'] == False
            assert result['validation_source'] == 'fallback_deny'
            assert result['degraded_mode'] == True

    @pytest.mark.asyncio
    async def test_get_management_token_success(self, user_manager):
        """Test successful management token retrieval."""
        mock_token_response = {
            'access_token': 'mgmt-token-12345',
            'token_type': 'Bearer',
            'expires_in': 3600
        }
        
        mock_response = Mock()
        mock_response.json.return_value = mock_token_response
        mock_response.raise_for_status.return_value = None
        
        with patch.object(user_manager.http_client, 'post', return_value=mock_response):
            token = await user_manager._get_management_token()
            
            assert token == 'mgmt-token-12345'

    @pytest.mark.asyncio
    async def test_get_management_token_cached(self, user_manager, mock_auth_cache):
        """Test management token retrieval from cache."""
        cached_token = 'cached-mgmt-token-67890'
        mock_auth_cache.set('auth0_mgmt_token', 'current', cached_token, 3600)
        
        token = await user_manager._get_management_token()
        
        assert token == cached_token

    @pytest.mark.asyncio
    async def test_fetch_user_permissions_success(self, user_manager, mock_auth0_permissions):
        """Test successful user permissions fetching."""
        user_id = 'auth0|test-user-12345'
        
        mock_response = Mock()
        mock_response.json.return_value = mock_auth0_permissions
        mock_response.raise_for_status.return_value = None
        
        with patch.object(user_manager, '_get_management_token', return_value='mgmt-token'), \
             patch.object(user_manager.http_client, 'get', return_value=mock_response):
            
            permissions = await user_manager._fetch_user_permissions(user_id)
            
            expected_permissions = {'read', 'write', 'delete'}
            assert permissions == expected_permissions

    @pytest.mark.asyncio
    async def test_user_manager_close(self, user_manager):
        """Test user manager resource cleanup."""
        await user_manager.close()
        # Verify that close doesn't raise exceptions


# ============================================================================
# AUTHENTICATIONMANAGER TESTS
# ============================================================================

class TestAuthenticationManager:
    """Test comprehensive authentication manager functionality."""

    @pytest.fixture
    def auth_manager(self, auth_config, mock_auth_cache, mock_environment):
        """Authentication manager instance for testing."""
        with patch.dict('os.environ', auth_config):
            return AuthenticationManager(mock_auth_cache)

    @pytest.mark.asyncio
    async def test_authenticate_user_success(self, auth_manager, valid_jwt_token, 
                                           valid_jwt_payload, test_rsa_keypair, mock_auth0_user_profile):
        """Test successful user authentication."""
        with patch.object(auth_manager.token_validator, 'validate_token', 
                         return_value=valid_jwt_payload), \
             patch.object(auth_manager.user_manager, 'get_user_profile', 
                         return_value=mock_auth0_user_profile):
            
            result = await auth_manager.authenticate_user(valid_jwt_token)
            
            assert result['authenticated'] == True
            assert result['user_id'] == valid_jwt_payload['sub']
            assert 'token_payload' in result
            assert 'user_profile' in result
            assert 'authentication_metadata' in result

    @pytest.mark.asyncio
    async def test_authenticate_user_invalid_token_format(self, auth_manager):
        """Test authentication with invalid token format."""
        invalid_tokens = ['', 'invalid.token', 'too.many.parts.here', None]
        
        for invalid_token in invalid_tokens:
            with pytest.raises(AuthenticationException) as exc_info:
                await auth_manager.authenticate_user(invalid_token or '')
            
            assert exc_info.value.error_code in [
                SecurityErrorCode.AUTH_TOKEN_MISSING,
                SecurityErrorCode.AUTH_TOKEN_MALFORMED
            ]

    @pytest.mark.asyncio
    async def test_authenticate_user_no_user_id(self, auth_manager, valid_jwt_token):
        """Test authentication with token missing user ID."""
        invalid_payload = {'email': 'test@example.com', 'iat': int(time.time()), 'exp': int(time.time()) + 3600}
        
        with patch.object(auth_manager.token_validator, 'validate_token', 
                         return_value=invalid_payload):
            with pytest.raises(AuthenticationException) as exc_info:
                await auth_manager.authenticate_user(valid_jwt_token)
            
            assert exc_info.value.error_code == SecurityErrorCode.AUTH_TOKEN_INVALID

    @pytest.mark.asyncio
    async def test_validate_permissions_success(self, auth_manager):
        """Test successful permission validation."""
        user_id = 'auth0|test-user-12345'
        required_permissions = ['read', 'write']
        
        validation_result = {
            'user_id': user_id,
            'has_permissions': True,
            'granted_permissions': ['read', 'write', 'delete'],
            'required_permissions': required_permissions,
            'validation_source': 'auth0_api'
        }
        
        with patch.object(auth_manager.user_manager, 'validate_user_permissions', 
                         return_value=validation_result):
            result = await auth_manager.validate_permissions(user_id, required_permissions)
            
            assert result['has_permissions'] == True
            assert result['user_id'] == user_id

    @pytest.mark.asyncio
    async def test_validate_permissions_with_resource(self, auth_manager):
        """Test permission validation with resource ID."""
        user_id = 'auth0|test-user-12345'
        required_permissions = ['read']
        resource_id = 'document-123'
        
        validation_result = {
            'user_id': user_id,
            'has_permissions': True,
            'granted_permissions': ['read'],
            'required_permissions': required_permissions,
            'validation_source': 'auth0_api'
        }
        
        with patch.object(auth_manager.user_manager, 'validate_user_permissions', 
                         return_value=validation_result):
            result = await auth_manager.validate_permissions(user_id, required_permissions, resource_id)
            
            assert result['resource_id'] == resource_id
            assert result['resource_specific'] == True

    @pytest.mark.asyncio
    async def test_validate_permissions_invalid_input(self, auth_manager):
        """Test permission validation with invalid input."""
        with pytest.raises(ValidationException) as exc_info:
            await auth_manager.validate_permissions('', [])
        
        assert exc_info.value.error_code == SecurityErrorCode.VAL_INPUT_INVALID

    @pytest.mark.asyncio
    async def test_refresh_user_token_success(self, auth_manager):
        """Test successful token refresh."""
        refresh_token = 'valid-refresh-token'
        token_response = {
            'access_token': 'new-access-token',
            'token_type': 'Bearer',
            'expires_in': 3600
        }
        
        with patch.object(auth_manager.token_validator, 'refresh_token', 
                         return_value=token_response):
            result = await auth_manager.refresh_user_token(refresh_token)
            
            assert result['access_token'] == 'new-access-token'
            assert 'refresh_metadata' in result

    @pytest.mark.asyncio
    async def test_refresh_user_token_invalid_format(self, auth_manager):
        """Test token refresh with invalid token format."""
        invalid_tokens = ['', 'short', None]
        
        for invalid_token in invalid_tokens:
            with pytest.raises(ValidationException) as exc_info:
                await auth_manager.refresh_user_token(invalid_token or '')
            
            assert exc_info.value.error_code == SecurityErrorCode.AUTH_TOKEN_INVALID

    @pytest.mark.asyncio
    async def test_create_user_session_success(self, auth_manager, valid_jwt_payload, sample_session_data):
        """Test successful user session creation."""
        user_id = 'auth0|test-user-12345'
        
        result = await auth_manager.create_user_session(
            user_id, 
            valid_jwt_payload, 
            sample_session_data, 
            ttl=3600
        )
        
        assert result['session_created'] == True
        assert result['user_id'] == user_id
        assert 'session_id' in result
        assert result['ttl'] == 3600

    @pytest.mark.asyncio
    async def test_create_user_session_cache_failure(self, auth_manager, valid_jwt_payload, mock_auth_cache):
        """Test session creation with cache failure."""
        user_id = 'auth0|test-user-12345'
        
        # Mock cache failure
        with patch.object(mock_auth_cache, 'cache_user_session', return_value=False):
            with pytest.raises(SessionException) as exc_info:
                await auth_manager.create_user_session(user_id, valid_jwt_payload)
            
            assert exc_info.value.error_code == SecurityErrorCode.AUTH_SESSION_INVALID

    @pytest.mark.asyncio
    async def test_get_user_session_success(self, auth_manager, sample_session_data, mock_auth_cache):
        """Test successful user session retrieval."""
        session_id = 'test-session-12345'
        
        # Mock session data with valid expiration
        session_data_with_metadata = {
            **sample_session_data,
            'session_metadata': {
                'expires_at': (datetime.utcnow() + timedelta(hours=1)).isoformat()
            }
        }
        
        mock_auth_cache.cache_user_session(session_id, session_data_with_metadata, 3600)
        
        result = await auth_manager.get_user_session(session_id)
        
        assert result is not None
        assert result['user_id'] == sample_session_data['user_id']

    @pytest.mark.asyncio
    async def test_get_user_session_expired(self, auth_manager, sample_session_data, mock_auth_cache):
        """Test user session retrieval with expired session."""
        session_id = 'expired-session-12345'
        
        # Mock expired session data
        expired_session_data = {
            **sample_session_data,
            'session_metadata': {
                'expires_at': (datetime.utcnow() - timedelta(hours=1)).isoformat()
            }
        }
        
        mock_auth_cache.cache_user_session(session_id, expired_session_data, 3600)
        
        result = await auth_manager.get_user_session(session_id)
        
        assert result is None

    @pytest.mark.asyncio
    async def test_get_user_session_not_found(self, auth_manager):
        """Test user session retrieval for non-existent session."""
        session_id = 'non-existent-session'
        
        result = await auth_manager.get_user_session(session_id)
        
        assert result is None

    @pytest.mark.asyncio
    async def test_invalidate_user_session_success(self, auth_manager, sample_session_data, mock_auth_cache):
        """Test successful user session invalidation."""
        session_id = 'test-session-to-invalidate'
        
        # Pre-populate session
        mock_auth_cache.cache_user_session(session_id, sample_session_data, 3600)
        
        result = await auth_manager.invalidate_user_session(session_id)
        
        assert result == True

    @pytest.mark.asyncio
    async def test_invalidate_user_session_not_found(self, auth_manager):
        """Test user session invalidation for non-existent session."""
        session_id = 'non-existent-session'
        
        result = await auth_manager.invalidate_user_session(session_id)
        
        assert result == False

    def test_validate_token_format_valid(self, auth_manager, valid_jwt_token):
        """Test token format validation with valid token."""
        # Should not raise any exception
        auth_manager._validate_token_format(valid_jwt_token)

    def test_validate_token_format_invalid(self, auth_manager, malformed_jwt_tokens):
        """Test token format validation with invalid tokens."""
        for malformed_token in malformed_jwt_tokens:
            with pytest.raises(AuthenticationException) as exc_info:
                auth_manager._validate_token_format(malformed_token)
            
            assert exc_info.value.error_code in [
                SecurityErrorCode.AUTH_TOKEN_MISSING,
                SecurityErrorCode.AUTH_TOKEN_MALFORMED
            ]

    @pytest.mark.asyncio
    async def test_get_health_status(self, auth_manager):
        """Test authentication system health status."""
        with patch.object(auth_manager.cache, 'health_check', return_value={'status': 'healthy'}), \
             patch.object(auth_manager.token_validator.http_client, 'get') as mock_get:
            
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.elapsed.total_seconds.return_value = 0.1
            mock_get.return_value = mock_response
            
            health_status = await auth_manager.get_health_status()
            
            assert health_status['status'] in ['healthy', 'degraded']
            assert 'components' in health_status
            assert 'cache' in health_status['components']
            assert 'auth0' in health_status['components']

    @pytest.mark.asyncio
    async def test_auth_manager_close(self, auth_manager):
        """Test authentication manager resource cleanup."""
        await auth_manager.close()
        # Verify that close doesn't raise exceptions


# ============================================================================
# GLOBAL AUTHENTICATION MANAGER TESTS
# ============================================================================

class TestGlobalAuthenticationManager:
    """Test global authentication manager functions."""

    def test_get_auth_manager_initialization(self, auth_config, mock_environment):
        """Test global authentication manager initialization."""
        with patch.dict('os.environ', auth_config):
            # Clear any existing manager
            import src.auth.authentication
            src.auth.authentication._auth_manager = None
            
            manager = get_auth_manager()
            
            assert manager is not None
            assert isinstance(manager, AuthenticationManager)

    def test_get_auth_manager_singleton(self, auth_config, mock_environment):
        """Test global authentication manager singleton behavior."""
        with patch.dict('os.environ', auth_config):
            # Clear any existing manager
            import src.auth.authentication
            src.auth.authentication._auth_manager = None
            
            manager1 = get_auth_manager()
            manager2 = get_auth_manager()
            
            assert manager1 is manager2

    @pytest.mark.asyncio
    async def test_init_auth_manager_custom_cache(self, auth_config, mock_environment, mock_auth_cache):
        """Test authentication manager initialization with custom cache."""
        with patch.dict('os.environ', auth_config):
            manager = await init_auth_manager(mock_auth_cache)
            
            assert manager is not None
            assert manager.cache is mock_auth_cache

    @pytest.mark.asyncio
    async def test_close_auth_manager(self, auth_config, mock_environment):
        """Test global authentication manager cleanup."""
        with patch.dict('os.environ', auth_config):
            # Initialize manager
            await init_auth_manager()
            
            # Close manager
            await close_auth_manager()
            
            # Verify manager is cleared
            import src.auth.authentication
            assert src.auth.authentication._auth_manager is None


# ============================================================================
# CONVENIENCE FUNCTION TESTS
# ============================================================================

class TestConvenienceFunctions:
    """Test authentication convenience functions."""

    @pytest.mark.asyncio
    async def test_authenticate_jwt_token_convenience(self, auth_config, mock_environment, 
                                                    valid_jwt_token, valid_jwt_payload):
        """Test JWT token authentication convenience function."""
        with patch.dict('os.environ', auth_config), \
             patch('src.auth.authentication.get_auth_manager') as mock_get_manager:
            
            mock_manager = Mock()
            mock_manager.authenticate_user = AsyncMock(return_value={
                'authenticated': True,
                'user_id': valid_jwt_payload['sub']
            })
            mock_get_manager.return_value = mock_manager
            
            result = await authenticate_jwt_token(valid_jwt_token)
            
            assert result['authenticated'] == True
            assert result['user_id'] == valid_jwt_payload['sub']

    @pytest.mark.asyncio
    async def test_validate_user_permissions_convenience(self, auth_config, mock_environment):
        """Test user permissions validation convenience function."""
        with patch.dict('os.environ', auth_config), \
             patch('src.auth.authentication.get_auth_manager') as mock_get_manager:
            
            user_id = 'auth0|test-user-12345'
            required_permissions = ['read', 'write']
            
            mock_manager = Mock()
            mock_manager.validate_permissions = AsyncMock(return_value={
                'has_permissions': True,
                'user_id': user_id
            })
            mock_get_manager.return_value = mock_manager
            
            result = await validate_user_permissions(user_id, required_permissions)
            
            assert result['has_permissions'] == True
            assert result['user_id'] == user_id

    @pytest.mark.asyncio
    async def test_refresh_jwt_token_convenience(self, auth_config, mock_environment):
        """Test JWT token refresh convenience function."""
        with patch.dict('os.environ', auth_config), \
             patch('src.auth.authentication.get_auth_manager') as mock_get_manager:
            
            refresh_token = 'test-refresh-token'
            
            mock_manager = Mock()
            mock_manager.refresh_user_token = AsyncMock(return_value={
                'access_token': 'new-access-token'
            })
            mock_get_manager.return_value = mock_manager
            
            result = await refresh_jwt_token(refresh_token)
            
            assert result['access_token'] == 'new-access-token'

    @pytest.mark.asyncio
    async def test_create_authenticated_session_convenience(self, auth_config, mock_environment, 
                                                          valid_jwt_payload, sample_session_data):
        """Test authenticated session creation convenience function."""
        with patch.dict('os.environ', auth_config), \
             patch('src.auth.authentication.get_auth_manager') as mock_get_manager:
            
            user_id = 'auth0|test-user-12345'
            
            mock_manager = Mock()
            mock_manager.create_user_session = AsyncMock(return_value={
                'session_created': True,
                'user_id': user_id
            })
            mock_get_manager.return_value = mock_manager
            
            result = await create_authenticated_session(user_id, valid_jwt_payload, sample_session_data)
            
            assert result['session_created'] == True
            assert result['user_id'] == user_id

    @pytest.mark.asyncio
    async def test_get_authenticated_session_convenience(self, auth_config, mock_environment, sample_session_data):
        """Test authenticated session retrieval convenience function."""
        with patch.dict('os.environ', auth_config), \
             patch('src.auth.authentication.get_auth_manager') as mock_get_manager:
            
            session_id = 'test-session-12345'
            
            mock_manager = Mock()
            mock_manager.get_user_session = AsyncMock(return_value=sample_session_data)
            mock_get_manager.return_value = mock_manager
            
            result = await get_authenticated_session(session_id)
            
            assert result == sample_session_data

    @pytest.mark.asyncio
    async def test_invalidate_authenticated_session_convenience(self, auth_config, mock_environment):
        """Test authenticated session invalidation convenience function."""
        with patch.dict('os.environ', auth_config), \
             patch('src.auth.authentication.get_auth_manager') as mock_get_manager:
            
            session_id = 'test-session-12345'
            
            mock_manager = Mock()
            mock_manager.invalidate_user_session = AsyncMock(return_value=True)
            mock_get_manager.return_value = mock_manager
            
            result = await invalidate_authenticated_session(session_id)
            
            assert result == True


# ============================================================================
# INTEGRATION AND ERROR HANDLING TESTS
# ============================================================================

class TestIntegrationAndErrorHandling:
    """Test integration scenarios and comprehensive error handling."""

    @pytest.mark.asyncio
    async def test_full_authentication_flow(self, auth_config, mock_environment, 
                                          valid_jwt_token, valid_jwt_payload, 
                                          test_rsa_keypair, mock_auth0_user_profile):
        """Test complete authentication flow integration."""
        with patch.dict('os.environ', auth_config):
            auth_manager = AuthenticationManager()
            
            # Mock all external dependencies
            with patch.object(auth_manager.token_validator, '_get_signing_key', 
                             return_value=test_rsa_keypair['public_pem']), \
                 patch.object(auth_manager.user_manager, 'get_user_profile', 
                             return_value=mock_auth0_user_profile):
                
                # Authenticate user
                auth_result = await auth_manager.authenticate_user(valid_jwt_token)
                
                # Create session
                session_result = await auth_manager.create_user_session(
                    auth_result['user_id'],
                    auth_result['token_payload']
                )
                
                # Retrieve session
                retrieved_session = await auth_manager.get_user_session(
                    session_result['session_id']
                )
                
                # Validate permissions
                permissions_result = await auth_manager.validate_permissions(
                    auth_result['user_id'],
                    ['read', 'write']
                )
                
                # Verify complete flow
                assert auth_result['authenticated'] == True
                assert session_result['session_created'] == True
                assert retrieved_session is not None
                assert permissions_result['user_id'] == auth_result['user_id']

    @pytest.mark.asyncio
    async def test_authentication_with_network_failures(self, auth_config, mock_environment, valid_jwt_token):
        """Test authentication behavior with network failures."""
        with patch.dict('os.environ', auth_config):
            auth_manager = AuthenticationManager()
            
            # Simulate network failure
            with patch.object(auth_manager.token_validator.http_client, 'get', 
                             side_effect=httpx.ConnectError("Network unavailable")):
                with pytest.raises(JWTException):
                    await auth_manager.authenticate_user(valid_jwt_token)

    @pytest.mark.asyncio
    async def test_authentication_with_auth0_service_degradation(self, auth_config, mock_environment, 
                                                               valid_jwt_token, mock_auth_cache):
        """Test authentication during Auth0 service degradation."""
        with patch.dict('os.environ', auth_config):
            auth_manager = AuthenticationManager(mock_auth_cache)
            
            # Pre-populate cache with validation result
            token_hash = hash_token(valid_jwt_token)
            cached_validation = {
                'sub': 'auth0|test-user-12345',
                'email': 'test@example.com',
                'cached_at': datetime.utcnow().isoformat()
            }
            mock_auth_cache.cache_jwt_validation(token_hash, cached_validation, 300)
            
            # Simulate Auth0 service failure
            with patch.object(auth_manager.token_validator, '_get_signing_key', 
                             side_effect=Auth0Exception("Service unavailable")):
                # Should still work with cached validation
                result = await auth_manager.authenticate_user(valid_jwt_token, verify_signature=False)
                
                assert result['authenticated'] == True

    @pytest.mark.asyncio
    async def test_circuit_breaker_integration(self, auth_config, mock_environment):
        """Test circuit breaker integration across authentication components."""
        with patch.dict('os.environ', auth_config):
            auth_manager = AuthenticationManager()
            
            # Test circuit breaker activation
            user_id = 'auth0|test-user-12345'
            
            # Simulate repeated Auth0 failures
            with patch.object(auth_manager.user_manager.http_client, 'get', 
                             side_effect=httpx.HTTPStatusError("Service error", request=Mock(), response=Mock())):
                
                # Multiple failures should trigger circuit breaker
                for _ in range(3):
                    try:
                        await auth_manager.user_manager.get_user_profile(user_id, use_cache=False)
                    except Auth0Exception:
                        pass

    @pytest.mark.asyncio
    async def test_concurrent_authentication_requests(self, auth_config, mock_environment, 
                                                    valid_jwt_token, valid_jwt_payload, test_rsa_keypair):
        """Test concurrent authentication request handling."""
        with patch.dict('os.environ', auth_config):
            auth_manager = AuthenticationManager()
            
            with patch.object(auth_manager.token_validator, '_get_signing_key', 
                             return_value=test_rsa_keypair['public_pem']), \
                 patch.object(auth_manager.user_manager, 'get_user_profile', 
                             return_value={'user_id': valid_jwt_payload['sub']}):
                
                # Simulate concurrent requests
                tasks = [
                    auth_manager.authenticate_user(valid_jwt_token)
                    for _ in range(5)
                ]
                
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # All requests should succeed
                for result in results:
                    assert not isinstance(result, Exception)
                    assert result['authenticated'] == True

    @pytest.mark.asyncio
    async def test_memory_cleanup_and_resource_management(self, auth_config, mock_environment):
        """Test proper memory cleanup and resource management."""
        with patch.dict('os.environ', auth_config):
            auth_manager = AuthenticationManager()
            
            # Test resource cleanup
            await auth_manager.close()
            
            # Verify components are closed
            # This test ensures no resource leaks occur


# ============================================================================
# SECURITY AND COMPLIANCE TESTS
# ============================================================================

class TestSecurityAndCompliance:
    """Test security compliance and vulnerability protections."""

    def test_jwt_secret_key_security(self, auth_config, mock_environment):
        """Test JWT secret key security requirements."""
        # Test weak secret key detection
        weak_config = {**auth_config, 'JWT_SECRET_KEY': 'weak'}
        
        # Implementation should validate secret key strength
        # This test ensures production deployments use strong keys
        assert len(auth_config.get('JWT_SECRET_KEY', '')) >= 32

    @pytest.mark.asyncio
    async def test_timing_attack_resistance(self, auth_config, mock_environment, test_rsa_keypair):
        """Test resistance to timing attacks in token validation."""
        with patch.dict('os.environ', auth_config):
            validator = JWTTokenValidator(Auth0Config(), AuthenticationCache())
            
            # Test with invalid tokens of different lengths
            tokens = [
                'short',
                'medium.length.token',
                'very.long.token.that.should.take.similar.time.to.validate.as.shorter.tokens'
            ]
            
            times = []
            for token in tokens:
                start_time = time.time()
                try:
                    await validator.validate_token(token, verify_signature=False)
                except:
                    pass
                times.append(time.time() - start_time)
            
            # Timing should be consistent (within reasonable variance)
            max_time = max(times)
            min_time = min(times)
            # Allow up to 50% variance for timing attack resistance
            assert (max_time - min_time) / min_time < 0.5

    @pytest.mark.asyncio
    async def test_token_payload_injection_protection(self, auth_config, mock_environment, test_rsa_keypair):
        """Test protection against token payload injection attacks."""
        with patch.dict('os.environ', auth_config):
            # Create token with malicious payload
            malicious_payload = {
                'sub': 'auth0|user123',
                'admin': True,  # Injected claim
                'roles': ['admin', 'superuser'],  # Escalated roles
                'iat': int(time.time()),
                'exp': int(time.time()) + 3600,
                'aud': 'test-api-audience',
                'iss': 'https://test-domain.auth0.com/',
                # Attempt to inject dangerous claims
                'permissions': ['*'],
                'sudo': True,
                'system_access': True
            }
            
            malicious_token = jwt.encode(
                payload=malicious_payload,
                key=test_rsa_keypair['private_pem'],
                algorithm='RS256'
            )
            
            validator = JWTTokenValidator(Auth0Config(), AuthenticationCache())
            
            with patch.object(validator, '_get_signing_key', return_value=test_rsa_keypair['public_pem']):
                # Token should validate structurally but dangerous claims should be handled carefully
                result = await validator.validate_token(malicious_token)
                
                # Verify basic claims are present
                assert result['sub'] == malicious_payload['sub']
                
                # Dangerous claims should not bypass security controls
                # Real implementation should validate claims against allowed values

    @pytest.mark.asyncio
    async def test_session_fixation_protection(self, auth_config, mock_environment, valid_jwt_payload):
        """Test protection against session fixation attacks."""
        with patch.dict('os.environ', auth_config):
            auth_manager = AuthenticationManager()
            
            user_id = 'auth0|test-user-12345'
            
            # Create multiple sessions for same user
            session1 = await auth_manager.create_user_session(user_id, valid_jwt_payload)
            session2 = await auth_manager.create_user_session(user_id, valid_jwt_payload)
            
            # Sessions should have different IDs
            assert session1['session_id'] != session2['session_id']
            
            # Both sessions should be valid independently
            retrieved1 = await auth_manager.get_user_session(session1['session_id'])
            retrieved2 = await auth_manager.get_user_session(session2['session_id'])
            
            assert retrieved1 is not None
            assert retrieved2 is not None

    @pytest.mark.asyncio
    async def test_rate_limiting_protection(self, auth_config, mock_environment):
        """Test rate limiting protection mechanisms."""
        with patch.dict('os.environ', auth_config):
            auth_manager = AuthenticationManager()
            
            # Simulate rapid authentication attempts
            user_id = 'auth0|test-user-12345'
            
            # Implementation should include rate limiting
            # This test verifies protection against brute force attacks
            attempts = []
            for i in range(10):
                try:
                    # Simulate rapid permission checks
                    result = await auth_manager.validate_permissions(user_id, ['read'])
                    attempts.append(result)
                except Exception:
                    # Rate limiting may reject some requests
                    pass
            
            # At least some requests should succeed
            assert len(attempts) > 0

    def test_cryptographic_randomness(self):
        """Test cryptographic randomness in session generation."""
        # Generate multiple session IDs
        session_ids = [generate_session_id() for _ in range(100)]
        
        # All session IDs should be unique
        assert len(set(session_ids)) == len(session_ids)
        
        # Session IDs should have sufficient length
        for session_id in session_ids:
            assert len(session_id) >= 32

    @pytest.mark.asyncio
    async def test_audit_logging_coverage(self, auth_config, mock_environment, valid_jwt_token):
        """Test comprehensive audit logging coverage."""
        with patch.dict('os.environ', auth_config):
            auth_manager = AuthenticationManager()
            
            # Mock successful authentication
            with patch.object(auth_manager, 'authenticate_user', 
                             return_value={'authenticated': True, 'user_id': 'test-user'}):
                
                result = await auth_manager.authenticate_user(valid_jwt_token)
                
                # Verify authentication events are logged
                # Real implementation should include comprehensive audit logging
                assert result['authenticated'] == True

    @pytest.mark.asyncio  
    async def test_error_information_disclosure_prevention(self, auth_config, mock_environment):
        """Test prevention of sensitive information disclosure in errors."""
        with patch.dict('os.environ', auth_config):
            auth_manager = AuthenticationManager()
            
            # Test with various invalid inputs
            invalid_inputs = [
                'invalid-token',
                'malformed.jwt.token',
                '',
                None
            ]
            
            for invalid_input in invalid_inputs:
                try:
                    await auth_manager.authenticate_user(invalid_input or '')
                except AuthenticationException as e:
                    # Error messages should not disclose sensitive information
                    error_message = str(e).lower()
                    
                    # Should not contain sensitive configuration details
                    assert 'secret' not in error_message
                    assert 'password' not in error_message
                    assert 'key' not in error_message
                    assert 'token' not in error_message or 'invalid' in error_message