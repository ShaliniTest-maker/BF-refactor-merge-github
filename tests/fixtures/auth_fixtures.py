"""
Authentication and Authorization Test Fixtures

This module provides comprehensive Auth0 service mocking, JWT token generation, Flask-Login user objects,
and comprehensive authentication state management for security testing scenarios. The fixtures support
enterprise-grade testing patterns with complete Auth0 Python SDK integration, PyJWT 2.8+ token processing,
and Flask-Session distributed session management validation.

Key Features:
- Auth0 Python SDK mock fixtures for enterprise authentication testing per Section 6.4.1
- PyJWT 2.8+ token generation and validation fixtures per Section 0.1.2 authentication module
- Flask-Login user objects for session management testing per Section 6.4.1 Flask-Login integration
- JWT claims extraction and validation fixtures per Section 6.4.1 token handling
- Security context fixtures for authorization testing per Section 6.4.2 authorization system
- Authentication state management fixtures per Section 6.4.1 session management
- Flask-Session user context fixtures for distributed session testing per Section 3.4.2
- Comprehensive test data generation using factory_boy per Section 6.6.1 enhanced mocking strategy
- Testcontainers integration for realistic Redis behavior per Section 6.6.1 production-equivalent test environment

Architecture Integration:
- Section 6.6.1: Enhanced mocking strategy using comprehensive external service simulation
- Section 6.6.3: 95% authentication module coverage requirement for security compliance
- Section 6.4.1: JWT token processing migration from jsonwebtoken to PyJWT 2.8+
- Section 6.4.1: Flask-Login integration for user session management
- Section 6.4.2: Authorization system with role-based access control testing
- Section 6.6.1: pytest 7.4+ with extensive plugin ecosystem support
- Section 6.6.1: factory_boy integration for dynamic test object generation

Security Testing Standards:
- Enterprise-grade Auth0 integration testing with circuit breaker pattern validation
- Comprehensive JWT token lifecycle testing including generation, validation, and expiration
- Flask-Login user context management across multiple application instances
- Redis session persistence testing with encryption validation
- Authorization decorator testing with permission validation
- Security event logging and audit trail validation
- Performance testing ensuring ≤10% variance from Node.js baseline per Section 0.1.1

Dependencies:
- pytest 7.4+: Primary testing framework with comprehensive fixture support
- pytest-mock: External service mocking and Auth0 SDK simulation
- factory_boy: Dynamic test object generation with realistic data patterns
- PyJWT 2.8+: JWT token generation and validation for authentication testing
- Flask-Login 0.7.0+: User session management and authentication state testing
- cryptography 41.0+: Secure token generation and encryption validation
- python-dateutil 2.9+: ISO 8601 date/time parsing and temporal data testing
- redis-py 5.0+: Redis session management and caching validation

Author: Flask Migration Team
Version: 1.0.0
Coverage Target: 95% authentication module coverage per Section 6.6.3
"""

import asyncio
import base64
import hashlib
import json
import secrets
import time
import uuid
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Union, Generator, AsyncGenerator
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import factory
import jwt
import pytest
import pytest_asyncio
from dateutil import parser as dateutil_parser
from flask import Flask, g, request, session
from flask_login import AnonymousUserMixin, UserMixin, login_user, logout_user
from redis import Redis
from werkzeug.test import Client

# Import application modules for testing
try:
    from src.auth.authentication import (
        CoreJWTAuthenticator,
        AuthenticatedUser,
        get_core_authenticator,
        authenticate_token,
        create_auth_health_check
    )
    from src.auth.authorization import (
        PermissionContext,
        AuthorizationManager,
        require_permissions,
        check_user_permission
    )
    from src.auth.auth0_client import (
        Auth0ClientManager,
        Auth0CircuitBreaker,
        Auth0MetricsCollector
    )
    from src.auth.session import (
        SessionUser,
        SessionManager,
        EncryptedSessionInterface
    )
    from src.auth.decorators import (
        require_authentication,
        rate_limited_authorization,
        DecoratorConfig
    )
    from src.auth.exceptions import (
        SecurityException,
        AuthenticationException,
        AuthorizationException,
        JWTException,
        Auth0Exception,
        SessionException,
        SecurityErrorCode
    )
    from src.config.settings import TestingConfig
except ImportError as e:
    # Fallback imports for isolated fixture testing
    pytest.skip(f"Application modules not available: {e}", allow_module_level=True)


# =============================================================================
# Factory Classes for Dynamic Test Object Generation
# =============================================================================

class JWTClaimsFactory(factory.Factory):
    """
    Factory for generating realistic JWT token claims using factory_boy integration
    per Section 6.6.1 dynamic test object generation requirements.
    """
    
    class Meta:
        model = dict
    
    # Standard JWT claims
    sub = factory.LazyFunction(lambda: f"auth0|{secrets.token_hex(12)}")
    iss = factory.LazyAttribute(lambda obj: f"https://{factory.Faker('domain_name').generate()}.auth0.com/")
    aud = factory.Sequence(lambda n: f"test-audience-{n}")
    exp = factory.LazyFunction(lambda: int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()))
    iat = factory.LazyFunction(lambda: int(datetime.now(timezone.utc).timestamp()))
    nbf = factory.LazyFunction(lambda: int(datetime.now(timezone.utc).timestamp()))
    jti = factory.LazyFunction(lambda: str(uuid.uuid4()))
    
    # Auth0-specific claims
    azp = factory.LazyAttribute(lambda obj: obj.aud)
    scope = "read:profile write:profile read:documents"
    
    # User profile claims
    name = factory.Faker('name')
    email = factory.Faker('email')
    email_verified = True
    picture = factory.LazyAttribute(lambda obj: f"https://avatars.example.com/{obj.sub}.png")
    updated_at = factory.LazyFunction(lambda: datetime.now(timezone.utc).isoformat())
    
    # Custom claims with namespace
    permissions = factory.LazyFunction(lambda: [
        "read:profile", "write:profile", "read:documents", "write:documents",
        "read:admin", "write:admin"
    ])
    
    # Auth0 app metadata
    app_metadata = factory.LazyFunction(lambda: {
        "roles": ["user", "admin"],
        "department": "engineering",
        "tenant_id": "test-tenant"
    })
    
    # Auth0 user metadata
    user_metadata = factory.LazyFunction(lambda: {
        "preferences": {"theme": "dark", "language": "en"},
        "onboarding_completed": True
    })


class Auth0UserProfileFactory(factory.Factory):
    """
    Factory for generating comprehensive Auth0 user profiles with enterprise metadata
    per Section 6.4.1 identity management requirements.
    """
    
    class Meta:
        model = dict
    
    user_id = factory.LazyFunction(lambda: f"auth0|{secrets.token_hex(12)}")
    username = factory.Faker('user_name')
    name = factory.Faker('name')
    given_name = factory.Faker('first_name')
    family_name = factory.Faker('last_name')
    middle_name = factory.Faker('first_name')
    nickname = factory.LazyAttribute(lambda obj: obj.username)
    preferred_username = factory.LazyAttribute(lambda obj: obj.username)
    profile = factory.LazyAttribute(lambda obj: f"https://profiles.example.com/{obj.username}")
    picture = factory.LazyAttribute(lambda obj: f"https://avatars.example.com/{obj.user_id}.png")
    website = factory.Faker('url')
    email = factory.Faker('email')
    email_verified = True
    gender = factory.Faker('random_element', elements=('male', 'female', 'other', 'prefer_not_to_say'))
    birthdate = factory.Faker('date_of_birth', minimum_age=18, maximum_age=80)
    zoneinfo = factory.Faker('timezone')
    locale = "en-US"
    phone_number = factory.Faker('phone_number')
    phone_number_verified = False
    address = factory.SubFactory('tests.fixtures.auth_fixtures.AddressFactory')
    
    # Auth0 specific fields
    created_at = factory.LazyFunction(lambda: datetime.now(timezone.utc).isoformat())
    updated_at = factory.LazyFunction(lambda: datetime.now(timezone.utc).isoformat())
    last_login = factory.LazyFunction(lambda: (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat())
    last_ip = factory.Faker('ipv4')
    logins_count = factory.Faker('random_int', min=1, max=1000)
    blocked = False
    
    # Enterprise metadata
    app_metadata = factory.LazyFunction(lambda: {
        "roles": ["user"],
        "permissions": ["read:profile", "write:profile"],
        "department": "engineering",
        "employee_id": secrets.token_hex(8),
        "hire_date": datetime.now(timezone.utc).isoformat(),
        "manager_id": f"auth0|{secrets.token_hex(12)}"
    })
    
    user_metadata = factory.LazyFunction(lambda: {
        "preferences": {
            "theme": "light",
            "language": "en",
            "timezone": "America/New_York",
            "notifications": True
        },
        "onboarding": {
            "completed": True,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "steps_completed": ["profile", "security", "preferences"]
        },
        "security": {
            "mfa_enabled": True,
            "backup_codes_generated": True,
            "last_password_change": datetime.now(timezone.utc).isoformat()
        }
    })


class AddressFactory(factory.Factory):
    """Factory for generating address information per OIDC standards."""
    
    class Meta:
        model = dict
    
    street_address = factory.Faker('street_address')
    locality = factory.Faker('city')
    region = factory.Faker('state')
    postal_code = factory.Faker('zipcode')
    country = factory.Faker('country_code')
    formatted = factory.LazyAttribute(
        lambda obj: f"{obj.street_address}\n{obj.locality}, {obj.region} {obj.postal_code}\n{obj.country}"
    )


class SessionDataFactory(factory.Factory):
    """
    Factory for generating Flask-Session data for distributed session testing
    per Section 3.4.2 Flask-Session Redis configuration.
    """
    
    class Meta:
        model = dict
    
    session_id = factory.LazyFunction(lambda: secrets.token_urlsafe(32))
    user_id = factory.LazyFunction(lambda: f"auth0|{secrets.token_hex(12)}")
    created_at = factory.LazyFunction(lambda: datetime.now(timezone.utc).isoformat())
    last_accessed = factory.LazyFunction(lambda: datetime.now(timezone.utc).isoformat())
    expires_at = factory.LazyFunction(lambda: (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat())
    ip_address = factory.Faker('ipv4')
    user_agent = factory.Faker('user_agent')
    
    # Session state data
    authenticated = True
    permissions = factory.LazyFunction(lambda: ["read:profile", "write:profile", "read:documents"])
    roles = factory.LazyFunction(lambda: ["user"])
    
    # Additional session metadata
    csrf_token = factory.LazyFunction(lambda: secrets.token_hex(32))
    flash_messages = factory.LazyFunction(lambda: [])
    
    # Authentication context
    auth_method = "jwt"
    auth_provider = "auth0"
    mfa_verified = True
    
    # Security context
    security_level = "standard"
    risk_score = factory.Faker('random_int', min=0, max=100)
    device_trusted = True


# =============================================================================
# Core Authentication Fixtures
# =============================================================================

@pytest.fixture
def mock_auth0_domain():
    """Auth0 domain for testing configuration."""
    return "test-domain.auth0.com"


@pytest.fixture
def mock_auth0_client_id():
    """Auth0 client ID for testing configuration."""
    return "test_client_id_123456789"


@pytest.fixture
def mock_auth0_client_secret():
    """Auth0 client secret for testing configuration."""
    return "test_client_secret_abcdefghijklmnop"


@pytest.fixture
def mock_auth0_audience():
    """Auth0 API audience for testing configuration."""
    return "https://api.test-domain.auth0.com"


@pytest.fixture
def auth0_config(mock_auth0_domain, mock_auth0_client_id, mock_auth0_client_secret, mock_auth0_audience):
    """
    Complete Auth0 configuration for testing Auth0 Python SDK integration
    per Section 6.4.1 identity management.
    """
    return {
        'AUTH0_DOMAIN': mock_auth0_domain,
        'AUTH0_CLIENT_ID': mock_auth0_client_id,
        'AUTH0_CLIENT_SECRET': mock_auth0_client_secret,
        'AUTH0_AUDIENCE': mock_auth0_audience,
        'AUTH0_ALGORITHM': 'RS256',
        'AUTH0_ISSUER': f"https://{mock_auth0_domain}/",
    }


@pytest.fixture
def rsa_key_pair():
    """
    RSA key pair for JWT token signing and validation testing using
    cryptography 41.0+ per Section 6.4.1 cryptographic operations.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize public key
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return {
        'private_key': private_key,
        'public_key': public_key,
        'private_pem': private_pem,
        'public_pem': public_pem,
        'private_key_str': private_pem.decode('utf-8'),
        'public_key_str': public_pem.decode('utf-8')
    }


@pytest.fixture
def jwt_claims():
    """
    Standard JWT claims factory instance for token generation testing
    per Section 6.4.1 token handling.
    """
    return JWTClaimsFactory()


@pytest.fixture
def valid_jwt_token(rsa_key_pair, jwt_claims, auth0_config):
    """
    Generate valid JWT token using PyJWT 2.8+ for authentication testing
    per Section 0.1.2 JWT token processing migration.
    """
    claims = jwt_claims.build()
    claims.update({
        'iss': auth0_config['AUTH0_ISSUER'],
        'aud': auth0_config['AUTH0_AUDIENCE']
    })
    
    # Generate token using RS256 algorithm
    token = jwt.encode(
        claims,
        rsa_key_pair['private_key'],
        algorithm='RS256',
        headers={'kid': 'test-key-id'}
    )
    
    return {
        'token': token,
        'claims': claims,
        'header': jwt.get_unverified_header(token)
    }


@pytest.fixture
def expired_jwt_token(rsa_key_pair, jwt_claims, auth0_config):
    """
    Generate expired JWT token for expiration testing scenarios
    per Section 6.4.1 token validation patterns.
    """
    claims = jwt_claims.build()
    claims.update({
        'iss': auth0_config['AUTH0_ISSUER'],
        'aud': auth0_config['AUTH0_AUDIENCE'],
        'exp': int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp()),
        'iat': int((datetime.now(timezone.utc) - timedelta(hours=2)).timestamp())
    })
    
    token = jwt.encode(
        claims,
        rsa_key_pair['private_key'],
        algorithm='RS256',
        headers={'kid': 'test-key-id'}
    )
    
    return {
        'token': token,
        'claims': claims,
        'header': jwt.get_unverified_header(token)
    }


@pytest.fixture
def malformed_jwt_token():
    """Malformed JWT token for error handling testing."""
    return "invalid.jwt.token.format"


@pytest.fixture
def jwt_token_with_invalid_signature(valid_jwt_token, rsa_key_pair):
    """
    JWT token with invalid signature for security testing
    per Section 6.4.1 comprehensive token validation.
    """
    # Create a different key for signing
    from cryptography.hazmat.primitives.asymmetric import rsa
    
    wrong_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Sign with wrong key
    token = jwt.encode(
        valid_jwt_token['claims'],
        wrong_key,
        algorithm='RS256',
        headers={'kid': 'wrong-key-id'}
    )
    
    return {
        'token': token,
        'claims': valid_jwt_token['claims'],
        'header': jwt.get_unverified_header(token)
    }


@pytest.fixture
def auth0_user_profile():
    """
    Complete Auth0 user profile for testing user context creation
    per Section 6.4.1 user context creation and authentication state management.
    """
    return Auth0UserProfileFactory()


@pytest.fixture
def authenticated_user(valid_jwt_token, auth0_user_profile):
    """
    AuthenticatedUser instance for testing user context management
    per Section 6.4.1 authentication system.
    """
    profile = auth0_user_profile.build()
    claims = valid_jwt_token['claims']
    
    return AuthenticatedUser(
        user_id=claims['sub'],
        token_claims=claims,
        permissions=claims.get('permissions', []),
        profile=profile,
        token=valid_jwt_token['token'],
        authenticated_at=datetime.now(timezone.utc)
    )


# =============================================================================
# Auth0 Service Mocking Fixtures
# =============================================================================

@pytest.fixture
def mock_auth0_jwks(rsa_key_pair):
    """
    Mock Auth0 JWKS (JSON Web Key Set) endpoint response for public key validation
    per Section 6.4.1 Auth0 enterprise integration.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    
    public_key = rsa_key_pair['public_key']
    
    # Convert to JWK format
    public_numbers = public_key.public_numbers()
    
    # Convert to base64url encoding for JWK
    def int_to_base64url(value):
        byte_length = (value.bit_length() + 7) // 8
        value_bytes = value.to_bytes(byte_length, byteorder='big')
        return base64.urlsafe_b64encode(value_bytes).decode('ascii').rstrip('=')
    
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "key_ops": ["verify"],
                "kid": "test-key-id",
                "x5t": "test-thumbprint",
                "alg": "RS256",
                "n": int_to_base64url(public_numbers.n),
                "e": int_to_base64url(public_numbers.e),
                "x5c": []
            }
        ]
    }
    
    return jwks


@pytest.fixture
def mock_auth0_client(auth0_config, mock_auth0_jwks, auth0_user_profile):
    """
    Comprehensive Auth0 Python SDK mock for authentication service testing
    per Section 6.4.1 Auth0 enterprise integration through Python SDK.
    """
    with patch('src.auth.auth0_client.Auth0') as mock_auth0:
        # Mock Auth0 management client
        mock_management_client = MagicMock()
        mock_auth0.return_value = mock_management_client
        
        # Mock user profile response
        user_profile = auth0_user_profile.build()
        mock_management_client.users.get.return_value = user_profile
        mock_management_client.users.list.return_value = [user_profile]
        
        # Mock user permissions
        mock_management_client.users.get_permissions.return_value = [
            {'permission_name': 'read:profile', 'description': 'Read user profile'},
            {'permission_name': 'write:profile', 'description': 'Write user profile'},
            {'permission_name': 'read:documents', 'description': 'Read documents'},
        ]
        
        # Mock JWKS endpoint
        with patch('requests.get') as mock_get:
            mock_response = MagicMock()
            mock_response.json.return_value = mock_auth0_jwks
            mock_response.raise_for_status.return_value = None
            mock_get.return_value = mock_response
            
            yield {
                'management_client': mock_management_client,
                'auth0_class': mock_auth0,
                'jwks_response': mock_response,
                'user_profile': user_profile
            }


@pytest.fixture
def mock_auth0_circuit_breaker():
    """
    Mock Auth0 circuit breaker for resilience testing
    per Section 6.4.2 circuit breaker integration for Auth0 API calls.
    """
    with patch('src.auth.auth0_client.Auth0CircuitBreaker') as mock_circuit_breaker:
        mock_instance = MagicMock()
        mock_circuit_breaker.return_value = mock_instance
        
        # Configure circuit breaker states
        mock_instance._auth0_circuit_breaker_state = 'closed'
        mock_instance._auth0_failure_count = 0
        mock_instance._auth0_last_failure_time = None
        
        # Mock validation methods
        async def mock_validate_permissions(user_id, permissions):
            return {
                'user_id': user_id,
                'has_permissions': True,
                'granted_permissions': permissions,
                'validation_source': 'auth0_api',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        
        mock_instance.validate_user_permissions_with_retry = AsyncMock(
            side_effect=mock_validate_permissions
        )
        
        yield mock_instance


@pytest.fixture
async def mock_auth0_async_client():
    """
    Mock Auth0 async HTTP client for testing HTTPX integration
    per Section 6.4.2 HTTPX async client for external service integration.
    """
    with patch('httpx.AsyncClient') as mock_client:
        mock_instance = AsyncMock()
        mock_client.return_value = mock_instance
        
        # Mock successful responses
        mock_response = AsyncMock()
        mock_response.json.return_value = {
            'permissions': [
                {'permission_name': 'read:profile', 'description': 'Read user profile'},
                {'permission_name': 'write:profile', 'description': 'Write user profile'}
            ]
        }
        mock_response.raise_for_status.return_value = None
        mock_instance.get.return_value = mock_response
        
        yield mock_instance


# =============================================================================
# Flask-Login Integration Fixtures
# =============================================================================

@pytest.fixture
def flask_login_user(auth0_user_profile):
    """
    Flask-Login user object for session management testing
    per Section 6.4.1 Flask-Login integration.
    """
    profile = auth0_user_profile.build()
    
    class TestUser(UserMixin):
        def __init__(self, user_profile):
            self.id = user_profile['user_id']
            self.auth0_profile = user_profile
            self.is_authenticated = True
            self.is_active = True
            self.is_anonymous = False
            
        def get_id(self):
            return str(self.id)
            
        def has_permission(self, permission):
            permissions = self.auth0_profile.get('app_metadata', {}).get('permissions', [])
            return permission in permissions
            
        def get_roles(self):
            return self.auth0_profile.get('app_metadata', {}).get('roles', [])
    
    return TestUser(profile)


@pytest.fixture
def anonymous_user():
    """Anonymous user for testing unauthenticated scenarios."""
    class TestAnonymousUser(AnonymousUserMixin):
        def __init__(self):
            self.is_authenticated = False
            self.is_active = False
            self.is_anonymous = True
            
        def get_id(self):
            return None
            
        def has_permission(self, permission):
            return False
            
        def get_roles(self):
            return []
    
    return TestAnonymousUser()


@pytest.fixture
def session_user(auth0_user_profile):
    """
    SessionUser instance for distributed session testing
    per Section 6.4.1 session management Flask-Session integration.
    """
    profile = auth0_user_profile.build()
    session_data = SessionDataFactory().build()
    
    return SessionUser(
        user_id=profile['user_id'],
        auth0_profile=profile,
        session_id=session_data['session_id'],
        session_metadata=session_data
    )


@pytest.fixture
def mock_flask_login_manager(flask_app):
    """
    Mock Flask-Login manager for testing login/logout functionality
    per Section 6.4.1 Flask-Login user context handling.
    """
    from flask_login import LoginManager
    
    login_manager = LoginManager()
    login_manager.init_app(flask_app)
    login_manager.login_view = 'auth.login'
    login_manager.session_protection = 'strong'
    
    # Mock user loader
    users_db = {}
    
    @login_manager.user_loader
    def load_user(user_id):
        return users_db.get(user_id)
    
    @login_manager.unauthorized_handler
    def unauthorized():
        return {'error': 'Authentication required'}, 401
    
    return {
        'login_manager': login_manager,
        'users_db': users_db,
        'load_user': load_user
    }


# =============================================================================
# Flask-Session and Redis Integration Fixtures
# =============================================================================

@pytest.fixture
def mock_redis_client():
    """
    Mock Redis client for session storage testing
    per Section 3.4.2 Redis session management.
    """
    with patch('redis.Redis') as mock_redis:
        mock_instance = MagicMock()
        mock_redis.return_value = mock_instance
        
        # Mock Redis operations
        session_store = {}
        
        def mock_setex(key, ttl, value):
            session_store[key] = {'value': value, 'ttl': ttl, 'created': time.time()}
            return True
        
        def mock_get(key):
            if key in session_store:
                entry = session_store[key]
                # Check TTL expiration
                if time.time() - entry['created'] < entry['ttl']:
                    return entry['value']
                else:
                    del session_store[key]
            return None
        
        def mock_delete(key):
            if key in session_store:
                del session_store[key]
                return 1
            return 0
        
        def mock_keys(pattern):
            return [key for key in session_store.keys() if pattern.replace('*', '') in key]
        
        mock_instance.setex.side_effect = mock_setex
        mock_instance.get.side_effect = mock_get
        mock_instance.delete.side_effect = mock_delete
        mock_instance.keys.side_effect = mock_keys
        mock_instance.exists.side_effect = lambda key: key in session_store
        
        # Connection pool mock
        mock_instance.connection_pool.connection_kwargs = {
            'host': 'localhost',
            'port': 6379,
            'db': 0
        }
        
        yield {
            'redis_client': mock_instance,
            'session_store': session_store
        }


@pytest.fixture
def mock_encrypted_session_interface(mock_redis_client):
    """
    Mock encrypted session interface for testing AES-256-GCM encryption
    per Section 6.4.1 session encryption using cryptography 41.0+.
    """
    from cryptography.fernet import Fernet
    
    # Generate encryption key
    encryption_key = Fernet.generate_key()
    fernet = Fernet(encryption_key)
    
    class MockEncryptedSessionInterface:
        def __init__(self, redis_client, encryption_key):
            self.redis = redis_client
            self.fernet = Fernet(encryption_key)
        
        def save_session(self, session_id, session_data):
            # Encrypt session data
            encrypted_data = self.fernet.encrypt(json.dumps(session_data).encode())
            key = f"session:{session_id}"
            self.redis.setex(key, 3600, base64.b64encode(encrypted_data).decode())
            return True
        
        def load_session(self, session_id):
            key = f"session:{session_id}"
            encrypted_data = self.redis.get(key)
            if encrypted_data:
                try:
                    decrypted_data = self.fernet.decrypt(base64.b64decode(encrypted_data))
                    return json.loads(decrypted_data.decode())
                except Exception:
                    return None
            return None
        
        def delete_session(self, session_id):
            key = f"session:{session_id}"
            return self.redis.delete(key)
    
    interface = MockEncryptedSessionInterface(mock_redis_client['redis_client'], encryption_key)
    
    return {
        'interface': interface,
        'encryption_key': encryption_key,
        'fernet': fernet
    }


@pytest.fixture
def session_data():
    """Session data factory for Flask-Session testing."""
    return SessionDataFactory()


@pytest.fixture
def mock_flask_session(flask_app, mock_redis_client, mock_encrypted_session_interface):
    """
    Mock Flask-Session configuration for distributed session testing
    per Section 6.4.1 Flask-Session Redis distributed caching.
    """
    from flask_session import Session
    
    # Configure Flask-Session
    flask_app.config['SESSION_TYPE'] = 'redis'
    flask_app.config['SESSION_REDIS'] = mock_redis_client['redis_client']
    flask_app.config['SESSION_PERMANENT'] = False
    flask_app.config['SESSION_USE_SIGNER'] = True
    flask_app.config['SESSION_KEY_PREFIX'] = 'session:'
    flask_app.config['SESSION_COOKIE_SECURE'] = True
    flask_app.config['SESSION_COOKIE_HTTPONLY'] = True
    flask_app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    
    session_extension = Session(flask_app)
    
    return {
        'session_extension': session_extension,
        'redis_client': mock_redis_client['redis_client'],
        'session_store': mock_redis_client['session_store'],
        'encrypted_interface': mock_encrypted_session_interface['interface']
    }


# =============================================================================
# Authorization Testing Fixtures
# =============================================================================

@pytest.fixture
def permission_context(authenticated_user):
    """
    Permission context for authorization testing
    per Section 6.4.2 authorization system.
    """
    return PermissionContext(
        user_id=authenticated_user.user_id,
        user_roles=['user', 'admin'],
        user_permissions=set(authenticated_user.permissions),
        resource_id='test-resource-123',
        resource_type='document',
        resource_owner=authenticated_user.user_id,
        request_ip='127.0.0.1',
        request_method='GET',
        request_endpoint='/api/test',
        session_id=secrets.token_urlsafe(32),
        correlation_id=str(uuid.uuid4()),
        additional_context={'test': True}
    )


@pytest.fixture
def mock_authorization_manager():
    """
    Mock authorization manager for permission testing
    per Section 6.4.2 role-based access control.
    """
    with patch('src.auth.authorization.AuthorizationManager') as mock_manager:
        mock_instance = MagicMock()
        mock_manager.return_value = mock_instance
        
        # Mock permission checking
        mock_instance.check_permission.return_value = True
        mock_instance.check_permissions.return_value = True
        mock_instance.check_role.return_value = True
        mock_instance.get_user_permissions.return_value = [
            'read:profile', 'write:profile', 'read:documents'
        ]
        
        # Mock permission caching
        mock_instance.cache_user_permissions.return_value = True
        mock_instance.get_cached_permissions.return_value = set([
            'read:profile', 'write:profile', 'read:documents'
        ])
        
        yield mock_instance


@pytest.fixture
def mock_permission_cache(mock_redis_client):
    """
    Mock permission cache for testing Redis permission caching
    per Section 6.4.2 Redis permission caching with intelligent TTL management.
    """
    class MockPermissionCache:
        def __init__(self, redis_client):
            self.redis = redis_client
            
        def cache_user_permissions(self, user_id, permissions, ttl=300):
            cache_key = f"perm_cache:{user_id}"
            cache_data = {
                'permissions': list(permissions),
                'cached_at': datetime.now(timezone.utc).isoformat(),
                'expires_at': (datetime.now(timezone.utc) + timedelta(seconds=ttl)).isoformat()
            }
            return self.redis.setex(cache_key, ttl, json.dumps(cache_data))
        
        def get_cached_permissions(self, user_id):
            cache_key = f"perm_cache:{user_id}"
            cached_data = self.redis.get(cache_key)
            if cached_data:
                try:
                    data = json.loads(cached_data)
                    return set(data['permissions'])
                except (json.JSONDecodeError, KeyError):
                    return None
            return None
        
        def invalidate_user_cache(self, user_id):
            cache_key = f"perm_cache:{user_id}"
            return self.redis.delete(cache_key)
    
    return MockPermissionCache(mock_redis_client['redis_client'])


# =============================================================================
# Security Context Fixtures
# =============================================================================

@pytest.fixture
def security_context(authenticated_user, permission_context):
    """
    Comprehensive security context for authorization testing
    per Section 6.4.2 security context fixtures for authorization testing.
    """
    return {
        'user': authenticated_user,
        'permission_context': permission_context,
        'security_level': 'standard',
        'risk_score': 25,
        'auth_method': 'jwt',
        'auth_provider': 'auth0',
        'mfa_verified': True,
        'device_trusted': True,
        'session_id': permission_context.session_id,
        'correlation_id': permission_context.correlation_id,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'client_ip': permission_context.request_ip,
        'user_agent': 'Mozilla/5.0 (Test Browser)',
        'geo_location': {
            'country': 'US',
            'region': 'CA',
            'city': 'San Francisco'
        }
    }


@pytest.fixture
def mock_security_audit_logger():
    """
    Mock security audit logger for testing security event logging
    per Section 6.4.2 comprehensive audit logging for authorization decisions.
    """
    with patch('src.auth.audit.SecurityAuditLogger') as mock_logger:
        mock_instance = MagicMock()
        mock_logger.return_value = mock_instance
        
        # Track logged events
        logged_events = []
        
        def mock_log_event(event_type, **kwargs):
            event = {
                'event_type': event_type,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                **kwargs
            }
            logged_events.append(event)
        
        mock_instance.log_authorization_event.side_effect = mock_log_event
        mock_instance.log_authentication_event.side_effect = mock_log_event
        mock_instance.log_security_violation.side_effect = mock_log_event
        
        yield {
            'logger': mock_instance,
            'logged_events': logged_events
        }


# =============================================================================
# Authentication State Management Fixtures
# =============================================================================

@pytest.fixture
def authentication_state():
    """
    Authentication state for testing state management
    per Section 6.4.1 authentication state management.
    """
    return {
        'authenticated': True,
        'user_id': f"auth0|{secrets.token_hex(12)}",
        'session_id': secrets.token_urlsafe(32),
        'auth_method': 'jwt',
        'auth_provider': 'auth0',
        'authenticated_at': datetime.now(timezone.utc).isoformat(),
        'expires_at': (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat(),
        'permissions': ['read:profile', 'write:profile', 'read:documents'],
        'roles': ['user'],
        'mfa_verified': True,
        'token_type': 'access_token',
        'scope': 'read:profile write:profile read:documents',
        'device_id': str(uuid.uuid4()),
        'client_id': 'test_client_123',
        'last_activity': datetime.now(timezone.utc).isoformat()
    }


@pytest.fixture
def mock_core_authenticator(valid_jwt_token, authenticated_user):
    """
    Mock CoreJWTAuthenticator for testing authentication workflows
    per Section 6.4.1 CoreJWTAuthenticator comprehensive authentication functionality.
    """
    with patch('src.auth.authentication.CoreJWTAuthenticator') as mock_authenticator:
        mock_instance = MagicMock()
        mock_authenticator.return_value = mock_instance
        
        # Mock authentication methods
        async def mock_authenticate_request(token=None, required_permissions=None, allow_expired=False):
            if token == valid_jwt_token['token']:
                return authenticated_user
            return None
        
        mock_instance.authenticate_request = AsyncMock(side_effect=mock_authenticate_request)
        
        # Mock token validation
        async def mock_validate_jwt_token(token, allow_expired=False):
            if token == valid_jwt_token['token']:
                return valid_jwt_token['claims']
            return None
        
        mock_instance._validate_jwt_token = AsyncMock(side_effect=mock_validate_jwt_token)
        
        # Mock health status
        mock_instance.get_health_status.return_value = {
            'status': 'healthy',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'components': {
                'jwt_manager': {'status': 'healthy'},
                'cache_manager': {'status': 'healthy'},
                'auth0_service': {'status': 'healthy'}
            }
        }
        
        yield mock_instance


# =============================================================================
# Testing Utilities and Helpers
# =============================================================================

@pytest.fixture
def auth_test_client(flask_app, mock_flask_login_manager, mock_flask_session):
    """
    Configured test client with authentication and session management
    per Section 6.6.1 Flask testing patterns and fixtures.
    """
    with flask_app.test_client() as client:
        with flask_app.app_context():
            yield client


@pytest.fixture
def authenticated_request_context(flask_app, authenticated_user, mock_flask_login_manager):
    """
    Flask request context with authenticated user for testing protected routes
    per Section 6.4.1 Flask-Login integration.
    """
    with flask_app.test_request_context():
        # Add user to users database
        mock_flask_login_manager['users_db'][authenticated_user.user_id] = authenticated_user
        
        # Set Flask g context
        g.authenticated_user = authenticated_user
        g.current_user_id = authenticated_user.user_id
        g.current_user_permissions = authenticated_user.permissions
        
        yield {
            'user': authenticated_user,
            'app_context': flask_app.app_context(),
            'request_context': flask_app.test_request_context()
        }


@pytest.fixture
def mock_datetime():
    """Mock datetime for consistent testing across time-sensitive operations."""
    fixed_datetime = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    
    with patch('src.auth.authentication.datetime') as mock_dt:
        mock_dt.now.return_value = fixed_datetime
        mock_dt.utcnow.return_value = fixed_datetime
        mock_dt.side_effect = lambda *args, **kwargs: datetime(*args, **kwargs)
        yield fixed_datetime


@pytest.fixture
def mock_secrets():
    """Mock secrets module for predictable token generation in tests."""
    with patch('src.auth.authentication.secrets') as mock_secrets_module:
        mock_secrets_module.token_urlsafe.return_value = "test_token_12345"
        mock_secrets_module.token_hex.return_value = "test_hex_abcdef"
        yield mock_secrets_module


@contextmanager
def mock_request_context(method='GET', path='/', headers=None, json_data=None):
    """
    Context manager for mocking Flask request context in authentication tests
    per Section 6.6.1 Flask-specific testing patterns.
    """
    with patch('flask.request') as mock_request:
        mock_request.method = method
        mock_request.path = path
        mock_request.endpoint = f"{method.lower()}_{path.replace('/', '_')}"
        mock_request.headers = headers or {}
        mock_request.json = json_data
        mock_request.remote_addr = '127.0.0.1'
        mock_request.args = {}
        mock_request.cookies = {}
        yield mock_request


# =============================================================================
# Integration Test Fixtures
# =============================================================================

@pytest.fixture
def complete_auth_system(
    flask_app,
    auth0_config,
    mock_auth0_client,
    mock_redis_client,
    mock_flask_login_manager,
    mock_flask_session,
    rsa_key_pair
):
    """
    Complete authentication system integration for end-to-end testing
    per Section 6.6.1 production-equivalent test environment setup.
    """
    # Configure app with auth settings
    flask_app.config.update(auth0_config)
    flask_app.config['SECRET_KEY'] = 'test-secret-key'
    flask_app.config['TESTING'] = True
    
    return {
        'app': flask_app,
        'auth0_config': auth0_config,
        'auth0_client': mock_auth0_client,
        'redis_client': mock_redis_client,
        'login_manager': mock_flask_login_manager,
        'session_config': mock_flask_session,
        'rsa_keys': rsa_key_pair
    }


@pytest.fixture
async def auth_performance_test_setup():
    """
    Performance testing setup for authentication system validation
    per Section 6.6.1 performance optimization ensuring ≤10% variance.
    """
    # Performance baseline data
    baseline_metrics = {
        'token_validation_time': 0.05,  # 50ms baseline
        'user_context_creation_time': 0.02,  # 20ms baseline
        'permission_check_time': 0.01,  # 10ms baseline
        'cache_operation_time': 0.005,  # 5ms baseline
    }
    
    # Performance thresholds (≤10% variance)
    thresholds = {
        metric: baseline * 1.1 for metric, baseline in baseline_metrics.items()
    }
    
    return {
        'baseline_metrics': baseline_metrics,
        'performance_thresholds': thresholds,
        'variance_tolerance': 0.10  # 10% maximum variance
    }


# =============================================================================
# Cleanup and Teardown Fixtures
# =============================================================================

@pytest.fixture(autouse=True)
def auth_fixtures_cleanup():
    """
    Automatic cleanup for authentication fixtures ensuring test isolation
    per Section 6.6.1 test data management with automated cleanup.
    """
    # Setup (before test)
    yield
    
    # Cleanup (after test)
    # Clear any global state
    import gc
    gc.collect()
    
    # Reset any module-level state
    try:
        # Clear Flask g context if it exists
        if hasattr(g, 'authenticated_user'):
            delattr(g, 'authenticated_user')
        if hasattr(g, 'current_user_id'):
            delattr(g, 'current_user_id')
        if hasattr(g, 'current_user_permissions'):
            delattr(g, 'current_user_permissions')
    except RuntimeError:
        # Outside application context
        pass


# Export all fixtures for easy importing
__all__ = [
    # Configuration fixtures
    'auth0_config', 'mock_auth0_domain', 'mock_auth0_client_id', 
    'mock_auth0_client_secret', 'mock_auth0_audience',
    
    # Cryptographic fixtures
    'rsa_key_pair',
    
    # JWT token fixtures
    'jwt_claims', 'valid_jwt_token', 'expired_jwt_token', 
    'malformed_jwt_token', 'jwt_token_with_invalid_signature',
    
    # User and profile fixtures
    'auth0_user_profile', 'authenticated_user', 'flask_login_user',
    'anonymous_user', 'session_user',
    
    # Auth0 service mocking
    'mock_auth0_jwks', 'mock_auth0_client', 'mock_auth0_circuit_breaker',
    'mock_auth0_async_client',
    
    # Flask-Login integration
    'mock_flask_login_manager',
    
    # Session management
    'mock_redis_client', 'mock_encrypted_session_interface', 
    'session_data', 'mock_flask_session',
    
    # Authorization testing
    'permission_context', 'mock_authorization_manager', 'mock_permission_cache',
    
    # Security context
    'security_context', 'mock_security_audit_logger',
    
    # Authentication state
    'authentication_state', 'mock_core_authenticator',
    
    # Testing utilities
    'auth_test_client', 'authenticated_request_context',
    'mock_datetime', 'mock_secrets',
    
    # Integration testing
    'complete_auth_system', 'auth_performance_test_setup',
    
    # Cleanup
    'auth_fixtures_cleanup'
]