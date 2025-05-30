"""
Authentication and Authorization Test Fixtures

This module provides comprehensive test fixtures for Auth0 service mocking, JWT token generation,
Flask-Login user objects, and authentication state management for security testing scenarios.

Key Features:
- Auth0 enterprise integration testing through Python SDK per Section 0.1.3 authentication/authorization considerations
- JWT token processing migration from jsonwebtoken to PyJWT 2.8+ per Section 0.1.2
- Flask-Login integration for user session management per Section 6.4.1
- 95% authentication module coverage per Section 6.6.3 security compliance
- Authentication system preserving JWT token validation patterns per Section 0.1.1

Fixtures Provided:
- Auth0 Python SDK mock fixtures for authentication testing per Section 6.4.1 identity management
- PyJWT 2.8+ token generation and validation fixtures per Section 0.1.2 authentication module
- Flask-Login user objects for session management testing per Section 6.4.1 Flask-Login integration
- JWT claims extraction and validation fixtures per Section 6.4.1 token handling
- Security context fixtures for authorization testing per Section 6.4.2 authorization system
- Authentication state management fixtures per Section 6.4.1 session management
- Flask-Session user context fixtures for distributed session testing per Section 3.4.2

Dependencies:
- pytest 7.4+ with extensive plugin ecosystem support
- pytest-mock for comprehensive external service simulation
- PyJWT 2.8+ for JWT token processing equivalent to Node.js jsonwebtoken
- auth0-python 4.7+ for Auth0 enterprise integration
- Flask-Login 0.7.0+ for user authentication state management
- factory_boy for dynamic test object generation
- cryptography 41.0+ for secure cryptographic operations
- redis-py 5.0+ for caching and session management
- structlog 23.1+ for enterprise audit logging

Author: Flask Migration Team
Version: 1.0.0
Compliance: SOC 2, ISO 27001, OWASP Top 10
"""

import asyncio
import base64
import hashlib
import json
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Union, Callable, Generator, AsyncGenerator
from unittest.mock import Mock, MagicMock, patch, AsyncMock
import uuid

import pytest
import pytest_asyncio
from flask import Flask, request, session, g
from flask_login import UserMixin, AnonymousUserMixin
import jwt
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
import factory
from factory import Faker, SubFactory, LazyAttribute, LazyFunction
import redis
from redis.exceptions import RedisError
import structlog

# Import authentication components with fallback handling
try:
    from src.auth.authentication import (
        AuthenticationManager, Auth0Config, JWTTokenValidator,
        Auth0UserManager, Auth0CircuitBreaker
    )
    from src.auth.authorization import (
        PermissionValidator, RoleManager, ResourceAuthorizationManager,
        AuthorizationDecorators, PermissionContext
    )
    from src.auth.session import (
        SessionManager, FlaskLoginManager, DistributedSessionManager,
        SessionSecurityManager
    )
    from src.auth.cache import (
        AuthenticationCache, PermissionCacheManager, get_auth_cache
    )
    from src.auth.exceptions import (
        AuthenticationException, AuthorizationException, 
        JWTException, Auth0Exception, SessionException,
        SecurityErrorCode, SecurityException
    )
    from src.config.settings import TestingConfig
except ImportError:
    # Fallback implementations for test isolation
    class AuthenticationException(Exception):
        pass
    
    class AuthorizationException(Exception):
        pass
    
    class JWTException(Exception):
        pass
    
    class Auth0Exception(Exception):
        pass
    
    class SessionException(Exception):
        pass
    
    class SecurityException(Exception):
        pass
    
    class SecurityErrorCode:
        AUTH_TOKEN_INVALID = "AUTH_TOKEN_INVALID"
        AUTH_TOKEN_EXPIRED = "AUTH_TOKEN_EXPIRED"
        AUTH_CREDENTIALS_INVALID = "AUTH_CREDENTIALS_INVALID"
        AUTHZ_PERMISSION_DENIED = "AUTHZ_PERMISSION_DENIED"
    
    class TestingConfig:
        TESTING = True
        SECRET_KEY = 'test-secret-key'


# Configure structured logging for test fixtures
logger = structlog.get_logger("tests.fixtures.auth")


class MockAuth0User(UserMixin):
    """
    Mock Flask-Login user object for authentication testing with Auth0 profile integration.
    
    This class provides a comprehensive user object that mimics the behavior of a real
    Auth0-authenticated user while providing controlled test data for authentication
    and authorization testing scenarios.
    
    Features:
    - Flask-Login UserMixin integration for session management
    - Auth0 profile simulation with realistic user attributes
    - Permission and role management for authorization testing
    - Session state management for distributed session testing
    - Security context for audit logging and compliance testing
    """
    
    def __init__(
        self,
        user_id: str,
        email: str,
        auth0_profile: Optional[Dict[str, Any]] = None,
        permissions: Optional[Set[str]] = None,
        roles: Optional[Set[str]] = None,
        is_authenticated: bool = True,
        is_active: bool = True
    ):
        """
        Initialize mock Auth0 user with comprehensive profile and security context.
        
        Args:
            user_id: Unique user identifier (Auth0 sub claim)
            email: User email address
            auth0_profile: Auth0 user profile data
            permissions: Set of user permissions for authorization testing
            roles: Set of user roles for RBAC testing
            is_authenticated: Whether user is authenticated
            is_active: Whether user account is active
        """
        self.id = user_id
        self.email = email
        self.auth0_profile = auth0_profile or self._generate_default_profile()
        self.permissions = permissions or set()
        self.roles = roles or {'user'}
        self._is_authenticated = is_authenticated
        self._is_active = is_active
        self._is_anonymous = False
        
        # Session and security metadata
        self.session_id = str(uuid.uuid4())
        self.login_timestamp = datetime.utcnow()
        self.last_activity = datetime.utcnow()
        self.ip_address = '127.0.0.1'
        self.user_agent = 'pytest-test-agent'
        
        logger.debug(
            "Mock Auth0 user created",
            user_id=user_id,
            email=email,
            permissions_count=len(self.permissions),
            roles_count=len(self.roles)
        )
    
    def _generate_default_profile(self) -> Dict[str, Any]:
        """Generate default Auth0 profile for testing"""
        return {
            'sub': self.id,
            'email': self.email,
            'email_verified': True,
            'name': f"Test User {self.id[:8]}",
            'nickname': f"test_{self.id[:8]}",
            'picture': f"https://example.com/avatars/{self.id}.jpg",
            'updated_at': datetime.utcnow().isoformat(),
            'created_at': (datetime.utcnow() - timedelta(days=30)).isoformat(),
            'last_login': datetime.utcnow().isoformat(),
            'logins_count': 42,
            'app_metadata': {
                'roles': list(self.roles),
                'permissions': list(self.permissions)
            },
            'user_metadata': {
                'preferences': {
                    'theme': 'dark',
                    'language': 'en'
                }
            }
        }
    
    @property
    def is_authenticated(self) -> bool:
        """Return authentication status for Flask-Login"""
        return self._is_authenticated
    
    @property
    def is_active(self) -> bool:
        """Return active status for Flask-Login"""
        return self._is_active
    
    @property
    def is_anonymous(self) -> bool:
        """Return anonymous status for Flask-Login"""
        return self._is_anonymous
    
    def get_id(self) -> str:
        """Return user ID for Flask-Login session management"""
        return self.id
    
    def has_permission(self, permission: str) -> bool:
        """Check if user has specific permission"""
        return permission in self.permissions
    
    def has_role(self, role: str) -> bool:
        """Check if user has specific role"""
        return role in self.roles
    
    def add_permission(self, permission: str) -> None:
        """Add permission to user for dynamic testing"""
        self.permissions.add(permission)
        logger.debug("Permission added to mock user", user_id=self.id, permission=permission)
    
    def remove_permission(self, permission: str) -> None:
        """Remove permission from user for dynamic testing"""
        self.permissions.discard(permission)
        logger.debug("Permission removed from mock user", user_id=self.id, permission=permission)
    
    def add_role(self, role: str) -> None:
        """Add role to user for dynamic testing"""
        self.roles.add(role)
        logger.debug("Role added to mock user", user_id=self.id, role=role)
    
    def remove_role(self, role: str) -> None:
        """Remove role from user for dynamic testing"""
        self.roles.discard(role)
        logger.debug("Role removed from mock user", user_id=self.id, role=role)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert user to dictionary for serialization"""
        return {
            'id': self.id,
            'email': self.email,
            'auth0_profile': self.auth0_profile,
            'permissions': list(self.permissions),
            'roles': list(self.roles),
            'is_authenticated': self.is_authenticated,
            'is_active': self.is_active,
            'session_id': self.session_id,
            'login_timestamp': self.login_timestamp.isoformat(),
            'last_activity': self.last_activity.isoformat()
        }


class MockAnonymousUser(AnonymousUserMixin):
    """
    Mock anonymous user for unauthenticated testing scenarios.
    
    Provides anonymous user behavior for testing authentication requirements
    and authorization denial scenarios.
    """
    
    def __init__(self):
        self.permissions = set()
        self.roles = set()
        self.auth0_profile = {}
    
    def has_permission(self, permission: str) -> bool:
        """Anonymous users have no permissions"""
        return False
    
    def has_role(self, role: str) -> bool:
        """Anonymous users have no roles"""
        return False


class JWTTokenFactory:
    """
    JWT token factory for generating test tokens with PyJWT 2.8+ compatibility.
    
    This factory provides comprehensive JWT token generation for testing authentication
    scenarios, including valid tokens, expired tokens, invalid signatures, and
    malformed tokens for comprehensive security testing.
    
    Features:
    - PyJWT 2.8+ token generation equivalent to Node.js jsonwebtoken
    - RSA key pair generation for signature testing
    - Configurable token claims and expiration
    - Invalid token generation for negative testing
    - Auth0-compatible token structure and claims
    """
    
    def __init__(self):
        """Initialize JWT token factory with RSA key pair"""
        self.private_key, self.public_key = self._generate_rsa_keypair()
        self.algorithm = 'RS256'
        self.issuer = 'https://test-domain.auth0.com/'
        self.audience = 'test-audience'
        
        logger.debug("JWT token factory initialized with RSA keypair")
    
    def _generate_rsa_keypair(self) -> tuple[bytes, bytes]:
        """Generate RSA key pair for JWT signing"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    def create_valid_token(
        self,
        user_id: str,
        email: str,
        permissions: Optional[List[str]] = None,
        roles: Optional[List[str]] = None,
        expires_in: int = 3600,
        additional_claims: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Create valid JWT token for authentication testing.
        
        Args:
            user_id: User identifier (sub claim)
            email: User email address
            permissions: List of user permissions
            roles: List of user roles
            expires_in: Token expiration in seconds
            additional_claims: Additional JWT claims
            
        Returns:
            Signed JWT token string
        """
        now = datetime.utcnow()
        
        payload = {
            'iss': self.issuer,
            'aud': self.audience,
            'sub': user_id,
            'email': email,
            'email_verified': True,
            'iat': int(now.timestamp()),
            'exp': int((now + timedelta(seconds=expires_in)).timestamp()),
            'azp': 'test-client-id',
            'scope': 'openid profile email',
            'permissions': permissions or [],
            'roles': roles or ['user'],
            'https://example.com/roles': roles or ['user'],
            'https://example.com/permissions': permissions or []
        }
        
        if additional_claims:
            payload.update(additional_claims)
        
        token = jwt.encode(
            payload=payload,
            key=self.private_key,
            algorithm=self.algorithm,
            headers={'kid': 'test-key-id'}
        )
        
        logger.debug(
            "Valid JWT token created",
            user_id=user_id,
            expires_in=expires_in,
            permissions_count=len(permissions or [])
        )
        
        return token
    
    def create_expired_token(
        self,
        user_id: str,
        email: str,
        expired_seconds_ago: int = 3600
    ) -> str:
        """
        Create expired JWT token for expiration testing.
        
        Args:
            user_id: User identifier
            email: User email address
            expired_seconds_ago: How many seconds ago the token expired
            
        Returns:
            Expired JWT token string
        """
        now = datetime.utcnow()
        
        payload = {
            'iss': self.issuer,
            'aud': self.audience,
            'sub': user_id,
            'email': email,
            'iat': int((now - timedelta(seconds=expired_seconds_ago + 7200)).timestamp()),
            'exp': int((now - timedelta(seconds=expired_seconds_ago)).timestamp())
        }
        
        token = jwt.encode(
            payload=payload,
            key=self.private_key,
            algorithm=self.algorithm
        )
        
        logger.debug(
            "Expired JWT token created",
            user_id=user_id,
            expired_seconds_ago=expired_seconds_ago
        )
        
        return token
    
    def create_invalid_signature_token(
        self,
        user_id: str,
        email: str
    ) -> str:
        """
        Create JWT token with invalid signature for signature validation testing.
        
        Args:
            user_id: User identifier
            email: User email address
            
        Returns:
            JWT token with invalid signature
        """
        # Create token with different key
        wrong_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        wrong_private_pem = wrong_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        now = datetime.utcnow()
        
        payload = {
            'iss': self.issuer,
            'aud': self.audience,
            'sub': user_id,
            'email': email,
            'iat': int(now.timestamp()),
            'exp': int((now + timedelta(hours=1)).timestamp())
        }
        
        token = jwt.encode(
            payload=payload,
            key=wrong_private_pem,
            algorithm=self.algorithm
        )
        
        logger.debug("Invalid signature JWT token created", user_id=user_id)
        
        return token
    
    def create_malformed_token(self) -> str:
        """
        Create malformed JWT token for format validation testing.
        
        Returns:
            Malformed JWT token string
        """
        # Return token with wrong number of parts
        malformed_token = "invalid.token"
        
        logger.debug("Malformed JWT token created")
        
        return malformed_token
    
    def get_public_key_pem(self) -> str:
        """Get public key in PEM format for verification"""
        return self.public_key.decode('utf-8')
    
    def get_jwks(self) -> Dict[str, Any]:
        """
        Get JWKS (JSON Web Key Set) for Auth0 mock integration.
        
        Returns:
            JWKS dictionary compatible with Auth0 format
        """
        public_key_obj = load_pem_public_key(self.public_key)
        public_numbers = public_key_obj.public_numbers()
        
        # Convert to base64url encoding
        def int_to_base64url(value: int) -> str:
            byte_length = (value.bit_length() + 7) // 8
            value_bytes = value.to_bytes(byte_length, byteorder='big')
            return base64.urlsafe_b64encode(value_bytes).decode('utf-8').rstrip('=')
        
        jwks = {
            'keys': [
                {
                    'kty': 'RSA',
                    'use': 'sig',
                    'kid': 'test-key-id',
                    'n': int_to_base64url(public_numbers.n),
                    'e': int_to_base64url(public_numbers.e),
                    'alg': 'RS256',
                    'x5c': [],
                    'x5t': '',
                    'x5t#S256': ''
                }
            ]
        }
        
        logger.debug("JWKS generated for Auth0 mock integration")
        
        return jwks


class Auth0ServiceMock:
    """
    Comprehensive Auth0 service mock for authentication testing.
    
    This mock provides realistic Auth0 API responses and behavior for testing
    authentication flows, user management, and permission validation without
    external dependencies.
    
    Features:
    - Auth0 Management API mock endpoints
    - User profile and permission management
    - Token validation and refresh mocking
    - JWKS endpoint simulation
    - Circuit breaker testing support
    - Rate limiting simulation
    """
    
    def __init__(self, jwt_factory: JWTTokenFactory):
        """
        Initialize Auth0 service mock with JWT token factory.
        
        Args:
            jwt_factory: JWT token factory for token generation
        """
        self.jwt_factory = jwt_factory
        self.users: Dict[str, Dict[str, Any]] = {}
        self.user_permissions: Dict[str, Set[str]] = {}
        self.user_roles: Dict[str, Set[str]] = {}
        self.circuit_breaker_enabled = False
        self.rate_limit_enabled = False
        self.response_delay = 0.0
        
        logger.debug("Auth0 service mock initialized")
    
    def add_user(
        self,
        user_id: str,
        email: str,
        profile_data: Optional[Dict[str, Any]] = None,
        permissions: Optional[Set[str]] = None,
        roles: Optional[Set[str]] = None
    ) -> None:
        """
        Add user to Auth0 mock for testing.
        
        Args:
            user_id: User identifier
            email: User email address
            profile_data: Additional profile data
            permissions: User permissions
            roles: User roles
        """
        self.users[user_id] = {
            'user_id': user_id,
            'email': email,
            'email_verified': True,
            'name': f"Test User {user_id[:8]}",
            'picture': f"https://example.com/avatars/{user_id}.jpg",
            'created_at': datetime.utcnow().isoformat(),
            'updated_at': datetime.utcnow().isoformat(),
            'last_login': datetime.utcnow().isoformat(),
            'logins_count': 1,
            **(profile_data or {})
        }
        
        self.user_permissions[user_id] = permissions or set()
        self.user_roles[user_id] = roles or {'user'}
        
        logger.debug(
            "User added to Auth0 mock",
            user_id=user_id,
            email=email,
            permissions_count=len(self.user_permissions[user_id])
        )
    
    def get_user_profile(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user profile from Auth0 mock"""
        if self.circuit_breaker_enabled:
            raise Auth0Exception("Circuit breaker is open")
        
        return self.users.get(user_id)
    
    def get_user_permissions(self, user_id: str) -> Set[str]:
        """Get user permissions from Auth0 mock"""
        if self.circuit_breaker_enabled:
            raise Auth0Exception("Circuit breaker is open")
        
        return self.user_permissions.get(user_id, set())
    
    def get_user_roles(self, user_id: str) -> Set[str]:
        """Get user roles from Auth0 mock"""
        if self.circuit_breaker_enabled:
            raise Auth0Exception("Circuit breaker is open")
        
        return self.user_roles.get(user_id, set())
    
    def validate_token(self, token: str) -> Dict[str, Any]:
        """Validate JWT token using mock"""
        try:
            payload = jwt.decode(
                jwt=token,
                key=self.jwt_factory.public_key,
                algorithms=[self.jwt_factory.algorithm],
                audience=self.jwt_factory.audience,
                issuer=self.jwt_factory.issuer
            )
            
            logger.debug("Token validated by Auth0 mock", user_id=payload.get('sub'))
            
            return payload
        except jwt.ExpiredSignatureError:
            raise Auth0Exception("Token has expired")
        except jwt.InvalidSignatureError:
            raise Auth0Exception("Invalid token signature")
        except jwt.InvalidTokenError as e:
            raise Auth0Exception(f"Invalid token: {str(e)}")
    
    def get_jwks(self) -> Dict[str, Any]:
        """Get JWKS for token validation"""
        return self.jwt_factory.get_jwks()
    
    def enable_circuit_breaker(self) -> None:
        """Enable circuit breaker for testing"""
        self.circuit_breaker_enabled = True
        logger.debug("Auth0 mock circuit breaker enabled")
    
    def disable_circuit_breaker(self) -> None:
        """Disable circuit breaker for testing"""
        self.circuit_breaker_enabled = False
        logger.debug("Auth0 mock circuit breaker disabled")
    
    def enable_rate_limiting(self) -> None:
        """Enable rate limiting simulation"""
        self.rate_limit_enabled = True
        logger.debug("Auth0 mock rate limiting enabled")
    
    def disable_rate_limiting(self) -> None:
        """Disable rate limiting simulation"""
        self.rate_limit_enabled = False
        logger.debug("Auth0 mock rate limiting disabled")


class MockRedisCache:
    """
    Mock Redis cache for authentication and session testing.
    
    Provides in-memory Redis-compatible cache behavior for testing authentication
    caching, session management, and permission caching without external Redis
    dependency.
    
    Features:
    - Redis command compatibility
    - TTL and expiration simulation
    - Key pattern matching
    - Connection error simulation
    - Memory usage tracking
    """
    
    def __init__(self):
        """Initialize mock Redis cache"""
        self.data: Dict[str, Any] = {}
        self.ttl_data: Dict[str, datetime] = {}
        self.connection_error = False
        self.operation_delay = 0.0
        
        logger.debug("Mock Redis cache initialized")
    
    def get(self, key: str) -> Optional[str]:
        """Get value from cache with expiration check"""
        if self.connection_error:
            raise RedisError("Connection error")
        
        self._check_expiration(key)
        return self.data.get(key)
    
    def set(self, key: str, value: str, ex: Optional[int] = None) -> bool:
        """Set value in cache with optional expiration"""
        if self.connection_error:
            raise RedisError("Connection error")
        
        self.data[key] = value
        
        if ex is not None:
            self.ttl_data[key] = datetime.utcnow() + timedelta(seconds=ex)
        
        logger.debug("Cache key set", key=key, has_expiration=ex is not None)
        
        return True
    
    def setex(self, key: str, time: int, value: str) -> bool:
        """Set value with expiration time"""
        return self.set(key, value, ex=time)
    
    def delete(self, *keys: str) -> int:
        """Delete keys from cache"""
        if self.connection_error:
            raise RedisError("Connection error")
        
        deleted_count = 0
        for key in keys:
            if key in self.data:
                del self.data[key]
                deleted_count += 1
            if key in self.ttl_data:
                del self.ttl_data[key]
        
        logger.debug("Cache keys deleted", keys=keys, deleted_count=deleted_count)
        
        return deleted_count
    
    def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        if self.connection_error:
            raise RedisError("Connection error")
        
        self._check_expiration(key)
        return key in self.data
    
    def keys(self, pattern: str) -> List[str]:
        """Get keys matching pattern"""
        if self.connection_error:
            raise RedisError("Connection error")
        
        # Simple pattern matching (supports * wildcard)
        import fnmatch
        matching_keys = []
        
        for key in list(self.data.keys()):
            self._check_expiration(key)
            if fnmatch.fnmatch(key, pattern):
                matching_keys.append(key)
        
        return matching_keys
    
    def ttl(self, key: str) -> int:
        """Get TTL for key"""
        if key not in self.data:
            return -2  # Key doesn't exist
        
        if key not in self.ttl_data:
            return -1  # Key exists but no expiration
        
        ttl = (self.ttl_data[key] - datetime.utcnow()).total_seconds()
        return max(0, int(ttl))
    
    def _check_expiration(self, key: str) -> None:
        """Check and handle key expiration"""
        if key in self.ttl_data:
            if datetime.utcnow() > self.ttl_data[key]:
                # Key expired, remove it
                self.data.pop(key, None)
                self.ttl_data.pop(key, None)
    
    def flush_db(self) -> None:
        """Clear all data from cache"""
        self.data.clear()
        self.ttl_data.clear()
        logger.debug("Mock Redis cache flushed")
    
    def enable_connection_error(self) -> None:
        """Enable connection error simulation"""
        self.connection_error = True
        logger.debug("Mock Redis connection error enabled")
    
    def disable_connection_error(self) -> None:
        """Disable connection error simulation"""
        self.connection_error = False
        logger.debug("Mock Redis connection error disabled")
    
    def health_check(self) -> Dict[str, Any]:
        """Return cache health status"""
        return {
            'status': 'healthy' if not self.connection_error else 'unhealthy',
            'keys_count': len(self.data),
            'memory_usage': sum(len(str(k)) + len(str(v)) for k, v in self.data.items()),
            'connection_error': self.connection_error
        }


# Factory classes using factory_boy for dynamic test object generation

class MockUserFactory(factory.Factory):
    """Factory for generating mock Auth0 users with varied test scenarios"""
    
    class Meta:
        model = MockAuth0User
    
    user_id = factory.LazyFunction(lambda: f"auth0|{uuid.uuid4().hex}")
    email = factory.Faker('email')
    is_authenticated = True
    is_active = True
    
    @factory.LazyAttribute
    def auth0_profile(obj):
        """Generate Auth0 profile with user-specific data"""
        return {
            'sub': obj.user_id,
            'email': obj.email,
            'email_verified': True,
            'name': f"Test User {obj.user_id[:8]}",
            'nickname': f"test_{obj.user_id[:8]}",
            'picture': f"https://example.com/avatars/{obj.user_id}.jpg",
            'updated_at': datetime.utcnow().isoformat(),
            'created_at': (datetime.utcnow() - timedelta(days=30)).isoformat(),
        }
    
    @factory.LazyAttribute
    def permissions(obj):
        """Generate varied permission sets for testing"""
        return {'read:profile', 'update:profile'}
    
    @factory.LazyAttribute
    def roles(obj):
        """Generate role sets for testing"""
        return {'user'}


class AdminUserFactory(MockUserFactory):
    """Factory for generating admin users with elevated permissions"""
    
    @factory.LazyAttribute
    def permissions(obj):
        return {
            'read:profile', 'update:profile', 'delete:profile',
            'read:admin', 'write:admin', 'delete:admin',
            'manage:users', 'manage:roles', 'manage:permissions'
        }
    
    @factory.LazyAttribute
    def roles(obj):
        return {'user', 'admin', 'superuser'}


class JWTTokenTestFactory(factory.Factory):
    """Factory for generating JWT tokens with varied test scenarios"""
    
    class Meta:
        model = dict
    
    user_id = factory.LazyFunction(lambda: f"auth0|{uuid.uuid4().hex}")
    email = factory.Faker('email')
    permissions = factory.LazyFunction(lambda: ['read:profile', 'update:profile'])
    roles = factory.LazyFunction(lambda: ['user'])
    expires_in = 3600
    
    @classmethod
    def _create(cls, model_class, **kwargs):
        """Create JWT token using token factory"""
        jwt_factory = JWTTokenFactory()
        return jwt_factory.create_valid_token(**kwargs)


# Pytest fixtures for authentication testing

@pytest.fixture
def jwt_token_factory() -> JWTTokenFactory:
    """
    Provide JWT token factory for test token generation.
    
    Returns:
        Configured JWT token factory instance
    """
    factory = JWTTokenFactory()
    logger.debug("JWT token factory fixture created")
    return factory


@pytest.fixture
def auth0_mock(jwt_token_factory: JWTTokenFactory) -> Auth0ServiceMock:
    """
    Provide Auth0 service mock for authentication testing.
    
    Args:
        jwt_token_factory: JWT token factory for token generation
        
    Returns:
        Configured Auth0 service mock instance
    """
    mock = Auth0ServiceMock(jwt_token_factory)
    
    # Add default test users
    mock.add_user(
        user_id="auth0|test_user_1",
        email="test@example.com",
        permissions={'read:profile', 'update:profile'},
        roles={'user'}
    )
    
    mock.add_user(
        user_id="auth0|test_admin_1", 
        email="admin@example.com",
        permissions={
            'read:profile', 'update:profile', 'delete:profile',
            'read:admin', 'write:admin', 'manage:users'
        },
        roles={'user', 'admin'}
    )
    
    logger.debug("Auth0 service mock fixture created with test users")
    return mock


@pytest.fixture
def mock_redis_cache() -> MockRedisCache:
    """
    Provide mock Redis cache for caching and session testing.
    
    Returns:
        Mock Redis cache instance
    """
    cache = MockRedisCache()
    logger.debug("Mock Redis cache fixture created")
    return cache


@pytest.fixture
def mock_auth_user() -> MockAuth0User:
    """
    Provide basic authenticated mock user for testing.
    
    Returns:
        Mock Auth0 user instance with standard permissions
    """
    user = MockUserFactory()
    logger.debug("Mock authenticated user fixture created", user_id=user.id)
    return user


@pytest.fixture
def mock_admin_user() -> MockAuth0User:
    """
    Provide admin mock user for elevated permission testing.
    
    Returns:
        Mock Auth0 user instance with admin permissions
    """
    user = AdminUserFactory()
    logger.debug("Mock admin user fixture created", user_id=user.id)
    return user


@pytest.fixture
def mock_anonymous_user() -> MockAnonymousUser:
    """
    Provide anonymous user for unauthenticated testing.
    
    Returns:
        Mock anonymous user instance
    """
    user = MockAnonymousUser()
    logger.debug("Mock anonymous user fixture created")
    return user


@pytest.fixture
def valid_jwt_token(jwt_token_factory: JWTTokenFactory) -> str:
    """
    Provide valid JWT token for authentication testing.
    
    Args:
        jwt_token_factory: JWT token factory
        
    Returns:
        Valid JWT token string
    """
    token = jwt_token_factory.create_valid_token(
        user_id="auth0|test_user_1",
        email="test@example.com",
        permissions=['read:profile', 'update:profile'],
        roles=['user']
    )
    logger.debug("Valid JWT token fixture created")
    return token


@pytest.fixture
def expired_jwt_token(jwt_token_factory: JWTTokenFactory) -> str:
    """
    Provide expired JWT token for expiration testing.
    
    Args:
        jwt_token_factory: JWT token factory
        
    Returns:
        Expired JWT token string
    """
    token = jwt_token_factory.create_expired_token(
        user_id="auth0|test_user_1",
        email="test@example.com",
        expired_seconds_ago=3600
    )
    logger.debug("Expired JWT token fixture created")
    return token


@pytest.fixture
def invalid_signature_token(jwt_token_factory: JWTTokenFactory) -> str:
    """
    Provide JWT token with invalid signature for signature testing.
    
    Args:
        jwt_token_factory: JWT token factory
        
    Returns:
        JWT token with invalid signature
    """
    token = jwt_token_factory.create_invalid_signature_token(
        user_id="auth0|test_user_1",
        email="test@example.com"
    )
    logger.debug("Invalid signature JWT token fixture created")
    return token


@pytest.fixture
def malformed_jwt_token(jwt_token_factory: JWTTokenFactory) -> str:
    """
    Provide malformed JWT token for format validation testing.
    
    Args:
        jwt_token_factory: JWT token factory
        
    Returns:
        Malformed JWT token string
    """
    token = jwt_token_factory.create_malformed_token()
    logger.debug("Malformed JWT token fixture created")
    return token


@pytest.fixture
def admin_jwt_token(jwt_token_factory: JWTTokenFactory) -> str:
    """
    Provide JWT token with admin permissions for authorization testing.
    
    Args:
        jwt_token_factory: JWT token factory
        
    Returns:
        JWT token with admin permissions
    """
    token = jwt_token_factory.create_valid_token(
        user_id="auth0|test_admin_1",
        email="admin@example.com",
        permissions=[
            'read:profile', 'update:profile', 'delete:profile',
            'read:admin', 'write:admin', 'manage:users'
        ],
        roles=['user', 'admin']
    )
    logger.debug("Admin JWT token fixture created")
    return token


@pytest.fixture
def session_data() -> Dict[str, Any]:
    """
    Provide session data for session management testing.
    
    Returns:
        Dictionary with session test data
    """
    data = {
        'user_id': 'auth0|test_user_1',
        'email': 'test@example.com',
        'login_timestamp': datetime.utcnow().isoformat(),
        'session_metadata': {
            'ip_address': '127.0.0.1',
            'user_agent': 'pytest-test-agent',
            'session_type': 'test_session'
        }
    }
    logger.debug("Session data fixture created")
    return data


@pytest.fixture
def mock_auth_cache(mock_redis_cache: MockRedisCache) -> MockRedisCache:
    """
    Provide configured authentication cache for caching testing.
    
    Args:
        mock_redis_cache: Mock Redis cache instance
        
    Returns:
        Configured authentication cache
    """
    # Pre-populate with some test data
    mock_redis_cache.setex(
        'jwt_validation:test_token_hash',
        300,
        json.dumps({
            'sub': 'auth0|test_user_1',
            'email': 'test@example.com',
            'validated_at': datetime.utcnow().isoformat()
        })
    )
    
    mock_redis_cache.setex(
        'perm_cache:auth0|test_user_1',
        300,
        json.dumps(['read:profile', 'update:profile'])
    )
    
    logger.debug("Mock authentication cache fixture created with test data")
    return mock_redis_cache


@pytest.fixture
def auth_test_context():
    """
    Provide authentication test context with mocked external services.
    
    This fixture sets up comprehensive mocking for authentication testing
    including Auth0 service calls, Redis caching, and JWT validation.
    
    Returns:
        Test context manager with mocked services
    """
    with patch('src.auth.authentication.httpx.AsyncClient') as mock_httpx, \
         patch('src.auth.cache.redis.Redis') as mock_redis, \
         patch('src.auth.authentication.Auth0Management') as mock_auth0_mgmt:
        
        # Configure mock HTTP client
        mock_client = AsyncMock()
        mock_httpx.return_value = mock_client
        
        # Configure mock Redis client
        mock_redis_instance = MockRedisCache()
        mock_redis.return_value = mock_redis_instance
        
        # Configure mock Auth0 management client
        mock_mgmt = Mock()
        mock_auth0_mgmt.return_value = mock_mgmt
        
        context = {
            'mock_httpx_client': mock_client,
            'mock_redis': mock_redis_instance,
            'mock_auth0_mgmt': mock_mgmt
        }
        
        logger.debug("Authentication test context fixture created")
        yield context


@pytest.fixture
def circuit_breaker_test_context():
    """
    Provide context for circuit breaker testing with controlled failure simulation.
    
    Returns:
        Circuit breaker test context
    """
    context = {
        'failure_count': 0,
        'circuit_state': 'closed',
        'failure_threshold': 5,
        'recovery_timeout': 60
    }
    
    def simulate_failure():
        context['failure_count'] += 1
        if context['failure_count'] >= context['failure_threshold']:
            context['circuit_state'] = 'open'
    
    def simulate_recovery():
        context['failure_count'] = 0
        context['circuit_state'] = 'closed'
    
    context['simulate_failure'] = simulate_failure
    context['simulate_recovery'] = simulate_recovery
    
    logger.debug("Circuit breaker test context fixture created")
    return context


@pytest.fixture 
def permission_test_scenarios() -> List[Dict[str, Any]]:
    """
    Provide permission test scenarios for authorization testing.
    
    Returns:
        List of permission test scenarios with expected outcomes
    """
    scenarios = [
        {
            'name': 'user_read_own_profile',
            'user_permissions': {'read:profile'},
            'required_permissions': ['read:profile'],
            'resource_owner': 'auth0|test_user_1',
            'requesting_user': 'auth0|test_user_1',
            'expected_result': True
        },
        {
            'name': 'user_write_others_profile', 
            'user_permissions': {'read:profile'},
            'required_permissions': ['write:profile'],
            'resource_owner': 'auth0|other_user',
            'requesting_user': 'auth0|test_user_1',
            'expected_result': False
        },
        {
            'name': 'admin_write_any_profile',
            'user_permissions': {'read:profile', 'write:profile', 'admin:write'},
            'required_permissions': ['write:profile'],
            'resource_owner': 'auth0|other_user', 
            'requesting_user': 'auth0|admin_user',
            'expected_result': True
        },
        {
            'name': 'anonymous_access_denied',
            'user_permissions': set(),
            'required_permissions': ['read:profile'],
            'resource_owner': None,
            'requesting_user': None,
            'expected_result': False
        }
    ]
    
    logger.debug("Permission test scenarios fixture created", scenarios_count=len(scenarios))
    return scenarios


@pytest.fixture
def auth_metrics_context() -> Dict[str, Any]:
    """
    Provide metrics context for authentication performance testing.
    
    Returns:
        Metrics tracking context for performance validation
    """
    context = {
        'auth_requests': 0,
        'auth_successes': 0,
        'auth_failures': 0,
        'cache_hits': 0,
        'cache_misses': 0,
        'avg_response_time': 0.0,
        'response_times': []
    }
    
    def record_auth_request(success: bool, response_time: float):
        context['auth_requests'] += 1
        if success:
            context['auth_successes'] += 1
        else:
            context['auth_failures'] += 1
        
        context['response_times'].append(response_time)
        context['avg_response_time'] = sum(context['response_times']) / len(context['response_times'])
    
    def record_cache_operation(hit: bool):
        if hit:
            context['cache_hits'] += 1
        else:
            context['cache_misses'] += 1
    
    context['record_auth_request'] = record_auth_request
    context['record_cache_operation'] = record_cache_operation
    
    logger.debug("Authentication metrics context fixture created")
    return context


# Async fixtures for comprehensive testing

@pytest_asyncio.fixture
async def async_auth_manager():
    """
    Provide async authentication manager for async authentication testing.
    
    Returns:
        Configured authentication manager for async operations
    """
    # Mock implementation for testing
    class MockAsyncAuthManager:
        def __init__(self):
            self.jwt_factory = JWTTokenFactory()
            self.auth0_mock = Auth0ServiceMock(self.jwt_factory)
        
        async def authenticate_user(self, token: str) -> Dict[str, Any]:
            """Mock async user authentication"""
            try:
                payload = self.auth0_mock.validate_token(token)
                return {
                    'authenticated': True,
                    'user_id': payload.get('sub'),
                    'token_payload': payload
                }
            except Exception as e:
                return {
                    'authenticated': False,
                    'error': str(e)
                }
        
        async def validate_permissions(self, user_id: str, permissions: List[str]) -> Dict[str, Any]:
            """Mock async permission validation"""
            user_permissions = self.auth0_mock.get_user_permissions(user_id)
            has_permissions = all(perm in user_permissions for perm in permissions)
            
            return {
                'user_id': user_id,
                'has_permissions': has_permissions,
                'granted_permissions': list(user_permissions),
                'required_permissions': permissions
            }
    
    manager = MockAsyncAuthManager()
    logger.debug("Async authentication manager fixture created")
    return manager


@pytest_asyncio.fixture
async def async_session_manager():
    """
    Provide async session manager for session testing.
    
    Returns:
        Configured session manager for async session operations
    """
    class MockAsyncSessionManager:
        def __init__(self):
            self.sessions: Dict[str, Dict[str, Any]] = {}
        
        async def create_session(self, user_id: str, session_data: Dict[str, Any]) -> str:
            """Create new session"""
            session_id = str(uuid.uuid4())
            self.sessions[session_id] = {
                'session_id': session_id,
                'user_id': user_id,
                'created_at': datetime.utcnow().isoformat(),
                **session_data
            }
            return session_id
        
        async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
            """Get session data"""
            return self.sessions.get(session_id)
        
        async def invalidate_session(self, session_id: str) -> bool:
            """Invalidate session"""
            if session_id in self.sessions:
                del self.sessions[session_id]
                return True
            return False
    
    manager = MockAsyncSessionManager()
    logger.debug("Async session manager fixture created")
    return manager


# Security and audit logging fixtures

@pytest.fixture
def security_audit_logger():
    """
    Provide security audit logger for compliance testing.
    
    Returns:
        Configured security audit logger instance
    """
    class MockSecurityAuditLogger:
        def __init__(self):
            self.events: List[Dict[str, Any]] = []
        
        def log_auth_event(self, event_type: str, user_id: str, success: bool, **kwargs):
            """Log authentication event"""
            event = {
                'timestamp': datetime.utcnow().isoformat(),
                'event_type': event_type,
                'user_id': user_id,
                'success': success,
                'metadata': kwargs
            }
            self.events.append(event)
            logger.debug("Security event logged", event_type=event_type, success=success)
        
        def log_authz_event(self, user_id: str, permissions: List[str], granted: bool, **kwargs):
            """Log authorization event"""
            event = {
                'timestamp': datetime.utcnow().isoformat(),
                'event_type': 'authorization',
                'user_id': user_id,
                'permissions': permissions,
                'granted': granted,
                'metadata': kwargs
            }
            self.events.append(event)
            logger.debug("Authorization event logged", user_id=user_id, granted=granted)
        
        def get_events(self) -> List[Dict[str, Any]]:
            """Get all logged events"""
            return self.events.copy()
        
        def clear_events(self) -> None:
            """Clear all logged events"""
            self.events.clear()
    
    audit_logger = MockSecurityAuditLogger()
    logger.debug("Security audit logger fixture created")
    return audit_logger


@pytest.fixture
def security_compliance_context() -> Dict[str, Any]:
    """
    Provide security compliance testing context.
    
    Returns:
        Compliance testing context with validation functions
    """
    context = {
        'audit_events': [],
        'security_violations': [],
        'compliance_checks': {
            'audit_logging': True,
            'session_security': True,
            'token_validation': True,
            'permission_enforcement': True
        }
    }
    
    def validate_audit_trail(required_events: List[str]) -> bool:
        """Validate required audit events are present"""
        logged_event_types = {event.get('event_type') for event in context['audit_events']}
        return all(event_type in logged_event_types for event_type in required_events)
    
    def record_security_violation(violation_type: str, details: Dict[str, Any]):
        """Record security violation for compliance tracking"""
        violation = {
            'timestamp': datetime.utcnow().isoformat(),
            'violation_type': violation_type,
            'details': details
        }
        context['security_violations'].append(violation)
        logger.warning("Security violation recorded", violation_type=violation_type)
    
    context['validate_audit_trail'] = validate_audit_trail
    context['record_security_violation'] = record_security_violation
    
    logger.debug("Security compliance context fixture created")
    return context


# Performance testing fixtures

@pytest.fixture
def performance_baseline_context() -> Dict[str, Any]:
    """
    Provide performance baseline context for ≤10% variance validation.
    
    Returns:
        Performance testing context with baseline comparison functions
    """
    # Simulated Node.js baseline performance metrics
    baseline_metrics = {
        'auth_request_time': 0.15,  # 150ms average
        'token_validation_time': 0.05,  # 50ms average
        'permission_check_time': 0.03,  # 30ms average
        'session_create_time': 0.08,  # 80ms average
        'cache_operation_time': 0.01   # 10ms average
    }
    
    context = {
        'baseline_metrics': baseline_metrics,
        'current_metrics': {},
        'variance_threshold': 0.10,  # 10% variance threshold
        'performance_violations': []
    }
    
    def record_performance_metric(metric_name: str, value: float):
        """Record performance metric"""
        context['current_metrics'][metric_name] = value
        
        # Check variance against baseline
        if metric_name in baseline_metrics:
            baseline_value = baseline_metrics[metric_name]
            variance = abs(value - baseline_value) / baseline_value
            
            if variance > context['variance_threshold']:
                violation = {
                    'metric': metric_name,
                    'baseline': baseline_value,
                    'current': value,
                    'variance': variance,
                    'threshold': context['variance_threshold'],
                    'timestamp': datetime.utcnow().isoformat()
                }
                context['performance_violations'].append(violation)
                logger.warning(
                    "Performance variance violation",
                    metric=metric_name,
                    variance=variance,
                    threshold=context['variance_threshold']
                )
    
    def validate_performance_compliance() -> bool:
        """Validate all metrics meet performance requirements"""
        return len(context['performance_violations']) == 0
    
    context['record_performance_metric'] = record_performance_metric
    context['validate_performance_compliance'] = validate_performance_compliance
    
    logger.debug("Performance baseline context fixture created")
    return context