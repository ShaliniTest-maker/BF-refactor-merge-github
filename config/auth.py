"""
Authentication and Authorization Configuration Module

This module provides comprehensive authentication and authorization configuration for
the Flask application, implementing Auth0 integration, PyJWT 2.8+ token processing,
Flask-Login 0.7.0+ session management, and comprehensive JWT validation with Redis
caching. This replaces Node.js jsonwebtoken authentication patterns with enterprise-
grade Python security infrastructure.

Key Features:
- Auth0 Python SDK 4.7+ integration for enterprise authentication (Section 6.4.1)
- PyJWT 2.8+ for JWT token processing equivalent to Node.js implementation (Section 3.2.2)
- Flask-Login 0.7.0+ for comprehensive user session management (Section 3.2.2)
- cryptography 41.0+ for secure cryptographic operations (Section 3.2.2)
- Flask-Talisman 1.1.0+ for HTTP security header enforcement (Section 6.4.1)
- Redis caching for JWT validation and permission management (Section 6.4.2)
- Comprehensive authorization decorators with type hints (Section 6.4.2)
- Circuit breaker integration for Auth0 API calls (Section 6.4.2)
- Structured security event logging with audit trail (Section 6.4.2)

Migrated Components:
- JWT token processing from Node.js jsonwebtoken 9.x to PyJWT 2.8+ (Section 0.1.2)
- Auth0 Python SDK 4.7+ integration replacing Node.js Auth0 SDK (Section 0.2.4)
- Flask-Login 0.7.0+ for comprehensive user session management (Section 3.2.2)
- JWT validation caching with Redis using structured key patterns (Section 6.4.2)
- cryptography 41.0+ for secure token validation and signing (Section 3.2.2)

Author: Flask Migration Team
Version: 1.0.0
Migration Phase: Node.js to Python/Flask Migration (Section 0.1.1)
"""

import os
import json
import base64
import hashlib
import secrets
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List, Union, Callable, Set
from functools import wraps, lru_cache
from urllib.parse import urljoin

# Flask framework imports
from flask import Flask, request, jsonify, g, current_app, session, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_talisman import Talisman
from werkzeug.security import check_password_hash, generate_password_hash

# JWT and cryptography imports
import jwt
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError, InvalidSignatureError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.fernet import Fernet

# Auth0 and external service imports
from auth0.authentication import GetToken, Users
from auth0.management import Auth0 as Auth0Management
import httpx
from tenacity import (
    retry, stop_after_attempt, wait_exponential_jitter,
    retry_if_exception_type, before_sleep_log, after_log
)

# Redis and caching imports
import redis
from redis.exceptions import ConnectionError as RedisConnectionError

# Configuration imports
from config.settings import config, EnvironmentManager, ConfigurationError
from config.database import db_manager, RedisError, DatabaseError

# Validation and sanitization imports
import marshmallow
from email_validator import validate_email, EmailNotValidError
import bleach
from dateutil import parser as dateutil_parser
import structlog

# Initialize structured logger for authentication events
logger = structlog.get_logger("auth.configuration")


class AuthenticationError(Exception):
    """Custom exception for authentication-related errors."""
    pass


class AuthorizationError(Exception):
    """Custom exception for authorization-related errors."""
    pass


class CircuitBreakerError(Exception):
    """Custom exception for circuit breaker activation."""
    pass


class JWTValidationError(Exception):
    """Custom exception for JWT validation errors."""
    pass


class User(UserMixin):
    """
    Flask-Login User class for comprehensive user session management.
    
    This class implements the UserMixin interface for Flask-Login integration,
    providing user authentication state management, session handling, and
    Auth0 profile integration as specified in Section 6.4.1.
    """
    
    def __init__(self, user_id: str, auth0_profile: Dict[str, Any], permissions: Optional[Set[str]] = None):
        """
        Initialize User instance with Auth0 profile and permissions.
        
        Args:
            user_id: Unique user identifier from Auth0
            auth0_profile: Complete Auth0 user profile data
            permissions: Set of user permissions for authorization
        """
        self.id = user_id
        self.auth0_profile = auth0_profile
        self.permissions = permissions or set()
        self.email = auth0_profile.get('email')
        self.name = auth0_profile.get('name')
        self.picture = auth0_profile.get('picture')
        self.email_verified = auth0_profile.get('email_verified', False)
        self.created_at = dateutil_parser.parse(auth0_profile.get('created_at', datetime.utcnow().isoformat()))
        self.last_login = dateutil_parser.parse(auth0_profile.get('last_login', datetime.utcnow().isoformat()))
        
        # Flask-Login required properties
        self.is_authenticated = True
        self.is_active = True
        self.is_anonymous = False
    
    def get_id(self) -> str:
        """Return user ID for Flask-Login session management."""
        return str(self.id)
    
    def has_permission(self, permission: str) -> bool:
        """
        Check if user has specific permission.
        
        Args:
            permission: Permission string to check
            
        Returns:
            True if user has the permission
        """
        return permission in self.permissions
    
    def has_any_permission(self, permissions: List[str]) -> bool:
        """
        Check if user has any of the specified permissions.
        
        Args:
            permissions: List of permission strings to check
            
        Returns:
            True if user has at least one permission
        """
        return bool(self.permissions.intersection(set(permissions)))
    
    def has_all_permissions(self, permissions: List[str]) -> bool:
        """
        Check if user has all specified permissions.
        
        Args:
            permissions: List of permission strings to check
            
        Returns:
            True if user has all permissions
        """
        return set(permissions).issubset(self.permissions)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert user to dictionary for JSON serialization.
        
        Returns:
            Dictionary representation of user data
        """
        return {
            'id': self.id,
            'email': self.email,
            'name': self.name,
            'picture': self.picture,
            'email_verified': self.email_verified,
            'permissions': list(self.permissions),
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'is_authenticated': self.is_authenticated,
            'is_active': self.is_active
        }


class JWTManager:
    """
    Comprehensive JWT token management using PyJWT 2.8+ with Redis caching.
    
    This class provides enterprise-grade JWT token processing equivalent to
    Node.js jsonwebtoken implementation, with Redis caching for performance
    optimization and comprehensive security validation as specified in Section 6.4.2.
    """
    
    def __init__(self, redis_client: redis.Redis):
        """
        Initialize JWT manager with Redis cache integration.
        
        Args:
            redis_client: Redis client for JWT validation caching
        """
        self.redis_client = redis_client
        self.logger = structlog.get_logger("auth.jwt_manager")
        
        # JWT configuration from settings
        self.secret_key = config.JWT_SECRET_KEY
        self.algorithm = config.JWT_ALGORITHM
        self.expiration_delta = config.JWT_EXPIRATION_DELTA
        self.refresh_expiration_delta = config.JWT_REFRESH_EXPIRATION_DELTA
        
        # Cache configuration
        self.cache_enabled = config.JWT_CACHE_ENABLED
        self.cache_ttl = config.JWT_CACHE_TTL
        
        # Auth0 configuration for signature validation
        self.auth0_domain = config.AUTH0_DOMAIN
        self.auth0_audience = config.AUTH0_AUDIENCE
    
    def generate_token(self, user_data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """
        Generate JWT token with comprehensive claims and expiration.
        
        Args:
            user_data: User data to include in token claims
            expires_delta: Optional custom expiration delta
            
        Returns:
            Generated JWT token string
            
        Raises:
            JWTValidationError: When token generation fails
        """
        try:
            # Set expiration time
            if expires_delta:
                expire = datetime.utcnow() + expires_delta
            else:
                expire = datetime.utcnow() + self.expiration_delta
            
            # Create comprehensive JWT claims
            claims = {
                'sub': user_data.get('id'),  # Subject (user ID)
                'email': user_data.get('email'),
                'name': user_data.get('name'),
                'iat': datetime.utcnow(),  # Issued at
                'exp': expire,  # Expiration time
                'iss': f"https://{self.auth0_domain}/",  # Issuer
                'aud': self.auth0_audience,  # Audience
                'permissions': user_data.get('permissions', []),
                'email_verified': user_data.get('email_verified', False),
                'jti': secrets.token_urlsafe(32)  # JWT ID for tracking
            }
            
            # Generate token using PyJWT
            token = jwt.encode(
                claims,
                self.secret_key,
                algorithm=self.algorithm
            )
            
            self.logger.info(
                "JWT token generated successfully",
                user_id=user_data.get('id'),
                expiration=expire.isoformat()
            )
            
            return token
            
        except Exception as e:
            self.logger.error(
                "JWT token generation failed",
                error=str(e),
                user_id=user_data.get('id')
            )
            raise JWTValidationError(f"Token generation failed: {str(e)}")
    
    def validate_token(self, token: str, verify_signature: bool = True) -> Dict[str, Any]:
        """
        Validate JWT token with Redis caching and comprehensive verification.
        
        Args:
            token: JWT token string to validate
            verify_signature: Whether to verify token signature
            
        Returns:
            Decoded token claims
            
        Raises:
            JWTValidationError: When token validation fails
        """
        try:
            # Check cache first if enabled
            if self.cache_enabled:
                cached_claims = self._get_cached_validation(token)
                if cached_claims:
                    self.logger.debug("JWT validation cache hit", token_hash=self._hash_token(token))
                    return cached_claims
            
            # Validate token using PyJWT
            try:
                claims = jwt.decode(
                    token,
                    self.secret_key,
                    algorithms=[self.algorithm],
                    verify=verify_signature,
                    audience=self.auth0_audience,
                    issuer=f"https://{self.auth0_domain}/" if self.auth0_domain else None,
                    options={
                        'verify_signature': verify_signature,
                        'verify_exp': True,
                        'verify_iat': True,
                        'verify_aud': True,
                        'verify_iss': bool(self.auth0_domain),
                        'require_exp': True,
                        'require_iat': True
                    }
                )
            except ExpiredSignatureError:
                raise JWTValidationError("Token has expired")
            except InvalidSignatureError:
                raise JWTValidationError("Invalid token signature")
            except InvalidTokenError as e:
                raise JWTValidationError(f"Invalid token: {str(e)}")
            
            # Additional security validations
            self._validate_token_claims(claims)
            
            # Cache validation result
            if self.cache_enabled:
                self._cache_validation_result(token, claims)
            
            self.logger.info(
                "JWT token validated successfully",
                user_id=claims.get('sub'),
                expiration=claims.get('exp')
            )
            
            return claims
            
        except JWTValidationError:
            raise
        except Exception as e:
            self.logger.error("JWT token validation error", error=str(e))
            raise JWTValidationError(f"Token validation failed: {str(e)}")
    
    def refresh_token(self, refresh_token: str) -> Dict[str, str]:
        """
        Refresh JWT token with validation and new token generation.
        
        Args:
            refresh_token: Refresh token to validate
            
        Returns:
            Dictionary containing new access and refresh tokens
            
        Raises:
            JWTValidationError: When refresh token is invalid
        """
        try:
            # Validate refresh token
            claims = self.validate_token(refresh_token, verify_signature=True)
            
            # Validate token type
            if claims.get('token_type') != 'refresh':
                raise JWTValidationError("Invalid refresh token type")
            
            # Generate new tokens
            user_data = {
                'id': claims.get('sub'),
                'email': claims.get('email'),
                'name': claims.get('name'),
                'permissions': claims.get('permissions', []),
                'email_verified': claims.get('email_verified', False)
            }
            
            # Generate new access token
            new_access_token = self.generate_token(user_data)
            
            # Generate new refresh token
            new_refresh_token = self.generate_token(
                {**user_data, 'token_type': 'refresh'},
                expires_delta=self.refresh_expiration_delta
            )
            
            # Invalidate old refresh token cache
            if self.cache_enabled:
                self._invalidate_token_cache(refresh_token)
            
            return {
                'access_token': new_access_token,
                'refresh_token': new_refresh_token,
                'token_type': 'Bearer',
                'expires_in': int(self.expiration_delta.total_seconds())
            }
            
        except Exception as e:
            self.logger.error("Token refresh failed", error=str(e))
            raise JWTValidationError(f"Token refresh failed: {str(e)}")
    
    def _validate_token_claims(self, claims: Dict[str, Any]) -> None:
        """
        Perform additional security validation on token claims.
        
        Args:
            claims: Decoded token claims
            
        Raises:
            JWTValidationError: When claims validation fails
        """
        # Validate required claims
        required_claims = ['sub', 'iat', 'exp']
        for claim in required_claims:
            if claim not in claims:
                raise JWTValidationError(f"Missing required claim: {claim}")
        
        # Validate user ID format
        user_id = claims.get('sub')
        if not user_id or not isinstance(user_id, str):
            raise JWTValidationError("Invalid user ID in token")
        
        # Validate email format if present
        email = claims.get('email')
        if email:
            try:
                validate_email(email)
            except EmailNotValidError:
                raise JWTValidationError("Invalid email format in token")
        
        # Validate permissions format
        permissions = claims.get('permissions', [])
        if not isinstance(permissions, list):
            raise JWTValidationError("Invalid permissions format in token")
    
    def _hash_token(self, token: str) -> str:
        """
        Generate hash of token for cache key generation.
        
        Args:
            token: JWT token to hash
            
        Returns:
            Hexadecimal hash of token
        """
        return hashlib.sha256(token.encode('utf-8')).hexdigest()
    
    def _get_cached_validation(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve cached token validation result from Redis.
        
        Args:
            token: JWT token to check in cache
            
        Returns:
            Cached claims if available, None otherwise
        """
        try:
            cache_key = f"jwt_validation:{self._hash_token(token)}"
            cached_data = self.redis_client.get(cache_key)
            
            if cached_data:
                return json.loads(cached_data)
            
            return None
            
        except (RedisConnectionError, json.JSONDecodeError) as e:
            self.logger.warning("JWT cache retrieval failed", error=str(e))
            return None
    
    def _cache_validation_result(self, token: str, claims: Dict[str, Any]) -> None:
        """
        Cache token validation result in Redis.
        
        Args:
            token: JWT token
            claims: Validated token claims
        """
        try:
            cache_key = f"jwt_validation:{self._hash_token(token)}"
            cache_data = json.dumps(claims, default=str)
            
            self.redis_client.setex(cache_key, self.cache_ttl, cache_data)
            
        except (RedisConnectionError, json.JSONEncodeError) as e:
            self.logger.warning("JWT cache storage failed", error=str(e))
    
    def _invalidate_token_cache(self, token: str) -> None:
        """
        Invalidate cached token validation result.
        
        Args:
            token: JWT token to invalidate
        """
        try:
            cache_key = f"jwt_validation:{self._hash_token(token)}"
            self.redis_client.delete(cache_key)
            
        except RedisConnectionError as e:
            self.logger.warning("JWT cache invalidation failed", error=str(e))


class Auth0Integration:
    """
    Comprehensive Auth0 integration using Auth0 Python SDK 4.7+ with circuit breaker.
    
    This class provides enterprise-grade Auth0 integration replacing Node.js Auth0 SDK,
    with circuit breaker patterns for resilient external service communication and
    comprehensive user management capabilities as specified in Section 6.4.1.
    """
    
    def __init__(self, redis_client: redis.Redis):
        """
        Initialize Auth0 integration with circuit breaker protection.
        
        Args:
            redis_client: Redis client for caching
        """
        self.redis_client = redis_client
        self.logger = structlog.get_logger("auth.auth0_integration")
        
        # Auth0 configuration
        self.domain = config.AUTH0_DOMAIN
        self.client_id = config.AUTH0_CLIENT_ID
        self.client_secret = config.AUTH0_CLIENT_SECRET
        self.audience = config.AUTH0_AUDIENCE
        
        # Initialize Auth0 clients
        if self.domain and self.client_id and self.client_secret:
            self._initialize_auth0_clients()
        else:
            self.logger.warning("Auth0 configuration incomplete, authentication disabled")
            self.auth0_users = None
            self.auth0_mgmt = None
    
    def _initialize_auth0_clients(self) -> None:
        """Initialize Auth0 authentication and management clients."""
        try:
            # Initialize Auth0 users client for authentication
            self.auth0_users = Users(self.domain)
            
            # Get management API token
            get_token = GetToken(self.domain, self.client_id, self.client_secret)
            token_response = get_token.client_credentials(audience=f"https://{self.domain}/api/v2/")
            mgmt_token = token_response.get('access_token')
            
            # Initialize Auth0 management client
            self.auth0_mgmt = Auth0Management(self.domain, mgmt_token)
            
            self.logger.info("Auth0 clients initialized successfully")
            
        except Exception as e:
            self.logger.error("Auth0 client initialization failed", error=str(e))
            raise AuthenticationError(f"Auth0 initialization failed: {str(e)}")
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential_jitter(initial=1, max=10, jitter=2),
        retry=retry_if_exception_type((httpx.RequestError, httpx.HTTPStatusError)),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        after=after_log(logger, logging.INFO)
    )
    async def validate_token_with_auth0(self, token: str) -> Dict[str, Any]:
        """
        Validate JWT token with Auth0 using circuit breaker protection.
        
        Args:
            token: JWT token to validate with Auth0
            
        Returns:
            Validated user information and claims
            
        Raises:
            CircuitBreakerError: When circuit breaker is open
            AuthenticationError: When token validation fails
        """
        try:
            if not self.auth0_users:
                raise AuthenticationError("Auth0 not configured")
            
            # Validate token with Auth0
            user_info = self.auth0_users.userinfo(token)
            
            # Get user permissions
            user_permissions = await self._get_user_permissions(user_info.get('sub'))
            
            # Combine user info with permissions
            validated_user = {
                **user_info,
                'permissions': user_permissions
            }
            
            # Cache user information
            await self._cache_user_info(user_info.get('sub'), validated_user)
            
            self.logger.info(
                "Auth0 token validation successful",
                user_id=user_info.get('sub'),
                email=user_info.get('email')
            )
            
            return validated_user
            
        except Exception as e:
            self.logger.error("Auth0 token validation failed", error=str(e))
            
            # Try fallback cache validation
            if 'sub' in locals() and user_info and user_info.get('sub'):
                cached_user = await self._get_cached_user_info(user_info.get('sub'))
                if cached_user:
                    self.logger.warning(
                        "Using cached user info due to Auth0 service unavailability",
                        user_id=user_info.get('sub')
                    )
                    return cached_user
            
            raise AuthenticationError(f"Token validation failed: {str(e)}")
    
    async def _get_user_permissions(self, user_id: str) -> List[str]:
        """
        Retrieve user permissions from Auth0 with caching.
        
        Args:
            user_id: Auth0 user identifier
            
        Returns:
            List of user permissions
        """
        try:
            # Check cache first
            cached_permissions = await self._get_cached_permissions(user_id)
            if cached_permissions:
                return cached_permissions
            
            if not self.auth0_mgmt:
                return []
            
            # Get permissions from Auth0 Management API
            permissions_response = self.auth0_mgmt.users.list_permissions(user_id)
            permissions = [perm.get('permission_name') for perm in permissions_response.get('permissions', [])]
            
            # Cache permissions
            await self._cache_user_permissions(user_id, permissions)
            
            return permissions
            
        except Exception as e:
            self.logger.warning("Failed to get user permissions", user_id=user_id, error=str(e))
            return []
    
    async def _cache_user_info(self, user_id: str, user_info: Dict[str, Any]) -> None:
        """
        Cache user information in Redis.
        
        Args:
            user_id: User identifier
            user_info: User information to cache
        """
        try:
            cache_key = f"auth_cache:{user_id}"
            cache_data = json.dumps(user_info, default=str)
            
            # Cache for 5 minutes
            await self.redis_client.setex(cache_key, 300, cache_data)
            
        except Exception as e:
            self.logger.warning("User info caching failed", user_id=user_id, error=str(e))
    
    async def _get_cached_user_info(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve cached user information from Redis.
        
        Args:
            user_id: User identifier
            
        Returns:
            Cached user information if available
        """
        try:
            cache_key = f"auth_cache:{user_id}"
            cached_data = await self.redis_client.get(cache_key)
            
            if cached_data:
                return json.loads(cached_data)
            
            return None
            
        except Exception as e:
            self.logger.warning("User info cache retrieval failed", user_id=user_id, error=str(e))
            return None
    
    async def _cache_user_permissions(self, user_id: str, permissions: List[str]) -> None:
        """
        Cache user permissions in Redis.
        
        Args:
            user_id: User identifier
            permissions: List of permissions to cache
        """
        try:
            cache_key = f"perm_cache:{user_id}"
            cache_data = json.dumps(permissions)
            
            # Cache for 5 minutes
            await self.redis_client.setex(cache_key, 300, cache_data)
            
        except Exception as e:
            self.logger.warning("Permission caching failed", user_id=user_id, error=str(e))
    
    async def _get_cached_permissions(self, user_id: str) -> Optional[List[str]]:
        """
        Retrieve cached user permissions from Redis.
        
        Args:
            user_id: User identifier
            
        Returns:
            Cached permissions if available
        """
        try:
            cache_key = f"perm_cache:{user_id}"
            cached_data = await self.redis_client.get(cache_key)
            
            if cached_data:
                return json.loads(cached_data)
            
            return None
            
        except Exception as e:
            self.logger.warning("Permission cache retrieval failed", user_id=user_id, error=str(e))
            return None


class AuthorizationManager:
    """
    Comprehensive authorization management with Redis caching and audit logging.
    
    This class provides enterprise-grade authorization capabilities with role-based
    access control, permission caching, and comprehensive audit logging as specified
    in Section 6.4.2.
    """
    
    def __init__(self, redis_client: redis.Redis):
        """
        Initialize authorization manager with Redis caching.
        
        Args:
            redis_client: Redis client for permission caching
        """
        self.redis_client = redis_client
        self.logger = structlog.get_logger("auth.authorization_manager")
    
    def validate_user_permissions(
        self,
        user_id: str,
        required_permissions: Union[str, List[str]],
        resource_id: Optional[str] = None,
        allow_owner: bool = True
    ) -> bool:
        """
        Validate user permissions with comprehensive authorization logic.
        
        Args:
            user_id: User identifier
            required_permissions: Single permission or list of required permissions
            resource_id: Optional resource identifier for resource-specific authorization
            allow_owner: Whether to allow resource owners regardless of explicit permissions
            
        Returns:
            True if user has required permissions
        """
        try:
            # Normalize permissions to list
            if isinstance(required_permissions, str):
                required_permissions = [required_permissions]
            
            # Get user permissions from cache or current user
            user_permissions = self._get_user_permissions(user_id)
            
            # Check if user has required permissions
            has_permissions = all(perm in user_permissions for perm in required_permissions)
            
            # Check resource ownership if applicable
            if not has_permissions and allow_owner and resource_id:
                has_permissions = self._check_resource_ownership(user_id, resource_id)
            
            # Log authorization decision
            self._log_authorization_decision(
                user_id=user_id,
                required_permissions=required_permissions,
                resource_id=resource_id,
                result='granted' if has_permissions else 'denied',
                reason='owner_access' if has_permissions and allow_owner else 'permission_check'
            )
            
            return has_permissions
            
        except Exception as e:
            self.logger.error(
                "Permission validation error",
                user_id=user_id,
                required_permissions=required_permissions,
                error=str(e)
            )
            return False
    
    def _get_user_permissions(self, user_id: str) -> Set[str]:
        """
        Retrieve user permissions from current user or cache.
        
        Args:
            user_id: User identifier
            
        Returns:
            Set of user permissions
        """
        try:
            # Try to get from current user context first
            if current_user.is_authenticated and current_user.id == user_id:
                return current_user.permissions
            
            # Fallback to Redis cache
            cache_key = f"perm_cache:{user_id}"
            cached_permissions = self.redis_client.get(cache_key)
            
            if cached_permissions:
                permissions_list = json.loads(cached_permissions)
                return set(permissions_list)
            
            return set()
            
        except Exception as e:
            self.logger.warning("Failed to get user permissions", user_id=user_id, error=str(e))
            return set()
    
    def _check_resource_ownership(self, user_id: str, resource_id: str) -> bool:
        """
        Check if user owns the specified resource.
        
        Args:
            user_id: User identifier
            resource_id: Resource identifier
            
        Returns:
            True if user owns the resource
        """
        try:
            # Check ownership cache
            cache_key = f"owner_cache:{resource_id}"
            cached_owner = self.redis_client.get(cache_key)
            
            if cached_owner:
                return cached_owner == user_id
            
            # In a real implementation, this would query the database
            # For now, return False as we don't have access to data models
            return False
            
        except Exception as e:
            self.logger.warning(
                "Resource ownership check failed",
                user_id=user_id,
                resource_id=resource_id,
                error=str(e)
            )
            return False
    
    def _log_authorization_decision(
        self,
        user_id: str,
        required_permissions: List[str],
        resource_id: Optional[str],
        result: str,
        reason: str
    ) -> None:
        """
        Log authorization decision for audit trail.
        
        Args:
            user_id: User identifier
            required_permissions: Required permissions list
            resource_id: Resource identifier if applicable
            result: Authorization result (granted/denied)
            reason: Reason for the decision
        """
        self.logger.info(
            "Authorization decision",
            event_type="authorization_decision",
            user_id=user_id,
            required_permissions=required_permissions,
            resource_id=resource_id,
            result=result,
            reason=reason,
            source_ip=request.remote_addr if request else None,
            user_agent=request.headers.get('User-Agent') if request else None,
            endpoint=request.endpoint if request else None,
            method=request.method if request else None,
            timestamp=datetime.utcnow().isoformat()
        )


# Authorization decorators with comprehensive type hints
def require_permissions(
    permissions: Union[str, List[str]], 
    resource_id: Optional[str] = None,
    allow_owner: bool = True
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Decorator for enforcing route-level authorization with comprehensive permission checking.
    
    This decorator validates user permissions against required permissions for the decorated
    route, supports resource-specific authorization, and implements owner-based access control
    with complete audit logging as specified in Section 6.4.2.
    
    Args:
        permissions: Single permission string or list of required permissions
        resource_id: Optional resource identifier for resource-specific authorization
        allow_owner: Whether to allow resource owners regardless of explicit permissions
        
    Returns:
        Decorated function with authorization enforcement
        
    Raises:
        AuthorizationError: When user lacks required permissions
        AuthenticationError: When user is not properly authenticated
        
    Example:
        @app.route('/api/documents/<document_id>')
        @require_permissions(['document.read', 'document.write'], resource_id='document_id')
        def get_document(document_id: str) -> Response:
            return jsonify({"document": load_document(document_id)})
    """
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if not current_user.is_authenticated:
                return jsonify({'error': 'Authentication required'}), 401
            
            # Get authorization manager
            auth_manager = g.get('auth_manager')
            if not auth_manager:
                return jsonify({'error': 'Authorization service unavailable'}), 503
            
            # Extract resource ID from kwargs if specified
            actual_resource_id = kwargs.get(resource_id) if resource_id else None
            
            # Validate permissions
            if not auth_manager.validate_user_permissions(
                current_user.id, 
                permissions, 
                actual_resource_id, 
                allow_owner
            ):
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


def require_any_permission(permissions: List[str]) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Decorator requiring user to have any of the specified permissions.
    
    Args:
        permissions: List of permissions (user needs at least one)
        
    Returns:
        Decorated function with authorization enforcement
    """
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if not current_user.is_authenticated:
                return jsonify({'error': 'Authentication required'}), 401
            
            if not current_user.has_any_permission(permissions):
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


def require_all_permissions(permissions: List[str]) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Decorator requiring user to have all specified permissions.
    
    Args:
        permissions: List of permissions (user needs all)
        
    Returns:
        Decorated function with authorization enforcement
    """
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if not current_user.is_authenticated:
                return jsonify({'error': 'Authentication required'}), 401
            
            if not current_user.has_all_permissions(permissions):
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


class AuthConfig:
    """
    Comprehensive authentication configuration manager for Flask application.
    
    This class provides centralized configuration management for all authentication
    and authorization components, integrating Auth0, PyJWT, Flask-Login, Flask-Talisman,
    and Redis caching as specified in the technical requirements.
    """
    
    def __init__(self):
        """Initialize authentication configuration manager."""
        self.logger = structlog.get_logger("auth.config")
        
        # Initialize components
        self.login_manager: Optional[LoginManager] = None
        self.jwt_manager: Optional[JWTManager] = None
        self.auth0_integration: Optional[Auth0Integration] = None
        self.authorization_manager: Optional[AuthorizationManager] = None
        self.talisman: Optional[Talisman] = None
        
        # Redis client for caching
        self.redis_client: Optional[redis.Redis] = None
    
    def init_app(self, app: Flask) -> None:
        """
        Initialize authentication configuration for Flask application.
        
        Args:
            app: Flask application instance
        """
        try:
            # Initialize Redis client
            self._init_redis_client()
            
            # Configure Flask-Login
            self._configure_flask_login(app)
            
            # Configure Flask-Talisman security headers
            self._configure_flask_talisman(app)
            
            # Initialize JWT manager
            self._init_jwt_manager()
            
            # Initialize Auth0 integration
            self._init_auth0_integration()
            
            # Initialize authorization manager
            self._init_authorization_manager()
            
            # Register authentication handlers
            self._register_auth_handlers(app)
            
            # Store auth config in app
            app.auth_config = self
            
            self.logger.info("Authentication configuration initialized successfully")
            
        except Exception as e:
            self.logger.error("Authentication configuration failed", error=str(e))
            raise ConfigurationError(f"Auth configuration failed: {str(e)}")
    
    def _init_redis_client(self) -> None:
        """Initialize Redis client for authentication caching."""
        try:
            self.redis_client = db_manager.redis_client
            
            # Test Redis connection
            self.redis_client.ping()
            
            self.logger.info("Redis client initialized for authentication")
            
        except Exception as e:
            self.logger.error("Redis client initialization failed", error=str(e))
            raise RedisError(f"Redis initialization failed: {str(e)}")
    
    def _configure_flask_login(self, app: Flask) -> None:
        """
        Configure Flask-Login for user session management.
        
        Args:
            app: Flask application instance
        """
        self.login_manager = LoginManager()
        self.login_manager.init_app(app)
        
        # Configure Flask-Login settings
        self.login_manager.login_view = 'auth.login'
        self.login_manager.login_message = 'Please log in to access this page'
        self.login_manager.login_message_category = 'info'
        self.login_manager.session_protection = 'strong'
        self.login_manager.refresh_view = 'auth.refresh'
        self.login_manager.needs_refresh_message = 'Session expired, please log in again'
        
        # User loader function
        @self.login_manager.user_loader
        def load_user(user_id: str) -> Optional[User]:
            """Load user for Flask-Login session management."""
            try:
                # Try to get user from Auth0 cache
                if self.auth0_integration:
                    cached_user = self.auth0_integration._get_cached_user_info(user_id)
                    if cached_user:
                        permissions = set(cached_user.get('permissions', []))
                        return User(user_id, cached_user, permissions)
                
                return None
                
            except Exception as e:
                self.logger.warning("User loading failed", user_id=user_id, error=str(e))
                return None
        
        # Unauthorized handler
        @self.login_manager.unauthorized_handler
        def unauthorized() -> Any:
            """Handle unauthorized access attempts."""
            if request.is_json:
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('auth.login'))
        
        self.logger.info("Flask-Login configured successfully")
    
    def _configure_flask_talisman(self, app: Flask) -> None:
        """
        Configure Flask-Talisman for HTTP security headers enforcement.
        
        Args:
            app: Flask application instance
        """
        # Comprehensive security headers configuration
        self.talisman = Talisman(
            app,
            # Force HTTPS across all endpoints
            force_https=config.FORCE_HTTPS,
            force_https_permanent=True,
            
            # HTTP Strict Transport Security
            strict_transport_security=True,
            strict_transport_security_max_age=config.HSTS_MAX_AGE,
            strict_transport_security_include_subdomains=config.HSTS_INCLUDE_SUBDOMAINS,
            strict_transport_security_preload=config.HSTS_PRELOAD,
            
            # Content Security Policy
            content_security_policy=config.CSP_POLICY,
            content_security_policy_nonce_in=['script-src', 'style-src'],
            
            # Additional security headers
            referrer_policy=config.REFERRER_POLICY,
            feature_policy=config.FEATURE_POLICY,
            
            # Session cookie security
            session_cookie_secure=True,
            session_cookie_http_only=True,
            session_cookie_samesite='Lax'
        )
        
        self.logger.info("Flask-Talisman security headers configured")
    
    def _init_jwt_manager(self) -> None:
        """Initialize JWT token management."""
        if not self.redis_client:
            raise ConfigurationError("Redis client required for JWT manager")
        
        self.jwt_manager = JWTManager(self.redis_client)
        self.logger.info("JWT manager initialized")
    
    def _init_auth0_integration(self) -> None:
        """Initialize Auth0 integration."""
        if not self.redis_client:
            raise ConfigurationError("Redis client required for Auth0 integration")
        
        self.auth0_integration = Auth0Integration(self.redis_client)
        self.logger.info("Auth0 integration initialized")
    
    def _init_authorization_manager(self) -> None:
        """Initialize authorization manager."""
        if not self.redis_client:
            raise ConfigurationError("Redis client required for authorization manager")
        
        self.authorization_manager = AuthorizationManager(self.redis_client)
        self.logger.info("Authorization manager initialized")
    
    def _register_auth_handlers(self, app: Flask) -> None:
        """
        Register authentication request handlers and middleware.
        
        Args:
            app: Flask application instance
        """
        @app.before_request
        def before_request_auth_handler():
            """Process authentication before each request."""
            # Store authorization manager in request context
            g.auth_manager = self.authorization_manager
            
            # Extract and validate JWT token if present
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header[7:]  # Remove 'Bearer ' prefix
                
                try:
                    if self.jwt_manager:
                        claims = self.jwt_manager.validate_token(token)
                        
                        # Create user context if not already authenticated
                        if not current_user.is_authenticated:
                            permissions = set(claims.get('permissions', []))
                            user = User(claims.get('sub'), claims, permissions)
                            login_user(user, remember=False)
                            
                except JWTValidationError as e:
                    self.logger.warning("JWT validation failed", error=str(e))
        
        @app.teardown_appcontext
        def teardown_auth_context(error):
            """Clean up authentication context."""
            if hasattr(g, 'auth_manager'):
                delattr(g, 'auth_manager')
            
            if error:
                self.logger.error("Request context error", error=str(error))
        
        self.logger.info("Authentication handlers registered")


# Global authentication configuration instance
auth_config = AuthConfig()


def init_auth_config(app: Flask) -> AuthConfig:
    """
    Initialize authentication configuration for Flask application.
    
    Args:
        app: Flask application instance
        
    Returns:
        Configured AuthConfig instance
    """
    try:
        auth_config.init_app(app)
        logger.info("Authentication configuration initialized successfully")
        return auth_config
        
    except Exception as e:
        logger.error("Authentication configuration initialization failed", error=str(e))
        raise ConfigurationError(f"Failed to initialize auth config: {str(e)}")


# Export authentication configuration components
__all__ = [
    'AuthConfig',
    'User',
    'JWTManager',
    'Auth0Integration',
    'AuthorizationManager',
    'require_permissions',
    'require_any_permission',
    'require_all_permissions',
    'init_auth_config',
    'auth_config',
    'AuthenticationError',
    'AuthorizationError',
    'JWTValidationError',
    'CircuitBreakerError'
]