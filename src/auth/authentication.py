"""
Core JWT Authentication Implementation

This module provides comprehensive JWT authentication functionality equivalent to Node.js
jsonwebtoken patterns while implementing enterprise-grade security features using PyJWT 2.8+,
Auth0 Python SDK 4.7+, and cryptography 41.0+ for secure token validation and signing.

The authentication system maintains complete API compatibility with the Node.js implementation
while providing enhanced security through Flask-Login integration, Redis-backed session
management with AES-256-GCM encryption, and comprehensive audit logging.

Key Features:
- JWT token processing migrated from jsonwebtoken to PyJWT 2.8+ per Section 0.1.2
- Auth0 enterprise integration through Python SDK per Section 6.4.1
- Cryptographic verification using cryptography 41.0+ per Section 6.4.1
- Comprehensive token validation patterns preserving Node.js compatibility per Section 0.1.4
- User context creation and authentication state management per Section 6.4.1
- Performance optimization with Redis caching per Section 6.4.2

Dependencies:
- PyJWT 2.8+: JWT token processing and validation
- cryptography 41.0+: Secure cryptographic operations
- auth0-python 4.7+: Auth0 service integration
- redis 5.0+: Authentication caching and session management
- structlog 23.1+: Comprehensive audit logging

Author: Flask Migration Team
Version: 1.0.0
Compliance: SOC 2, ISO 27001, OWASP Top 10
"""

import jwt
import json
import time
import secrets
import hashlib
import base64
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, Union, List, Tuple, Callable
from functools import wraps, lru_cache
from urllib.parse import urlparse
import asyncio

# Flask and HTTP libraries
from flask import request, g, current_app, jsonify
from flask_login import current_user, login_user, logout_user
import requests
import httpx
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Authentication and security libraries
from auth0.authentication import GetToken
from auth0.management import Auth0
from auth0.exceptions import Auth0Error
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# Internal dependencies
from .config import get_auth_config, User, JWTManager, auth_metrics
from .exceptions import (
    AuthenticationException,
    JWTException,
    Auth0Exception,
    SessionException,
    SecurityErrorCode,
    create_safe_error_response
)
from .utils import (
    jwt_manager,
    datetime_utils,
    input_validator,
    crypto_utils,
    log_security_event,
    get_current_user_id,
    create_token_hash
)
from .cache import (
    get_auth_cache_manager,
    create_token_hash as cache_token_hash,
    extract_user_id_from_session
)

# Monitoring and logging
import structlog
from prometheus_client import Counter, Histogram, Gauge

# Configure structured logging for authentication operations
logger = structlog.get_logger(__name__)

# Prometheus metrics for authentication monitoring
auth_operation_metrics = {
    'token_validations_total': Counter(
        'auth_token_validations_total',
        'Total JWT token validations by result',
        ['result', 'token_type', 'issuer']
    ),
    'auth0_operations_total': Counter(
        'auth0_operations_total',
        'Total Auth0 operations by type and result',
        ['operation', 'result']
    ),
    'user_context_operations': Counter(
        'auth_user_context_operations_total',
        'User context creation and management operations',
        ['operation', 'result']
    ),
    'authentication_duration': Histogram(
        'auth_authentication_duration_seconds',
        'Time spent on authentication operations',
        ['operation', 'auth_method']
    ),
    'active_authenticated_users': Gauge(
        'auth_active_authenticated_users',
        'Number of currently authenticated users'
    ),
    'token_cache_operations': Counter(
        'auth_token_cache_operations_total',
        'Token validation cache operations',
        ['operation', 'result']
    )
}


class CoreJWTAuthenticator:
    """
    Core JWT authentication implementation providing comprehensive token validation,
    user context management, and Auth0 integration equivalent to Node.js jsonwebtoken
    patterns with enterprise-grade security enhancements.
    
    This class serves as the primary authentication interface, orchestrating JWT token
    validation, Auth0 service integration, user session management, and comprehensive
    security auditing while maintaining complete API compatibility with the original
    Node.js implementation.
    
    Features:
    - PyJWT 2.8+ token validation equivalent to Node.js jsonwebtoken
    - Auth0 Python SDK integration for enterprise authentication services
    - Cryptographic operations using cryptography 41.0+ for secure token processing
    - Redis-backed token validation caching for performance optimization
    - Comprehensive audit logging and security event tracking
    - Circuit breaker patterns for Auth0 service resilience
    
    Example:
        authenticator = CoreJWTAuthenticator()
        user_context = await authenticator.authenticate_request(token)
        if user_context:
            print(f"Authenticated user: {user_context.user_id}")
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize core JWT authenticator with comprehensive security configuration.
        
        Args:
            config: Optional configuration override (uses global config if None)
        """
        self.config = config or get_auth_config()
        self.jwt_manager = jwt_manager
        self.cache_manager = get_auth_cache_manager()
        self.logger = logger.bind(component="core_jwt_authenticator")
        
        # Auth0 configuration
        self.auth0_domain = self.config.config.get('AUTH0_DOMAIN')
        self.auth0_client_id = self.config.config.get('AUTH0_CLIENT_ID')
        self.auth0_client_secret = self.config.config.get('AUTH0_CLIENT_SECRET')
        self.auth0_audience = self.config.config.get('AUTH0_AUDIENCE')
        
        # JWT configuration
        self.jwt_algorithm = 'RS256'  # Use RS256 for Auth0 compatibility
        self.token_leeway = 10  # 10 seconds leeway for clock skew
        
        # Initialize Auth0 clients
        self._auth0_management_client = None
        self._auth0_public_keys = None
        self._public_keys_cache_expiry = None
        
        # Circuit breaker state for Auth0 operations
        self._auth0_circuit_breaker_state = 'closed'
        self._auth0_failure_count = 0
        self._auth0_last_failure_time = None
        
        # Performance optimization settings
        self.cache_ttl_seconds = 300  # 5 minutes default cache TTL
        self.max_concurrent_validations = 100
        
        self.logger.info(
            "Core JWT authenticator initialized",
            auth0_domain=self.auth0_domain,
            jwt_algorithm=self.jwt_algorithm,
            cache_enabled=True
        )
    
    async def authenticate_request(
        self,
        token: Optional[str] = None,
        required_permissions: Optional[List[str]] = None,
        allow_expired: bool = False
    ) -> Optional['AuthenticatedUser']:
        """
        Comprehensive request authentication with JWT validation and user context creation.
        
        This method provides complete authentication functionality equivalent to Node.js
        authentication middleware, including token extraction, validation, user context
        creation, and permission verification with comprehensive caching and monitoring.
        
        Args:
            token: JWT token string (extracted from request if None)
            required_permissions: List of required permissions for authorization
            allow_expired: Whether to allow expired tokens (for refresh operations)
            
        Returns:
            AuthenticatedUser object if authentication succeeds, None otherwise
            
        Raises:
            AuthenticationException: When authentication fails
            JWTException: When token validation fails
            Auth0Exception: When Auth0 service is unavailable
            
        Example:
            # Extract and validate token from request
            user = await authenticator.authenticate_request()
            
            # Validate token with specific permissions
            user = await authenticator.authenticate_request(
                token=jwt_token,
                required_permissions=['read:documents', 'write:documents']
            )
        """
        start_time = time.time()
        operation_result = "success"
        
        try:
            # Extract token from request if not provided
            if token is None:
                token = self._extract_token_from_request()
            
            if not token:
                auth_operation_metrics['token_validations_total'].labels(
                    result='missing_token',
                    token_type='access_token',
                    issuer='unknown'
                ).inc()
                
                self.logger.warning("Authentication failed: missing token")
                return None
            
            # Validate JWT token with comprehensive security checks
            token_claims = await self._validate_jwt_token(
                token, 
                allow_expired=allow_expired
            )
            
            if not token_claims:
                operation_result = "invalid_token"
                return None
            
            # Create authenticated user context
            authenticated_user = await self._create_user_context(
                token_claims, 
                token
            )
            
            if not authenticated_user:
                operation_result = "context_creation_failed"
                return None
            
            # Verify required permissions if specified
            if required_permissions:
                if not await self._verify_user_permissions(
                    authenticated_user, 
                    required_permissions
                ):
                    operation_result = "insufficient_permissions"
                    self.logger.warning(
                        "Authentication failed: insufficient permissions",
                        user_id=authenticated_user.user_id,
                        required_permissions=required_permissions,
                        user_permissions=authenticated_user.permissions
                    )
                    
                    raise AuthenticationException(
                        message="Insufficient permissions for this operation",
                        error_code=SecurityErrorCode.AUTHZ_INSUFFICIENT_PERMISSIONS,
                        user_id=authenticated_user.user_id,
                        metadata={
                            'required_permissions': required_permissions,
                            'user_permissions': authenticated_user.permissions[:10]  # Limit for security
                        }
                    )
            
            # Update authentication metrics
            auth_operation_metrics['token_validations_total'].labels(
                result='success',
                token_type=token_claims.get('type', 'access_token'),
                issuer=token_claims.get('iss', 'unknown')
            ).inc()
            
            # Log successful authentication
            self.logger.info(
                "Request authenticated successfully",
                user_id=authenticated_user.user_id,
                token_type=token_claims.get('type'),
                permissions_count=len(authenticated_user.permissions) if authenticated_user.permissions else 0,
                duration=time.time() - start_time
            )
            
            # Update active users metric
            try:
                auth_operation_metrics['active_authenticated_users'].set(
                    len(self.cache_manager.redis_client.keys('session:*'))
                )
            except Exception:
                pass  # Don't fail authentication for metrics errors
            
            return authenticated_user
            
        except (AuthenticationException, JWTException, Auth0Exception):
            operation_result = "authentication_error"
            raise
        except Exception as e:
            operation_result = "unexpected_error"
            self.logger.error(
                "Unexpected authentication error",
                error=str(e),
                error_type=type(e).__name__,
                duration=time.time() - start_time
            )
            
            raise AuthenticationException(
                message="Authentication system error",
                error_code=SecurityErrorCode.AUTH_TOKEN_INVALID,
                metadata={'error_type': type(e).__name__}
            )
        finally:
            # Record operation duration
            auth_operation_metrics['authentication_duration'].labels(
                operation='authenticate_request',
                auth_method='jwt'
            ).observe(time.time() - start_time)
            
            # Log authentication attempt for audit
            log_security_event(
                'authentication_attempt',
                user_id=getattr(g, 'current_user_id', None),
                metadata={
                    'result': operation_result,
                    'duration': time.time() - start_time,
                    'has_required_permissions': required_permissions is not None,
                    'allow_expired': allow_expired
                }
            )
    
    async def _validate_jwt_token(
        self,
        token: str,
        allow_expired: bool = False
    ) -> Optional[Dict[str, Any]]:
        """
        Comprehensive JWT token validation using PyJWT 2.8+ with Auth0 integration.
        
        This method provides enterprise-grade JWT validation equivalent to Node.js
        jsonwebtoken verify() functionality with performance caching, Auth0 public key
        validation, and comprehensive security checks.
        
        Args:
            token: JWT token string to validate
            allow_expired: Whether to allow expired tokens
            
        Returns:
            Validated token claims or None if validation fails
            
        Raises:
            JWTException: When token validation fails
            Auth0Exception: When Auth0 service is unavailable
        """
        try:
            # Check cache first for performance optimization
            token_hash = create_token_hash(token)
            cached_result = self.cache_manager.get_cached_jwt_validation_result(token_hash)
            
            if cached_result and not allow_expired:
                auth_operation_metrics['token_cache_operations'].labels(
                    operation='hit',
                    result='success'
                ).inc()
                
                self.logger.debug(
                    "JWT validation result retrieved from cache",
                    token_hash=token_hash[:8] + "...",
                    cache_hit=True
                )
                return cached_result
            
            # Decode token header without verification to get key ID
            try:
                unverified_header = jwt.get_unverified_header(token)
                kid = unverified_header.get('kid')
                algorithm = unverified_header.get('alg', 'RS256')
            except jwt.InvalidTokenError as e:
                raise JWTException(
                    message=f"Invalid token header: {str(e)}",
                    error_code=SecurityErrorCode.AUTH_TOKEN_MALFORMED,
                    jwt_error=e,
                    token_header=None
                )
            
            # Get Auth0 public key for signature verification
            public_key = await self._get_auth0_public_key(kid)
            if not public_key:
                raise JWTException(
                    message=f"Unable to find public key for kid: {kid}",
                    error_code=SecurityErrorCode.AUTH_TOKEN_INVALID,
                    token_header=unverified_header
                )
            
            # Configure JWT validation options
            validation_options = {
                'verify_signature': True,
                'verify_exp': not allow_expired,
                'verify_aud': True,
                'verify_iss': True,
                'require': ['sub', 'iss', 'aud', 'exp', 'iat']
            }
            
            # Validate token with Auth0 public key
            try:
                decoded_token = jwt.decode(
                    token,
                    public_key,
                    algorithms=[algorithm],
                    audience=self.auth0_audience,
                    issuer=f"https://{self.auth0_domain}/",
                    options=validation_options,
                    leeway=self.token_leeway
                )
            except jwt.ExpiredSignatureError as e:
                if allow_expired:
                    # Decode without expiration check for refresh operations
                    validation_options['verify_exp'] = False
                    decoded_token = jwt.decode(
                        token,
                        public_key,
                        algorithms=[algorithm],
                        audience=self.auth0_audience,
                        issuer=f"https://{self.auth0_domain}/",
                        options=validation_options,
                        leeway=self.token_leeway
                    )
                    decoded_token['_expired'] = True
                else:
                    raise JWTException(
                        message="Token has expired",
                        error_code=SecurityErrorCode.AUTH_TOKEN_EXPIRED,
                        jwt_error=e,
                        token_header=unverified_header
                    )
            except jwt.InvalidAudienceError as e:
                raise JWTException(
                    message="Invalid token audience",
                    error_code=SecurityErrorCode.AUTH_TOKEN_INVALID,
                    jwt_error=e,
                    token_header=unverified_header
                )
            except jwt.InvalidIssuerError as e:
                raise JWTException(
                    message="Invalid token issuer",
                    error_code=SecurityErrorCode.AUTH_TOKEN_INVALID,
                    jwt_error=e,
                    token_header=unverified_header
                )
            except jwt.InvalidTokenError as e:
                raise JWTException(
                    message=f"Token validation failed: {str(e)}",
                    error_code=SecurityErrorCode.AUTH_TOKEN_INVALID,
                    jwt_error=e,
                    token_header=unverified_header
                )
            
            # Additional security validations
            await self._perform_additional_token_validations(decoded_token)
            
            # Cache validation result for performance (if not expired)
            if not decoded_token.get('_expired', False):
                self.cache_manager.cache_jwt_validation_result(
                    token_hash,
                    decoded_token,
                    ttl=min(
                        self.cache_ttl_seconds,
                        decoded_token.get('exp', 0) - int(time.time())
                    )
                )
                
                auth_operation_metrics['token_cache_operations'].labels(
                    operation='write',
                    result='success'
                ).inc()
            
            self.logger.debug(
                "JWT token validated successfully",
                user_id=decoded_token.get('sub'),
                algorithm=algorithm,
                kid=kid,
                expired=decoded_token.get('_expired', False)
            )
            
            return decoded_token
            
        except JWTException:
            auth_operation_metrics['token_cache_operations'].labels(
                operation='miss',
                result='validation_failed'
            ).inc()
            raise
        except Exception as e:
            self.logger.error(
                "Unexpected JWT validation error",
                error=str(e),
                error_type=type(e).__name__
            )
            
            raise JWTException(
                message="Token validation system error",
                error_code=SecurityErrorCode.AUTH_TOKEN_INVALID,
                jwt_error=e
            )
    
    async def _get_auth0_public_key(self, kid: str) -> Optional[str]:
        """
        Retrieve Auth0 public key for JWT signature verification with caching.
        
        Args:
            kid: Key ID from JWT header
            
        Returns:
            Public key for signature verification or None if not found
            
        Raises:
            Auth0Exception: When Auth0 JWKS endpoint is unavailable
        """
        try:
            # Check if we have cached public keys
            current_time = time.time()
            if (self._auth0_public_keys and self._public_keys_cache_expiry and
                current_time < self._public_keys_cache_expiry):
                
                # Find matching key in cache
                for key_data in self._auth0_public_keys.get('keys', []):
                    if key_data.get('kid') == kid:
                        return jwt.algorithms.RSAAlgorithm.from_jwk(key_data)
            
            # Check circuit breaker state
            if self._auth0_circuit_breaker_state == 'open':
                if (current_time - self._auth0_last_failure_time) < 60:  # 60 second timeout
                    raise Auth0Exception(
                        message="Auth0 service circuit breaker is open",
                        error_code=SecurityErrorCode.EXT_CIRCUIT_BREAKER_OPEN,
                        circuit_breaker_state='open'
                    )
                else:
                    # Attempt to close circuit breaker
                    self._auth0_circuit_breaker_state = 'half-open'
            
            # Fetch JWKS from Auth0
            jwks_url = f"https://{self.auth0_domain}/.well-known/jwks.json"
            
            # Configure requests session with retry strategy
            session = requests.Session()
            retry_strategy = Retry(
                total=3,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=["GET"]
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            
            try:
                response = session.get(jwks_url, timeout=10)
                response.raise_for_status()
                
                self._auth0_public_keys = response.json()
                self._public_keys_cache_expiry = current_time + 3600  # Cache for 1 hour
                
                # Reset circuit breaker on success
                self._auth0_circuit_breaker_state = 'closed'
                self._auth0_failure_count = 0
                
                auth_operation_metrics['auth0_operations_total'].labels(
                    operation='jwks_fetch',
                    result='success'
                ).inc()
                
                self.logger.debug(
                    "Auth0 JWKS retrieved successfully",
                    keys_count=len(self._auth0_public_keys.get('keys', []))
                )
                
            except requests.RequestException as e:
                # Update circuit breaker state
                self._auth0_failure_count += 1
                self._auth0_last_failure_time = current_time
                
                if self._auth0_failure_count >= 5:
                    self._auth0_circuit_breaker_state = 'open'
                
                auth_operation_metrics['auth0_operations_total'].labels(
                    operation='jwks_fetch',
                    result='failure'
                ).inc()
                
                self.logger.error(
                    "Failed to retrieve Auth0 JWKS",
                    error=str(e),
                    circuit_breaker_state=self._auth0_circuit_breaker_state,
                    failure_count=self._auth0_failure_count
                )
                
                raise Auth0Exception(
                    message=f"Unable to retrieve Auth0 JWKS: {str(e)}",
                    error_code=SecurityErrorCode.EXT_AUTH0_UNAVAILABLE,
                    service_response={'error': str(e)},
                    circuit_breaker_state=self._auth0_circuit_breaker_state
                )
            
            # Find matching key
            for key_data in self._auth0_public_keys.get('keys', []):
                if key_data.get('kid') == kid:
                    return jwt.algorithms.RSAAlgorithm.from_jwk(key_data)
            
            # Key not found
            self.logger.warning(
                "Public key not found for kid",
                kid=kid,
                available_kids=[k.get('kid') for k in self._auth0_public_keys.get('keys', [])]
            )
            return None
            
        except Auth0Exception:
            raise
        except Exception as e:
            self.logger.error(
                "Unexpected error retrieving Auth0 public key",
                error=str(e),
                error_type=type(e).__name__,
                kid=kid
            )
            
            raise Auth0Exception(
                message="Auth0 public key retrieval failed",
                error_code=SecurityErrorCode.EXT_AUTH0_API_ERROR,
                service_response={'error': str(e)}
            )
    
    async def _perform_additional_token_validations(
        self, 
        token_claims: Dict[str, Any]
    ) -> None:
        """
        Perform additional security validations on JWT token claims.
        
        Args:
            token_claims: Decoded JWT token claims
            
        Raises:
            JWTException: When additional validations fail
        """
        try:
            # Validate token age (prevent extremely old tokens)
            iat = token_claims.get('iat')
            if iat:
                token_age = time.time() - iat
                max_age = 24 * 3600  # 24 hours
                if token_age > max_age:
                    raise JWTException(
                        message="Token is too old",
                        error_code=SecurityErrorCode.AUTH_TOKEN_INVALID,
                        validation_context={'token_age_seconds': token_age}
                    )
            
            # Validate subject (user ID) format
            sub = token_claims.get('sub')
            if not sub or not isinstance(sub, str) or len(sub) < 1:
                raise JWTException(
                    message="Invalid or missing subject in token",
                    error_code=SecurityErrorCode.AUTH_TOKEN_MALFORMED,
                    validation_context={'subject': sub}
                )
            
            # Validate scope and permissions format
            scope = token_claims.get('scope')
            if scope and not isinstance(scope, str):
                raise JWTException(
                    message="Invalid scope format in token",
                    error_code=SecurityErrorCode.AUTH_TOKEN_MALFORMED,
                    validation_context={'scope_type': type(scope).__name__}
                )
            
            # Validate permissions if present
            permissions = token_claims.get('permissions')
            if permissions and not isinstance(permissions, list):
                raise JWTException(
                    message="Invalid permissions format in token",
                    error_code=SecurityErrorCode.AUTH_TOKEN_MALFORMED,
                    validation_context={'permissions_type': type(permissions).__name__}
                )
            
            # Validate custom claims structure
            for claim_name, claim_value in token_claims.items():
                if claim_name.startswith('https://') and not isinstance(claim_value, (str, list, dict)):
                    self.logger.warning(
                        "Unexpected custom claim type",
                        claim_name=claim_name,
                        claim_type=type(claim_value).__name__
                    )
            
        except JWTException:
            raise
        except Exception as e:
            self.logger.error(
                "Unexpected error in additional token validations",
                error=str(e),
                error_type=type(e).__name__
            )
            
            raise JWTException(
                message="Additional token validation failed",
                error_code=SecurityErrorCode.AUTH_TOKEN_INVALID,
                jwt_error=e
            )
    
    async def _create_user_context(
        self,
        token_claims: Dict[str, Any],
        token: str
    ) -> Optional['AuthenticatedUser']:
        """
        Create authenticated user context from validated JWT token claims.
        
        Args:
            token_claims: Validated JWT token claims
            token: Original JWT token string
            
        Returns:
            AuthenticatedUser object or None if creation fails
            
        Raises:
            AuthenticationException: When user context creation fails
        """
        try:
            user_id = token_claims.get('sub')
            if not user_id:
                raise AuthenticationException(
                    message="Missing user ID in token claims",
                    error_code=SecurityErrorCode.AUTH_TOKEN_MALFORMED,
                    token_claims=token_claims
                )
            
            # Extract permissions from token claims
            permissions = []
            
            # Check for permissions in different claim formats
            if 'permissions' in token_claims:
                permissions.extend(token_claims['permissions'])
            
            if 'scope' in token_claims:
                # Parse space-separated scopes
                scopes = token_claims['scope'].split(' ')
                permissions.extend(scopes)
            
            # Check for custom permission claims
            for claim_name, claim_value in token_claims.items():
                if claim_name.startswith('https://') and 'permissions' in claim_name.lower():
                    if isinstance(claim_value, list):
                        permissions.extend(claim_value)
            
            # Remove duplicates while preserving order
            permissions = list(dict.fromkeys(permissions))
            
            # Get or fetch user profile data
            user_profile = await self._get_user_profile(user_id, token_claims)
            
            # Create authenticated user object
            authenticated_user = AuthenticatedUser(
                user_id=user_id,
                token_claims=token_claims,
                permissions=permissions,
                profile=user_profile,
                token=token,
                authenticated_at=datetime.now(timezone.utc)
            )
            
            # Cache user session data
            await self._cache_user_session(authenticated_user)
            
            # Update user context metrics
            auth_operation_metrics['user_context_operations'].labels(
                operation='create',
                result='success'
            ).inc()
            
            self.logger.debug(
                "User context created successfully",
                user_id=user_id,
                permissions_count=len(permissions),
                has_profile=user_profile is not None
            )
            
            return authenticated_user
            
        except AuthenticationException:
            auth_operation_metrics['user_context_operations'].labels(
                operation='create',
                result='failure'
            ).inc()
            raise
        except Exception as e:
            auth_operation_metrics['user_context_operations'].labels(
                operation='create',
                result='error'
            ).inc()
            
            self.logger.error(
                "Failed to create user context",
                error=str(e),
                error_type=type(e).__name__,
                user_id=token_claims.get('sub')
            )
            
            raise AuthenticationException(
                message="User context creation failed",
                error_code=SecurityErrorCode.AUTH_TOKEN_INVALID,
                user_id=token_claims.get('sub'),
                metadata={'error_type': type(e).__name__}
            )
    
    async def _get_user_profile(
        self,
        user_id: str,
        token_claims: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieve user profile data with caching and Auth0 integration.
        
        Args:
            user_id: User identifier
            token_claims: JWT token claims containing basic profile data
            
        Returns:
            User profile dictionary or None if unavailable
        """
        try:
            # Check cache first
            cached_profile = self.cache_manager.get_cached_session_data(f"profile:{user_id}")
            if cached_profile:
                return cached_profile
            
            # Extract basic profile from token claims
            profile = {
                'user_id': user_id,
                'sub': token_claims.get('sub'),
                'email': token_claims.get('email'),
                'name': token_claims.get('name'),
                'picture': token_claims.get('picture'),
                'updated_at': token_claims.get('updated_at'),
                'email_verified': token_claims.get('email_verified', False)
            }
            
            # Add custom claims to profile
            for claim_name, claim_value in token_claims.items():
                if claim_name.startswith('https://'):
                    profile[claim_name] = claim_value
            
            # Try to get additional profile data from Auth0 if management client is available
            try:
                if self._should_fetch_extended_profile(user_id):
                    extended_profile = await self._fetch_auth0_user_profile(user_id)
                    if extended_profile:
                        profile.update(extended_profile)
            except Exception as e:
                # Don't fail authentication if extended profile fetch fails
                self.logger.warning(
                    "Failed to fetch extended user profile",
                    user_id=user_id,
                    error=str(e)
                )
            
            # Cache profile data
            self.cache_manager.cache_session_data(
                f"profile:{user_id}",
                profile,
                ttl=600  # Cache profile for 10 minutes
            )
            
            return profile
            
        except Exception as e:
            self.logger.warning(
                "Failed to get user profile",
                user_id=user_id,
                error=str(e),
                error_type=type(e).__name__
            )
            
            # Return minimal profile from token claims
            return {
                'user_id': user_id,
                'sub': token_claims.get('sub'),
                'email': token_claims.get('email'),
                'name': token_claims.get('name')
            }
    
    def _should_fetch_extended_profile(self, user_id: str) -> bool:
        """
        Determine if extended profile should be fetched from Auth0.
        
        Args:
            user_id: User identifier
            
        Returns:
            Boolean indicating if extended profile fetch should be attempted
        """
        # Skip extended profile fetch if circuit breaker is open
        if self._auth0_circuit_breaker_state == 'open':
            return False
        
        # Check if we've recently attempted to fetch this user's profile
        cache_key = f"profile_fetch_attempt:{user_id}"
        recent_attempt = self.cache_manager.redis_client.get(cache_key)
        
        if recent_attempt:
            return False
        
        # Record attempt to prevent frequent API calls
        self.cache_manager.redis_client.setex(cache_key, 300, "1")  # 5 minute cooldown
        
        return True
    
    async def _fetch_auth0_user_profile(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch extended user profile from Auth0 Management API.
        
        Args:
            user_id: Auth0 user identifier
            
        Returns:
            Extended user profile data or None if unavailable
        """
        try:
            # Initialize Auth0 management client if needed
            if not self._auth0_management_client:
                await self._initialize_auth0_management_client()
            
            if not self._auth0_management_client:
                return None
            
            # Fetch user profile from Auth0
            user_profile = self._auth0_management_client.users.get(user_id)
            
            auth_operation_metrics['auth0_operations_total'].labels(
                operation='get_user_profile',
                result='success'
            ).inc()
            
            # Extract relevant profile fields
            extended_profile = {
                'last_login': user_profile.get('last_login'),
                'login_count': user_profile.get('logins_count', 0),
                'created_at': user_profile.get('created_at'),
                'app_metadata': user_profile.get('app_metadata', {}),
                'user_metadata': user_profile.get('user_metadata', {})
            }
            
            return extended_profile
            
        except Auth0Error as e:
            auth_operation_metrics['auth0_operations_total'].labels(
                operation='get_user_profile',
                result='failure'
            ).inc()
            
            self.logger.warning(
                "Auth0 user profile fetch failed",
                user_id=user_id,
                error=str(e)
            )
            return None
        except Exception as e:
            self.logger.error(
                "Unexpected error fetching Auth0 user profile",
                user_id=user_id,
                error=str(e),
                error_type=type(e).__name__
            )
            return None
    
    async def _initialize_auth0_management_client(self) -> None:
        """Initialize Auth0 management client for user operations."""
        try:
            if not all([self.auth0_domain, self.auth0_client_id, self.auth0_client_secret]):
                self.logger.warning("Auth0 credentials incomplete, skipping management client initialization")
                return
            
            # Get management API token
            get_token = GetToken(self.auth0_domain, self.auth0_client_id, self.auth0_client_secret)
            token_response = get_token.client_credentials(f"https://{self.auth0_domain}/api/v2/")
            
            # Initialize management client
            self._auth0_management_client = Auth0(
                self.auth0_domain,
                token_response['access_token']
            )
            
            self.logger.info("Auth0 management client initialized successfully")
            
        except Exception as e:
            self.logger.error(
                "Failed to initialize Auth0 management client",
                error=str(e),
                error_type=type(e).__name__
            )
            self._auth0_management_client = None
    
    async def _cache_user_session(self, user: 'AuthenticatedUser') -> None:
        """
        Cache user session data for performance optimization.
        
        Args:
            user: Authenticated user object to cache
        """
        try:
            session_data = {
                'user_id': user.user_id,
                'permissions': user.permissions,
                'profile': user.profile,
                'authenticated_at': user.authenticated_at.isoformat(),
                'token_type': user.token_claims.get('type', 'access_token')
            }
            
            # Cache user permissions
            if user.permissions:
                self.cache_manager.cache_user_permissions(
                    user.user_id,
                    set(user.permissions),
                    ttl=self.cache_ttl_seconds
                )
            
            # Cache session data
            session_id = secrets.token_urlsafe(32)
            self.cache_manager.cache_session_data(
                session_id,
                session_data,
                ttl=3600  # 1 hour session cache
            )
            
            self.logger.debug(
                "User session cached successfully",
                user_id=user.user_id,
                session_id=session_id,
                cache_ttl=self.cache_ttl_seconds
            )
            
        except Exception as e:
            # Don't fail authentication if caching fails
            self.logger.warning(
                "Failed to cache user session",
                user_id=user.user_id,
                error=str(e),
                error_type=type(e).__name__
            )
    
    async def _verify_user_permissions(
        self,
        user: 'AuthenticatedUser',
        required_permissions: List[str]
    ) -> bool:
        """
        Verify user has required permissions for the operation.
        
        Args:
            user: Authenticated user object
            required_permissions: List of required permissions
            
        Returns:
            Boolean indicating if user has all required permissions
        """
        try:
            if not required_permissions:
                return True
            
            if not user.permissions:
                return False
            
            user_permissions = set(user.permissions)
            required_permissions_set = set(required_permissions)
            
            # Check if user has all required permissions
            has_permissions = required_permissions_set.issubset(user_permissions)
            
            if not has_permissions:
                missing_permissions = required_permissions_set - user_permissions
                self.logger.debug(
                    "Permission verification failed",
                    user_id=user.user_id,
                    required_permissions=required_permissions,
                    missing_permissions=list(missing_permissions)
                )
            
            return has_permissions
            
        except Exception as e:
            self.logger.error(
                "Error verifying user permissions",
                user_id=user.user_id,
                error=str(e),
                error_type=type(e).__name__
            )
            return False
    
    def _extract_token_from_request(self) -> Optional[str]:
        """
        Extract JWT token from Flask request headers.
        
        Returns:
            JWT token string or None if not found
        """
        try:
            # Check Authorization header
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                return auth_header[7:]  # Remove 'Bearer ' prefix
            
            # Check for token in cookies (if configured)
            token_cookie = request.cookies.get('access_token')
            if token_cookie:
                return token_cookie
            
            # Check for token in query parameters (less secure, for specific use cases)
            token_param = request.args.get('access_token')
            if token_param:
                self.logger.warning(
                    "Token extracted from query parameter",
                    endpoint=request.endpoint,
                    remote_addr=request.remote_addr
                )
                return token_param
            
            return None
            
        except Exception as e:
            self.logger.error(
                "Error extracting token from request",
                error=str(e),
                error_type=type(e).__name__
            )
            return None
    
    async def refresh_token(
        self,
        refresh_token: str,
        current_access_token: Optional[str] = None
    ) -> Tuple[str, str]:
        """
        Refresh JWT access token using refresh token.
        
        Args:
            refresh_token: Valid refresh token
            current_access_token: Current access token (for validation)
            
        Returns:
            Tuple of (new_access_token, new_refresh_token)
            
        Raises:
            JWTException: When refresh token is invalid
            Auth0Exception: When Auth0 service is unavailable
        """
        try:
            # Validate refresh token (allow expired access tokens)
            refresh_claims = await self._validate_jwt_token(
                refresh_token,
                allow_expired=False
            )
            
            if refresh_claims.get('type') != 'refresh_token':
                raise JWTException(
                    message="Invalid token type for refresh operation",
                    error_code=SecurityErrorCode.AUTH_TOKEN_INVALID,
                    validation_context={'token_type': refresh_claims.get('type')}
                )
            
            user_id = refresh_claims.get('sub')
            
            # Use JWT manager to refresh tokens
            new_access_token, new_refresh_token = self.jwt_manager.refresh_access_token(refresh_token)
            
            # Invalidate cached validation results for old tokens
            if current_access_token:
                old_token_hash = create_token_hash(current_access_token)
                # Note: Cache invalidation would be implemented here
            
            # Log successful token refresh
            self.logger.info(
                "Token refreshed successfully",
                user_id=user_id,
                operation='token_refresh'
            )
            
            log_security_event(
                'token_refresh_success',
                user_id=user_id,
                metadata={'refresh_method': 'jwt_refresh_token'}
            )
            
            return new_access_token, new_refresh_token
            
        except (JWTException, Auth0Exception):
            raise
        except Exception as e:
            self.logger.error(
                "Token refresh failed",
                error=str(e),
                error_type=type(e).__name__
            )
            
            raise JWTException(
                message="Token refresh failed",
                error_code=SecurityErrorCode.AUTH_TOKEN_INVALID,
                jwt_error=e
            )
    
    async def revoke_token(
        self,
        token: str,
        reason: str = "user_logout"
    ) -> bool:
        """
        Revoke JWT token and invalidate associated sessions.
        
        Args:
            token: JWT token to revoke
            reason: Reason for revocation (for audit logging)
            
        Returns:
            Boolean indicating successful revocation
        """
        try:
            # Validate token to get claims
            token_claims = await self._validate_jwt_token(token, allow_expired=True)
            if not token_claims:
                return False
            
            user_id = token_claims.get('sub')
            
            # Revoke token using JWT manager
            revocation_success = self.jwt_manager.revoke_token(token, reason)
            
            if revocation_success:
                # Invalidate user caches
                self.cache_manager.bulk_invalidate_user_cache(user_id)
                
                # Log token revocation
                self.logger.info(
                    "Token revoked successfully",
                    user_id=user_id,
                    reason=reason,
                    token_type=token_claims.get('type', 'access_token')
                )
                
                log_security_event(
                    'token_revocation',
                    user_id=user_id,
                    metadata={'reason': reason, 'revocation_method': 'manual'}
                )
            
            return revocation_success
            
        except Exception as e:
            self.logger.error(
                "Token revocation failed",
                error=str(e),
                error_type=type(e).__name__,
                reason=reason
            )
            return False
    
    def get_health_status(self) -> Dict[str, Any]:
        """
        Get comprehensive health status of authentication system.
        
        Returns:
            Health status dictionary with component statuses
        """
        try:
            health_status = {
                'status': 'healthy',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'components': {}
            }
            
            # Check JWT manager health
            health_status['components']['jwt_manager'] = {
                'status': 'healthy' if self.jwt_manager else 'unhealthy',
                'details': 'JWT token processing available'
            }
            
            # Check cache manager health
            cache_health = self.cache_manager.perform_health_check()
            health_status['components']['cache_manager'] = cache_health
            
            # Check Auth0 connectivity
            auth0_status = 'healthy'
            if self._auth0_circuit_breaker_state == 'open':
                auth0_status = 'degraded'
            elif self._auth0_failure_count > 0:
                auth0_status = 'warning'
            
            health_status['components']['auth0_service'] = {
                'status': auth0_status,
                'circuit_breaker_state': self._auth0_circuit_breaker_state,
                'failure_count': self._auth0_failure_count
            }
            
            # Determine overall status
            component_statuses = [comp['status'] for comp in health_status['components'].values()]
            if 'unhealthy' in component_statuses:
                health_status['status'] = 'unhealthy'
            elif 'degraded' in component_statuses:
                health_status['status'] = 'degraded'
            
            return health_status
            
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }


class AuthenticatedUser:
    """
    Authenticated user context containing user information, permissions, and session data.
    
    This class represents a successfully authenticated user with all relevant context
    information including JWT token claims, user profile data, permissions, and
    authentication metadata required for authorization decisions.
    
    Attributes:
        user_id: Unique user identifier from Auth0
        token_claims: Complete JWT token claims
        permissions: List of user permissions for authorization
        profile: User profile information
        token: Original JWT token string
        authenticated_at: Timestamp of authentication
    """
    
    def __init__(
        self,
        user_id: str,
        token_claims: Dict[str, Any],
        permissions: List[str],
        profile: Optional[Dict[str, Any]] = None,
        token: Optional[str] = None,
        authenticated_at: Optional[datetime] = None
    ):
        """
        Initialize authenticated user context.
        
        Args:
            user_id: Unique user identifier
            token_claims: JWT token claims
            permissions: User permissions list
            profile: User profile data
            token: Original JWT token
            authenticated_at: Authentication timestamp
        """
        self.user_id = user_id
        self.token_claims = token_claims
        self.permissions = permissions or []
        self.profile = profile or {}
        self.token = token
        self.authenticated_at = authenticated_at or datetime.now(timezone.utc)
    
    def has_permission(self, permission: str) -> bool:
        """
        Check if user has specific permission.
        
        Args:
            permission: Permission to check
            
        Returns:
            Boolean indicating if user has the permission
        """
        return permission in self.permissions
    
    def has_any_permission(self, permissions: List[str]) -> bool:
        """
        Check if user has any of the specified permissions.
        
        Args:
            permissions: List of permissions to check
            
        Returns:
            Boolean indicating if user has any of the permissions
        """
        return any(perm in self.permissions for perm in permissions)
    
    def has_all_permissions(self, permissions: List[str]) -> bool:
        """
        Check if user has all of the specified permissions.
        
        Args:
            permissions: List of permissions to check
            
        Returns:
            Boolean indicating if user has all permissions
        """
        return all(perm in self.permissions for perm in permissions)
    
    def get_profile_value(self, key: str, default: Any = None) -> Any:
        """
        Get value from user profile with default fallback.
        
        Args:
            key: Profile key to retrieve
            default: Default value if key not found
            
        Returns:
            Profile value or default
        """
        return self.profile.get(key, default)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert authenticated user to dictionary representation.
        
        Returns:
            Dictionary representation of authenticated user
        """
        return {
            'user_id': self.user_id,
            'permissions': self.permissions,
            'profile': self.profile,
            'authenticated_at': self.authenticated_at.isoformat(),
            'token_claims': {
                'sub': self.token_claims.get('sub'),
                'iss': self.token_claims.get('iss'),
                'aud': self.token_claims.get('aud'),
                'exp': self.token_claims.get('exp'),
                'iat': self.token_claims.get('iat')
            }
        }


# Global authenticator instance
_core_authenticator: Optional[CoreJWTAuthenticator] = None


def get_core_authenticator() -> CoreJWTAuthenticator:
    """
    Get global core JWT authenticator instance.
    
    Returns:
        CoreJWTAuthenticator: Global authenticator instance
    """
    global _core_authenticator
    
    if _core_authenticator is None:
        _core_authenticator = CoreJWTAuthenticator()
    
    return _core_authenticator


def require_authentication(
    required_permissions: Optional[List[str]] = None,
    allow_expired: bool = False
):
    """
    Decorator for routes requiring JWT authentication with permission validation.
    
    This decorator provides comprehensive authentication and authorization for Flask
    routes, equivalent to Node.js authentication middleware patterns with enhanced
    security features including permission validation and audit logging.
    
    Args:
        required_permissions: List of required permissions for authorization
        allow_expired: Whether to allow expired tokens (for refresh operations)
        
    Returns:
        Decorated function with authentication enforcement
        
    Example:
        @app.route('/api/protected')
        @require_authentication(['read:documents'])
        def protected_endpoint():
            user = g.authenticated_user
            return jsonify({'user_id': user.user_id})
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                authenticator = get_core_authenticator()
                
                # Authenticate request
                authenticated_user = await authenticator.authenticate_request(
                    required_permissions=required_permissions,
                    allow_expired=allow_expired
                )
                
                if not authenticated_user:
                    return jsonify({
                        'error': 'Authentication required',
                        'error_code': SecurityErrorCode.AUTH_TOKEN_MISSING.value
                    }), 401
                
                # Store authenticated user in Flask g context
                g.authenticated_user = authenticated_user
                g.current_user_id = authenticated_user.user_id
                g.current_user_permissions = authenticated_user.permissions
                
                # Execute the protected function
                return await func(*args, **kwargs) if asyncio.iscoroutinefunction(func) else func(*args, **kwargs)
                
            except (AuthenticationException, JWTException, Auth0Exception) as e:
                error_response = create_safe_error_response(e)
                return jsonify(error_response), e.http_status
            except Exception as e:
                logger.error(
                    "Unexpected authentication decorator error",
                    error=str(e),
                    error_type=type(e).__name__,
                    endpoint=request.endpoint
                )
                
                return jsonify({
                    'error': 'Authentication system error',
                    'error_code': SecurityErrorCode.AUTH_TOKEN_INVALID.value
                }), 500
        
        return wrapper
    return decorator


def get_authenticated_user() -> Optional[AuthenticatedUser]:
    """
    Get current authenticated user from Flask request context.
    
    Returns:
        AuthenticatedUser object if available, None otherwise
        
    Example:
        user = get_authenticated_user()
        if user:
            print(f"Current user: {user.user_id}")
    """
    return getattr(g, 'authenticated_user', None)


async def authenticate_token(token: str) -> Optional[AuthenticatedUser]:
    """
    Standalone token authentication function for external use.
    
    Args:
        token: JWT token string to authenticate
        
    Returns:
        AuthenticatedUser object if authentication succeeds, None otherwise
        
    Example:
        user = await authenticate_token(jwt_token)
        if user:
            print(f"Token is valid for user: {user.user_id}")
    """
    try:
        authenticator = get_core_authenticator()
        return await authenticator.authenticate_request(token=token)
    except Exception as e:
        logger.warning(
            "Standalone token authentication failed",
            error=str(e),
            error_type=type(e).__name__
        )
        return None


def create_auth_health_check() -> Dict[str, Any]:
    """
    Create comprehensive authentication system health check.
    
    Returns:
        Health check status dictionary
        
    Example:
        health = create_auth_health_check()
        print(f"Auth system status: {health['status']}")
    """
    try:
        authenticator = get_core_authenticator()
        return authenticator.get_health_status()
    except Exception as e:
        return {
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }


# Export public interface
__all__ = [
    'CoreJWTAuthenticator',
    'AuthenticatedUser',
    'get_core_authenticator',
    'require_authentication',
    'get_authenticated_user',
    'authenticate_token',
    'create_auth_health_check',
    'auth_operation_metrics'
]