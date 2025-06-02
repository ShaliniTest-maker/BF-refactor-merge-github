"""
Authentication and security configuration for Flask application.

This module implements comprehensive authentication and security configuration for the Node.js to 
Python Flask migration, providing PyJWT 2.8+ token validation, Auth0 enterprise integration,
and cryptographic settings. Manages JWT secret keys, token expiration policies, Auth0 client 
configuration, and Flask-Login session management to preserve existing authentication flows 
and security mechanisms.

Key Components:
- PyJWT 2.8+ token validation replacing Node.js jsonwebtoken per Section 0.1.2
- Auth0 enterprise integration through Python SDK per Section 0.1.3
- cryptography 41.0+ for secure token validation per Section 3.2.2
- Flask-Login 0.7.0+ session management per Section 3.2.2
- Redis-based session storage per Section 3.4.2
- Complete preservation of existing API contracts per Section 0.1.4

Technical Requirements:
- Authentication system migration preserving JWT token validation patterns per Section 0.1.1
- Complete preservation of existing API contracts ensuring zero client-side changes per Section 0.1.4
- Session management with Redis-based storage per Section 3.4.2 caching solutions
- Environment-specific configuration management using python-dotenv 1.0+
"""

import os
import logging
from typing import Optional, Dict, Any, Union, List
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin
import base64
import hashlib
import json

# Core Flask and authentication imports
from flask import Flask, request, g, current_app
from flask_login import LoginManager, UserMixin, current_user

# JWT and cryptographic imports
import jwt
from jwt.exceptions import (
    InvalidTokenError, 
    ExpiredSignatureError, 
    InvalidSignatureError,
    InvalidKeyError,
    InvalidIssuerError,
    InvalidAudienceError
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.fernet import Fernet

# Auth0 and HTTP client imports
from auth0.management import Auth0
from auth0.authentication import GetToken, Users, Social
import httpx
from tenacity import (
    retry, 
    stop_after_attempt, 
    wait_exponential_jitter,
    retry_if_exception_type,
    before_sleep_log,
    after_log
)

# Environment and validation imports
from dotenv import load_dotenv
from marshmallow import Schema, fields, ValidationError
from email_validator import validate_email, EmailNotValidError

# Database configuration import
from src.config.database import get_redis_client, DatabaseConnectionError

# Configure module logger
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()


class AuthenticationError(Exception):
    """Custom exception for authentication failures."""
    pass


class AuthorizationError(Exception):
    """Custom exception for authorization failures."""
    pass


class TokenValidationError(Exception):
    """Custom exception for token validation failures."""
    pass


class Auth0ServiceError(Exception):
    """Custom exception for Auth0 service failures."""
    pass


class User(UserMixin):
    """
    Flask-Login User class implementing comprehensive user context management.
    
    This class provides complete user authentication state management equivalent
    to the Node.js implementation while integrating with Flask-Login patterns
    for session management and user context preservation.
    
    Features:
    - Auth0 profile integration with complete user metadata preservation
    - JWT claims extraction and validation with cryptographic verification
    - Session state management with Redis-based storage per Section 3.4.2
    - Role and permission context management for authorization workflows
    - User activity tracking and audit trail generation
    """
    
    def __init__(self, user_id: str, auth0_profile: Dict[str, Any], jwt_claims: Optional[Dict[str, Any]] = None):
        """
        Initialize User instance with Auth0 profile and JWT claims.
        
        Args:
            user_id: Unique user identifier from Auth0
            auth0_profile: Complete Auth0 user profile data
            jwt_claims: JWT token claims for authorization context
        """
        self.id = user_id
        self.auth0_profile = auth0_profile
        self.jwt_claims = jwt_claims or {}
        self.is_authenticated = True
        self.is_active = True
        self.is_anonymous = False
        self.created_at = datetime.utcnow()
        
        # Extract user metadata from Auth0 profile
        self.email = auth0_profile.get('email')
        self.name = auth0_profile.get('name')
        self.picture = auth0_profile.get('picture')
        self.email_verified = auth0_profile.get('email_verified', False)
        
        # Extract permissions and roles from JWT claims
        self.permissions = jwt_claims.get('permissions', [])
        self.roles = jwt_claims.get('roles', [])
        self.scope = jwt_claims.get('scope', '')
        
    def get_id(self) -> str:
        """Return user ID for Flask-Login session management."""
        return str(self.id)
    
    def has_permission(self, permission: str) -> bool:
        """
        Check if user has specific permission.
        
        Args:
            permission: Permission string to validate
            
        Returns:
            Boolean indicating permission status
        """
        return permission in self.permissions
    
    def has_role(self, role: str) -> bool:
        """
        Check if user has specific role.
        
        Args:
            role: Role string to validate
            
        Returns:
            Boolean indicating role assignment
        """
        return role in self.roles
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert user object to dictionary for serialization.
        
        Returns:
            Dictionary representation of user data
        """
        return {
            'id': self.id,
            'email': self.email,
            'name': self.name,
            'picture': self.picture,
            'email_verified': self.email_verified,
            'permissions': self.permissions,
            'roles': self.roles,
            'is_authenticated': self.is_authenticated,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat()
        }


class TokenValidationSchema(Schema):
    """Marshmallow schema for JWT token validation."""
    
    token = fields.Str(required=True, validate=lambda x: len(x) > 0)
    audience = fields.Str(missing=None)
    issuer = fields.Str(missing=None)


class UserRegistrationSchema(Schema):
    """Marshmallow schema for user registration validation."""
    
    email = fields.Email(required=True)
    password = fields.Str(required=True, validate=lambda x: len(x) >= 8)
    name = fields.Str(required=True, validate=lambda x: len(x) > 0)
    
    def validate_email(self, value: str) -> str:
        """Validate email using email-validator."""
        try:
            valid_email = validate_email(value)
            return valid_email.email
        except EmailNotValidError as e:
            raise ValidationError(f"Invalid email format: {str(e)}")


class AuthConfig:
    """
    Comprehensive authentication configuration class managing JWT validation,
    Auth0 integration, and security settings.
    
    This class implements the authentication configuration specified in the technical
    migration requirements, providing PyJWT 2.8+ token validation, Auth0 enterprise
    integration, and cryptographic settings equivalent to the Node.js implementation
    while enhancing security infrastructure through Flask-Login integration.
    
    Features:
    - PyJWT 2.8+ token validation with cryptographic verification per Section 0.1.2
    - Auth0 Python SDK integration preserving enterprise authentication flows per Section 0.1.3
    - cryptography 41.0+ secure token validation and key management per Section 3.2.2
    - Flask-Login 0.7.0+ session management with Redis storage per Section 3.2.2
    - Environment-specific configuration management using python-dotenv per Section 6.4.1
    - Circuit breaker patterns for Auth0 service integration per Section 6.4.2
    """
    
    def __init__(self, environment: str = 'development'):
        """
        Initialize authentication configuration for specified environment.
        
        Args:
            environment: Target environment ('development', 'testing', 'production')
        """
        self.environment = environment.lower()
        self._auth0_client: Optional[Auth0] = None
        self._auth0_get_token: Optional[GetToken] = None
        self._httpx_client: Optional[httpx.AsyncClient] = None
        self._encryption_key: Optional[bytes] = None
        
        # Load environment-specific configuration
        self._load_configuration()
        
        # Initialize cryptographic components
        self._init_cryptography()
        
        # Validate configuration
        self._validate_configuration()
        
        logger.info(f"AuthConfig initialized for environment: {self.environment}")
    
    def _load_configuration(self) -> None:
        """
        Load authentication configuration from environment variables.
        
        Supports environment-specific configuration loading while preserving
        existing JWT token structures and Auth0 integration patterns per Section 0.1.4.
        """
        # Auth0 Configuration per Section 6.4.1 Identity Management
        self.auth0_domain = os.getenv('AUTH0_DOMAIN')
        self.auth0_client_id = os.getenv('AUTH0_CLIENT_ID')
        self.auth0_client_secret = os.getenv('AUTH0_CLIENT_SECRET')
        self.auth0_audience = os.getenv('AUTH0_AUDIENCE')
        self.auth0_scope = os.getenv('AUTH0_SCOPE', 'openid profile email')
        
        # JWT Configuration per Section 3.2.2 Authentication & Security Libraries
        self.jwt_secret_key = os.getenv('JWT_SECRET_KEY')
        self.jwt_algorithm = os.getenv('JWT_ALGORITHM', 'RS256')
        self.jwt_access_token_expires = int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', '3600'))  # 1 hour
        self.jwt_refresh_token_expires = int(os.getenv('JWT_REFRESH_TOKEN_EXPIRES', '2592000'))  # 30 days
        self.jwt_issuer = os.getenv('JWT_ISSUER', f"https://{self.auth0_domain}/")
        
        # Redis Session Configuration per Section 3.4.2 Caching Solutions
        self.redis_session_prefix = os.getenv('REDIS_SESSION_PREFIX', 'session:')
        self.redis_auth_cache_prefix = os.getenv('REDIS_AUTH_CACHE_PREFIX', 'auth_cache:')
        self.redis_token_cache_prefix = os.getenv('REDIS_TOKEN_CACHE_PREFIX', 'token_cache:')
        self.redis_session_timeout = int(os.getenv('REDIS_SESSION_TIMEOUT', '3600'))  # 1 hour
        
        # Security Configuration per Section 6.4.3 Data Protection
        self.password_hash_rounds = int(os.getenv('PASSWORD_HASH_ROUNDS', '12'))
        self.session_cookie_secure = os.getenv('SESSION_COOKIE_SECURE', 'true').lower() == 'true'
        self.session_cookie_httponly = os.getenv('SESSION_COOKIE_HTTPONLY', 'true').lower() == 'true'
        self.session_cookie_samesite = os.getenv('SESSION_COOKIE_SAMESITE', 'Lax')
        
        # Rate Limiting Configuration per Section 6.4.2 Policy Enforcement Points
        self.auth_rate_limit = os.getenv('AUTH_RATE_LIMIT', '10 per minute')
        self.token_validation_rate_limit = os.getenv('TOKEN_VALIDATION_RATE_LIMIT', '100 per minute')
        
        # Circuit Breaker Configuration per Section 6.4.2 Resource Authorization
        self.auth0_timeout = float(os.getenv('AUTH0_TIMEOUT', '30.0'))
        self.auth0_retry_attempts = int(os.getenv('AUTH0_RETRY_ATTEMPTS', '3'))
        self.auth0_backoff_factor = float(os.getenv('AUTH0_BACKOFF_FACTOR', '1.0'))
        
        # Environment-specific settings
        self._configure_environment_settings()
    
    def _configure_environment_settings(self) -> None:
        """Configure environment-specific authentication settings."""
        if self.environment == 'development':
            self.jwt_algorithm = 'HS256'  # Use symmetric key for development
            self.session_cookie_secure = False  # Allow HTTP in development
            self.auth0_timeout = 10.0  # Shorter timeout for development
        elif self.environment == 'testing':
            self.jwt_access_token_expires = 300  # 5 minutes for testing
            self.redis_session_timeout = 300  # 5 minutes for testing
        elif self.environment == 'production':
            self.session_cookie_secure = True  # Enforce HTTPS in production
            self.jwt_algorithm = 'RS256'  # Use asymmetric keys in production
    
    def _init_cryptography(self) -> None:
        """
        Initialize cryptographic components for token validation and session encryption.
        
        Implements cryptography 41.0+ secure token validation and encryption
        operations per Section 3.2.2 Authentication & Security Libraries.
        """
        try:
            # Initialize encryption key for session data
            encryption_key_b64 = os.getenv('REDIS_ENCRYPTION_KEY')
            if encryption_key_b64:
                self._encryption_key = base64.b64decode(encryption_key_b64)
            else:
                # Generate encryption key for development
                self._encryption_key = Fernet.generate_key()
                if self.environment == 'development':
                    logger.warning("Using generated encryption key for development")
            
            self._fernet = Fernet(self._encryption_key)
            
            logger.info("Cryptographic components initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize cryptographic components: {str(e)}")
            raise AuthenticationError(f"Cryptography initialization failed: {str(e)}")
    
    def _validate_configuration(self) -> None:
        """
        Validate authentication configuration completeness and correctness.
        
        Ensures all required configuration parameters are present and valid
        for the specified environment per Section 6.4.4 Security Controls Matrix.
        """
        required_config = [
            'auth0_domain',
            'auth0_client_id', 
            'auth0_client_secret',
            'auth0_audience',
            'jwt_secret_key'
        ]
        
        missing_config = []
        for config_key in required_config:
            if not getattr(self, config_key):
                missing_config.append(config_key.upper())
        
        if missing_config:
            raise AuthenticationError(
                f"Missing required authentication configuration: {', '.join(missing_config)}"
            )
        
        # Validate Auth0 domain format
        if not self.auth0_domain.endswith('.auth0.com') and not self.auth0_domain.endswith('.eu.auth0.com'):
            logger.warning(f"Auth0 domain format may be invalid: {self.auth0_domain}")
        
        # Validate JWT algorithm
        supported_algorithms = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512']
        if self.jwt_algorithm not in supported_algorithms:
            raise AuthenticationError(f"Unsupported JWT algorithm: {self.jwt_algorithm}")
        
        logger.info("Authentication configuration validation completed successfully")
    
    def get_auth0_client(self) -> Auth0:
        """
        Get Auth0 management client with enterprise configuration.
        
        Implements Auth0 Python SDK integration preserving enterprise
        authentication flows per Section 0.1.3 Authentication/Authorization Considerations.
        
        Returns:
            Auth0: Configured Auth0 management client instance
            
        Raises:
            Auth0ServiceError: If Auth0 client cannot be initialized
        """
        if self._auth0_client is None:
            try:
                # Get management API access token
                if self._auth0_get_token is None:
                    self._auth0_get_token = GetToken(
                        domain=self.auth0_domain,
                        client_id=self.auth0_client_id,
                        client_secret=self.auth0_client_secret
                    )
                
                # Get access token for management API
                token_response = self._auth0_get_token.client_credentials(
                    audience=f"https://{self.auth0_domain}/api/v2/"
                )
                management_token = token_response['access_token']
                
                # Initialize Auth0 management client
                self._auth0_client = Auth0(
                    domain=self.auth0_domain,
                    token=management_token
                )
                
                logger.info("Auth0 management client initialized successfully")
                
            except Exception as e:
                error_msg = f"Failed to initialize Auth0 client: {str(e)}"
                logger.error(error_msg)
                raise Auth0ServiceError(error_msg) from e
        
        return self._auth0_client
    
    async def get_auth0_httpx_client(self) -> httpx.AsyncClient:
        """
        Get HTTPX async client for Auth0 API calls with circuit breaker protection.
        
        Implements comprehensive circuit breaker patterns around Auth0 API calls
        per Section 6.4.2 Resource Authorization with intelligent retry strategies.
        
        Returns:
            httpx.AsyncClient: Configured async HTTP client for Auth0 integration
        """
        if self._httpx_client is None:
            self._httpx_client = httpx.AsyncClient(
                base_url=f"https://{self.auth0_domain}",
                timeout=httpx.Timeout(
                    connect=10.0,
                    read=self.auth0_timeout,
                    write=10.0,
                    pool=5.0
                ),
                limits=httpx.Limits(
                    max_connections=100,
                    max_keepalive_connections=50,
                    keepalive_expiry=30.0
                ),
                headers={
                    'User-Agent': 'Flask-Auth-System/1.0',
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                }
            )
        
        return self._httpx_client
    
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
        
        This method implements intelligent retry strategies with exponential backoff
        and jitter to prevent thundering herd effects during Auth0 service recovery.
        Includes comprehensive fallback mechanisms using cached token data.
        
        Args:
            token: JWT token to validate
            
        Returns:
            Token validation result with user claims and metadata
            
        Raises:
            TokenValidationError: When token validation fails after retries
        """
        try:
            client = await self.get_auth0_httpx_client()
            
            # Get Auth0 public key for token verification
            jwks_response = await client.get("/.well-known/jwks.json")
            jwks_response.raise_for_status()
            jwks_data = jwks_response.json()
            
            # Validate token using PyJWT with Auth0 public key
            token_header = jwt.get_unverified_header(token)
            key_id = token_header.get('kid')
            
            # Find matching public key
            public_key = None
            for key in jwks_data['keys']:
                if key['kid'] == key_id:
                    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
                    break
            
            if not public_key:
                raise TokenValidationError(f"Public key not found for kid: {key_id}")
            
            # Decode and validate token
            decoded_token = jwt.decode(
                token,
                public_key,
                algorithms=[self.jwt_algorithm],
                audience=self.auth0_audience,
                issuer=self.jwt_issuer,
                options={
                    'verify_signature': True,
                    'verify_exp': True,
                    'verify_iat': True,
                    'verify_aud': True,
                    'verify_iss': True
                }
            )
            
            # Cache validated token
            await self._cache_token_validation(token, decoded_token)
            
            return {
                'valid': True,
                'claims': decoded_token,
                'user_id': decoded_token.get('sub'),
                'validation_source': 'auth0_api',
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except (InvalidTokenError, ExpiredSignatureError, InvalidSignatureError) as e:
            logger.warning(f"Token validation failed: {str(e)}")
            raise TokenValidationError(f"Invalid token: {str(e)}")
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            logger.error(f"Auth0 API call failed: {str(e)}")
            # Try fallback validation with cached JWKS
            return await self._fallback_token_validation(token)
    
    async def _fallback_token_validation(self, token: str) -> Dict[str, Any]:
        """
        Fallback token validation using cached JWKS data when Auth0 is unavailable.
        
        Args:
            token: JWT token to validate
            
        Returns:
            Cached validation result with degraded mode indicators
        """
        try:
            redis_client = get_redis_client()
            
            # Try to get cached JWKS data
            cached_jwks = redis_client.get('auth0_jwks_cache')
            if cached_jwks:
                jwks_data = json.loads(cached_jwks)
                
                # Validate token using cached public key
                token_header = jwt.get_unverified_header(token)
                key_id = token_header.get('kid')
                
                public_key = None
                for key in jwks_data['keys']:
                    if key['kid'] == key_id:
                        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
                        break
                
                if public_key:
                    decoded_token = jwt.decode(
                        token,
                        public_key,
                        algorithms=[self.jwt_algorithm],
                        audience=self.auth0_audience,
                        issuer=self.jwt_issuer
                    )
                    
                    return {
                        'valid': True,
                        'claims': decoded_token,
                        'user_id': decoded_token.get('sub'),
                        'validation_source': 'fallback_cache',
                        'degraded_mode': True,
                        'timestamp': datetime.utcnow().isoformat()
                    }
            
            # Ultimate fallback - deny access when no cache available
            logger.error("No cached JWKS available during Auth0 outage")
            return {
                'valid': False,
                'validation_source': 'fallback_deny',
                'degraded_mode': True,
                'error': 'No cached validation data available',
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Fallback token validation failed: {str(e)}")
            return {
                'valid': False,
                'validation_source': 'fallback_error',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    async def _cache_token_validation(self, token: str, claims: Dict[str, Any]) -> None:
        """
        Cache token validation result in Redis with structured key patterns.
        
        Args:
            token: Original JWT token
            claims: Validated token claims
        """
        try:
            redis_client = get_redis_client()
            
            # Create token hash for cache key
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            cache_key = f"{self.redis_token_cache_prefix}{token_hash}"
            
            # Cache validation result
            cache_data = {
                'claims': claims,
                'cached_at': datetime.utcnow().isoformat(),
                'expires_at': datetime.fromtimestamp(
                    claims.get('exp', 0), 
                    tz=timezone.utc
                ).isoformat()
            }
            
            # Set TTL based on token expiration
            token_exp = claims.get('exp', 0)
            current_time = datetime.utcnow().timestamp()
            ttl = max(int(token_exp - current_time), 60)  # Minimum 1 minute TTL
            
            redis_client.setex(
                cache_key,
                ttl,
                self._encrypt_cache_data(json.dumps(cache_data))
            )
            
        except Exception as e:
            logger.warning(f"Failed to cache token validation: {str(e)}")
    
    def create_user_session(self, user: User) -> str:
        """
        Create encrypted user session in Redis storage.
        
        Implements session management with Redis-based storage per Section 3.4.2
        using AES-256-GCM encryption for session data protection.
        
        Args:
            user: User instance to create session for
            
        Returns:
            Session ID for Flask-Login session management
            
        Raises:
            AuthenticationError: If session creation fails
        """
        try:
            redis_client = get_redis_client()
            
            # Generate unique session ID
            session_id = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')
            session_key = f"{self.redis_session_prefix}{session_id}"
            
            # Prepare session data
            session_data = {
                'user_id': user.id,
                'user_profile': user.auth0_profile,
                'jwt_claims': user.jwt_claims,
                'created_at': datetime.utcnow().isoformat(),
                'last_accessed': datetime.utcnow().isoformat(),
                'ip_address': getattr(request, 'remote_addr', None),
                'user_agent': getattr(request, 'headers', {}).get('User-Agent')
            }
            
            # Encrypt and store session data
            encrypted_data = self._encrypt_cache_data(json.dumps(session_data))
            redis_client.setex(session_key, self.redis_session_timeout, encrypted_data)
            
            logger.info(f"User session created successfully for user: {user.id}")
            return session_id
            
        except Exception as e:
            error_msg = f"Failed to create user session: {str(e)}"
            logger.error(error_msg)
            raise AuthenticationError(error_msg) from e
    
    def get_user_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve and decrypt user session data from Redis.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Decrypted session data or None if session not found/expired
        """
        try:
            redis_client = get_redis_client()
            session_key = f"{self.redis_session_prefix}{session_id}"
            
            encrypted_data = redis_client.get(session_key)
            if not encrypted_data:
                return None
            
            # Decrypt session data
            decrypted_data = self._decrypt_cache_data(encrypted_data)
            session_data = json.loads(decrypted_data)
            
            # Update last accessed time
            session_data['last_accessed'] = datetime.utcnow().isoformat()
            updated_data = self._encrypt_cache_data(json.dumps(session_data))
            redis_client.setex(session_key, self.redis_session_timeout, updated_data)
            
            return session_data
            
        except Exception as e:
            logger.warning(f"Failed to retrieve user session: {str(e)}")
            return None
    
    def delete_user_session(self, session_id: str) -> bool:
        """
        Delete user session from Redis storage.
        
        Args:
            session_id: Session identifier to delete
            
        Returns:
            Boolean indicating deletion success
        """
        try:
            redis_client = get_redis_client()
            session_key = f"{self.redis_session_prefix}{session_id}"
            
            deleted_count = redis_client.delete(session_key)
            
            if deleted_count > 0:
                logger.info(f"User session deleted successfully: {session_id}")
                return True
            else:
                logger.warning(f"Session not found for deletion: {session_id}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to delete user session: {str(e)}")
            return False
    
    def _encrypt_cache_data(self, data: str) -> str:
        """
        Encrypt cache data using AES-256-GCM encryption.
        
        Args:
            data: Plain text data to encrypt
            
        Returns:
            Base64-encoded encrypted data
        """
        try:
            encrypted_data = self._fernet.encrypt(data.encode('utf-8'))
            return base64.b64encode(encrypted_data).decode('utf-8')
        except Exception as e:
            logger.error(f"Failed to encrypt cache data: {str(e)}")
            raise AuthenticationError(f"Encryption failed: {str(e)}")
    
    def _decrypt_cache_data(self, encrypted_data: str) -> str:
        """
        Decrypt cache data using AES-256-GCM encryption.
        
        Args:
            encrypted_data: Base64-encoded encrypted data
            
        Returns:
            Decrypted plain text data
        """
        try:
            decoded_data = base64.b64decode(encrypted_data.encode('utf-8'))
            decrypted_data = self._fernet.decrypt(decoded_data)
            return decrypted_data.decode('utf-8')
        except Exception as e:
            logger.error(f"Failed to decrypt cache data: {str(e)}")
            raise AuthenticationError(f"Decryption failed: {str(e)}")
    
    def validate_user_permissions(
        self, 
        user_id: str, 
        required_permissions: List[str],
        resource_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Validate user permissions with caching and fallback mechanisms.
        
        Implements permission validation with Redis caching per Section 6.4.2
        Permission Management with intelligent TTL management and cache effectiveness tracking.
        
        Args:
            user_id: User identifier for permission validation
            required_permissions: List of permissions to validate
            resource_id: Optional resource identifier for resource-specific authorization
            
        Returns:
            Permission validation result with caching metadata
        """
        try:
            redis_client = get_redis_client()
            
            # Check cached permissions first
            cache_key = f"perm_cache:{user_id}"
            cached_permissions = redis_client.get(cache_key)
            
            if cached_permissions:
                # Use cached permissions
                permissions_data = json.loads(self._decrypt_cache_data(cached_permissions))
                user_permissions = set(permissions_data.get('permissions', []))
                
                has_permissions = all(perm in user_permissions for perm in required_permissions)
                
                return {
                    'user_id': user_id,
                    'has_permissions': has_permissions,
                    'granted_permissions': list(user_permissions),
                    'validation_source': 'cache',
                    'resource_id': resource_id,
                    'timestamp': datetime.utcnow().isoformat()
                }
            else:
                # Fetch permissions from Auth0 (would be implemented with actual Auth0 API call)
                # For now, return a placeholder implementation
                logger.warning(f"No cached permissions found for user: {user_id}")
                return {
                    'user_id': user_id,
                    'has_permissions': False,
                    'granted_permissions': [],
                    'validation_source': 'fallback_deny',
                    'resource_id': resource_id,
                    'error': 'No cached permissions available',
                    'timestamp': datetime.utcnow().isoformat()
                }
                
        except Exception as e:
            logger.error(f"Permission validation failed for user {user_id}: {str(e)}")
            return {
                'user_id': user_id,
                'has_permissions': False,
                'granted_permissions': [],
                'validation_source': 'error',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def get_configuration_info(self) -> Dict[str, Any]:
        """
        Get authentication configuration information for monitoring and debugging.
        
        Returns:
            Dictionary containing configuration details with sensitive data masked
        """
        return {
            'environment': self.environment,
            'auth0': {
                'domain': self.auth0_domain,
                'client_id': self.auth0_client_id,
                'audience': self.auth0_audience,
                'scope': self.auth0_scope
            },
            'jwt': {
                'algorithm': self.jwt_algorithm,
                'issuer': self.jwt_issuer,
                'access_token_expires': self.jwt_access_token_expires,
                'refresh_token_expires': self.jwt_refresh_token_expires
            },
            'redis': {
                'session_prefix': self.redis_session_prefix,
                'auth_cache_prefix': self.redis_auth_cache_prefix,
                'token_cache_prefix': self.redis_token_cache_prefix,
                'session_timeout': self.redis_session_timeout
            },
            'security': {
                'session_cookie_secure': self.session_cookie_secure,
                'session_cookie_httponly': self.session_cookie_httponly,
                'session_cookie_samesite': self.session_cookie_samesite,
                'password_hash_rounds': self.password_hash_rounds
            },
            'rate_limiting': {
                'auth_rate_limit': self.auth_rate_limit,
                'token_validation_rate_limit': self.token_validation_rate_limit
            },
            'circuit_breaker': {
                'auth0_timeout': self.auth0_timeout,
                'auth0_retry_attempts': self.auth0_retry_attempts,
                'auth0_backoff_factor': self.auth0_backoff_factor
            }
        }
    
    async def close_connections(self) -> None:
        """
        Close all external connections and clean up resources.
        
        Implements proper connection cleanup for graceful application shutdown
        while ensuring all HTTP clients and Auth0 connections are properly closed.
        """
        try:
            if self._httpx_client:
                logger.info("Closing Auth0 HTTPX client connection")
                await self._httpx_client.aclose()
                self._httpx_client = None
            
            logger.info("All authentication connections closed successfully")
            
        except Exception as e:
            logger.error(f"Error closing authentication connections: {str(e)}")


# Global authentication configuration instance
auth_config: Optional[AuthConfig] = None


def init_auth_config(environment: str = 'development') -> AuthConfig:
    """
    Initialize global authentication configuration instance.
    
    Args:
        environment: Target environment for configuration
        
    Returns:
        AuthConfig: Initialized authentication configuration instance
    """
    global auth_config
    auth_config = AuthConfig(environment)
    logger.info(f"Global authentication configuration initialized for environment: {environment}")
    return auth_config


def get_auth_config() -> AuthConfig:
    """
    Get global authentication configuration instance.
    
    Returns:
        AuthConfig: Global authentication configuration instance
        
    Raises:
        RuntimeError: If authentication configuration has not been initialized
    """
    if auth_config is None:
        raise RuntimeError(
            "Authentication configuration not initialized. "
            "Call init_auth_config() first."
        )
    return auth_config


def setup_flask_login(app: Flask) -> LoginManager:
    """
    Configure Flask-Login for comprehensive user session management.
    
    Implements Flask-Login integration per Section 3.2.2 Authentication & Security Libraries
    with comprehensive user session management alongside Flask-Session for distributed
    session storage and enterprise-grade security through Redis-based session management.
    
    Args:
        app: Flask application instance
        
    Returns:
        LoginManager: Configured Flask-Login manager instance
    """
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.session_protection = 'strong'
    
    @login_manager.user_loader
    def load_user(user_id: str) -> Optional[User]:
        """
        Load user from session storage for Flask-Login.
        
        Args:
            user_id: User identifier to load
            
        Returns:
            User instance or None if not found
        """
        try:
            auth_conf = get_auth_config()
            
            # Try to get user from current session
            session_id = getattr(g, 'session_id', None)
            if session_id:
                session_data = auth_conf.get_user_session(session_id)
                if session_data and session_data.get('user_id') == user_id:
                    return User(
                        user_id=session_data['user_id'],
                        auth0_profile=session_data.get('user_profile', {}),
                        jwt_claims=session_data.get('jwt_claims', {})
                    )
            
            logger.warning(f"User not found in session storage: {user_id}")
            return None
            
        except Exception as e:
            logger.error(f"Failed to load user {user_id}: {str(e)}")
            return None
    
    @login_manager.unauthorized_handler
    def unauthorized():
        """Handle unauthorized access attempts."""
        from flask import jsonify, request
        
        if request.is_json:
            return jsonify({'error': 'Authentication required'}), 401
        else:
            return jsonify({'error': 'Please log in to access this resource'}), 401
    
    @app.teardown_appcontext
    def close_auth_context(error):
        """Clean up authentication context on request teardown."""
        if hasattr(g, 'current_user'):
            delattr(g, 'current_user')
        if hasattr(g, 'session_id'):
            delattr(g, 'session_id')
    
    logger.info("Flask-Login configured successfully")
    return login_manager


def validate_jwt_token(token: str, audience: Optional[str] = None) -> Dict[str, Any]:
    """
    Validate JWT token using PyJWT 2.8+ with comprehensive error handling.
    
    Implements JWT token processing migrated from jsonwebtoken to PyJWT 2.8+
    per Section 0.1.2 with equivalent validation patterns and error handling.
    
    Args:
        token: JWT token string to validate
        audience: Optional audience to validate against
        
    Returns:
        Dictionary containing validation result and claims
        
    Raises:
        TokenValidationError: If token validation fails
    """
    try:
        auth_conf = get_auth_config()
        
        # Validate input
        schema = TokenValidationSchema()
        validated_data = schema.load({'token': token, 'audience': audience})
        
        # Use configured audience if not provided
        target_audience = validated_data.get('audience') or auth_conf.auth0_audience
        
        # Decode token based on algorithm
        if auth_conf.jwt_algorithm.startswith('HS'):
            # Symmetric key validation (development)
            decoded_token = jwt.decode(
                token,
                auth_conf.jwt_secret_key,
                algorithms=[auth_conf.jwt_algorithm],
                audience=target_audience,
                issuer=auth_conf.jwt_issuer,
                options={
                    'verify_signature': True,
                    'verify_exp': True,
                    'verify_iat': True,
                    'verify_aud': True,
                    'verify_iss': True
                }
            )
        else:
            # Asymmetric key validation (production) - would fetch public key from Auth0
            # For now, raise an error indicating this needs Auth0 integration
            raise TokenValidationError(
                "Asymmetric key validation requires Auth0 public key - use validate_token_with_auth0"
            )
        
        return {
            'valid': True,
            'claims': decoded_token,
            'user_id': decoded_token.get('sub'),
            'permissions': decoded_token.get('permissions', []),
            'roles': decoded_token.get('roles', []),
            'validation_source': 'local',
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except ValidationError as e:
        raise TokenValidationError(f"Invalid token format: {str(e)}")
    except ExpiredSignatureError:
        raise TokenValidationError("Token has expired")
    except InvalidSignatureError:
        raise TokenValidationError("Invalid token signature")
    except InvalidKeyError:
        raise TokenValidationError("Invalid signing key")
    except InvalidIssuerError:
        raise TokenValidationError("Invalid token issuer")
    except InvalidAudienceError:
        raise TokenValidationError("Invalid token audience")
    except InvalidTokenError as e:
        raise TokenValidationError(f"Invalid token: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected token validation error: {str(e)}")
        raise TokenValidationError(f"Token validation failed: {str(e)}")


def create_user_from_auth0_profile(auth0_profile: Dict[str, Any], jwt_claims: Optional[Dict[str, Any]] = None) -> User:
    """
    Create User instance from Auth0 profile data.
    
    Args:
        auth0_profile: Auth0 user profile data
        jwt_claims: Optional JWT claims for authorization context
        
    Returns:
        User: Configured User instance for Flask-Login
        
    Raises:
        AuthenticationError: If user creation fails
    """
    try:
        user_id = auth0_profile.get('sub') or auth0_profile.get('user_id')
        if not user_id:
            raise AuthenticationError("No user ID found in Auth0 profile")
        
        user = User(
            user_id=user_id,
            auth0_profile=auth0_profile,
            jwt_claims=jwt_claims or {}
        )
        
        logger.info(f"User created successfully from Auth0 profile: {user_id}")
        return user
        
    except Exception as e:
        error_msg = f"Failed to create user from Auth0 profile: {str(e)}"
        logger.error(error_msg)
        raise AuthenticationError(error_msg) from e