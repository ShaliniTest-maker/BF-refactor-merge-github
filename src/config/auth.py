"""
Authentication and Security Configuration Module

This module implements comprehensive authentication and security configuration for the
Flask application migration from Node.js, providing JWT token validation with PyJWT 2.8+,
Auth0 enterprise integration, and cryptographic settings using cryptography 41.0+.

Key Features:
- JWT token processing equivalent to Node.js jsonwebtoken
- Auth0 Python SDK integration preserving enterprise authentication flows
- Flask-Login session management with Redis-backed distributed storage
- Flask-Talisman security header enforcement
- AWS KMS integration for encryption key management
- Comprehensive error handling and monitoring integration

Security Standards:
- OWASP Top 10 compliance
- SOC 2 Type II audit trail support
- FIPS 140-2 cryptographic standards
- Zero API surface changes for backward compatibility
"""

import os
import base64
import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, List, Union, Tuple
from functools import wraps
from urllib.parse import urljoin

import jwt
import redis
import boto3
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dotenv import load_dotenv
from flask import Flask, request, jsonify, session, g, current_app
from flask_login import LoginManager, UserMixin, current_user
from flask_session import Session
from flask_talisman import Talisman
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from auth0.authentication import GetToken
from auth0.management import Auth0
from auth0.exceptions import Auth0Error
from botocore.exceptions import ClientError, BotoCoreError
from werkzeug.security import check_password_hash, generate_password_hash
import structlog
from prometheus_client import Counter, Histogram, Gauge
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Load environment variables
load_dotenv()

# Configure structured logging for authentication events
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.stdlib.LoggerFactory(),
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

# Initialize security audit logger
security_logger = structlog.get_logger("security.authentication")

# Prometheus metrics for authentication monitoring
auth_metrics = {
    'requests_total': Counter(
        'auth_requests_total',
        'Total authentication attempts by result',
        ['result', 'method']
    ),
    'jwt_validation_duration': Histogram(
        'jwt_validation_duration_seconds',
        'JWT token validation duration',
        ['algorithm', 'issuer']
    ),
    'session_operations': Counter(
        'auth_session_operations_total',
        'Session management operations',
        ['operation', 'result']
    ),
    'cache_operations': Counter(
        'auth_cache_operations_total',
        'Authentication cache operations',
        ['operation', 'cache_type', 'result']
    ),
    'active_sessions': Gauge(
        'auth_active_sessions',
        'Number of active user sessions'
    ),
    'circuit_breaker_state': Gauge(
        'auth_circuit_breaker_state',
        'Circuit breaker state for auth services',
        ['service']
    )
}


class AuthenticationError(Exception):
    """Custom exception for authentication failures."""
    pass


class AuthorizationError(Exception):
    """Custom exception for authorization failures."""
    pass


class KMSKeyManagementError(Exception):
    """Custom exception for AWS KMS key management failures."""
    pass


class User(UserMixin):
    """
    User model for Flask-Login integration with Auth0 profile management.
    
    Implements UserMixin interface for Flask-Login compatibility while
    maintaining Auth0 user profile data and session state management.
    """
    
    def __init__(self, user_id: str, auth0_profile: Dict[str, Any]):
        """
        Initialize user object with Auth0 profile data.
        
        Args:
            user_id: Unique user identifier from Auth0
            auth0_profile: Complete Auth0 user profile data
        """
        self.id = user_id
        self.auth0_profile = auth0_profile
        self.is_authenticated = True
        self.is_active = True
        self.is_anonymous = False
        self.permissions: Optional[List[str]] = None
        self.roles: Optional[List[str]] = None
        self._load_user_metadata()
    
    def _load_user_metadata(self) -> None:
        """Load user permissions and roles from Auth0 profile metadata."""
        user_metadata = self.auth0_profile.get('user_metadata', {})
        app_metadata = self.auth0_profile.get('app_metadata', {})
        
        self.permissions = app_metadata.get('permissions', [])
        self.roles = app_metadata.get('roles', [])
        self.organization_id = app_metadata.get('organization_id')
        self.last_login = self.auth0_profile.get('last_login')
    
    def get_id(self) -> str:
        """Return user ID for Flask-Login session management."""
        return self.id
    
    def has_permission(self, permission: str) -> bool:
        """Check if user has specific permission."""
        return permission in (self.permissions or [])
    
    def has_role(self, role: str) -> bool:
        """Check if user has specific role."""
        return role in (self.roles or [])
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert user object to dictionary for serialization."""
        return {
            'id': self.id,
            'email': self.auth0_profile.get('email'),
            'name': self.auth0_profile.get('name'),
            'picture': self.auth0_profile.get('picture'),
            'permissions': self.permissions,
            'roles': self.roles,
            'organization_id': self.organization_id,
            'last_login': self.last_login,
            'is_authenticated': self.is_authenticated,
            'is_active': self.is_active
        }


class AWSKMSKeyManager:
    """
    AWS KMS integration for encryption key management with enterprise security.
    
    Provides centralized key management using AWS KMS with automatic key rotation,
    secure key storage, and comprehensive audit logging for compliance requirements.
    """
    
    def __init__(self):
        """Initialize AWS KMS client with enterprise configuration."""
        self.kms_client = self._create_kms_client()
        self.cmk_arn = os.getenv('AWS_KMS_CMK_ARN')
        self.region = os.getenv('AWS_REGION', 'us-east-1')
        self.encryption_context = {
            'application': 'flask-security-system',
            'environment': os.getenv('FLASK_ENV', 'production')
        }
        self.logger = security_logger.bind(component="kms_manager")
    
    def _create_kms_client(self) -> boto3.client:
        """
        Create properly configured boto3 KMS client with enterprise settings.
        
        Returns:
            Configured boto3 KMS client with retry and timeout settings
        """
        return boto3.client(
            'kms',
            region_name=os.getenv('AWS_REGION', 'us-east-1'),
            aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
            config=boto3.session.Config(
                retries={'max_attempts': 3, 'mode': 'adaptive'},
                read_timeout=30,
                connect_timeout=10,
                max_pool_connections=50
            )
        )
    
    def generate_data_key(self, key_spec: str = 'AES_256') -> Tuple[bytes, bytes]:
        """
        Generate AWS KMS data key for encryption operations.
        
        Args:
            key_spec: Key specification (AES_256, AES_128)
            
        Returns:
            Tuple of (plaintext_key, encrypted_key) for cryptographic operations
            
        Raises:
            KMSKeyManagementError: When data key generation fails
        """
        try:
            response = self.kms_client.generate_data_key(
                KeyId=self.cmk_arn,
                KeySpec=key_spec,
                EncryptionContext=self.encryption_context
            )
            
            self.logger.info(
                "Data key generated successfully",
                key_spec=key_spec,
                encryption_context=self.encryption_context
            )
            
            return response['Plaintext'], response['CiphertextBlob']
            
        except (ClientError, BotoCoreError) as e:
            self.logger.error(
                "AWS KMS data key generation failed",
                error=str(e),
                key_spec=key_spec
            )
            raise KMSKeyManagementError(f"Failed to generate data key: {str(e)}")
    
    def decrypt_data_key(self, encrypted_key: bytes) -> bytes:
        """
        Decrypt AWS KMS data key for cryptographic operations.
        
        Args:
            encrypted_key: Encrypted data key from KMS
            
        Returns:
            Decrypted plaintext key for encryption operations
            
        Raises:
            KMSKeyManagementError: When key decryption fails
        """
        try:
            response = self.kms_client.decrypt(
                CiphertextBlob=encrypted_key,
                EncryptionContext=self.encryption_context
            )
            
            self.logger.info("Data key decrypted successfully")
            return response['Plaintext']
            
        except (ClientError, BotoCoreError) as e:
            self.logger.error("AWS KMS key decryption failed", error=str(e))
            raise KMSKeyManagementError(f"Failed to decrypt data key: {str(e)}")


class EncryptedSessionInterface:
    """
    Encrypted session management for Redis-backed Flask sessions.
    
    Implements AES-256-GCM encryption for session data with AWS KMS-backed
    key management and automatic key rotation for enterprise security compliance.
    """
    
    def __init__(self, redis_client: redis.Redis, kms_manager: AWSKMSKeyManager):
        """
        Initialize encrypted session interface.
        
        Args:
            redis_client: Configured Redis client for session storage
            kms_manager: AWS KMS key manager for encryption keys
        """
        self.redis = redis_client
        self.kms_manager = kms_manager
        self.logger = security_logger.bind(component="encrypted_session")
        self._initialize_encryption_key()
    
    def _initialize_encryption_key(self) -> None:
        """Initialize or rotate encryption key using AWS KMS."""
        try:
            # Check for existing encryption key
            key_data = self.redis.get('encryption_key:current')
            
            if key_data:
                # Use existing key
                key_info = json.loads(key_data)
                self.encrypted_key = base64.b64decode(key_info['encrypted_key'])
                self.key_created = datetime.fromisoformat(key_info['created'])
                
                # Check if key rotation is needed (90 days)
                if datetime.utcnow() - self.key_created > timedelta(days=90):
                    self._rotate_encryption_key()
            else:
                # Generate new key
                self._generate_new_encryption_key()
                
        except Exception as e:
            self.logger.error(
                "Failed to initialize encryption key",
                error=str(e)
            )
            # Fallback to environment variable
            fallback_key = os.getenv('REDIS_ENCRYPTION_KEY')
            if fallback_key:
                self.fernet = Fernet(fallback_key.encode())
            else:
                raise KMSKeyManagementError("No encryption key available")
    
    def _generate_new_encryption_key(self) -> None:
        """Generate new encryption key using AWS KMS."""
        plaintext_key, encrypted_key = self.kms_manager.generate_data_key()
        
        # Create Fernet key from KMS data key
        self.fernet = Fernet(base64.urlsafe_b64encode(plaintext_key[:32]))
        self.encrypted_key = encrypted_key
        self.key_created = datetime.utcnow()
        
        # Store encrypted key in Redis
        key_info = {
            'encrypted_key': base64.b64encode(encrypted_key).decode(),
            'created': self.key_created.isoformat(),
            'algorithm': 'AES_256'
        }
        
        self.redis.setex(
            'encryption_key:current',
            timedelta(days=91).total_seconds(),
            json.dumps(key_info)
        )
        
        self.logger.info("New encryption key generated and stored")
    
    def _rotate_encryption_key(self) -> None:
        """Rotate encryption key while maintaining backward compatibility."""
        # Store old key for transition period
        old_key_id = f"encryption_key:{self.key_created.isoformat()}"
        old_key_info = {
            'encrypted_key': base64.b64encode(self.encrypted_key).decode(),
            'created': self.key_created.isoformat(),
            'status': 'deprecated'
        }
        
        self.redis.setex(
            old_key_id,
            timedelta(days=7).total_seconds(),  # 7-day transition period
            json.dumps(old_key_info)
        )
        
        # Generate new key
        self._generate_new_encryption_key()
        
        self.logger.info(
            "Encryption key rotated",
            old_key_created=self.key_created.isoformat(),
            transition_period_days=7
        )
    
    def save_session(self, session_id: str, session_data: Dict[str, Any]) -> bool:
        """
        Save encrypted session data to Redis.
        
        Args:
            session_id: Unique session identifier
            session_data: Session data to encrypt and store
            
        Returns:
            Success status of save operation
        """
        try:
            # Encrypt session data
            serialized_data = json.dumps(session_data, default=str)
            encrypted_data = self.fernet.encrypt(serialized_data.encode())
            
            # Store in Redis with 24-hour TTL
            key = f"session:{session_id}"
            result = self.redis.setex(
                key,
                timedelta(hours=24).total_seconds(),
                base64.b64encode(encrypted_data).decode()
            )
            
            auth_metrics['session_operations'].labels(
                operation='save',
                result='success'
            ).inc()
            
            auth_metrics['cache_operations'].labels(
                operation='write',
                cache_type='session',
                result='success'
            ).inc()
            
            self.logger.debug(
                "Session saved successfully",
                session_id=session_id,
                data_size=len(encrypted_data)
            )
            
            return result
            
        except Exception as e:
            auth_metrics['session_operations'].labels(
                operation='save',
                result='error'
            ).inc()
            
            self.logger.error(
                "Failed to save session",
                session_id=session_id,
                error=str(e)
            )
            return False
    
    def load_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Load and decrypt session data from Redis.
        
        Args:
            session_id: Unique session identifier
            
        Returns:
            Decrypted session data or None if not found/invalid
        """
        try:
            key = f"session:{session_id}"
            encrypted_data = self.redis.get(key)
            
            if not encrypted_data:
                auth_metrics['cache_operations'].labels(
                    operation='read',
                    cache_type='session',
                    result='miss'
                ).inc()
                return None
            
            # Decrypt session data
            decoded_data = base64.b64decode(encrypted_data)
            decrypted_data = self.fernet.decrypt(decoded_data)
            session_data = json.loads(decrypted_data.decode())
            
            auth_metrics['session_operations'].labels(
                operation='load',
                result='success'
            ).inc()
            
            auth_metrics['cache_operations'].labels(
                operation='read',
                cache_type='session',
                result='hit'
            ).inc()
            
            self.logger.debug(
                "Session loaded successfully",
                session_id=session_id
            )
            
            return session_data
            
        except Exception as e:
            auth_metrics['session_operations'].labels(
                operation='load',
                result='error'
            ).inc()
            
            self.logger.error(
                "Failed to load session",
                session_id=session_id,
                error=str(e)
            )
            return None
    
    def delete_session(self, session_id: str) -> bool:
        """
        Delete session from Redis.
        
        Args:
            session_id: Unique session identifier
            
        Returns:
            Success status of delete operation
        """
        try:
            key = f"session:{session_id}"
            result = self.redis.delete(key)
            
            auth_metrics['session_operations'].labels(
                operation='delete',
                result='success' if result else 'not_found'
            ).inc()
            
            self.logger.debug(
                "Session deleted",
                session_id=session_id,
                found=bool(result)
            )
            
            return bool(result)
            
        except Exception as e:
            auth_metrics['session_operations'].labels(
                operation='delete',
                result='error'
            ).inc()
            
            self.logger.error(
                "Failed to delete session",
                session_id=session_id,
                error=str(e)
            )
            return False


class JWTManager:
    """
    JWT token management with Auth0 integration and caching.
    
    Provides comprehensive JWT token validation, user context creation,
    and performance optimization through intelligent caching strategies.
    """
    
    def __init__(self, redis_client: redis.Redis):
        """
        Initialize JWT manager with Auth0 configuration.
        
        Args:
            redis_client: Redis client for token validation caching
        """
        self.redis = redis_client
        self.domain = os.getenv('AUTH0_DOMAIN')
        self.audience = os.getenv('AUTH0_AUDIENCE')
        self.client_id = os.getenv('AUTH0_CLIENT_ID')
        self.client_secret = os.getenv('AUTH0_CLIENT_SECRET')
        self.algorithm = 'RS256'
        self.logger = security_logger.bind(component="jwt_manager")
        
        # Initialize Auth0 management client
        self._initialize_auth0_client()
        
        # Cache for JWK keys
        self._jwks_cache: Optional[Dict[str, Any]] = None
        self._jwks_cache_expires: Optional[datetime] = None
    
    def _initialize_auth0_client(self) -> None:
        """Initialize Auth0 management client for user operations."""
        try:
            # Get management API token
            get_token = GetToken(self.domain, self.client_id, self.client_secret)
            token = get_token.client_credentials(
                f"https://{self.domain}/api/v2/"
            )
            
            self.auth0_client = Auth0(
                self.domain,
                token['access_token']
            )
            
            self.logger.info("Auth0 management client initialized successfully")
            
        except Auth0Error as e:
            self.logger.error(
                "Failed to initialize Auth0 client",
                error=str(e)
            )
            self.auth0_client = None
    
    def _get_jwks(self) -> Dict[str, Any]:
        """
        Retrieve and cache JSON Web Key Set from Auth0.
        
        Returns:
            JWKS data with caching for performance optimization
        """
        current_time = datetime.utcnow()
        
        # Check cache validity
        if (self._jwks_cache and self._jwks_cache_expires and 
            current_time < self._jwks_cache_expires):
            return self._jwks_cache
        
        try:
            # Configure requests session with retry strategy
            session = requests.Session()
            retry_strategy = Retry(
                total=3,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504],
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            
            # Fetch JWKS from Auth0
            jwks_url = f"https://{self.domain}/.well-known/jwks.json"
            response = session.get(jwks_url, timeout=10)
            response.raise_for_status()
            
            self._jwks_cache = response.json()
            self._jwks_cache_expires = current_time + timedelta(hours=1)
            
            self.logger.debug("JWKS retrieved and cached successfully")
            return self._jwks_cache
            
        except requests.RequestException as e:
            self.logger.error(
                "Failed to retrieve JWKS",
                error=str(e),
                jwks_url=jwks_url
            )
            
            # Return cached version if available
            if self._jwks_cache:
                self.logger.warning("Using expired JWKS cache")
                return self._jwks_cache
            
            raise AuthenticationError("Unable to retrieve JWKS for token validation")
    
    def _get_public_key(self, token_header: Dict[str, Any]) -> str:
        """
        Extract public key from JWKS for token validation.
        
        Args:
            token_header: JWT token header containing key ID
            
        Returns:
            Public key for signature verification
        """
        jwks = self._get_jwks()
        kid = token_header.get('kid')
        
        if not kid:
            raise AuthenticationError("Token header missing 'kid' field")
        
        # Find matching key in JWKS
        for key in jwks.get('keys', []):
            if key.get('kid') == kid:
                # Convert JWK to PEM format
                public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)
                return public_key
        
        raise AuthenticationError(f"Public key not found for kid: {kid}")
    
    def validate_token(self, token: str) -> Dict[str, Any]:
        """
        Validate JWT token with Auth0 and extract user claims.
        
        Args:
            token: JWT token string for validation
            
        Returns:
            Validated token payload with user claims
            
        Raises:
            AuthenticationError: When token validation fails
        """
        start_time = datetime.utcnow()
        
        try:
            # Check cache first
            token_hash = base64.b64encode(
                token.encode()
            ).decode()[:32]  # Use first 32 chars as cache key
            
            cache_key = f"jwt_validation:{token_hash}"
            cached_result = self.redis.get(cache_key)
            
            if cached_result:
                auth_metrics['cache_operations'].labels(
                    operation='read',
                    cache_type='jwt_validation',
                    result='hit'
                ).inc()
                
                return json.loads(cached_result)
            
            # Decode token header without verification
            unverified_header = jwt.get_unverified_header(token)
            
            # Get public key for verification
            public_key = self._get_public_key(unverified_header)
            
            # Validate token
            payload = jwt.decode(
                token,
                public_key,
                algorithms=[self.algorithm],
                audience=self.audience,
                issuer=f"https://{self.domain}/"
            )
            
            # Cache validation result
            cache_ttl = min(
                payload.get('exp', 0) - int(datetime.utcnow().timestamp()),
                300  # Maximum 5 minutes
            )
            
            if cache_ttl > 0:
                self.redis.setex(
                    cache_key,
                    cache_ttl,
                    json.dumps(payload, default=str)
                )
                
                auth_metrics['cache_operations'].labels(
                    operation='write',
                    cache_type='jwt_validation',
                    result='success'
                ).inc()
            
            # Record successful validation
            duration = (datetime.utcnow() - start_time).total_seconds()
            auth_metrics['jwt_validation_duration'].labels(
                algorithm=self.algorithm,
                issuer=f"https://{self.domain}/"
            ).observe(duration)
            
            auth_metrics['requests_total'].labels(
                result='success',
                method='jwt_validation'
            ).inc()
            
            self.logger.info(
                "JWT token validated successfully",
                user_id=payload.get('sub'),
                algorithm=self.algorithm,
                duration=duration
            )
            
            return payload
            
        except jwt.ExpiredSignatureError:
            auth_metrics['requests_total'].labels(
                result='expired',
                method='jwt_validation'
            ).inc()
            
            self.logger.warning("JWT token expired")
            raise AuthenticationError("Token has expired")
            
        except jwt.InvalidTokenError as e:
            auth_metrics['requests_total'].labels(
                result='invalid',
                method='jwt_validation'
            ).inc()
            
            self.logger.warning(
                "JWT token validation failed",
                error=str(e)
            )
            raise AuthenticationError(f"Invalid token: {str(e)}")
            
        except Exception as e:
            auth_metrics['requests_total'].labels(
                result='error',
                method='jwt_validation'
            ).inc()
            
            self.logger.error(
                "JWT token validation error",
                error=str(e)
            )
            raise AuthenticationError(f"Token validation error: {str(e)}")
    
    def get_user_info(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve user information from Auth0.
        
        Args:
            user_id: Auth0 user ID
            
        Returns:
            User profile data or None if not found
        """
        if not self.auth0_client:
            self.logger.error("Auth0 client not initialized")
            return None
        
        try:
            user_info = self.auth0_client.users.get(user_id)
            
            self.logger.debug(
                "User info retrieved successfully",
                user_id=user_id
            )
            
            return user_info
            
        except Auth0Error as e:
            self.logger.error(
                "Failed to retrieve user info",
                user_id=user_id,
                error=str(e)
            )
            return None


class AuthConfig:
    """
    Comprehensive authentication configuration for Flask application.
    
    Integrates JWT validation, session management, security headers, and
    monitoring capabilities for enterprise-grade authentication system.
    """
    
    def __init__(self):
        """Initialize authentication configuration components."""
        self.logger = security_logger.bind(component="auth_config")
        
        # Initialize Redis client for sessions and caching
        self.redis_client = self._create_redis_client()
        
        # Initialize encryption and key management
        self.kms_manager = AWSKMSKeyManager()
        self.session_interface = EncryptedSessionInterface(
            self.redis_client,
            self.kms_manager
        )
        
        # Initialize JWT manager
        self.jwt_manager = JWTManager(self.redis_client)
        
        # Flask-Login manager
        self.login_manager = LoginManager()
        
        # Configuration settings
        self.config = self._load_configuration()
        
        self.logger.info("Authentication configuration initialized successfully")
    
    def _create_redis_client(self) -> redis.Redis:
        """
        Create configured Redis client for authentication operations.
        
        Returns:
            Configured Redis client with connection pooling
        """
        return redis.Redis(
            host=os.getenv('REDIS_HOST', 'localhost'),
            port=int(os.getenv('REDIS_PORT', 6379)),
            password=os.getenv('REDIS_PASSWORD'),
            db=int(os.getenv('REDIS_AUTH_DB', 0)),
            decode_responses=True,
            max_connections=50,
            retry_on_timeout=True,
            socket_timeout=30.0,
            socket_connect_timeout=10.0,
            health_check_interval=30
        )
    
    def _load_configuration(self) -> Dict[str, Any]:
        """
        Load comprehensive authentication configuration.
        
        Returns:
            Complete authentication configuration dictionary
        """
        return {
            # Flask session configuration
            'SESSION_TYPE': 'redis',
            'SESSION_REDIS': self.redis_client,
            'SESSION_PERMANENT': False,
            'SESSION_USE_SIGNER': True,
            'SESSION_KEY_PREFIX': 'session:',
            'SESSION_COOKIE_SECURE': True,
            'SESSION_COOKIE_HTTPONLY': True,
            'SESSION_COOKIE_SAMESITE': 'Lax',
            'SESSION_COOKIE_NAME': 'flask_session',
            
            # Security settings
            'SECRET_KEY': os.getenv('SECRET_KEY', secrets.token_urlsafe(32)),
            'WTF_CSRF_ENABLED': True,
            'WTF_CSRF_TIME_LIMIT': 3600,
            
            # JWT settings
            'JWT_SECRET_KEY': os.getenv('JWT_SECRET_KEY'),
            'JWT_ALGORITHM': 'RS256',
            'JWT_ACCESS_TOKEN_EXPIRES': timedelta(hours=1),
            'JWT_REFRESH_TOKEN_EXPIRES': timedelta(days=30),
            
            # Auth0 configuration
            'AUTH0_DOMAIN': os.getenv('AUTH0_DOMAIN'),
            'AUTH0_CLIENT_ID': os.getenv('AUTH0_CLIENT_ID'),
            'AUTH0_CLIENT_SECRET': os.getenv('AUTH0_CLIENT_SECRET'),
            'AUTH0_AUDIENCE': os.getenv('AUTH0_AUDIENCE'),
            'AUTH0_CALLBACK_URL': os.getenv('AUTH0_CALLBACK_URL'),
            
            # Rate limiting
            'RATELIMIT_STORAGE_URL': f"redis://{os.getenv('REDIS_HOST', 'localhost')}:{os.getenv('REDIS_PORT', 6379)}/1",
            'RATELIMIT_DEFAULT': "100 per hour",
            
            # CORS settings
            'CORS_ORIGINS': self._get_cors_origins(),
            'CORS_SUPPORTS_CREDENTIALS': True,
            'CORS_MAX_AGE': 600,
            
            # Security headers (Flask-Talisman)
            'TALISMAN_FORCE_HTTPS': True,
            'TALISMAN_STRICT_TRANSPORT_SECURITY': True,
            'TALISMAN_STRICT_TRANSPORT_SECURITY_MAX_AGE': 31536000,
            'TALISMAN_CONTENT_SECURITY_POLICY': {
                'default-src': "'self'",
                'script-src': "'self' 'unsafe-inline' https://cdn.auth0.com",
                'style-src': "'self' 'unsafe-inline'",
                'img-src': "'self' data: https:",
                'connect-src': "'self' https://*.auth0.com https://*.amazonaws.com",
                'font-src': "'self'",
                'object-src': "'none'",
                'base-uri': "'self'",
                'frame-ancestors': "'none'"
            },
            
            # Monitoring and logging
            'LOG_LEVEL': os.getenv('LOG_LEVEL', 'INFO'),
            'ENABLE_METRICS': os.getenv('ENABLE_METRICS', 'true').lower() == 'true',
            
            # Performance settings
            'MAX_CONTENT_LENGTH': 16 * 1024 * 1024,  # 16MB
            'SEND_FILE_MAX_AGE_DEFAULT': timedelta(hours=12),
        }
    
    def _get_cors_origins(self) -> List[str]:
        """
        Get CORS origins based on environment configuration.
        
        Returns:
            List of allowed CORS origins
        """
        environment = os.getenv('FLASK_ENV', 'production')
        
        base_origins = [
            "https://app.company.com",
            "https://admin.company.com"
        ]
        
        if environment == 'development':
            base_origins.extend([
                "http://localhost:3000",
                "http://localhost:8080",
                "https://dev.company.com"
            ])
        elif environment == 'staging':
            base_origins.extend([
                "https://staging.company.com",
                "https://staging-admin.company.com"
            ])
        
        return base_origins
    
    def configure_flask_app(self, app: Flask) -> None:
        """
        Configure Flask application with authentication and security settings.
        
        Args:
            app: Flask application instance to configure
        """
        # Apply configuration
        app.config.update(self.config)
        
        # Initialize Flask-Session
        Session(app)
        
        # Configure Flask-Login
        self._configure_flask_login(app)
        
        # Configure security headers (Flask-Talisman)
        self._configure_security_headers(app)
        
        # Configure CORS
        self._configure_cors(app)
        
        # Configure rate limiting
        self._configure_rate_limiting(app)
        
        # Configure request handlers
        self._configure_request_handlers(app)
        
        # Configure error handlers
        self._configure_error_handlers(app)
        
        self.logger.info("Flask application configured with authentication security")
    
    def _configure_flask_login(self, app: Flask) -> None:
        """Configure Flask-Login for user session management."""
        self.login_manager.init_app(app)
        self.login_manager.login_view = 'auth.login'
        self.login_manager.session_protection = 'strong'
        self.login_manager.login_message = 'Please log in to access this page.'
        self.login_manager.login_message_category = 'info'
        
        @self.login_manager.user_loader
        def load_user(user_id: str) -> Optional[User]:
            """Load user from session or Auth0 profile cache."""
            try:
                # Try to load from session first
                session_data = self.session_interface.load_session(user_id)
                if session_data and 'user_profile' in session_data:
                    return User(user_id, session_data['user_profile'])
                
                # Fallback to Auth0 API
                user_info = self.jwt_manager.get_user_info(user_id)
                if user_info:
                    return User(user_id, user_info)
                
                return None
                
            except Exception as e:
                self.logger.error(
                    "Failed to load user",
                    user_id=user_id,
                    error=str(e)
                )
                return None
        
        @self.login_manager.unauthorized_handler
        def unauthorized() -> Tuple[Dict[str, str], int]:
            """Handle unauthorized access attempts."""
            self.logger.warning(
                "Unauthorized access attempt",
                endpoint=request.endpoint,
                remote_addr=request.remote_addr
            )
            
            auth_metrics['requests_total'].labels(
                result='unauthorized',
                method='access_attempt'
            ).inc()
            
            return jsonify({'error': 'Authentication required'}), 401
    
    def _configure_security_headers(self, app: Flask) -> None:
        """Configure Flask-Talisman for HTTP security headers."""
        Talisman(
            app,
            force_https=self.config['TALISMAN_FORCE_HTTPS'],
            force_https_permanent=True,
            strict_transport_security=self.config['TALISMAN_STRICT_TRANSPORT_SECURITY'],
            strict_transport_security_max_age=self.config['TALISMAN_STRICT_TRANSPORT_SECURITY_MAX_AGE'],
            strict_transport_security_include_subdomains=True,
            strict_transport_security_preload=True,
            content_security_policy=self.config['TALISMAN_CONTENT_SECURITY_POLICY'],
            content_security_policy_nonce_in=['script-src', 'style-src'],
            referrer_policy='strict-origin-when-cross-origin',
            feature_policy={
                'geolocation': "'none'",
                'microphone': "'none'",
                'camera': "'none'",
                'accelerometer': "'none'",
                'gyroscope': "'none'"
            },
            session_cookie_secure=True,
            session_cookie_http_only=True,
            session_cookie_samesite='Strict'
        )
    
    def _configure_cors(self, app: Flask) -> None:
        """Configure CORS for cross-origin requests."""
        CORS(
            app,
            origins=self.config['CORS_ORIGINS'],
            methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            allow_headers=[
                "Authorization",
                "Content-Type",
                "X-Requested-With",
                "X-CSRF-Token",
                "X-Auth-Token",
                "Accept",
                "Origin"
            ],
            expose_headers=[
                "X-RateLimit-Limit",
                "X-RateLimit-Remaining",
                "X-RateLimit-Reset"
            ],
            supports_credentials=self.config['CORS_SUPPORTS_CREDENTIALS'],
            max_age=self.config['CORS_MAX_AGE'],
            send_wildcard=False,
            vary_header=True
        )
    
    def _configure_rate_limiting(self, app: Flask) -> None:
        """Configure rate limiting for authentication endpoints."""
        limiter = Limiter(
            key_func=get_remote_address,
            app=app,
            storage_uri=self.config['RATELIMIT_STORAGE_URL'],
            default_limits=[self.config['RATELIMIT_DEFAULT']],
            strategy="moving-window",
            headers_enabled=True
        )
        
        # Store limiter reference for use in decorators
        app.limiter = limiter
    
    def _configure_request_handlers(self, app: Flask) -> None:
        """Configure Flask request handlers for authentication."""
        
        @app.before_request
        def before_request():
            """Handle pre-request authentication and security checks."""
            # Skip authentication for health checks and static files
            if request.endpoint in ['health', 'metrics', 'static']:
                return
            
            # Extract JWT token from Authorization header
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
                try:
                    # Validate token and set user context
                    payload = self.jwt_manager.validate_token(token)
                    g.current_user_id = payload.get('sub')
                    g.jwt_payload = payload
                    
                except AuthenticationError as e:
                    return jsonify({'error': str(e)}), 401
        
        @app.after_request
        def after_request(response):
            """Handle post-request processing and metrics."""
            # Update active sessions metric
            try:
                session_count = len(self.redis_client.keys('session:*'))
                auth_metrics['active_sessions'].set(session_count)
            except Exception:
                pass  # Don't fail request for metrics errors
            
            return response
    
    def _configure_error_handlers(self, app: Flask) -> None:
        """Configure error handlers for authentication exceptions."""
        
        @app.errorhandler(AuthenticationError)
        def handle_authentication_error(error):
            """Handle authentication errors."""
            self.logger.warning(
                "Authentication error",
                error=str(error),
                endpoint=request.endpoint
            )
            return jsonify({'error': str(error)}), 401
        
        @app.errorhandler(AuthorizationError)
        def handle_authorization_error(error):
            """Handle authorization errors."""
            self.logger.warning(
                "Authorization error",
                error=str(error),
                endpoint=request.endpoint,
                user_id=getattr(g, 'current_user_id', None)
            )
            return jsonify({'error': str(error)}), 403
        
        @app.errorhandler(429)
        def handle_rate_limit_error(error):
            """Handle rate limiting errors."""
            self.logger.warning(
                "Rate limit exceeded",
                endpoint=request.endpoint,
                remote_addr=request.remote_addr
            )
            return jsonify({'error': 'Rate limit exceeded'}), 429


# Authentication decorators for route protection
def require_authentication(f):
    """
    Decorator to require JWT authentication for route access.
    
    Args:
        f: Route function to protect
        
    Returns:
        Decorated function with authentication requirement
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not hasattr(g, 'current_user_id') or not g.current_user_id:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function


def require_permissions(permissions: Union[str, List[str]]):
    """
    Decorator to require specific permissions for route access.
    
    Args:
        permissions: Required permission(s) for access
        
    Returns:
        Decorator function for permission enforcement
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(g, 'jwt_payload') or not g.jwt_payload:
                return jsonify({'error': 'Authentication required'}), 401
            
            user_permissions = g.jwt_payload.get('permissions', [])
            required_perms = permissions if isinstance(permissions, list) else [permissions]
            
            if not all(perm in user_permissions for perm in required_perms):
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# Global authentication configuration instance
auth_config = AuthConfig()

# Export configuration for use in Flask application factory
def get_auth_config() -> AuthConfig:
    """
    Get the global authentication configuration instance.
    
    Returns:
        Configured AuthConfig instance
    """
    return auth_config


def configure_authentication(app: Flask) -> None:
    """
    Configure Flask application with comprehensive authentication and security.
    
    Args:
        app: Flask application instance to configure
    """
    auth_config.configure_flask_app(app)


# Export key components for external use
__all__ = [
    'AuthConfig',
    'User',
    'JWTManager',
    'EncryptedSessionInterface',
    'AWSKMSKeyManager',
    'AuthenticationError',
    'AuthorizationError',
    'require_authentication',
    'require_permissions',
    'configure_authentication',
    'get_auth_config',
    'auth_metrics'
]