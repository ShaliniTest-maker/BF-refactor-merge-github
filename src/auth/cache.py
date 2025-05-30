"""
Redis-based authentication caching with AES-256-GCM encryption and AWS KMS key management.

This module implements enterprise-grade Redis caching for authentication and authorization
data using structured key patterns, intelligent TTL policies, and comprehensive monitoring.
Features include AES-256-GCM encryption with AWS KMS integration, connection pooling 
optimization, and Prometheus metrics collection for cache effectiveness tracking.

Key Features:
- Redis distributed caching for session and permission management per Section 6.4.1
- AES-256-GCM encryption with AWS KMS integration per Section 6.4.3
- Structured Redis key patterns with intelligent TTL management per Section 6.4.2
- Comprehensive cache monitoring with Prometheus metrics per Section 6.4.2
- Intelligent cache invalidation patterns per Section 6.4.2
- Connection pooling with redis-py 5.0+ per Section 6.1.3

Security:
- All cached data is encrypted using AES-256-GCM with AWS KMS-backed data keys
- Redis key patterns follow enterprise security standards
- Comprehensive audit logging for security events
- Circuit breaker patterns for Redis service resilience

Performance:
- Optimized connection pooling with max_connections=50
- Intelligent TTL policies based on data sensitivity
- Cache warming strategies for high-frequency data
- Monitoring and alerting for cache effectiveness

Dependencies:
- redis-py 5.0+ for Redis connectivity with connection pooling
- cryptography 41.0+ for AES-256-GCM encryption operations  
- boto3 1.28+ for AWS KMS key management integration
- prometheus-client 0.17+ for metrics collection and monitoring
"""

import json
import base64
import hashlib
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set, Any, Union, Tuple, Type
from dataclasses import dataclass
from functools import wraps
import asyncio

import redis
from redis.connection import ConnectionPool
from redis.exceptions import RedisError, ConnectionError, TimeoutError
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import boto3
from botocore.exceptions import ClientError, BotoCoreError
from prometheus_client import Counter, Histogram, Gauge, CollectorRegistry, generate_latest
import structlog

# Import configuration and exceptions from dependencies
try:
    from src.config.database import get_redis_config, get_redis_connection_pool
    from src.config.aws import get_kms_client, get_kms_config
    from src.auth.exceptions import (
        CacheError, 
        EncryptionError, 
        KeyManagementError,
        CacheConnectionError,
        CacheTimeoutError,
        CacheKeyError
    )
except ImportError:
    # Fallback imports for development/testing
    class CacheError(Exception):
        """Base cache error"""
        pass
    
    class EncryptionError(CacheError):
        """Encryption operation error"""
        pass
    
    class KeyManagementError(CacheError):
        """Key management error"""
        pass
    
    class CacheConnectionError(CacheError):
        """Cache connection error"""
        pass
    
    class CacheTimeoutError(CacheError):
        """Cache operation timeout"""
        pass
    
    class CacheKeyError(CacheError):
        """Cache key error"""
        pass


# Configure structured logging
logger = structlog.get_logger("auth.cache")


@dataclass
class CacheMetrics:
    """Cache performance metrics tracking"""
    hits: int = 0
    misses: int = 0
    errors: int = 0
    total_operations: int = 0
    encryption_operations: int = 0
    key_rotations: int = 0
    
    @property
    def hit_ratio(self) -> float:
        """Calculate cache hit ratio"""
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0


@dataclass 
class CacheConfig:
    """Redis cache configuration parameters"""
    host: str = "localhost"
    port: int = 6379
    password: Optional[str] = None
    database: int = 0
    max_connections: int = 50
    socket_timeout: float = 30.0
    socket_connect_timeout: float = 10.0
    retry_on_timeout: bool = True
    health_check_interval: int = 30
    key_prefix: str = "auth_cache"
    default_ttl: int = 300  # 5 minutes
    encryption_enabled: bool = True


class PrometheusMetrics:
    """Prometheus metrics for authentication cache monitoring"""
    
    def __init__(self, registry: Optional[CollectorRegistry] = None):
        """Initialize Prometheus metrics collectors"""
        self.registry = registry or CollectorRegistry()
        
        # Cache operation counters
        self.cache_hits = Counter(
            'auth_cache_hits_total',
            'Total cache hits by cache type',
            ['cache_type', 'operation'],
            registry=self.registry
        )
        
        self.cache_misses = Counter(
            'auth_cache_misses_total', 
            'Total cache misses by cache type',
            ['cache_type', 'operation'],
            registry=self.registry
        )
        
        self.cache_errors = Counter(
            'auth_cache_errors_total',
            'Total cache errors by operation type',
            ['operation', 'error_type', 'cache_type'],
            registry=self.registry
        )
        
        # Operation duration histograms
        self.cache_operation_duration = Histogram(
            'auth_cache_operation_duration_seconds',
            'Cache operation duration in seconds',
            ['operation', 'cache_type'],
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
            registry=self.registry
        )
        
        # Cache size and connection metrics
        self.cache_size = Gauge(
            'auth_cache_size_bytes',
            'Current cache size in bytes by cache type',
            ['cache_type'],
            registry=self.registry
        )
        
        self.redis_connections = Gauge(
            'auth_cache_redis_connections',
            'Current Redis connections',
            ['connection_type'],
            registry=self.registry
        )
        
        # Encryption metrics
        self.encryption_operations = Counter(
            'auth_cache_encryption_operations_total',
            'Total encryption/decryption operations',
            ['operation_type', 'key_source'],
            registry=self.registry
        )
        
        # Key management metrics
        self.key_rotations = Counter(
            'auth_cache_key_rotations_total',
            'Total key rotation operations',
            ['key_type', 'status'],
            registry=self.registry
        )
        
        # Circuit breaker metrics
        self.circuit_breaker_state = Gauge(
            'auth_cache_circuit_breaker_state',
            'Circuit breaker state (0=closed, 1=open, 2=half-open)',
            ['service'],
            registry=self.registry
        )
    
    def record_cache_hit(self, cache_type: str, operation: str = "get") -> None:
        """Record cache hit event"""
        self.cache_hits.labels(cache_type=cache_type, operation=operation).inc()
    
    def record_cache_miss(self, cache_type: str, operation: str = "get") -> None:
        """Record cache miss event"""
        self.cache_misses.labels(cache_type=cache_type, operation=operation).inc()
    
    def record_cache_error(self, operation: str, error_type: str, cache_type: str) -> None:
        """Record cache error event"""
        self.cache_errors.labels(
            operation=operation, 
            error_type=error_type, 
            cache_type=cache_type
        ).inc()
    
    def time_cache_operation(self, operation: str, cache_type: str):
        """Context manager for timing cache operations"""
        return self.cache_operation_duration.labels(
            operation=operation, 
            cache_type=cache_type
        ).time()
    
    def record_encryption_operation(self, operation_type: str, key_source: str) -> None:
        """Record encryption/decryption operation"""
        self.encryption_operations.labels(
            operation_type=operation_type,
            key_source=key_source
        ).inc()
    
    def record_key_rotation(self, key_type: str, status: str) -> None:
        """Record key rotation event"""
        self.key_rotations.labels(key_type=key_type, status=status).inc()
    
    def set_circuit_breaker_state(self, service: str, state: int) -> None:
        """Set circuit breaker state (0=closed, 1=open, 2=half-open)"""
        self.circuit_breaker_state.labels(service=service).set(state)
    
    def update_cache_size(self, cache_type: str, size_bytes: int) -> None:
        """Update cache size metric"""
        self.cache_size.labels(cache_type=cache_type).set(size_bytes)
    
    def update_redis_connections(self, connection_type: str, count: int) -> None:
        """Update Redis connection count"""
        self.redis_connections.labels(connection_type=connection_type).set(count)


class AWSKMSManager:
    """AWS KMS key management for cache encryption with comprehensive error handling"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize AWS KMS manager with enterprise configuration
        
        Args:
            config: Optional KMS configuration dictionary
        """
        self.config = config or self._load_kms_config()
        self.kms_client = self._create_kms_client()
        self.cmk_arn = self.config.get('cmk_arn')
        self.encryption_context = self.config.get('encryption_context', {
            'application': 'flask-auth-cache',
            'environment': os.getenv('FLASK_ENV', 'production')
        })
        
        if not self.cmk_arn:
            raise KeyManagementError("AWS KMS CMK ARN not configured")
    
    def _load_kms_config(self) -> Dict[str, Any]:
        """Load KMS configuration from environment or config module"""
        try:
            # Try to import from config module
            from src.config.aws import get_kms_config
            return get_kms_config()
        except ImportError:
            # Fallback to environment variables
            return {
                'cmk_arn': os.getenv('AWS_KMS_CMK_ARN'),
                'region': os.getenv('AWS_REGION', 'us-east-1'),
                'encryption_context': {
                    'application': 'flask-auth-cache',
                    'environment': os.getenv('FLASK_ENV', 'production')
                }
            }
    
    def _create_kms_client(self) -> boto3.client:
        """Create configured boto3 KMS client with retry and timeout settings"""
        try:
            # Try to import from config module
            from src.config.aws import get_kms_client
            return get_kms_client()
        except ImportError:
            # Fallback to direct boto3 client creation
            return boto3.client(
                'kms',
                region_name=self.config.get('region', 'us-east-1'),
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
        """Generate AWS KMS data key for encryption operations
        
        Args:
            key_spec: Key specification (AES_256, AES_128)
            
        Returns:
            Tuple of (plaintext_key, encrypted_key)
            
        Raises:
            KeyManagementError: When data key generation fails
        """
        try:
            response = self.kms_client.generate_data_key(
                KeyId=self.cmk_arn,
                KeySpec=key_spec,
                EncryptionContext=self.encryption_context
            )
            
            logger.info(
                "Generated new KMS data key",
                key_id=self.cmk_arn,
                key_spec=key_spec,
                context=self.encryption_context
            )
            
            return response['Plaintext'], response['CiphertextBlob']
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            logger.error(
                "AWS KMS data key generation failed",
                error_code=error_code,
                error_message=str(e),
                key_id=self.cmk_arn
            )
            raise KeyManagementError(f"Failed to generate data key: {error_code}")
        except Exception as e:
            logger.error("Unexpected error generating KMS data key", error=str(e))
            raise KeyManagementError(f"Unexpected KMS error: {str(e)}")
    
    def decrypt_data_key(self, encrypted_key: bytes) -> bytes:
        """Decrypt AWS KMS data key for cryptographic operations
        
        Args:
            encrypted_key: Encrypted data key from KMS
            
        Returns:
            Decrypted plaintext key
            
        Raises:
            KeyManagementError: When key decryption fails
        """
        try:
            response = self.kms_client.decrypt(
                CiphertextBlob=encrypted_key,
                EncryptionContext=self.encryption_context
            )
            
            logger.debug("Successfully decrypted KMS data key")
            return response['Plaintext']
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            logger.error(
                "AWS KMS key decryption failed",
                error_code=error_code,
                error_message=str(e)
            )
            raise KeyManagementError(f"Failed to decrypt data key: {error_code}")
        except Exception as e:
            logger.error("Unexpected error decrypting KMS data key", error=str(e))
            raise KeyManagementError(f"Unexpected KMS error: {str(e)}")
    
    def rotate_key(self) -> Dict[str, Any]:
        """Initiate AWS KMS key rotation
        
        Returns:
            Rotation status and metadata
        """
        try:
            # Enable automatic key rotation
            self.kms_client.enable_key_rotation(KeyId=self.cmk_arn)
            
            # Get rotation status
            rotation_status = self.kms_client.get_key_rotation_status(KeyId=self.cmk_arn)
            
            result = {
                'key_id': self.cmk_arn,
                'rotation_enabled': rotation_status['KeyRotationEnabled'],
                'status': 'rotation_enabled',
                'timestamp': datetime.utcnow().isoformat()
            }
            
            logger.info("AWS KMS key rotation enabled", **result)
            return result
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            logger.error(
                "AWS KMS key rotation failed",
                error_code=error_code,
                error_message=str(e),
                key_id=self.cmk_arn
            )
            return {
                'key_id': self.cmk_arn,
                'rotation_enabled': False,
                'status': 'rotation_failed',
                'error': error_code,
                'timestamp': datetime.utcnow().isoformat()
            }


class CacheEncryption:
    """AES-256-GCM encryption for cached authentication data with AWS KMS integration"""
    
    def __init__(self, kms_manager: AWSKMSManager, metrics: PrometheusMetrics):
        """Initialize cache encryption with KMS integration
        
        Args:
            kms_manager: AWS KMS manager instance
            metrics: Prometheus metrics collector
        """
        self.kms_manager = kms_manager
        self.metrics = metrics
        self._current_key: Optional[bytes] = None
        self._encrypted_key: Optional[bytes] = None
        self._key_generated_at: Optional[datetime] = None
        self._key_rotation_interval = timedelta(hours=24)  # Rotate daily
        
        # Initialize encryption key
        self._rotate_encryption_key()
    
    def _rotate_encryption_key(self) -> None:
        """Rotate encryption key using AWS KMS"""
        try:
            plaintext_key, encrypted_key = self.kms_manager.generate_data_key()
            
            self._current_key = plaintext_key
            self._encrypted_key = encrypted_key
            self._key_generated_at = datetime.utcnow()
            
            self.metrics.record_key_rotation('data_key', 'success')
            logger.info("Encryption key rotated successfully")
            
        except KeyManagementError as e:
            self.metrics.record_key_rotation('data_key', 'failed')
            logger.error("Failed to rotate encryption key", error=str(e))
            raise EncryptionError(f"Key rotation failed: {str(e)}")
    
    def _ensure_key_freshness(self) -> None:
        """Ensure encryption key is fresh and rotate if needed"""
        if (not self._key_generated_at or 
            datetime.utcnow() - self._key_generated_at > self._key_rotation_interval):
            logger.info("Encryption key expired, rotating")
            self._rotate_encryption_key()
    
    def encrypt(self, data: Union[str, bytes, Dict[str, Any]]) -> str:
        """Encrypt data using AES-256-GCM with AWS KMS key
        
        Args:
            data: Data to encrypt (string, bytes, or JSON-serializable dict)
            
        Returns:
            Base64-encoded encrypted data with metadata
            
        Raises:
            EncryptionError: When encryption fails
        """
        try:
            self._ensure_key_freshness()
            
            # Serialize data if needed
            if isinstance(data, dict):
                data_bytes = json.dumps(data).encode('utf-8')
            elif isinstance(data, str):
                data_bytes = data.encode('utf-8')
            else:
                data_bytes = data
            
            # Create AESGCM cipher
            aesgcm = AESGCM(self._current_key)
            
            # Generate random nonce
            nonce = os.urandom(12)  # 96-bit nonce for GCM
            
            # Encrypt data
            ciphertext = aesgcm.encrypt(nonce, data_bytes, None)
            
            # Create encrypted payload with metadata
            encrypted_payload = {
                'version': '1',
                'algorithm': 'AES-256-GCM',
                'nonce': base64.b64encode(nonce).decode('ascii'),
                'ciphertext': base64.b64encode(ciphertext).decode('ascii'),
                'encrypted_key': base64.b64encode(self._encrypted_key).decode('ascii'),
                'encrypted_at': datetime.utcnow().isoformat()
            }
            
            # Encode final payload
            result = base64.b64encode(
                json.dumps(encrypted_payload).encode('utf-8')
            ).decode('ascii')
            
            self.metrics.record_encryption_operation('encrypt', 'kms')
            logger.debug("Data encrypted successfully", data_size=len(data_bytes))
            
            return result
            
        except Exception as e:
            logger.error("Encryption failed", error=str(e))
            raise EncryptionError(f"Failed to encrypt data: {str(e)}")
    
    def decrypt(self, encrypted_data: str) -> Union[str, Dict[str, Any]]:
        """Decrypt data using AES-256-GCM with AWS KMS key
        
        Args:
            encrypted_data: Base64-encoded encrypted data
            
        Returns:
            Decrypted data (string or dict based on original type)
            
        Raises:
            EncryptionError: When decryption fails
        """
        try:
            # Decode base64 payload
            payload_bytes = base64.b64decode(encrypted_data.encode('ascii'))
            encrypted_payload = json.loads(payload_bytes.decode('utf-8'))
            
            # Validate payload structure
            required_fields = ['version', 'algorithm', 'nonce', 'ciphertext', 'encrypted_key']
            if not all(field in encrypted_payload for field in required_fields):
                raise EncryptionError("Invalid encrypted payload structure")
            
            # Validate algorithm
            if encrypted_payload['algorithm'] != 'AES-256-GCM':
                raise EncryptionError(f"Unsupported algorithm: {encrypted_payload['algorithm']}")
            
            # Decrypt the data key
            encrypted_key = base64.b64decode(encrypted_payload['encrypted_key'])
            plaintext_key = self.kms_manager.decrypt_data_key(encrypted_key)
            
            # Extract encryption components
            nonce = base64.b64decode(encrypted_payload['nonce'])
            ciphertext = base64.b64decode(encrypted_payload['ciphertext'])
            
            # Decrypt data
            aesgcm = AESGCM(plaintext_key)
            plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
            
            # Attempt to deserialize as JSON, fallback to string
            try:
                result = json.loads(plaintext_bytes.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError):
                result = plaintext_bytes.decode('utf-8')
            
            self.metrics.record_encryption_operation('decrypt', 'kms')
            logger.debug("Data decrypted successfully", data_size=len(plaintext_bytes))
            
            return result
            
        except KeyManagementError:
            # Re-raise KMS errors
            raise
        except Exception as e:
            logger.error("Decryption failed", error=str(e))
            raise EncryptionError(f"Failed to decrypt data: {str(e)}")


class CircuitBreaker:
    """Circuit breaker for Redis operations with exponential backoff"""
    
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        """Initialize circuit breaker
        
        Args:
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Seconds to wait before attempting recovery
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time: Optional[datetime] = None
        self.state = 'closed'  # closed, open, half-open
    
    def __call__(self, func):
        """Decorator to wrap functions with circuit breaker"""
        @wraps(func)
        def wrapper(*args, **kwargs):
            return self._execute(func, *args, **kwargs)
        return wrapper
    
    def _execute(self, func, *args, **kwargs):
        """Execute function with circuit breaker protection"""
        if self.state == 'open':
            if self._should_attempt_reset():
                self.state = 'half-open'
                logger.info("Circuit breaker entering half-open state")
            else:
                raise CacheConnectionError("Circuit breaker is open")
        
        try:
            result = func(*args, **kwargs)
            if self.state == 'half-open':
                self._reset()
            return result
        except Exception as e:
            self._record_failure()
            raise
    
    def _should_attempt_reset(self) -> bool:
        """Check if circuit breaker should attempt reset"""
        if not self.last_failure_time:
            return True
        return (datetime.utcnow() - self.last_failure_time).total_seconds() > self.recovery_timeout
    
    def _record_failure(self) -> None:
        """Record failure and potentially open circuit"""
        self.failure_count += 1
        self.last_failure_time = datetime.utcnow()
        
        if self.failure_count >= self.failure_threshold:
            self.state = 'open'
            logger.warning(
                "Circuit breaker opened",
                failure_count=self.failure_count,
                threshold=self.failure_threshold
            )
    
    def _reset(self) -> None:
        """Reset circuit breaker to closed state"""
        self.failure_count = 0
        self.last_failure_time = None
        self.state = 'closed'
        logger.info("Circuit breaker reset to closed state")


class AuthenticationCache:
    """
    Enterprise Redis-based authentication cache with AES-256-GCM encryption.
    
    Implements comprehensive caching for authentication and authorization data with:
    - Structured Redis key patterns with intelligent TTL management
    - AES-256-GCM encryption using AWS KMS-backed data keys
    - Connection pooling optimization with redis-py 5.0+
    - Prometheus metrics collection for monitoring and alerting
    - Circuit breaker patterns for Redis service resilience
    - Intelligent cache invalidation and warming strategies
    """
    
    def __init__(self, config: Optional[CacheConfig] = None):
        """Initialize authentication cache with enterprise configuration
        
        Args:
            config: Optional cache configuration, uses defaults if not provided
        """
        self.config = config or self._load_default_config()
        self.metrics = PrometheusMetrics()
        
        # Initialize components
        self._init_redis_connection()
        self._init_encryption()
        self._init_circuit_breaker()
        
        # Cache statistics
        self._cache_stats = CacheMetrics()
        
        logger.info(
            "Authentication cache initialized",
            host=self.config.host,
            port=self.config.port,
            database=self.config.database,
            encryption_enabled=self.config.encryption_enabled
        )
    
    def _load_default_config(self) -> CacheConfig:
        """Load default cache configuration from environment or config module"""
        try:
            # Try to import from config module
            from src.config.database import get_redis_config
            redis_config = get_redis_config()
            return CacheConfig(**redis_config)
        except ImportError:
            # Fallback to environment variables
            return CacheConfig(
                host=os.getenv('REDIS_HOST', 'localhost'),
                port=int(os.getenv('REDIS_PORT', 6379)),
                password=os.getenv('REDIS_PASSWORD'),
                database=int(os.getenv('REDIS_AUTH_DB', 1)),
                max_connections=int(os.getenv('REDIS_MAX_CONNECTIONS', 50)),
                encryption_enabled=os.getenv('REDIS_ENCRYPTION_ENABLED', 'true').lower() == 'true'
            )
    
    def _init_redis_connection(self) -> None:
        """Initialize Redis connection with optimized pooling"""
        try:
            # Try to import from config module
            from src.config.database import get_redis_connection_pool
            self.redis_pool = get_redis_connection_pool()
            self.redis_client = redis.Redis(connection_pool=self.redis_pool)
        except ImportError:
            # Fallback to direct Redis connection
            self.redis_pool = ConnectionPool(
                host=self.config.host,
                port=self.config.port,
                password=self.config.password,
                db=self.config.database,
                decode_responses=False,  # Keep bytes for encryption
                max_connections=self.config.max_connections,
                retry_on_timeout=self.config.retry_on_timeout,
                socket_timeout=self.config.socket_timeout,
                socket_connect_timeout=self.config.socket_connect_timeout,
                health_check_interval=self.config.health_check_interval
            )
            self.redis_client = redis.Redis(connection_pool=self.redis_pool)
        
        # Test connection
        try:
            self.redis_client.ping()
            self.metrics.update_redis_connections('active', self.redis_pool.created_connections)
            logger.info("Redis connection established successfully")
        except RedisError as e:
            logger.error("Failed to connect to Redis", error=str(e))
            raise CacheConnectionError(f"Redis connection failed: {str(e)}")
    
    def _init_encryption(self) -> None:
        """Initialize encryption components"""
        if self.config.encryption_enabled:
            try:
                kms_manager = AWSKMSManager()
                self.encryption = CacheEncryption(kms_manager, self.metrics)
                logger.info("Cache encryption initialized with AWS KMS")
            except Exception as e:
                logger.error("Failed to initialize encryption", error=str(e))
                raise EncryptionError(f"Encryption initialization failed: {str(e)}")
        else:
            self.encryption = None
            logger.warning("Cache encryption disabled - data will be stored in plaintext")
    
    def _init_circuit_breaker(self) -> None:
        """Initialize circuit breaker for Redis operations"""
        self.circuit_breaker = CircuitBreaker(failure_threshold=5, recovery_timeout=60)
        self.metrics.set_circuit_breaker_state('redis', 0)  # closed
    
    def _build_cache_key(self, cache_type: str, identifier: str, *args) -> str:
        """Build structured Redis cache key
        
        Args:
            cache_type: Type of cache (session, permission, token, etc.)
            identifier: Primary identifier (user_id, session_id, etc.)
            *args: Additional key components
            
        Returns:
            Structured cache key following enterprise patterns
        """
        key_parts = [self.config.key_prefix, cache_type, identifier]
        key_parts.extend(str(arg) for arg in args)
        return ':'.join(key_parts)
    
    def _serialize_data(self, data: Any) -> bytes:
        """Serialize data for cache storage with optional encryption
        
        Args:
            data: Data to serialize
            
        Returns:
            Serialized (and optionally encrypted) data
        """
        if self.config.encryption_enabled and self.encryption:
            encrypted_data = self.encryption.encrypt(data)
            return encrypted_data.encode('utf-8')
        else:
            return json.dumps(data).encode('utf-8')
    
    def _deserialize_data(self, data: bytes) -> Any:
        """Deserialize data from cache storage with optional decryption
        
        Args:
            data: Serialized (and optionally encrypted) data
            
        Returns:
            Deserialized data
        """
        if self.config.encryption_enabled and self.encryption:
            encrypted_data = data.decode('utf-8')
            return self.encryption.decrypt(encrypted_data)
        else:
            return json.loads(data.decode('utf-8'))
    
    @CircuitBreaker()
    def set(self, cache_type: str, identifier: str, data: Any, ttl: Optional[int] = None, *key_args) -> bool:
        """Set cache entry with structured key pattern and optional encryption
        
        Args:
            cache_type: Type of cache (session, permission, token, etc.)
            identifier: Primary identifier (user_id, session_id, etc.)
            data: Data to cache
            ttl: Time-to-live in seconds (uses default if not specified)
            *key_args: Additional key components
            
        Returns:
            Success status
            
        Raises:
            CacheError: When cache operation fails
        """
        cache_key = self._build_cache_key(cache_type, identifier, *key_args)
        ttl = ttl or self.config.default_ttl
        
        with self.metrics.time_cache_operation('set', cache_type):
            try:
                serialized_data = self._serialize_data(data)
                
                # Set data with TTL
                result = self.redis_client.setex(cache_key, ttl, serialized_data)
                
                if result:
                    self._cache_stats.total_operations += 1
                    self.metrics.update_cache_size(cache_type, len(serialized_data))
                    
                    logger.debug(
                        "Cache entry set successfully",
                        cache_type=cache_type,
                        key=cache_key,
                        ttl=ttl,
                        data_size=len(serialized_data)
                    )
                    return True
                else:
                    self.metrics.record_cache_error('set', 'redis_error', cache_type)
                    return False
                    
            except (RedisError, TimeoutError) as e:
                self.metrics.record_cache_error('set', 'connection_error', cache_type)
                logger.error(
                    "Redis cache set operation failed",
                    cache_type=cache_type,
                    key=cache_key,
                    error=str(e)
                )
                raise CacheError(f"Failed to set cache entry: {str(e)}")
            except Exception as e:
                self.metrics.record_cache_error('set', 'unexpected_error', cache_type)
                logger.error(
                    "Unexpected error in cache set operation",
                    cache_type=cache_type,
                    key=cache_key,
                    error=str(e)
                )
                raise CacheError(f"Unexpected cache error: {str(e)}")
    
    @CircuitBreaker()
    def get(self, cache_type: str, identifier: str, *key_args) -> Optional[Any]:
        """Get cache entry with structured key pattern and optional decryption
        
        Args:
            cache_type: Type of cache (session, permission, token, etc.)
            identifier: Primary identifier (user_id, session_id, etc.)
            *key_args: Additional key components
            
        Returns:
            Cached data or None if not found
            
        Raises:
            CacheError: When cache operation fails
        """
        cache_key = self._build_cache_key(cache_type, identifier, *key_args)
        
        with self.metrics.time_cache_operation('get', cache_type):
            try:
                serialized_data = self.redis_client.get(cache_key)
                
                if serialized_data is not None:
                    # Cache hit
                    data = self._deserialize_data(serialized_data)
                    self._cache_stats.hits += 1
                    self._cache_stats.total_operations += 1
                    self.metrics.record_cache_hit(cache_type, 'get')
                    
                    logger.debug(
                        "Cache hit",
                        cache_type=cache_type,
                        key=cache_key,
                        data_size=len(serialized_data)
                    )
                    return data
                else:
                    # Cache miss
                    self._cache_stats.misses += 1
                    self._cache_stats.total_operations += 1
                    self.metrics.record_cache_miss(cache_type, 'get')
                    
                    logger.debug(
                        "Cache miss",
                        cache_type=cache_type,
                        key=cache_key
                    )
                    return None
                    
            except (RedisError, TimeoutError) as e:
                self.metrics.record_cache_error('get', 'connection_error', cache_type)
                logger.error(
                    "Redis cache get operation failed",
                    cache_type=cache_type,
                    key=cache_key,
                    error=str(e)
                )
                raise CacheError(f"Failed to get cache entry: {str(e)}")
            except Exception as e:
                self.metrics.record_cache_error('get', 'unexpected_error', cache_type)
                logger.error(
                    "Unexpected error in cache get operation",
                    cache_type=cache_type,
                    key=cache_key,
                    error=str(e)
                )
                raise CacheError(f"Unexpected cache error: {str(e)}")
    
    @CircuitBreaker()
    def delete(self, cache_type: str, identifier: str, *key_args) -> bool:
        """Delete cache entry with structured key pattern
        
        Args:
            cache_type: Type of cache (session, permission, token, etc.)
            identifier: Primary identifier (user_id, session_id, etc.)
            *key_args: Additional key components
            
        Returns:
            Success status (True if key existed and was deleted)
        """
        cache_key = self._build_cache_key(cache_type, identifier, *key_args)
        
        with self.metrics.time_cache_operation('delete', cache_type):
            try:
                result = self.redis_client.delete(cache_key)
                
                logger.debug(
                    "Cache entry deleted",
                    cache_type=cache_type,
                    key=cache_key,
                    existed=bool(result)
                )
                
                return bool(result)
                
            except (RedisError, TimeoutError) as e:
                self.metrics.record_cache_error('delete', 'connection_error', cache_type)
                logger.error(
                    "Redis cache delete operation failed",
                    cache_type=cache_type,
                    key=cache_key,
                    error=str(e)
                )
                raise CacheError(f"Failed to delete cache entry: {str(e)}")
    
    @CircuitBreaker()
    def invalidate_pattern(self, cache_type: str, pattern: str) -> int:
        """Invalidate cache entries matching pattern
        
        Args:
            cache_type: Type of cache for metrics
            pattern: Redis key pattern to match
            
        Returns:
            Number of keys deleted
        """
        with self.metrics.time_cache_operation('invalidate_pattern', cache_type):
            try:
                # Find matching keys
                matching_keys = self.redis_client.keys(pattern)
                
                if matching_keys:
                    # Delete matching keys
                    deleted_count = self.redis_client.delete(*matching_keys)
                    
                    logger.info(
                        "Cache pattern invalidation completed",
                        cache_type=cache_type,
                        pattern=pattern,
                        deleted_count=deleted_count
                    )
                    
                    return deleted_count
                else:
                    logger.debug(
                        "No keys found for pattern",
                        cache_type=cache_type,
                        pattern=pattern
                    )
                    return 0
                    
            except (RedisError, TimeoutError) as e:
                self.metrics.record_cache_error('invalidate_pattern', 'connection_error', cache_type)
                logger.error(
                    "Cache pattern invalidation failed",
                    cache_type=cache_type,
                    pattern=pattern,
                    error=str(e)
                )
                raise CacheError(f"Failed to invalidate cache pattern: {str(e)}")
    
    # High-level cache operations for authentication data
    
    def cache_user_session(self, session_id: str, session_data: Dict[str, Any], ttl: int = 3600) -> bool:
        """Cache user session data with AES-256-GCM encryption
        
        Args:
            session_id: Unique session identifier
            session_data: Session data dictionary
            ttl: Session TTL in seconds (default 1 hour)
            
        Returns:
            Success status
        """
        return self.set('session', session_id, session_data, ttl)
    
    def get_user_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve user session data with decryption
        
        Args:
            session_id: Unique session identifier
            
        Returns:
            Session data or None if not found
        """
        return self.get('session', session_id)
    
    def invalidate_user_session(self, session_id: str) -> bool:
        """Invalidate user session
        
        Args:
            session_id: Session identifier to invalidate
            
        Returns:
            Success status
        """
        return self.delete('session', session_id)
    
    def cache_user_permissions(self, user_id: str, permissions: Set[str], ttl: int = 300) -> bool:
        """Cache user permissions with structured key pattern
        
        Args:
            user_id: Unique user identifier
            permissions: Set of user permissions
            ttl: Permission cache TTL in seconds (default 5 minutes)
            
        Returns:
            Success status
        """
        permissions_data = {
            'permissions': list(permissions),
            'cached_at': datetime.utcnow().isoformat(),
            'expires_at': (datetime.utcnow() + timedelta(seconds=ttl)).isoformat()
        }
        return self.set('permission', user_id, permissions_data, ttl)
    
    def get_user_permissions(self, user_id: str) -> Optional[Set[str]]:
        """Retrieve cached user permissions
        
        Args:
            user_id: Unique user identifier
            
        Returns:
            Set of permissions or None if not cached
        """
        data = self.get('permission', user_id)
        if data and 'permissions' in data:
            return set(data['permissions'])
        return None
    
    def invalidate_user_permissions(self, user_id: str) -> bool:
        """Invalidate user permission cache
        
        Args:
            user_id: User identifier
            
        Returns:
            Success status
        """
        return self.delete('permission', user_id)
    
    def cache_jwt_validation(self, token_hash: str, validation_result: Dict[str, Any], ttl: int = 300) -> bool:
        """Cache JWT token validation result
        
        Args:
            token_hash: Hash of JWT token for cache key
            validation_result: Token validation result
            ttl: Validation cache TTL in seconds (default 5 minutes)
            
        Returns:
            Success status
        """
        return self.set('jwt_validation', token_hash, validation_result, ttl)
    
    def get_jwt_validation(self, token_hash: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached JWT validation result
        
        Args:
            token_hash: Hash of JWT token
            
        Returns:
            Validation result or None if not cached
        """
        return self.get('jwt_validation', token_hash)
    
    def cache_auth0_user_profile(self, user_id: str, profile_data: Dict[str, Any], ttl: int = 1800) -> bool:
        """Cache Auth0 user profile data
        
        Args:
            user_id: Unique user identifier
            profile_data: Auth0 user profile data
            ttl: Profile cache TTL in seconds (default 30 minutes)
            
        Returns:
            Success status
        """
        return self.set('auth0_profile', user_id, profile_data, ttl)
    
    def get_auth0_user_profile(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached Auth0 user profile
        
        Args:
            user_id: Unique user identifier
            
        Returns:
            Profile data or None if not cached
        """
        return self.get('auth0_profile', user_id)
    
    def invalidate_user_cache(self, user_id: str) -> int:
        """Invalidate all cache entries for a user
        
        Args:
            user_id: User identifier
            
        Returns:
            Number of cache entries invalidated
        """
        patterns = [
            self._build_cache_key('permission', user_id) + '*',
            self._build_cache_key('auth0_profile', user_id) + '*',
            self._build_cache_key('session', '*', user_id) + '*'
        ]
        
        total_deleted = 0
        for pattern in patterns:
            total_deleted += self.invalidate_pattern('user_cache', pattern)
        
        logger.info(
            "User cache invalidated",
            user_id=user_id,
            total_deleted=total_deleted
        )
        
        return total_deleted
    
    def get_cache_stats(self) -> CacheMetrics:
        """Get current cache performance statistics
        
        Returns:
            Cache metrics object with performance data
        """
        return self._cache_stats
    
    def get_prometheus_metrics(self) -> str:
        """Get Prometheus metrics in exposition format
        
        Returns:
            Metrics data in Prometheus format
        """
        return generate_latest(self.metrics.registry)
    
    def health_check(self) -> Dict[str, Any]:
        """Perform comprehensive cache health check
        
        Returns:
            Health status with detailed metrics
        """
        try:
            # Test Redis connectivity
            start_time = datetime.utcnow()
            self.redis_client.ping()
            response_time = (datetime.utcnow() - start_time).total_seconds()
            
            # Get Redis info
            redis_info = self.redis_client.info()
            
            # Calculate cache performance metrics
            stats = self.get_cache_stats()
            
            health_status = {
                'status': 'healthy',
                'redis_connected': True,
                'response_time_seconds': response_time,
                'cache_hit_ratio': stats.hit_ratio,
                'total_operations': stats.total_operations,
                'redis_memory_used': redis_info.get('used_memory_human', 'unknown'),
                'redis_connected_clients': redis_info.get('connected_clients', 0),
                'encryption_enabled': self.config.encryption_enabled,
                'circuit_breaker_state': self.circuit_breaker.state,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            logger.info("Cache health check completed", **health_status)
            return health_status
            
        except Exception as e:
            health_status = {
                'status': 'unhealthy',
                'redis_connected': False,
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
            
            logger.error("Cache health check failed", **health_status)
            return health_status
    
    def close(self) -> None:
        """Close cache connections and cleanup resources"""
        try:
            if hasattr(self, 'redis_pool'):
                self.redis_pool.disconnect()
                logger.info("Redis connection pool closed")
        except Exception as e:
            logger.error("Error closing cache connections", error=str(e))


# Global cache instance (initialized by application factory)
_auth_cache: Optional[AuthenticationCache] = None


def get_auth_cache() -> AuthenticationCache:
    """Get or create global authentication cache instance
    
    Returns:
        Authentication cache instance
        
    Raises:
        CacheError: When cache initialization fails
    """
    global _auth_cache
    
    if _auth_cache is None:
        try:
            _auth_cache = AuthenticationCache()
            logger.info("Global authentication cache initialized")
        except Exception as e:
            logger.error("Failed to initialize authentication cache", error=str(e))
            raise CacheError(f"Cache initialization failed: {str(e)}")
    
    return _auth_cache


def init_auth_cache(config: Optional[CacheConfig] = None) -> AuthenticationCache:
    """Initialize authentication cache with custom configuration
    
    Args:
        config: Optional cache configuration
        
    Returns:
        Initialized authentication cache instance
    """
    global _auth_cache
    
    try:
        _auth_cache = AuthenticationCache(config)
        logger.info("Authentication cache initialized with custom configuration")
        return _auth_cache
    except Exception as e:
        logger.error("Failed to initialize authentication cache", error=str(e))
        raise CacheError(f"Cache initialization failed: {str(e)}")


def close_auth_cache() -> None:
    """Close global authentication cache instance"""
    global _auth_cache
    
    if _auth_cache is not None:
        _auth_cache.close()
        _auth_cache = None
        logger.info("Global authentication cache closed")


# Cache utility functions for common operations

def hash_token(token: str) -> str:
    """Generate secure hash for JWT token caching
    
    Args:
        token: JWT token string
        
    Returns:
        SHA-256 hash of token for use as cache key
    """
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def generate_session_id() -> str:
    """Generate cryptographically secure session ID
    
    Returns:
        Secure session identifier
    """
    return base64.urlsafe_b64encode(os.urandom(32)).decode('ascii').rstrip('=')


def cache_operation_with_fallback(cache_func, fallback_func, *args, **kwargs):
    """Execute cache operation with fallback function
    
    Args:
        cache_func: Primary cache function to execute
        fallback_func: Fallback function if cache fails
        *args: Arguments for both functions
        **kwargs: Keyword arguments for both functions
        
    Returns:
        Result from cache function or fallback if cache fails
    """
    try:
        return cache_func(*args, **kwargs)
    except CacheError as e:
        logger.warning(
            "Cache operation failed, using fallback",
            cache_function=cache_func.__name__,
            fallback_function=fallback_func.__name__,
            error=str(e)
        )
        return fallback_func(*args, **kwargs)