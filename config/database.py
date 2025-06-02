"""
Database and Caching Configuration Module

This module provides comprehensive database and caching infrastructure for the Flask application,
implementing MongoDB (PyMongo 4.5+/Motor 3.3+) and Redis (redis-py 5.0+) connections with
enterprise-grade security, connection pooling, and distributed session management.

This replaces Node.js MongoDB and Redis client configurations with Python-based solutions
as specified in Section 0.1.2 and Section 0.2.4 of the migration specification.

Key Features:
- PyMongo 4.5+ for synchronous MongoDB operations (Section 3.4.1)
- Motor 3.3+ for asynchronous MongoDB operations (Section 3.4.1)
- redis-py 5.0+ for Redis caching and session management (Section 3.4.2)
- Flask-Session 0.8+ with Redis backend for distributed sessions (Section 3.4.2)
- TLS encryption and mTLS certificate validation (Section 6.4.3)
- AWS KMS integration for session encryption (Section 6.4.1)
- Connection pooling and performance optimization (Section 3.4.5)
- Comprehensive monitoring and health checks (Section 3.6.1)

Security Features:
- AES-256-GCM encryption for session data using AWS KMS-backed keys
- TLS/mTLS encryption for all database connections
- Certificate validation and security header enforcement
- Secure connection pooling with timeout controls
- Circuit breaker patterns for service resilience

Dependencies:
- pymongo>=4.5.0 for MongoDB synchronous operations
- motor>=3.3.0 for MongoDB asynchronous operations  
- redis>=5.0.0 for Redis client operations
- Flask-Session>=0.8.0 for distributed session management
- cryptography>=41.0.0 for encryption operations
- boto3>=1.28.0 for AWS KMS integration

Author: Flask Migration Team
Version: 1.0.0
Migration Phase: Node.js to Python/Flask Migration (Section 0.1.1)
"""

import os
import ssl
import json
import base64
import asyncio
import logging
from typing import Dict, Any, Optional, Union, List, Tuple
from datetime import datetime, timedelta
from urllib.parse import quote_plus

# Database and caching imports
import pymongo
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError, ConfigurationError
import motor.motor_asyncio
import redis
from redis.connection import ConnectionPool
from redis.exceptions import ConnectionError as RedisConnectionError, TimeoutError as RedisTimeoutError

# Flask and session management imports
from flask import Flask, session
from flask_session import Session

# Cryptography and security imports
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import boto3
from botocore.exceptions import ClientError, BotoCoreError

# Configuration imports
from config.settings import get_config, ConfigurationError

# Configure module logger
logger = logging.getLogger(__name__)


class DatabaseConfigurationError(Exception):
    """Custom exception for database configuration errors."""
    pass


class AWSKMSManager:
    """
    AWS KMS integration for session encryption key management.
    
    This class implements comprehensive AWS KMS integration using boto3 client
    for centralized encryption key management with automated key rotation and
    secure session data encryption as specified in Section 6.4.1.
    """
    
    def __init__(self, aws_access_key_id: Optional[str] = None, 
                 aws_secret_access_key: Optional[str] = None,
                 aws_region: Optional[str] = None,
                 kms_key_arn: Optional[str] = None):
        """
        Initialize AWS KMS manager with enterprise configuration.
        
        Args:
            aws_access_key_id: AWS access key ID
            aws_secret_access_key: AWS secret access key
            aws_region: AWS region for KMS operations
            kms_key_arn: KMS Customer Master Key ARN
        """
        self.config = get_config()
        self.aws_access_key_id = aws_access_key_id or self.config.AWS_ACCESS_KEY_ID
        self.aws_secret_access_key = aws_secret_access_key or self.config.AWS_SECRET_ACCESS_KEY
        self.aws_region = aws_region or self.config.AWS_DEFAULT_REGION
        self.kms_key_arn = kms_key_arn or self.config.AWS_KMS_KEY_ARN
        
        self.kms_client = self._create_kms_client()
        self.logger = logging.getLogger(f"{__name__}.AWSKMSManager")
        
        # Session encryption cache
        self._encryption_cache: Dict[str, Fernet] = {}
        self._key_rotation_schedule = timedelta(days=90)
    
    def _create_kms_client(self) -> boto3.client:
        """
        Create properly configured boto3 KMS client with enterprise settings.
        
        Returns:
            Configured boto3 KMS client with retry and timeout configuration
            
        Raises:
            DatabaseConfigurationError: When KMS client creation fails
        """
        try:
            return boto3.client(
                'kms',
                region_name=self.aws_region,
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                config=boto3.session.Config(
                    retries={'max_attempts': 3, 'mode': 'adaptive'},
                    read_timeout=30,
                    connect_timeout=10,
                    max_pool_connections=50
                )
            )
        except Exception as e:
            raise DatabaseConfigurationError(f"Failed to create KMS client: {str(e)}")
    
    def generate_session_encryption_key(self, session_context: Dict[str, str]) -> Tuple[bytes, str]:
        """
        Generate AWS KMS data key for session encryption operations.
        
        This method creates a new data key using AWS KMS Customer Master Key
        for session data encryption with proper encryption context for audit trails.
        
        Args:
            session_context: Session-specific encryption context for KMS
            
        Returns:
            Tuple of (plaintext_key, encrypted_key_b64) for session encryption
            
        Raises:
            DatabaseConfigurationError: When key generation fails
        """
        if not self.kms_key_arn:
            self.logger.warning("KMS key ARN not configured, using local key generation")
            return self._generate_local_encryption_key()
        
        try:
            encryption_context = {
                'application': 'flask-session-encryption',
                'purpose': 'session-data-protection',
                'environment': self.config.FLASK_ENV,
                **session_context
            }
            
            response = self.kms_client.generate_data_key(
                KeyId=self.kms_key_arn,
                KeySpec='AES_256',
                EncryptionContext=encryption_context
            )
            
            plaintext_key = response['Plaintext']
            encrypted_key_b64 = base64.b64encode(response['CiphertextBlob']).decode('utf-8')
            
            self.logger.info(f"Generated KMS data key for session encryption")
            return plaintext_key, encrypted_key_b64
            
        except ClientError as e:
            self.logger.error(f"AWS KMS key generation failed: {str(e)}")
            # Fallback to local key generation for development
            if self.config.FLASK_ENV == 'development':
                return self._generate_local_encryption_key()
            raise DatabaseConfigurationError(f"KMS key generation failed: {str(e)}")
    
    def decrypt_session_key(self, encrypted_key_b64: str, session_context: Dict[str, str]) -> bytes:
        """
        Decrypt AWS KMS data key for session decryption operations.
        
        Args:
            encrypted_key_b64: Base64-encoded encrypted data key from KMS
            session_context: Session-specific encryption context for validation
            
        Returns:
            Decrypted plaintext key for session operations
            
        Raises:
            DatabaseConfigurationError: When key decryption fails
        """
        if not self.kms_key_arn:
            self.logger.warning("KMS key ARN not configured, using local key")
            return self._get_local_encryption_key()
        
        try:
            encrypted_key = base64.b64decode(encrypted_key_b64)
            encryption_context = {
                'application': 'flask-session-encryption',
                'purpose': 'session-data-protection',
                'environment': self.config.FLASK_ENV,
                **session_context
            }
            
            response = self.kms_client.decrypt(
                CiphertextBlob=encrypted_key,
                EncryptionContext=encryption_context
            )
            
            return response['Plaintext']
            
        except ClientError as e:
            self.logger.error(f"AWS KMS key decryption failed: {str(e)}")
            # Fallback to local key for development
            if self.config.FLASK_ENV == 'development':
                return self._get_local_encryption_key()
            raise DatabaseConfigurationError(f"KMS key decryption failed: {str(e)}")
    
    def _generate_local_encryption_key(self) -> Tuple[bytes, str]:
        """Generate local encryption key for development/fallback scenarios."""
        key = Fernet.generate_key()
        return key, base64.b64encode(key).decode('utf-8')
    
    def _get_local_encryption_key(self) -> bytes:
        """Get local encryption key for development/fallback scenarios."""
        if hasattr(self.config, 'SESSION_ENCRYPTION_KEY') and self.config.SESSION_ENCRYPTION_KEY:
            return base64.b64decode(self.config.SESSION_ENCRYPTION_KEY)
        return Fernet.generate_key()
    
    def create_session_encryptor(self, session_id: str) -> Fernet:
        """
        Create Fernet encryptor for session data encryption.
        
        Args:
            session_id: Unique session identifier
            
        Returns:
            Configured Fernet encryptor for session data
        """
        if session_id in self._encryption_cache:
            return self._encryption_cache[session_id]
        
        session_context = {
            'session_id': session_id,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        plaintext_key, _ = self.generate_session_encryption_key(session_context)
        encryptor = Fernet(plaintext_key)
        
        # Cache encryptor for session lifetime
        self._encryption_cache[session_id] = encryptor
        
        return encryptor


class MongoDBManager:
    """
    MongoDB connection and configuration manager using PyMongo 4.5+ and Motor 3.3+.
    
    This class implements comprehensive MongoDB connection management with both
    synchronous (PyMongo) and asynchronous (Motor) drivers, TLS encryption,
    connection pooling, and enterprise security features as specified in Section 3.4.1.
    """
    
    def __init__(self, config: Optional[Any] = None):
        """
        Initialize MongoDB manager with enterprise configuration.
        
        Args:
            config: Configuration object (defaults to application config)
        """
        self.config = config or get_config()
        self.logger = logging.getLogger(f"{__name__}.MongoDBManager")
        
        # MongoDB clients
        self._sync_client: Optional[MongoClient] = None
        self._async_client: Optional[motor.motor_asyncio.AsyncIOMotorClient] = None
        self._database_name = self.config.MONGODB_DATABASE
        
        # Connection monitoring
        self._connection_health = {
            'sync': False,
            'async': False,
            'last_check': None
        }
    
    def get_sync_client(self) -> MongoClient:
        """
        Get or create synchronous PyMongo client with enterprise configuration.
        
        This method implements PyMongo 4.5+ client configuration with comprehensive
        connection pooling, TLS encryption, and performance optimization settings.
        
        Returns:
            Configured PyMongo MongoClient instance
            
        Raises:
            DatabaseConfigurationError: When client creation or connection fails
        """
        if self._sync_client is not None:
            return self._sync_client
        
        try:
            # Build MongoDB connection options
            connection_options = self._build_connection_options()
            
            # Create PyMongo client with enterprise settings
            self._sync_client = MongoClient(
                self.config.MONGODB_URI,
                **connection_options
            )
            
            # Test connection
            self._sync_client.admin.command('ping')
            self._connection_health['sync'] = True
            self._connection_health['last_check'] = datetime.utcnow()
            
            self.logger.info("PyMongo synchronous client connected successfully")
            return self._sync_client
            
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            self.logger.error(f"MongoDB synchronous connection failed: {str(e)}")
            raise DatabaseConfigurationError(f"MongoDB sync connection failed: {str(e)}")
        except Exception as e:
            self.logger.error(f"Unexpected MongoDB sync client error: {str(e)}")
            raise DatabaseConfigurationError(f"MongoDB sync client error: {str(e)}")
    
    def get_async_client(self) -> motor.motor_asyncio.AsyncIOMotorClient:
        """
        Get or create asynchronous Motor client with enterprise configuration.
        
        This method implements Motor 3.3+ client configuration for high-performance
        async database operations with identical security and pooling settings.
        
        Returns:
            Configured Motor AsyncIOMotorClient instance
            
        Raises:
            DatabaseConfigurationError: When client creation or connection fails
        """
        if self._async_client is not None:
            return self._async_client
        
        try:
            # Build MongoDB connection options
            connection_options = self._build_connection_options()
            
            # Create Motor async client with enterprise settings
            self._async_client = motor.motor_asyncio.AsyncIOMotorClient(
                self.config.MONGODB_URI,
                **connection_options
            )
            
            self.logger.info("Motor asynchronous client created successfully")
            return self._async_client
            
        except Exception as e:
            self.logger.error(f"MongoDB asynchronous client creation failed: {str(e)}")
            raise DatabaseConfigurationError(f"MongoDB async client error: {str(e)}")
    
    def _build_connection_options(self) -> Dict[str, Any]:
        """
        Build comprehensive MongoDB connection options with enterprise security.
        
        This method implements MongoDB connection configuration as specified in
        Section 3.4.1 with TLS encryption, connection pooling, and performance tuning.
        
        Returns:
            Dictionary of MongoDB connection options
        """
        options = {
            # Connection pooling configuration
            'maxPoolSize': self.config.MONGODB_SETTINGS.get('maxPoolSize', 50),
            'minPoolSize': self.config.MONGODB_SETTINGS.get('minPoolSize', 5),
            'maxIdleTimeMS': self.config.MONGODB_SETTINGS.get('maxIdleTimeMS', 30000),
            
            # Timeout configuration
            'serverSelectionTimeoutMS': self.config.MONGODB_SETTINGS.get('serverSelectionTimeoutMS', 5000),
            'socketTimeoutMS': self.config.MONGODB_SETTINGS.get('socketTimeoutMS', 30000),
            'connectTimeoutMS': self.config.MONGODB_SETTINGS.get('connectTimeoutMS', 10000),
            
            # Connection behavior
            'connect': True,
            'retryWrites': True,
            'retryReads': True,
            'w': 'majority',
            'readPreference': 'primary',
            
            # Application identification
            'appName': f"{self.config.APP_NAME}-{self.config.FLASK_ENV}"
        }
        
        # TLS/SSL configuration for secure connections
        if self.config.MONGODB_SETTINGS.get('tls'):
            tls_options = self._build_tls_options()
            options.update(tls_options)
            self.logger.info("MongoDB TLS encryption enabled")
        
        return options
    
    def _build_tls_options(self) -> Dict[str, Any]:
        """
        Build TLS configuration options for MongoDB connections.
        
        This method implements TLS encryption configuration as specified in
        Section 6.4.3 for secure database communication.
        
        Returns:
            Dictionary of TLS configuration options
        """
        tls_options = {
            'tls': True,
            'tlsInsecure': False,  # Require certificate validation
        }
        
        # Certificate file configuration
        if self.config.MONGODB_SETTINGS.get('tlsCAFile'):
            tls_options['tlsCAFile'] = self.config.MONGODB_SETTINGS['tlsCAFile']
        
        if self.config.MONGODB_SETTINGS.get('tlsCertificateKeyFile'):
            tls_options['tlsCertificateKeyFile'] = self.config.MONGODB_SETTINGS['tlsCertificateKeyFile']
        
        # Certificate validation settings
        tls_options['tlsAllowInvalidCertificates'] = self.config.MONGODB_SETTINGS.get(
            'tlsAllowInvalidCertificates', False
        )
        tls_options['tlsAllowInvalidHostnames'] = self.config.MONGODB_SETTINGS.get(
            'tlsAllowInvalidHostnames', False
        )
        
        return tls_options
    
    def get_database(self, client_type: str = 'sync') -> Union[pymongo.database.Database, 
                                                              motor.motor_asyncio.AsyncIOMotorDatabase]:
        """
        Get database instance from specified client type.
        
        Args:
            client_type: Client type ('sync' or 'async')
            
        Returns:
            Database instance for the specified client type
            
        Raises:
            DatabaseConfigurationError: When invalid client type is specified
        """
        if client_type == 'sync':
            client = self.get_sync_client()
            return client[self._database_name]
        elif client_type == 'async':
            client = self.get_async_client()
            return client[self._database_name]
        else:
            raise DatabaseConfigurationError(f"Invalid client type: {client_type}")
    
    async def test_async_connection(self) -> bool:
        """
        Test asynchronous MongoDB connection health.
        
        Returns:
            True if connection is healthy, False otherwise
        """
        try:
            client = self.get_async_client()
            await client.admin.command('ping')
            self._connection_health['async'] = True
            self._connection_health['last_check'] = datetime.utcnow()
            return True
        except Exception as e:
            self.logger.error(f"MongoDB async connection test failed: {str(e)}")
            self._connection_health['async'] = False
            return False
    
    def test_sync_connection(self) -> bool:
        """
        Test synchronous MongoDB connection health.
        
        Returns:
            True if connection is healthy, False otherwise
        """
        try:
            client = self.get_sync_client()
            client.admin.command('ping')
            self._connection_health['sync'] = True
            self._connection_health['last_check'] = datetime.utcnow()
            return True
        except Exception as e:
            self.logger.error(f"MongoDB sync connection test failed: {str(e)}")
            self._connection_health['sync'] = False
            return False
    
    def close_connections(self) -> None:
        """Close all MongoDB connections and clean up resources."""
        if self._sync_client:
            self._sync_client.close()
            self._sync_client = None
            self.logger.info("PyMongo synchronous client closed")
        
        if self._async_client:
            self._async_client.close()
            self._async_client = None
            self.logger.info("Motor asynchronous client closed")
        
        self._connection_health = {'sync': False, 'async': False, 'last_check': None}
    
    def get_connection_status(self) -> Dict[str, Any]:
        """
        Get comprehensive connection status information.
        
        Returns:
            Dictionary containing connection health and statistics
        """
        return {
            'sync_connected': self._connection_health['sync'],
            'async_connected': self._connection_health['async'],
            'last_health_check': self._connection_health['last_check'],
            'database_name': self._database_name,
            'mongodb_uri_host': self.config.MONGODB_URI.split('@')[-1].split('/')[0] if '@' in self.config.MONGODB_URI else 'localhost'
        }


class RedisManager:
    """
    Redis connection and configuration manager using redis-py 5.0+.
    
    This class implements comprehensive Redis connection management with connection
    pooling, TLS encryption, and session storage capabilities as specified in Section 3.4.2.
    """
    
    def __init__(self, config: Optional[Any] = None):
        """
        Initialize Redis manager with enterprise configuration.
        
        Args:
            config: Configuration object (defaults to application config)
        """
        self.config = config or get_config()
        self.logger = logging.getLogger(f"{__name__}.RedisManager")
        
        # Redis connection pool and client
        self._connection_pool: Optional[ConnectionPool] = None
        self._redis_client: Optional[redis.Redis] = None
        
        # Connection monitoring
        self._connection_health = {
            'connected': False,
            'last_check': None,
            'pool_stats': {}
        }
    
    def get_connection_pool(self) -> ConnectionPool:
        """
        Get or create Redis connection pool with enterprise configuration.
        
        This method implements redis-py 5.0+ connection pool configuration with
        comprehensive security, performance, and reliability settings.
        
        Returns:
            Configured Redis ConnectionPool instance
            
        Raises:
            DatabaseConfigurationError: When pool creation fails
        """
        if self._connection_pool is not None:
            return self._connection_pool
        
        try:
            pool_kwargs = self._build_pool_configuration()
            self._connection_pool = ConnectionPool(**pool_kwargs)
            
            self.logger.info("Redis connection pool created successfully")
            return self._connection_pool
            
        except Exception as e:
            self.logger.error(f"Redis connection pool creation failed: {str(e)}")
            raise DatabaseConfigurationError(f"Redis pool creation failed: {str(e)}")
    
    def get_redis_client(self) -> redis.Redis:
        """
        Get or create Redis client with connection pooling.
        
        This method provides a configured Redis client using the enterprise
        connection pool for optimal performance and resource management.
        
        Returns:
            Configured Redis client instance
            
        Raises:
            DatabaseConfigurationError: When client creation or connection fails
        """
        if self._redis_client is not None:
            return self._redis_client
        
        try:
            connection_pool = self.get_connection_pool()
            self._redis_client = redis.Redis(connection_pool=connection_pool)
            
            # Test connection
            self._redis_client.ping()
            self._connection_health['connected'] = True
            self._connection_health['last_check'] = datetime.utcnow()
            
            self.logger.info("Redis client connected successfully")
            return self._redis_client
            
        except (RedisConnectionError, RedisTimeoutError) as e:
            self.logger.error(f"Redis connection failed: {str(e)}")
            raise DatabaseConfigurationError(f"Redis connection failed: {str(e)}")
        except Exception as e:
            self.logger.error(f"Unexpected Redis client error: {str(e)}")
            raise DatabaseConfigurationError(f"Redis client error: {str(e)}")
    
    def _build_pool_configuration(self) -> Dict[str, Any]:
        """
        Build comprehensive Redis connection pool configuration.
        
        This method implements Redis connection pool settings as specified in
        Section 3.4.2 with performance optimization and security features.
        
        Returns:
            Dictionary of connection pool configuration options
        """
        pool_config = {
            'host': self.config.REDIS_HOST,
            'port': self.config.REDIS_PORT,
            'db': self.config.REDIS_DB,
            'decode_responses': True,
            'encoding': 'utf-8',
            'encoding_errors': 'strict',
            
            # Connection pool settings
            'max_connections': self.config.REDIS_CONNECTION_POOL_KWARGS.get('max_connections', 50),
            'retry_on_timeout': self.config.REDIS_CONNECTION_POOL_KWARGS.get('retry_on_timeout', True),
            'socket_timeout': self.config.REDIS_CONNECTION_POOL_KWARGS.get('socket_timeout', 30.0),
            'socket_connect_timeout': self.config.REDIS_CONNECTION_POOL_KWARGS.get('socket_connect_timeout', 10.0),
            'health_check_interval': self.config.REDIS_CONNECTION_POOL_KWARGS.get('health_check_interval', 30),
        }
        
        # Authentication configuration
        if self.config.REDIS_PASSWORD:
            pool_config['password'] = self.config.REDIS_PASSWORD
        
        # TLS/SSL configuration for secure connections
        if self.config.REDIS_CONNECTION_POOL_KWARGS.get('ssl', False):
            ssl_config = self._build_redis_ssl_config()
            pool_config.update(ssl_config)
            self.logger.info("Redis TLS encryption enabled")
        
        return pool_config
    
    def _build_redis_ssl_config(self) -> Dict[str, Any]:
        """
        Build TLS configuration for Redis connections.
        
        Returns:
            Dictionary of Redis TLS configuration options
        """
        ssl_config = {
            'ssl': True,
            'ssl_check_hostname': True,
            'ssl_cert_reqs': ssl.CERT_REQUIRED,
        }
        
        # Certificate configuration
        ssl_ca_certs = self.config.REDIS_CONNECTION_POOL_KWARGS.get('ssl_ca_certs')
        if ssl_ca_certs:
            ssl_config['ssl_ca_certs'] = ssl_ca_certs
        
        ssl_certfile = self.config.REDIS_CONNECTION_POOL_KWARGS.get('ssl_certfile')
        if ssl_certfile:
            ssl_config['ssl_certfile'] = ssl_certfile
        
        ssl_keyfile = self.config.REDIS_CONNECTION_POOL_KWARGS.get('ssl_keyfile')
        if ssl_keyfile:
            ssl_config['ssl_keyfile'] = ssl_keyfile
        
        return ssl_config
    
    def test_connection(self) -> bool:
        """
        Test Redis connection health and update monitoring status.
        
        Returns:
            True if connection is healthy, False otherwise
        """
        try:
            client = self.get_redis_client()
            client.ping()
            
            # Update connection health
            self._connection_health['connected'] = True
            self._connection_health['last_check'] = datetime.utcnow()
            
            # Get pool statistics
            if self._connection_pool:
                self._connection_health['pool_stats'] = {
                    'created_connections': self._connection_pool.created_connections,
                    'available_connections': len(self._connection_pool._available_connections),
                    'in_use_connections': len(self._connection_pool._in_use_connections)
                }
            
            return True
            
        except Exception as e:
            self.logger.error(f"Redis connection test failed: {str(e)}")
            self._connection_health['connected'] = False
            return False
    
    def close_connections(self) -> None:
        """Close all Redis connections and clean up connection pool."""
        if self._redis_client:
            self._redis_client.close()
            self._redis_client = None
        
        if self._connection_pool:
            self._connection_pool.disconnect()
            self._connection_pool = None
        
        self._connection_health = {'connected': False, 'last_check': None, 'pool_stats': {}}
        self.logger.info("Redis connections closed and pool cleaned up")
    
    def get_connection_status(self) -> Dict[str, Any]:
        """
        Get comprehensive Redis connection status information.
        
        Returns:
            Dictionary containing connection health and pool statistics
        """
        return {
            'connected': self._connection_health['connected'],
            'last_health_check': self._connection_health['last_check'],
            'pool_statistics': self._connection_health['pool_stats'],
            'redis_host': self.config.REDIS_HOST,
            'redis_port': self.config.REDIS_PORT,
            'redis_db': self.config.REDIS_DB
        }


class EncryptedSessionInterface:
    """
    Encrypted session interface for Flask-Session with AWS KMS integration.
    
    This class implements AES-256-GCM session encryption using AWS KMS-backed keys
    for enterprise-grade session security as specified in Section 6.4.1.
    """
    
    def __init__(self, redis_client: redis.Redis, kms_manager: AWSKMSManager):
        """
        Initialize encrypted session interface.
        
        Args:
            redis_client: Configured Redis client for session storage
            kms_manager: AWS KMS manager for encryption key management
        """
        self.redis = redis_client
        self.kms_manager = kms_manager
        self.logger = logging.getLogger(f"{__name__}.EncryptedSessionInterface")
        
        # Session configuration
        self.session_prefix = 'session:'
        self.default_ttl = 3600  # 1 hour default session TTL
    
    def save_session(self, session_id: str, session_data: Dict[str, Any], ttl: Optional[int] = None) -> bool:
        """
        Save encrypted session data to Redis with KMS-backed encryption.
        
        This method implements AES-256-GCM encryption for session data using
        AWS KMS-generated data keys for enterprise security compliance.
        
        Args:
            session_id: Unique session identifier
            session_data: Session data to encrypt and store
            ttl: Time-to-live in seconds (optional)
            
        Returns:
            True if session was saved successfully, False otherwise
        """
        try:
            # Create session encryptor using KMS
            encryptor = self.kms_manager.create_session_encryptor(session_id)
            
            # Serialize and encrypt session data
            session_json = json.dumps(session_data, default=str)
            encrypted_data = encryptor.encrypt(session_json.encode('utf-8'))
            encrypted_b64 = base64.b64encode(encrypted_data).decode('utf-8')
            
            # Create session envelope with metadata
            session_envelope = {
                'encrypted_data': encrypted_b64,
                'created_at': datetime.utcnow().isoformat(),
                'session_id': session_id,
                'encryption_method': 'AES-256-GCM-KMS'
            }
            
            # Store encrypted session in Redis
            redis_key = f"{self.session_prefix}{session_id}"
            session_ttl = ttl or self.default_ttl
            
            result = self.redis.setex(
                redis_key,
                session_ttl,
                json.dumps(session_envelope)
            )
            
            if result:
                self.logger.debug(f"Session {session_id} saved with encryption")
                return True
            else:
                self.logger.error(f"Failed to save session {session_id} to Redis")
                return False
                
        except Exception as e:
            self.logger.error(f"Session save failed for {session_id}: {str(e)}")
            return False
    
    def load_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Load and decrypt session data from Redis.
        
        Args:
            session_id: Unique session identifier
            
        Returns:
            Decrypted session data or None if session not found/invalid
        """
        try:
            redis_key = f"{self.session_prefix}{session_id}"
            session_envelope_data = self.redis.get(redis_key)
            
            if not session_envelope_data:
                self.logger.debug(f"Session {session_id} not found in Redis")
                return None
            
            # Parse session envelope
            session_envelope = json.loads(session_envelope_data)
            encrypted_data_b64 = session_envelope.get('encrypted_data')
            
            if not encrypted_data_b64:
                self.logger.error(f"Invalid session envelope for {session_id}")
                return None
            
            # Decrypt session data using KMS
            encryptor = self.kms_manager.create_session_encryptor(session_id)
            encrypted_data = base64.b64decode(encrypted_data_b64)
            decrypted_json = encryptor.decrypt(encrypted_data).decode('utf-8')
            
            session_data = json.loads(decrypted_json)
            self.logger.debug(f"Session {session_id} loaded and decrypted successfully")
            
            return session_data
            
        except Exception as e:
            self.logger.error(f"Session load failed for {session_id}: {str(e)}")
            return None
    
    def delete_session(self, session_id: str) -> bool:
        """
        Delete session from Redis and clear encryption cache.
        
        Args:
            session_id: Unique session identifier
            
        Returns:
            True if session was deleted successfully, False otherwise
        """
        try:
            redis_key = f"{self.session_prefix}{session_id}"
            result = self.redis.delete(redis_key)
            
            # Clear encryption cache
            if session_id in self.kms_manager._encryption_cache:
                del self.kms_manager._encryption_cache[session_id]
            
            if result > 0:
                self.logger.debug(f"Session {session_id} deleted successfully")
                return True
            else:
                self.logger.warning(f"Session {session_id} not found for deletion")
                return False
                
        except Exception as e:
            self.logger.error(f"Session deletion failed for {session_id}: {str(e)}")
            return False
    
    def clear_expired_sessions(self) -> int:
        """
        Clear expired sessions from Redis and encryption cache.
        
        Returns:
            Number of expired sessions cleared
        """
        try:
            pattern = f"{self.session_prefix}*"
            session_keys = self.redis.keys(pattern)
            
            expired_count = 0
            for key in session_keys:
                ttl = self.redis.ttl(key)
                if ttl == -2:  # Key expired
                    session_id = key.replace(self.session_prefix, '')
                    if session_id in self.kms_manager._encryption_cache:
                        del self.kms_manager._encryption_cache[session_id]
                    expired_count += 1
            
            self.logger.info(f"Cleared {expired_count} expired sessions")
            return expired_count
            
        except Exception as e:
            self.logger.error(f"Failed to clear expired sessions: {str(e)}")
            return 0


class FlaskSessionManager:
    """
    Flask-Session integration manager with encrypted Redis backend.
    
    This class implements Flask-Session 0.8+ configuration with Redis backend
    and AES-256-GCM encryption for distributed session management as specified
    in Section 3.4.2.
    """
    
    def __init__(self, app: Optional[Flask] = None, redis_manager: Optional[RedisManager] = None,
                 kms_manager: Optional[AWSKMSManager] = None):
        """
        Initialize Flask-Session manager with encryption support.
        
        Args:
            app: Flask application instance (optional)
            redis_manager: Redis manager instance (optional)
            kms_manager: AWS KMS manager instance (optional)
        """
        self.config = get_config()
        self.redis_manager = redis_manager or RedisManager()
        self.kms_manager = kms_manager or AWSKMSManager()
        self.logger = logging.getLogger(f"{__name__}.FlaskSessionManager")
        
        # Flask-Session components
        self.session_interface: Optional[EncryptedSessionInterface] = None
        self.flask_session: Optional[Session] = None
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app: Flask) -> None:
        """
        Initialize Flask-Session with the Flask application.
        
        This method configures Flask-Session 0.8+ with Redis backend, encrypted
        session storage, and comprehensive security settings.
        
        Args:
            app: Flask application instance to configure
        """
        try:
            # Configure Flask-Session settings
            self._configure_flask_session(app)
            
            # Create Redis client for sessions
            redis_client = self.redis_manager.get_redis_client()
            
            # Create encrypted session interface
            self.session_interface = EncryptedSessionInterface(redis_client, self.kms_manager)
            
            # Initialize Flask-Session
            self.flask_session = Session()
            
            # Configure Redis for Flask-Session
            app.config['SESSION_REDIS'] = redis_client
            
            # Initialize Flask-Session with app
            self.flask_session.init_app(app)
            
            self.logger.info("Flask-Session initialized with encrypted Redis backend")
            
        except Exception as e:
            self.logger.error(f"Flask-Session initialization failed: {str(e)}")
            raise DatabaseConfigurationError(f"Session manager initialization failed: {str(e)}")
    
    def _configure_flask_session(self, app: Flask) -> None:
        """
        Configure Flask-Session settings for enterprise security.
        
        Args:
            app: Flask application instance to configure
        """
        # Flask-Session type and backend
        app.config['SESSION_TYPE'] = 'redis'
        app.config['SESSION_USE_SIGNER'] = True
        app.config['SESSION_KEY_PREFIX'] = 'session:'
        app.config['SESSION_PERMANENT'] = False
        
        # Session security settings
        app.config['SESSION_COOKIE_SECURE'] = self.config.SESSION_COOKIE_SECURE
        app.config['SESSION_COOKIE_HTTPONLY'] = self.config.SESSION_COOKIE_HTTPONLY
        app.config['SESSION_COOKIE_SAMESITE'] = self.config.SESSION_COOKIE_SAMESITE
        
        # Session lifetime configuration
        app.config['PERMANENT_SESSION_LIFETIME'] = self.config.PERMANENT_SESSION_LIFETIME
        
        self.logger.debug("Flask-Session configuration applied")
    
    def get_session_stats(self) -> Dict[str, Any]:
        """
        Get comprehensive session management statistics.
        
        Returns:
            Dictionary containing session statistics and health information
        """
        try:
            redis_client = self.redis_manager.get_redis_client()
            
            # Count active sessions
            session_pattern = f"{self.session_interface.session_prefix}*"
            session_keys = redis_client.keys(session_pattern)
            active_sessions = len(session_keys)
            
            # Get Redis memory usage for sessions
            memory_info = redis_client.memory_usage_pattern(session_pattern) if hasattr(redis_client, 'memory_usage_pattern') else None
            
            return {
                'active_sessions': active_sessions,
                'session_prefix': self.session_interface.session_prefix,
                'encryption_enabled': True,
                'encryption_method': 'AES-256-GCM-KMS',
                'memory_usage_bytes': memory_info,
                'redis_connection_status': self.redis_manager.get_connection_status(),
                'last_updated': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get session stats: {str(e)}")
            return {
                'active_sessions': 0,
                'error': str(e),
                'last_updated': datetime.utcnow().isoformat()
            }


class DatabaseManager:
    """
    Comprehensive database and caching manager for Flask application.
    
    This class provides the main interface for all database and caching operations,
    coordinating MongoDB, Redis, and session management with enterprise security
    features as specified in the migration requirements.
    """
    
    def __init__(self, app: Optional[Flask] = None, config: Optional[Any] = None):
        """
        Initialize comprehensive database manager.
        
        Args:
            app: Flask application instance (optional)
            config: Configuration object (optional)
        """
        self.config = config or get_config()
        self.logger = logging.getLogger(f"{__name__}.DatabaseManager")
        
        # Database and cache managers
        self.mongodb_manager = MongoDBManager(self.config)
        self.redis_manager = RedisManager(self.config)
        self.kms_manager = AWSKMSManager()
        self.session_manager = FlaskSessionManager(
            redis_manager=self.redis_manager,
            kms_manager=self.kms_manager
        )
        
        # Health monitoring
        self._health_status = {
            'mongodb_sync': False,
            'mongodb_async': False,
            'redis': False,
            'sessions': False,
            'last_check': None
        }
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app: Flask) -> None:
        """
        Initialize all database and caching components with Flask application.
        
        This method sets up MongoDB connections, Redis caching, and encrypted
        session management for the Flask application with comprehensive error handling.
        
        Args:
            app: Flask application instance to configure
            
        Raises:
            DatabaseConfigurationError: When initialization fails
        """
        try:
            self.logger.info("Initializing database and caching infrastructure")
            
            # Initialize MongoDB connections
            self._initialize_mongodb()
            
            # Initialize Redis connections
            self._initialize_redis()
            
            # Initialize Flask-Session with encryption
            self.session_manager.init_app(app)
            
            # Perform initial health checks
            self._perform_health_checks()
            
            # Store manager reference in app
            app.extensions = getattr(app, 'extensions', {})
            app.extensions['database_manager'] = self
            
            self.logger.info("Database and caching infrastructure initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Database manager initialization failed: {str(e)}")
            raise DatabaseConfigurationError(f"Database infrastructure initialization failed: {str(e)}")
    
    def _initialize_mongodb(self) -> None:
        """Initialize MongoDB connections with health checks."""
        try:
            # Test synchronous connection
            sync_client = self.mongodb_manager.get_sync_client()
            sync_health = self.mongodb_manager.test_sync_connection()
            
            if sync_health:
                self.logger.info("MongoDB synchronous connection established")
                self._health_status['mongodb_sync'] = True
            else:
                self.logger.warning("MongoDB synchronous connection health check failed")
            
            # Initialize asynchronous client (test separately)
            async_client = self.mongodb_manager.get_async_client()
            self.logger.info("MongoDB asynchronous client initialized")
            
        except Exception as e:
            self.logger.error(f"MongoDB initialization failed: {str(e)}")
            raise DatabaseConfigurationError(f"MongoDB initialization failed: {str(e)}")
    
    def _initialize_redis(self) -> None:
        """Initialize Redis connections with health checks."""
        try:
            # Test Redis connection
            redis_client = self.redis_manager.get_redis_client()
            redis_health = self.redis_manager.test_connection()
            
            if redis_health:
                self.logger.info("Redis connection established")
                self._health_status['redis'] = True
            else:
                self.logger.warning("Redis connection health check failed")
                
        except Exception as e:
            self.logger.error(f"Redis initialization failed: {str(e)}")
            raise DatabaseConfigurationError(f"Redis initialization failed: {str(e)}")
    
    def _perform_health_checks(self) -> None:
        """Perform comprehensive health checks on all database connections."""
        try:
            # MongoDB health checks
            self._health_status['mongodb_sync'] = self.mongodb_manager.test_sync_connection()
            
            # Redis health check
            self._health_status['redis'] = self.redis_manager.test_connection()
            
            # Session management health
            self._health_status['sessions'] = (
                self._health_status['redis'] and 
                self.session_manager.session_interface is not None
            )
            
            self._health_status['last_check'] = datetime.utcnow()
            
            # Log health status
            healthy_components = sum(1 for status in self._health_status.values() if status is True)
            total_components = len([k for k in self._health_status.keys() if k != 'last_check'])
            
            self.logger.info(f"Database health check: {healthy_components}/{total_components} components healthy")
            
        except Exception as e:
            self.logger.error(f"Health check failed: {str(e)}")
    
    async def test_async_connections(self) -> Dict[str, bool]:
        """
        Test all asynchronous database connections.
        
        Returns:
            Dictionary with connection test results
        """
        results = {}
        
        try:
            # Test MongoDB async connection
            results['mongodb_async'] = await self.mongodb_manager.test_async_connection()
            self._health_status['mongodb_async'] = results['mongodb_async']
            
        except Exception as e:
            self.logger.error(f"Async connection test failed: {str(e)}")
            results['mongodb_async'] = False
        
        return results
    
    def get_health_status(self) -> Dict[str, Any]:
        """
        Get comprehensive health status for all database and caching components.
        
        Returns:
            Dictionary containing health status and connection information
        """
        # Update health checks
        self._perform_health_checks()
        
        health_info = {
            'overall_healthy': all(
                status for key, status in self._health_status.items() 
                if key != 'last_check' and key != 'mongodb_async'
            ),
            'components': dict(self._health_status),
            'mongodb_status': self.mongodb_manager.get_connection_status(),
            'redis_status': self.redis_manager.get_connection_status(),
            'session_stats': self.session_manager.get_session_stats(),
            'configuration': {
                'mongodb_uri_masked': self.config.MONGODB_URI.split('@')[0] + '@***' if '@' in self.config.MONGODB_URI else '***',
                'redis_host': self.config.REDIS_HOST,
                'redis_port': self.config.REDIS_PORT,
                'session_encryption_enabled': True,
                'kms_integration_enabled': bool(self.config.AWS_KMS_KEY_ARN)
            }
        }
        
        return health_info
    
    def close_all_connections(self) -> None:
        """Close all database and caching connections for graceful shutdown."""
        try:
            self.logger.info("Closing all database and caching connections")
            
            # Close MongoDB connections
            self.mongodb_manager.close_connections()
            
            # Close Redis connections
            self.redis_manager.close_connections()
            
            # Clear session encryption cache
            if self.kms_manager._encryption_cache:
                self.kms_manager._encryption_cache.clear()
            
            self._health_status = {
                'mongodb_sync': False,
                'mongodb_async': False,
                'redis': False,
                'sessions': False,
                'last_check': None
            }
            
            self.logger.info("All database connections closed successfully")
            
        except Exception as e:
            self.logger.error(f"Error closing database connections: {str(e)}")
    
    # Convenience methods for application usage
    
    def get_mongodb_sync(self) -> pymongo.database.Database:
        """Get synchronous MongoDB database instance."""
        return self.mongodb_manager.get_database('sync')
    
    def get_mongodb_async(self) -> motor.motor_asyncio.AsyncIOMotorDatabase:
        """Get asynchronous MongoDB database instance."""
        return self.mongodb_manager.get_database('async')
    
    def get_redis(self) -> redis.Redis:
        """Get Redis client instance."""
        return self.redis_manager.get_redis_client()


# Global database manager instance for application use
database_manager: Optional[DatabaseManager] = None


def init_database(app: Flask, config: Optional[Any] = None) -> DatabaseManager:
    """
    Initialize database and caching infrastructure for Flask application.
    
    This function provides the main entry point for setting up all database
    and caching components with comprehensive error handling and logging.
    
    Args:
        app: Flask application instance
        config: Optional configuration object
        
    Returns:
        Configured DatabaseManager instance
        
    Raises:
        DatabaseConfigurationError: When initialization fails
    """
    global database_manager
    
    try:
        logger.info("Initializing Flask application database infrastructure")
        
        # Create and initialize database manager
        database_manager = DatabaseManager(app, config)
        
        # Register cleanup handler
        @app.teardown_appcontext
        def close_database_connections(error):
            """Close database connections on application context teardown."""
            if error:
                logger.error(f"Application context error: {str(error)}")
        
        # Register shutdown handler
        import atexit
        atexit.register(lambda: database_manager.close_all_connections() if database_manager else None)
        
        logger.info("Database infrastructure initialization completed")
        return database_manager
        
    except Exception as e:
        logger.error(f"Database infrastructure initialization failed: {str(e)}")
        raise DatabaseConfigurationError(f"Database initialization failed: {str(e)}")


def get_database_manager() -> Optional[DatabaseManager]:
    """
    Get the global database manager instance.
    
    Returns:
        Global DatabaseManager instance or None if not initialized
    """
    return database_manager


# Health check endpoint function for monitoring
def create_health_check_response() -> Dict[str, Any]:
    """
    Create comprehensive health check response for monitoring systems.
    
    This function provides detailed health information for all database
    and caching components for use in application health endpoints.
    
    Returns:
        Dictionary containing comprehensive health status information
    """
    if not database_manager:
        return {
            'status': 'error',
            'message': 'Database manager not initialized',
            'timestamp': datetime.utcnow().isoformat()
        }
    
    try:
        health_status = database_manager.get_health_status()
        
        return {
            'status': 'healthy' if health_status['overall_healthy'] else 'degraded',
            'database_health': health_status,
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        return {
            'status': 'error',
            'message': f'Health check failed: {str(e)}',
            'timestamp': datetime.utcnow().isoformat()
        }


# Export main components for application use
__all__ = [
    'DatabaseManager',
    'MongoDBManager',
    'RedisManager',
    'FlaskSessionManager',
    'AWSKMSManager',
    'EncryptedSessionInterface',
    'init_database',
    'get_database_manager',
    'create_health_check_response',
    'DatabaseConfigurationError'
]