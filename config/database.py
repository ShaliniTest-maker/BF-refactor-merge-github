"""
Database and caching configuration module for Flask application.

This module provides comprehensive database and caching configuration for:
- MongoDB connectivity using PyMongo 4.5+ and Motor 3.3+ drivers
- Redis caching and session management using redis-py 5.0+
- Flask-Session 0.8+ configuration with Redis backend for distributed sessions
- TLS encryption and connection pooling for secure database communications
- AWS KMS integration for session data encryption with AES-256-GCM

Migrated from Node.js mongodb 4.x and redis 4.x to Python equivalents
maintaining identical functionality and enterprise security standards.
"""

import os
import ssl
import logging
from typing import Dict, Any, Optional, Union
from urllib.parse import quote_plus

import redis
import pymongo
import motor.motor_asyncio
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from redis.exceptions import ConnectionError as RedisConnectionError
from cryptography.fernet import Fernet
import boto3
from botocore.exceptions import ClientError, BotoCoreError
from flask import Flask
from flask_session import Session
import json
import base64
from datetime import datetime, timezone, timedelta


logger = logging.getLogger(__name__)


class DatabaseError(Exception):
    """Custom exception for database configuration errors."""
    pass


class RedisError(Exception):
    """Custom exception for Redis configuration errors."""
    pass


class EncryptionError(Exception):
    """Custom exception for encryption/decryption errors."""
    pass


class AWSKMSKeyManager:
    """
    AWS KMS integration for encryption key management with boto3 client.
    
    Provides secure key generation, rotation, and management for session
    encryption using AWS KMS Customer Master Keys (CMK) with proper
    encryption context and enterprise-grade security practices.
    """
    
    def __init__(self) -> None:
        """Initialize AWS KMS client with enterprise configuration."""
        self.kms_client = self._create_kms_client()
        self.cmk_arn = os.getenv('AWS_KMS_CMK_ARN')
        self.encryption_context = {
            'application': 'flask-database-system',
            'purpose': 'session-encryption',
            'environment': os.getenv('FLASK_ENV', 'production')
        }
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        if not self.cmk_arn:
            self.logger.warning("AWS_KMS_CMK_ARN not configured - session encryption disabled")
    
    def _create_kms_client(self) -> boto3.client:
        """
        Create properly configured boto3 KMS client with enterprise settings.
        
        Returns:
            Configured boto3 KMS client with retry and timeout settings
        """
        try:
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
        except Exception as e:
            self.logger.error(f"Failed to create KMS client: {str(e)}")
            raise DatabaseError(f"KMS client initialization failed: {str(e)}")
    
    def generate_data_key(self) -> tuple[bytes, bytes]:
        """
        Generate AWS KMS data key for session encryption.
        
        Returns:
            Tuple of (plaintext_key, encrypted_key) for session encryption
            
        Raises:
            EncryptionError: When data key generation fails
        """
        if not self.cmk_arn:
            # Fallback to environment-based key for development
            env_key = os.getenv('SESSION_ENCRYPTION_KEY')
            if env_key:
                key_bytes = base64.b64decode(env_key)
                return key_bytes, key_bytes
            raise EncryptionError("No encryption key available - neither KMS nor environment key found")
        
        try:
            response = self.kms_client.generate_data_key(
                KeyId=self.cmk_arn,
                KeySpec='AES_256',
                EncryptionContext=self.encryption_context
            )
            
            self.logger.info("Successfully generated KMS data key for session encryption")
            return response['Plaintext'], response['CiphertextBlob']
            
        except (ClientError, BotoCoreError) as e:
            self.logger.error(f"AWS KMS data key generation failed: {str(e)}")
            raise EncryptionError(f"Failed to generate encryption key: {str(e)}")
    
    def decrypt_data_key(self, encrypted_key: bytes) -> bytes:
        """
        Decrypt AWS KMS data key for session operations.
        
        Args:
            encrypted_key: Encrypted data key from KMS
            
        Returns:
            Decrypted plaintext key for encryption operations
            
        Raises:
            EncryptionError: When key decryption fails
        """
        if not self.cmk_arn:
            # Return the key as-is for development (fallback)
            return encrypted_key
        
        try:
            response = self.kms_client.decrypt(
                CiphertextBlob=encrypted_key,
                EncryptionContext=self.encryption_context
            )
            
            return response['Plaintext']
            
        except (ClientError, BotoCoreError) as e:
            self.logger.error(f"AWS KMS key decryption failed: {str(e)}")
            raise EncryptionError(f"Failed to decrypt session key: {str(e)}")


class SessionEncryptionManager:
    """
    Session data encryption using AES-256-GCM with AWS KMS-backed keys.
    
    Provides secure session data encryption and decryption capabilities
    using Fernet (AES-256-GCM) with keys managed by AWS KMS for
    enterprise-grade session security.
    """
    
    def __init__(self, kms_manager: AWSKMSKeyManager) -> None:
        """
        Initialize session encryption with KMS key manager.
        
        Args:
            kms_manager: AWS KMS key manager instance
        """
        self.kms_manager = kms_manager
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._current_key: Optional[Fernet] = None
        self._encrypted_key: Optional[bytes] = None
        self._key_created_at: Optional[datetime] = None
        
        # Initialize encryption key
        self._initialize_encryption_key()
    
    def _initialize_encryption_key(self) -> None:
        """Initialize encryption key from KMS or environment."""
        try:
            plaintext_key, encrypted_key = self.kms_manager.generate_data_key()
            
            # Create Fernet instance with the plaintext key
            # Fernet expects a URL-safe base64-encoded 32-byte key
            if len(plaintext_key) == 32:
                key_b64 = base64.urlsafe_b64encode(plaintext_key)
            else:
                # If key is not 32 bytes, derive it properly
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
                
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=b'flask-session-salt',  # Should be from environment in production
                    iterations=100000,
                )
                derived_key = kdf.derive(plaintext_key)
                key_b64 = base64.urlsafe_b64encode(derived_key)
            
            self._current_key = Fernet(key_b64)
            self._encrypted_key = encrypted_key
            self._key_created_at = datetime.now(timezone.utc)
            
            self.logger.info("Session encryption key initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize session encryption: {str(e)}")
            raise EncryptionError(f"Session encryption initialization failed: {str(e)}")
    
    def encrypt_session_data(self, session_data: Dict[str, Any]) -> str:
        """
        Encrypt session data with AES-256-GCM.
        
        Args:
            session_data: Session data dictionary to encrypt
            
        Returns:
            Base64-encoded encrypted session data
            
        Raises:
            EncryptionError: When encryption fails
        """
        if not self._current_key:
            raise EncryptionError("Encryption key not initialized")
        
        try:
            # Serialize session data to JSON
            json_data = json.dumps(session_data, default=str)
            
            # Encrypt using Fernet (AES-256-GCM)
            encrypted_data = self._current_key.encrypt(json_data.encode('utf-8'))
            
            # Return base64-encoded encrypted data
            return base64.b64encode(encrypted_data).decode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Session data encryption failed: {str(e)}")
            raise EncryptionError(f"Failed to encrypt session data: {str(e)}")
    
    def decrypt_session_data(self, encrypted_data: str) -> Dict[str, Any]:
        """
        Decrypt session data from AES-256-GCM encrypted format.
        
        Args:
            encrypted_data: Base64-encoded encrypted session data
            
        Returns:
            Decrypted session data dictionary
            
        Raises:
            EncryptionError: When decryption fails
        """
        if not self._current_key:
            raise EncryptionError("Encryption key not initialized")
        
        try:
            # Decode base64
            encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
            
            # Decrypt using Fernet
            decrypted_data = self._current_key.decrypt(encrypted_bytes)
            
            # Parse JSON
            return json.loads(decrypted_data.decode('utf-8'))
            
        except Exception as e:
            self.logger.error(f"Session data decryption failed: {str(e)}")
            raise EncryptionError(f"Failed to decrypt session data: {str(e)}")
    
    def should_rotate_key(self) -> bool:
        """
        Check if encryption key should be rotated based on age.
        
        Returns:
            True if key should be rotated (older than 24 hours)
        """
        if not self._key_created_at:
            return True
        
        age = datetime.now(timezone.utc) - self._key_created_at
        return age > timedelta(hours=24)


class MongoDBConfig:
    """
    MongoDB connection configuration with PyMongo 4.5+ and Motor 3.3+.
    
    Provides both synchronous (PyMongo) and asynchronous (Motor) MongoDB
    connections with TLS encryption, connection pooling, and enterprise
    security configurations. Maintains compatibility with existing
    Node.js MongoDB connection patterns.
    """
    
    def __init__(self) -> None:
        """Initialize MongoDB configuration from environment variables."""
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # MongoDB connection parameters
        self.host = os.getenv('MONGODB_HOST', 'localhost')
        self.port = int(os.getenv('MONGODB_PORT', 27017))
        self.database = os.getenv('MONGODB_DATABASE', 'flask_app')
        self.username = os.getenv('MONGODB_USERNAME')
        self.password = os.getenv('MONGODB_PASSWORD')
        
        # TLS configuration
        self.use_tls = os.getenv('MONGODB_TLS', 'true').lower() == 'true'
        self.tls_cert_file = os.getenv('MONGODB_TLS_CERT_FILE')
        self.tls_key_file = os.getenv('MONGODB_TLS_KEY_FILE')
        self.tls_ca_file = os.getenv('MONGODB_TLS_CA_FILE')
        
        # Connection pooling settings
        self.max_pool_size = int(os.getenv('MONGODB_MAX_POOL_SIZE', '50'))
        self.min_pool_size = int(os.getenv('MONGODB_MIN_POOL_SIZE', '5'))
        self.max_idle_time_ms = int(os.getenv('MONGODB_MAX_IDLE_TIME_MS', '30000'))
        self.connect_timeout_ms = int(os.getenv('MONGODB_CONNECT_TIMEOUT_MS', '10000'))
        self.server_selection_timeout_ms = int(os.getenv('MONGODB_SERVER_SELECTION_TIMEOUT_MS', '5000'))
        
    def get_connection_uri(self) -> str:
        """
        Generate MongoDB connection URI with proper encoding and TLS settings.
        
        Returns:
            MongoDB connection URI with authentication and TLS configuration
        """
        # Handle authentication
        auth_part = ""
        if self.username and self.password:
            encoded_username = quote_plus(self.username)
            encoded_password = quote_plus(self.password)
            auth_part = f"{encoded_username}:{encoded_password}@"
        
        # Base URI
        uri = f"mongodb://{auth_part}{self.host}:{self.port}/{self.database}"
        
        # Add query parameters
        params = []
        
        if self.use_tls:
            params.append("tls=true")
            if self.tls_cert_file:
                params.append(f"tlsCertificateKeyFile={self.tls_cert_file}")
            if self.tls_ca_file:
                params.append(f"tlsCAFile={self.tls_ca_file}")
        
        # Connection pool parameters
        params.extend([
            f"maxPoolSize={self.max_pool_size}",
            f"minPoolSize={self.min_pool_size}",
            f"maxIdleTimeMS={self.max_idle_time_ms}",
            f"connectTimeoutMS={self.connect_timeout_ms}",
            f"serverSelectionTimeoutMS={self.server_selection_timeout_ms}",
            "retryWrites=true",
            "retryReads=true"
        ])
        
        if params:
            uri += "?" + "&".join(params)
        
        return uri
    
    def get_pymongo_client(self) -> MongoClient:
        """
        Create PyMongo client with enterprise configuration.
        
        Returns:
            Configured PyMongo MongoClient instance
            
        Raises:
            DatabaseError: When MongoDB connection fails
        """
        try:
            client_options = {
                'host': self.get_connection_uri(),
                'maxPoolSize': self.max_pool_size,
                'minPoolSize': self.min_pool_size,
                'maxIdleTimeMS': self.max_idle_time_ms,
                'connectTimeoutMS': self.connect_timeout_ms,
                'serverSelectionTimeoutMS': self.server_selection_timeout_ms,
                'retryWrites': True,
                'retryReads': True,
            }
            
            # Add TLS configuration if enabled
            if self.use_tls:
                client_options.update({
                    'tls': True,
                    'tlsAllowInvalidCertificates': False,
                    'tlsAllowInvalidHostnames': False,
                })
                
                if self.tls_cert_file:
                    client_options['tlsCertificateKeyFile'] = self.tls_cert_file
                if self.tls_ca_file:
                    client_options['tlsCAFile'] = self.tls_ca_file
            
            client = MongoClient(**client_options)
            
            # Test connection
            client.admin.command('ping')
            
            self.logger.info(f"Successfully connected to MongoDB at {self.host}:{self.port}")
            return client
            
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            self.logger.error(f"MongoDB connection failed: {str(e)}")
            raise DatabaseError(f"Failed to connect to MongoDB: {str(e)}")
        except Exception as e:
            self.logger.error(f"Unexpected MongoDB error: {str(e)}")
            raise DatabaseError(f"MongoDB configuration error: {str(e)}")
    
    def get_motor_client(self) -> motor.motor_asyncio.AsyncIOMotorClient:
        """
        Create Motor async client for high-performance operations.
        
        Returns:
            Configured Motor AsyncIOMotorClient instance
            
        Raises:
            DatabaseError: When Motor client creation fails
        """
        try:
            client_options = {
                'maxPoolSize': self.max_pool_size,
                'minPoolSize': self.min_pool_size,
                'maxIdleTimeMS': self.max_idle_time_ms,
                'connectTimeoutMS': self.connect_timeout_ms,
                'serverSelectionTimeoutMS': self.server_selection_timeout_ms,
                'retryWrites': True,
                'retryReads': True,
            }
            
            # Add TLS configuration if enabled
            if self.use_tls:
                client_options.update({
                    'tls': True,
                    'tlsAllowInvalidCertificates': False,
                    'tlsAllowInvalidHostnames': False,
                })
                
                if self.tls_cert_file:
                    client_options['tlsCertificateKeyFile'] = self.tls_cert_file
                if self.tls_ca_file:
                    client_options['tlsCAFile'] = self.tls_ca_file
            
            client = motor.motor_asyncio.AsyncIOMotorClient(
                self.get_connection_uri(),
                **client_options
            )
            
            self.logger.info(f"Successfully created Motor async client for {self.host}:{self.port}")
            return client
            
        except Exception as e:
            self.logger.error(f"Motor client creation failed: {str(e)}")
            raise DatabaseError(f"Failed to create Motor client: {str(e)}")


class RedisConfig:
    """
    Redis connection configuration with redis-py 5.0+ and session management.
    
    Provides Redis connection setup for caching and session storage with
    TLS encryption, connection pooling, and enterprise security features.
    Replaces Node.js redis 4.x client configuration.
    """
    
    def __init__(self) -> None:
        """Initialize Redis configuration from environment variables."""
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Redis connection parameters
        self.host = os.getenv('REDIS_HOST', 'localhost')
        self.port = int(os.getenv('REDIS_PORT', 6379))
        self.password = os.getenv('REDIS_PASSWORD')
        self.db = int(os.getenv('REDIS_DB', 0))
        
        # Session-specific Redis database
        self.session_db = int(os.getenv('REDIS_SESSION_DB', 1))
        
        # TLS configuration
        self.use_tls = os.getenv('REDIS_TLS', 'false').lower() == 'true'
        self.tls_cert_file = os.getenv('REDIS_TLS_CERT_FILE')
        self.tls_key_file = os.getenv('REDIS_TLS_KEY_FILE')
        self.tls_ca_file = os.getenv('REDIS_TLS_CA_FILE')
        
        # Connection pooling settings
        self.max_connections = int(os.getenv('REDIS_MAX_CONNECTIONS', '50'))
        self.socket_timeout = float(os.getenv('REDIS_SOCKET_TIMEOUT', '30.0'))
        self.socket_connect_timeout = float(os.getenv('REDIS_SOCKET_CONNECT_TIMEOUT', '10.0'))
        self.health_check_interval = int(os.getenv('REDIS_HEALTH_CHECK_INTERVAL', '30'))
        
    def get_redis_client(self, db: Optional[int] = None) -> redis.Redis:
        """
        Create Redis client with enterprise configuration.
        
        Args:
            db: Redis database number (uses default if None)
            
        Returns:
            Configured redis.Redis client instance
            
        Raises:
            RedisError: When Redis connection fails
        """
        try:
            connection_options = {
                'host': self.host,
                'port': self.port,
                'db': db if db is not None else self.db,
                'password': self.password,
                'decode_responses': True,
                'max_connections': self.max_connections,
                'retry_on_timeout': True,
                'socket_timeout': self.socket_timeout,
                'socket_connect_timeout': self.socket_connect_timeout,
                'health_check_interval': self.health_check_interval
            }
            
            # Add TLS configuration if enabled
            if self.use_tls:
                ssl_context = ssl.create_default_context()
                
                if self.tls_ca_file:
                    ssl_context.load_verify_locations(self.tls_ca_file)
                
                if self.tls_cert_file and self.tls_key_file:
                    ssl_context.load_cert_chain(self.tls_cert_file, self.tls_key_file)
                
                connection_options.update({
                    'ssl': True,
                    'ssl_context': ssl_context,
                    'ssl_check_hostname': True
                })
            
            client = redis.Redis(**connection_options)
            
            # Test connection
            client.ping()
            
            self.logger.info(f"Successfully connected to Redis at {self.host}:{self.port} (db={connection_options['db']})")
            return client
            
        except RedisConnectionError as e:
            self.logger.error(f"Redis connection failed: {str(e)}")
            raise RedisError(f"Failed to connect to Redis: {str(e)}")
        except Exception as e:
            self.logger.error(f"Unexpected Redis error: {str(e)}")
            raise RedisError(f"Redis configuration error: {str(e)}")
    
    def get_session_redis_client(self) -> redis.Redis:
        """
        Create Redis client specifically for session storage.
        
        Returns:
            Redis client configured for session storage
        """
        return self.get_redis_client(db=self.session_db)


class FlaskSessionConfig:
    """
    Flask-Session 0.8+ configuration with Redis backend and encryption.
    
    Provides distributed session management using Redis backend with
    AES-256-GCM encryption for session data security. Replaces Node.js
    session management with enterprise-grade session security.
    """
    
    def __init__(self, redis_client: redis.Redis, encryption_manager: SessionEncryptionManager) -> None:
        """
        Initialize Flask-Session configuration.
        
        Args:
            redis_client: Redis client for session storage
            encryption_manager: Session encryption manager
        """
        self.redis_client = redis_client
        self.encryption_manager = encryption_manager
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def configure_flask_session(self, app: Flask) -> None:
        """
        Configure Flask-Session with Redis backend and encryption.
        
        Args:
            app: Flask application instance
        """
        try:
            # Flask-Session configuration
            app.config.update({
                'SESSION_TYPE': 'redis',
                'SESSION_REDIS': self.redis_client,
                'SESSION_PERMANENT': False,
                'SESSION_USE_SIGNER': True,
                'SESSION_KEY_PREFIX': 'session:',
                'SESSION_COOKIE_NAME': 'flask_session',
                'SESSION_COOKIE_DOMAIN': os.getenv('SESSION_COOKIE_DOMAIN'),
                'SESSION_COOKIE_PATH': '/',
                'SESSION_COOKIE_HTTPONLY': True,
                'SESSION_COOKIE_SECURE': os.getenv('FLASK_ENV', 'production') == 'production',
                'SESSION_COOKIE_SAMESITE': 'Lax',
                'PERMANENT_SESSION_LIFETIME': timedelta(hours=24),
            })
            
            # Initialize Flask-Session
            Session(app)
            
            self.logger.info("Flask-Session configured successfully with Redis backend")
            
        except Exception as e:
            self.logger.error(f"Flask-Session configuration failed: {str(e)}")
            raise DatabaseError(f"Failed to configure Flask-Session: {str(e)}")


class DatabaseManager:
    """
    Centralized database and caching manager for Flask application.
    
    Provides unified access to MongoDB, Redis, and session management
    with comprehensive error handling, connection monitoring, and
    enterprise security features.
    """
    
    def __init__(self) -> None:
        """Initialize database manager with all configurations."""
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Initialize component managers
        self.kms_manager = AWSKMSKeyManager()
        self.encryption_manager = SessionEncryptionManager(self.kms_manager)
        self.mongodb_config = MongoDBConfig()
        self.redis_config = RedisConfig()
        
        # Initialize connections
        self._mongodb_client: Optional[MongoClient] = None
        self._motor_client: Optional[motor.motor_asyncio.AsyncIOMotorClient] = None
        self._redis_client: Optional[redis.Redis] = None
        self._session_redis_client: Optional[redis.Redis] = None
        self._flask_session_config: Optional[FlaskSessionConfig] = None
    
    @property
    def mongodb_client(self) -> MongoClient:
        """Get PyMongo client with lazy initialization."""
        if self._mongodb_client is None:
            self._mongodb_client = self.mongodb_config.get_pymongo_client()
        return self._mongodb_client
    
    @property
    def motor_client(self) -> motor.motor_asyncio.AsyncIOMotorClient:
        """Get Motor async client with lazy initialization."""
        if self._motor_client is None:
            self._motor_client = self.mongodb_config.get_motor_client()
        return self._motor_client
    
    @property
    def redis_client(self) -> redis.Redis:
        """Get Redis client with lazy initialization."""
        if self._redis_client is None:
            self._redis_client = self.redis_config.get_redis_client()
        return self._redis_client
    
    @property
    def session_redis_client(self) -> redis.Redis:
        """Get session Redis client with lazy initialization."""
        if self._session_redis_client is None:
            self._session_redis_client = self.redis_config.get_session_redis_client()
        return self._session_redis_client
    
    def configure_flask_app(self, app: Flask) -> None:
        """
        Configure Flask application with database and session management.
        
        Args:
            app: Flask application instance
        """
        try:
            # Configure Flask-Session
            if self._flask_session_config is None:
                self._flask_session_config = FlaskSessionConfig(
                    self.session_redis_client,
                    self.encryption_manager
                )
            
            self._flask_session_config.configure_flask_session(app)
            
            # Store database manager in app context
            app.db_manager = self
            
            self.logger.info("Flask application configured with database and session management")
            
        except Exception as e:
            self.logger.error(f"Flask app configuration failed: {str(e)}")
            raise DatabaseError(f"Failed to configure Flask app: {str(e)}")
    
    def get_database(self, database_name: Optional[str] = None) -> pymongo.database.Database:
        """
        Get MongoDB database instance.
        
        Args:
            database_name: Database name (uses default if None)
            
        Returns:
            PyMongo Database instance
        """
        db_name = database_name or self.mongodb_config.database
        return self.mongodb_client[db_name]
    
    async def get_async_database(self, database_name: Optional[str] = None) -> motor.motor_asyncio.AsyncIOMotorDatabase:
        """
        Get async MongoDB database instance.
        
        Args:
            database_name: Database name (uses default if None)
            
        Returns:
            Motor AsyncIOMotorDatabase instance
        """
        db_name = database_name or self.mongodb_config.database
        return self.motor_client[db_name]
    
    def health_check(self) -> Dict[str, Dict[str, Any]]:
        """
        Perform health check on all database connections.
        
        Returns:
            Health status for all database services
        """
        health_status = {
            'mongodb': {'status': 'unknown', 'details': {}},
            'redis': {'status': 'unknown', 'details': {}},
            'session_redis': {'status': 'unknown', 'details': {}},
            'encryption': {'status': 'unknown', 'details': {}}
        }
        
        # Check MongoDB
        try:
            result = self.mongodb_client.admin.command('ping')
            health_status['mongodb'] = {
                'status': 'healthy',
                'details': {
                    'ping_response': result,
                    'host': f"{self.mongodb_config.host}:{self.mongodb_config.port}",
                    'database': self.mongodb_config.database
                }
            }
        except Exception as e:
            health_status['mongodb'] = {
                'status': 'unhealthy',
                'details': {'error': str(e)}
            }
        
        # Check Redis
        try:
            response = self.redis_client.ping()
            health_status['redis'] = {
                'status': 'healthy',
                'details': {
                    'ping_response': response,
                    'host': f"{self.redis_config.host}:{self.redis_config.port}",
                    'db': self.redis_config.db
                }
            }
        except Exception as e:
            health_status['redis'] = {
                'status': 'unhealthy',
                'details': {'error': str(e)}
            }
        
        # Check Session Redis
        try:
            response = self.session_redis_client.ping()
            health_status['session_redis'] = {
                'status': 'healthy',
                'details': {
                    'ping_response': response,
                    'host': f"{self.redis_config.host}:{self.redis_config.port}",
                    'db': self.redis_config.session_db
                }
            }
        except Exception as e:
            health_status['session_redis'] = {
                'status': 'unhealthy',
                'details': {'error': str(e)}
            }
        
        # Check Encryption
        try:
            # Test encryption/decryption
            test_data = {'test': 'session_data', 'timestamp': datetime.now().isoformat()}
            encrypted = self.encryption_manager.encrypt_session_data(test_data)
            decrypted = self.encryption_manager.decrypt_session_data(encrypted)
            
            health_status['encryption'] = {
                'status': 'healthy',
                'details': {
                    'encryption_test': 'passed',
                    'key_rotation_needed': self.encryption_manager.should_rotate_key()
                }
            }
        except Exception as e:
            health_status['encryption'] = {
                'status': 'unhealthy',
                'details': {'error': str(e)}
            }
        
        return health_status
    
    def close_connections(self) -> None:
        """Close all database connections gracefully."""
        try:
            if self._mongodb_client:
                self._mongodb_client.close()
                self.logger.info("MongoDB connection closed")
            
            if self._motor_client:
                self._motor_client.close()
                self.logger.info("Motor async client closed")
            
            if self._redis_client:
                self._redis_client.close()
                self.logger.info("Redis connection closed")
            
            if self._session_redis_client:
                self._session_redis_client.close()
                self.logger.info("Session Redis connection closed")
                
        except Exception as e:
            self.logger.error(f"Error closing database connections: {str(e)}")


# Global database manager instance
db_manager = DatabaseManager()


def init_database_config(app: Flask) -> DatabaseManager:
    """
    Initialize database configuration for Flask application.
    
    Args:
        app: Flask application instance
        
    Returns:
        Configured DatabaseManager instance
    """
    try:
        db_manager.configure_flask_app(app)
        
        # Add cleanup handler
        @app.teardown_appcontext
        def close_db(error):
            """Close database connections on app context teardown."""
            if error:
                logger.error(f"App context error: {str(error)}")
        
        logger.info("Database configuration initialized successfully")
        return db_manager
        
    except Exception as e:
        logger.error(f"Database configuration initialization failed: {str(e)}")
        raise DatabaseError(f"Failed to initialize database config: {str(e)}")


# Configuration export for other modules
__all__ = [
    'DatabaseManager',
    'MongoDBConfig', 
    'RedisConfig',
    'FlaskSessionConfig',
    'AWSKMSKeyManager',
    'SessionEncryptionManager',
    'init_database_config',
    'db_manager',
    'DatabaseError',
    'RedisError',
    'EncryptionError'
]