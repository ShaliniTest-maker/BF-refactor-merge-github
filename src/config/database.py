"""
Database connectivity configuration for MongoDB and Redis.

This module implements database connectivity configuration for the Node.js to Python Flask migration,
providing PyMongo 4.5+ synchronous and Motor 3.3+ asynchronous database drivers with optimized
connection pooling to ensure ≤10% performance variance from Node.js baseline.

Key Components:
- MongoDB synchronous connection management via PyMongo 4.5+
- MongoDB asynchronous connection management via Motor 3.3+
- Redis caching configuration via redis-py 5.0+
- Optimized connection pooling for enterprise-grade performance
- Environment-specific database configuration support
- Comprehensive error handling and connection monitoring

Technical Requirements:
- Database driver conversion from Node.js MongoDB drivers to PyMongo/Motor per Section 0.1.1
- Redis client migration from Node.js to redis-py 5.0+ per Section 0.1.2
- Connection pool management with equivalent patterns per Section 0.1.2
- Performance optimization to ensure ≤10% variance from Node.js baseline per Section 0.1.1
"""

import os
import logging
from typing import Optional, Dict, Any, Union
from urllib.parse import quote_plus

import pymongo
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from motor.motor_asyncio import AsyncIOMotorClient
import redis
from redis.connection import ConnectionPool
from redis.exceptions import ConnectionError as RedisConnectionError, TimeoutError as RedisTimeoutError

# Configure module logger
logger = logging.getLogger(__name__)


class DatabaseConnectionError(Exception):
    """Custom exception for database connection failures."""
    pass


class DatabaseConfig:
    """
    Centralized database configuration class managing MongoDB and Redis connections.
    
    This class implements the database connectivity configuration specified in the technical
    migration requirements, providing optimized connection pooling patterns equivalent to
    the Node.js implementation while ensuring enterprise-grade performance and reliability.
    
    Features:
    - PyMongo 4.5+ synchronous MongoDB driver configuration
    - Motor 3.3+ asynchronous MongoDB driver configuration  
    - redis-py 5.0+ Redis client configuration
    - Optimized connection pool settings per Section 6.1.3
    - Environment-specific configuration management
    - Comprehensive connection monitoring and error handling
    """
    
    def __init__(self, environment: str = 'development'):
        """
        Initialize database configuration for specified environment.
        
        Args:
            environment: Target environment ('development', 'testing', 'production')
        """
        self.environment = environment.lower()
        self._mongo_client: Optional[MongoClient] = None
        self._motor_client: Optional[AsyncIOMotorClient] = None
        self._redis_client: Optional[redis.Redis] = None
        self._redis_pool: Optional[ConnectionPool] = None
        
        # Load environment-specific configuration
        self._load_configuration()
        
        logger.info(f"DatabaseConfig initialized for environment: {self.environment}")
    
    def _load_configuration(self) -> None:
        """
        Load database configuration from environment variables.
        
        Supports environment-specific configuration loading while preserving
        existing MongoDB connection strings and query patterns per Section 0.1.3.
        """
        # MongoDB Configuration
        self.mongodb_uri = os.getenv('MONGODB_URI', self._get_default_mongodb_uri())
        self.mongodb_database = os.getenv('MONGODB_DATABASE', self._get_default_database_name())
        
        # Redis Configuration  
        self.redis_host = os.getenv('REDIS_HOST', 'localhost')
        self.redis_port = int(os.getenv('REDIS_PORT', '6379'))
        self.redis_password = os.getenv('REDIS_PASSWORD')
        self.redis_db = int(os.getenv('REDIS_DB', '0'))
        self.redis_ssl = os.getenv('REDIS_SSL', 'false').lower() == 'true'
        
        # Connection Pool Configuration per Section 6.1.3 Resource Optimization
        self._configure_connection_pools()
        
    def _get_default_mongodb_uri(self) -> str:
        """Generate default MongoDB URI based on environment."""
        if self.environment == 'testing':
            return 'mongodb://localhost:27017/test_database'
        elif self.environment == 'production':
            # Production URI should be provided via environment variables
            return os.getenv('MONGODB_URI', 'mongodb://localhost:27017/production_database')
        else:
            return 'mongodb://localhost:27017/development_database'
    
    def _get_default_database_name(self) -> str:
        """Get default database name based on environment."""
        env_suffix = {
            'development': 'dev',
            'testing': 'test', 
            'production': 'prod'
        }
        return f"application_{env_suffix.get(self.environment, 'dev')}"
    
    def _configure_connection_pools(self) -> None:
        """
        Configure optimized connection pool settings per Section 6.1.3.
        
        MongoDB Connection Pool Configuration:
        - maxPoolSize=50 for concurrent connections
        - waitQueueTimeoutMS=30000 for connection acquisition timeout
        - serverSelectionTimeoutMS=10000 for replica set operations
        
        Motor Async Driver Configuration:
        - maxPoolSize=100 for enhanced async throughput
        - waitQueueMultiple=2 for async operation optimization
        
        Redis Connection Pool Settings:
        - max_connections=50 for connection pool size
        - retry_on_timeout=True for automatic reconnection
        - socket_timeout=30.0 for individual operation timeout
        - socket_connect_timeout=10.0 for initial connection establishment
        """
        # MongoDB Synchronous Connection Pool Settings
        self.mongodb_pool_config = {
            'maxPoolSize': 50,
            'minPoolSize': 5,
            'maxIdleTimeMS': 30000,
            'waitQueueTimeoutMS': 30000,
            'serverSelectionTimeoutMS': 10000,
            'connectTimeoutMS': 10000,
            'socketTimeoutMS': 30000,
            'heartbeatFrequencyMS': 10000,
            'retryWrites': True,
            'retryReads': True
        }
        
        # Motor Async Connection Pool Settings  
        self.motor_pool_config = {
            'maxPoolSize': 100,
            'minPoolSize': 10,
            'maxIdleTimeMS': 30000,
            'waitQueueTimeoutMS': 30000,
            'waitQueueMultiple': 2,
            'serverSelectionTimeoutMS': 10000,
            'connectTimeoutMS': 10000,
            'socketTimeoutMS': 30000,
            'heartbeatFrequencyMS': 10000,
            'retryWrites': True,
            'retryReads': True
        }
        
        # Redis Connection Pool Settings
        self.redis_pool_config = {
            'max_connections': 50,
            'retry_on_timeout': True,
            'socket_timeout': 30.0,
            'socket_connect_timeout': 10.0,
            'socket_keepalive': True,
            'socket_keepalive_options': {},
            'health_check_interval': 30
        }
    
    def get_mongodb_client(self) -> MongoClient:
        """
        Get PyMongo 4.5+ synchronous MongoDB client with optimized connection pooling.
        
        Implements connection management patterns equivalent to Node.js MongoDB driver
        while providing enhanced connection pooling for enterprise-grade performance.
        
        Returns:
            MongoClient: Configured PyMongo client instance
            
        Raises:
            DatabaseConnectionError: If MongoDB connection cannot be established
        """
        if self._mongo_client is None:
            try:
                logger.info("Initializing PyMongo 4.5+ synchronous MongoDB client")
                
                self._mongo_client = MongoClient(
                    self.mongodb_uri,
                    **self.mongodb_pool_config
                )
                
                # Test connection
                self._mongo_client.admin.command('ping')
                logger.info("PyMongo MongoDB client connection established successfully")
                
            except (ConnectionFailure, ServerSelectionTimeoutError) as e:
                error_msg = f"Failed to connect to MongoDB: {str(e)}"
                logger.error(error_msg)
                raise DatabaseConnectionError(error_msg) from e
            except Exception as e:
                error_msg = f"Unexpected error connecting to MongoDB: {str(e)}"
                logger.error(error_msg)
                raise DatabaseConnectionError(error_msg) from e
        
        return self._mongo_client
    
    def get_motor_client(self) -> AsyncIOMotorClient:
        """
        Get Motor 3.3+ asynchronous MongoDB client for high-performance async operations.
        
        Implements async MongoDB driver configuration per Section 0.1.2 data access
        components with enhanced connection pooling for non-blocking database operations.
        
        Returns:
            AsyncIOMotorClient: Configured Motor async client instance
            
        Raises:
            DatabaseConnectionError: If Motor async connection cannot be established
        """
        if self._motor_client is None:
            try:
                logger.info("Initializing Motor 3.3+ asynchronous MongoDB client")
                
                self._motor_client = AsyncIOMotorClient(
                    self.mongodb_uri,
                    **self.motor_pool_config
                )
                
                logger.info("Motor async MongoDB client initialized successfully")
                
            except Exception as e:
                error_msg = f"Failed to initialize Motor async client: {str(e)}"
                logger.error(error_msg)
                raise DatabaseConnectionError(error_msg) from e
        
        return self._motor_client
    
    def get_redis_client(self) -> redis.Redis:
        """
        Get redis-py 5.0+ Redis client with optimized connection pooling.
        
        Implements Redis client migration from Node.js to redis-py 5.0+ per Section 0.1.2
        with connection pool management equivalent to existing patterns.
        
        Returns:
            redis.Redis: Configured Redis client instance
            
        Raises:
            DatabaseConnectionError: If Redis connection cannot be established
        """
        if self._redis_client is None:
            try:
                logger.info("Initializing redis-py 5.0+ Redis client")
                
                # Create connection pool
                self._redis_pool = ConnectionPool(
                    host=self.redis_host,
                    port=self.redis_port,
                    password=self.redis_password,
                    db=self.redis_db,
                    ssl=self.redis_ssl,
                    **self.redis_pool_config
                )
                
                # Create Redis client with connection pool
                self._redis_client = redis.Redis(
                    connection_pool=self._redis_pool,
                    decode_responses=True
                )
                
                # Test connection
                self._redis_client.ping()
                logger.info("Redis client connection established successfully")
                
            except (RedisConnectionError, RedisTimeoutError) as e:
                error_msg = f"Failed to connect to Redis: {str(e)}"
                logger.error(error_msg)
                raise DatabaseConnectionError(error_msg) from e
            except Exception as e:
                error_msg = f"Unexpected error connecting to Redis: {str(e)}"
                logger.error(error_msg)
                raise DatabaseConnectionError(error_msg) from e
        
        return self._redis_client
    
    def get_database(self, database_name: Optional[str] = None) -> pymongo.database.Database:
        """
        Get MongoDB database instance from synchronous client.
        
        Args:
            database_name: Database name (defaults to configured database)
            
        Returns:
            pymongo.database.Database: MongoDB database instance
        """
        client = self.get_mongodb_client()
        db_name = database_name or self.mongodb_database
        return client[db_name]
    
    def get_async_database(self, database_name: Optional[str] = None):
        """
        Get MongoDB database instance from asynchronous Motor client.
        
        Args:
            database_name: Database name (defaults to configured database)
            
        Returns:
            motor.motor_asyncio.AsyncIOMotorDatabase: Async MongoDB database instance
        """
        client = self.get_motor_client()
        db_name = database_name or self.mongodb_database
        return client[db_name]
    
    def close_connections(self) -> None:
        """
        Close all database connections and clean up resources.
        
        Implements proper connection cleanup for graceful application shutdown
        while ensuring connection pool resources are properly released.
        """
        try:
            if self._mongo_client:
                logger.info("Closing PyMongo client connection")
                self._mongo_client.close()
                self._mongo_client = None
            
            if self._motor_client:
                logger.info("Closing Motor async client connection")
                self._motor_client.close()
                self._motor_client = None
            
            if self._redis_client:
                logger.info("Closing Redis client connection")
                self._redis_client.close()
                self._redis_client = None
            
            if self._redis_pool:
                logger.info("Closing Redis connection pool")
                self._redis_pool.disconnect()
                self._redis_pool = None
            
            logger.info("All database connections closed successfully")
            
        except Exception as e:
            logger.error(f"Error closing database connections: {str(e)}")
    
    def health_check(self) -> Dict[str, Any]:
        """
        Perform health check on all database connections.
        
        Returns:
            Dict[str, Any]: Health status for each database connection
        """
        health_status = {
            'mongodb': {'status': 'unknown', 'details': None},
            'redis': {'status': 'unknown', 'details': None}
        }
        
        # MongoDB Health Check
        try:
            client = self.get_mongodb_client()
            result = client.admin.command('ping')
            health_status['mongodb'] = {
                'status': 'healthy',
                'details': f"Connection successful, response: {result}"
            }
        except Exception as e:
            health_status['mongodb'] = {
                'status': 'unhealthy',
                'details': f"Connection failed: {str(e)}"
            }
        
        # Redis Health Check
        try:
            redis_client = self.get_redis_client()
            redis_client.ping()
            health_status['redis'] = {
                'status': 'healthy',
                'details': "Connection successful, ping response: PONG"
            }
        except Exception as e:
            health_status['redis'] = {
                'status': 'unhealthy',
                'details': f"Connection failed: {str(e)}"
            }
        
        return health_status
    
    def get_connection_info(self) -> Dict[str, Any]:
        """
        Get detailed connection configuration information.
        
        Returns:
            Dict[str, Any]: Connection configuration details for monitoring
        """
        return {
            'environment': self.environment,
            'mongodb': {
                'uri_masked': self._mask_credentials(self.mongodb_uri),
                'database': self.mongodb_database,
                'pool_config': self.mongodb_pool_config
            },
            'motor': {
                'uri_masked': self._mask_credentials(self.mongodb_uri),
                'database': self.mongodb_database,
                'pool_config': self.motor_pool_config
            },
            'redis': {
                'host': self.redis_host,
                'port': self.redis_port,
                'database': self.redis_db,
                'ssl': self.redis_ssl,
                'pool_config': self.redis_pool_config
            }
        }
    
    def _mask_credentials(self, uri: str) -> str:
        """
        Mask credentials in URI for logging/monitoring purposes.
        
        Args:
            uri: Database URI potentially containing credentials
            
        Returns:
            str: URI with masked credentials
        """
        try:
            if '@' in uri:
                protocol_and_creds, host_and_path = uri.split('@', 1)
                if '://' in protocol_and_creds:
                    protocol, creds = protocol_and_creds.split('://', 1)
                    if ':' in creds:
                        user, _ = creds.split(':', 1)
                        return f"{protocol}://{user}:***@{host_and_path}"
                    else:
                        return f"{protocol}://{creds}:***@{host_and_path}"
            return uri
        except Exception:
            return "***URI_MASKED***"


# Global database configuration instance
db_config: Optional[DatabaseConfig] = None


def init_database_config(environment: str = 'development') -> DatabaseConfig:
    """
    Initialize global database configuration instance.
    
    Args:
        environment: Target environment for configuration
        
    Returns:
        DatabaseConfig: Initialized database configuration instance
    """
    global db_config
    db_config = DatabaseConfig(environment)
    logger.info(f"Global database configuration initialized for environment: {environment}")
    return db_config


def get_database_config() -> DatabaseConfig:
    """
    Get global database configuration instance.
    
    Returns:
        DatabaseConfig: Global database configuration instance
        
    Raises:
        RuntimeError: If database configuration has not been initialized
    """
    if db_config is None:
        raise RuntimeError(
            "Database configuration not initialized. "
            "Call init_database_config() first."
        )
    return db_config


def get_mongodb_client() -> MongoClient:
    """
    Get PyMongo synchronous MongoDB client from global configuration.
    
    Returns:
        MongoClient: Configured PyMongo client instance
    """
    return get_database_config().get_mongodb_client()


def get_motor_client() -> AsyncIOMotorClient:
    """
    Get Motor asynchronous MongoDB client from global configuration.
    
    Returns:
        AsyncIOMotorClient: Configured Motor async client instance
    """
    return get_database_config().get_motor_client()


def get_redis_client() -> redis.Redis:
    """
    Get Redis client from global configuration.
    
    Returns:
        redis.Redis: Configured Redis client instance
    """
    return get_database_config().get_redis_client()


def get_database(database_name: Optional[str] = None) -> pymongo.database.Database:
    """
    Get MongoDB database instance from global configuration.
    
    Args:
        database_name: Database name (defaults to configured database)
        
    Returns:
        pymongo.database.Database: MongoDB database instance
    """
    return get_database_config().get_database(database_name)


def get_async_database(database_name: Optional[str] = None):
    """
    Get async MongoDB database instance from global configuration.
    
    Args:
        database_name: Database name (defaults to configured database)
        
    Returns:
        motor.motor_asyncio.AsyncIOMotorDatabase: Async MongoDB database instance
    """
    return get_database_config().get_async_database(database_name)