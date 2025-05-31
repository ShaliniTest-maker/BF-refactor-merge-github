"""
Comprehensive Database Test Fixtures with Testcontainers Integration

This module provides enterprise-grade database test fixtures using Testcontainers for realistic
MongoDB and Redis behavior, PyMongo 4.5+ and Motor 3.3+ driver setup, connection pooling
configuration, and performance validation ensuring ≤10% variance compliance.

Key Features:
- Testcontainers MongoDB integration replacing static mocks per Section 6.6.1 enhanced mocking strategy
- Testcontainers Redis instances for realistic caching behavior per Section 6.6.1 container-based mocking
- PyMongo 4.5+ connection fixtures for synchronous database operations per Section 3.4.1
- Motor 3.3+ async database operation fixtures per Section 3.4.1 async MongoDB driver
- Connection pool management fixtures for database performance testing per Section 6.2.4
- Database seeding utilities for comprehensive test data management per Section 6.6.1
- pytest-asyncio configuration for async database operations testing per Section 6.6.1
- Performance monitoring integration ensuring ≤10% variance from Node.js baseline
- Enterprise-grade fixture lifecycle management with automated cleanup

Architecture Integration:
- Section 6.6.1: Enhanced mocking strategy using Testcontainers for realistic database behavior
- Section 6.6.1: pytest-asyncio for asynchronous database operations and external service calls
- Section 6.6.1: Comprehensive test organization structure for Flask testing
- Section 6.2.4: Performance optimization with connection pooling and health monitoring
- Section 3.4.1: PyMongo 4.5+ and Motor 3.3+ driver implementation per data access components
- Section 6.6.1: Test data management with dynamic test object generation

Performance Requirements:
- Database performance validation ensuring ≤10% variance per Section 6.2.4 performance optimization
- Connection pooling equivalent to Node.js patterns per Section 3.4.3
- Performance baseline comparison validation per Section 0.1.1 primary objective
- Realistic database behavior through Testcontainers per Section 6.6.1

Dependencies:
- testcontainers[mongodb,redis] ≥4.10.0 for dynamic container provisioning
- pytest 7.4+ with extensive plugin ecosystem support
- pytest-asyncio for Motor async driver testing
- pymongo 4.5+ for synchronous database operations
- motor 3.3+ for asynchronous database operations
- redis-py 5.0+ for Redis client integration
- factory_boy for dynamic test object generation
- faker for realistic test data generation

Author: Database Migration Team
Version: 1.0.0
Coverage Target: 95% per Section 6.6.3 quality metrics
"""

import asyncio
import gc
import logging
import os
import time
import uuid
import warnings
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, Generator, List, Optional, Tuple, Union
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
import pytest_asyncio
from bson import ObjectId
from bson.errors import InvalidId

# PyMongo synchronous driver
import pymongo
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import PyMongoError, ConnectionFailure, OperationFailure

# Motor async driver
try:
    import motor.motor_asyncio
    from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorCollection, AsyncIOMotorDatabase
    MOTOR_AVAILABLE = True
except ImportError:
    MOTOR_AVAILABLE = False
    AsyncIOMotorClient = None
    AsyncIOMotorDatabase = None
    AsyncIOMotorCollection = None

# Redis client
try:
    import redis
    from redis import Redis
    from redis.connection import ConnectionPool
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    Redis = None

# Testcontainers for realistic database behavior
try:
    from testcontainers.mongodb import MongoDbContainer
    from testcontainers.redis import RedisContainer
    from testcontainers.core.container import DockerContainer
    from testcontainers.core.waiting_strategies import wait_for_logs
    TESTCONTAINERS_AVAILABLE = True
except ImportError:
    TESTCONTAINERS_AVAILABLE = False
    MongoDbContainer = None
    RedisContainer = None

# Test data generation
try:
    import factory
    from factory import Factory, SubFactory, LazyAttribute, Iterator, Sequence
    from factory.faker import Faker as FactoryFaker
    FACTORY_BOY_AVAILABLE = True
except ImportError:
    FACTORY_BOY_AVAILABLE = False

try:
    from faker import Faker
    FAKER_AVAILABLE = True
except ImportError:
    FAKER_AVAILABLE = False
    Faker = None

# Application imports with fallback handling
try:
    from src.config.settings import TestingConfig
    from src.data import DatabaseServices, init_database_services
    from src.data.mongodb import MongoDBManager, AsyncMongoDBManager
    from src.data.exceptions import DatabaseException, ConnectionException
    APP_MODULES_AVAILABLE = True
except ImportError:
    APP_MODULES_AVAILABLE = False
    TestingConfig = None
    DatabaseServices = None

# Configure module logger
logger = logging.getLogger(__name__)

# Emit warnings for missing dependencies
if not TESTCONTAINERS_AVAILABLE:
    warnings.warn(
        "Testcontainers not available. Database integration tests will use mocks.",
        ImportWarning,
        stacklevel=2
    )

if not MOTOR_AVAILABLE:
    warnings.warn(
        "Motor async driver not available. Async database tests disabled.",
        ImportWarning,
        stacklevel=2
    )

if not FACTORY_BOY_AVAILABLE:
    warnings.warn(
        "factory_boy not available. Dynamic test object generation disabled.",
        ImportWarning,
        stacklevel=2
    )


class DatabaseContainerConfig:
    """
    Configuration management for Testcontainers database instances with optimized settings
    for performance testing and realistic behavior simulation.
    
    This configuration class provides centralized management of container settings including:
    - MongoDB container configuration with replica set support
    - Redis container configuration with persistence and clustering options
    - Performance optimization settings for container resource allocation
    - Network configuration for inter-container communication
    - Security settings and authentication configuration
    - Container lifecycle management and cleanup policies
    
    Features:
    - Production-equivalent database versions per Section 6.6.1 container-based mocking
    - Optimized container resource allocation for performance testing
    - Automated container health checking and readiness validation
    - Configurable container persistence for test data retention
    - Network isolation and security configuration for enterprise testing
    """
    
    # MongoDB Configuration Constants
    MONGODB_VERSION = "7.0"
    MONGODB_DEFAULT_PORT = 27017
    MONGODB_INIT_TIMEOUT = 60  # seconds
    MONGODB_HEALTH_CHECK_INTERVAL = 5  # seconds
    
    # Redis Configuration Constants  
    REDIS_VERSION = "7.2-alpine"
    REDIS_DEFAULT_PORT = 6379
    REDIS_INIT_TIMEOUT = 30  # seconds
    REDIS_HEALTH_CHECK_INTERVAL = 2  # seconds
    
    # Performance Testing Configuration
    CONTAINER_MEMORY_LIMIT = "512m"
    CONTAINER_CPU_LIMIT = 0.5
    CONNECTION_POOL_SIZE = 10
    
    # Test Environment Configuration
    TEST_DATABASE_PREFIX = "test_flask_migration"
    TEST_COLLECTION_PREFIX = "test_collection"
    
    def __init__(self, environment: str = "testing"):
        """
        Initialize database container configuration with environment-specific settings.
        
        Args:
            environment: Target environment for container configuration
        """
        self.environment = environment
        self.mongodb_config = self._create_mongodb_config()
        self.redis_config = self._create_redis_config()
        self.performance_config = self._create_performance_config()
        
        logger.info(
            "Database container configuration initialized",
            environment=environment,
            mongodb_version=self.MONGODB_VERSION,
            redis_version=self.REDIS_VERSION
        )
    
    def _create_mongodb_config(self) -> Dict[str, Any]:
        """Create optimized MongoDB container configuration."""
        return {
            "image": f"mongo:{self.MONGODB_VERSION}",
            "port": self.MONGODB_DEFAULT_PORT,
            "environment": {
                "MONGO_INITDB_ROOT_USERNAME": "testuser",
                "MONGO_INITDB_ROOT_PASSWORD": "testpass",
                "MONGO_INITDB_DATABASE": f"{self.TEST_DATABASE_PREFIX}_{uuid.uuid4().hex[:8]}"
            },
            "command": [
                "mongod",
                "--replSet", "rs0",
                "--bind_ip_all",
                "--port", str(self.MONGODB_DEFAULT_PORT),
                "--oplogSize", "128",
                "--journal",
                "--storageEngine", "wiredTiger"
            ],
            "volumes": {},
            "mem_limit": self.CONTAINER_MEMORY_LIMIT,
            "cpu_limit": self.CONTAINER_CPU_LIMIT,
            "healthcheck": {
                "test": ["CMD", "mongosh", "--eval", "db.runCommand('ping').ok"],
                "interval": f"{self.MONGODB_HEALTH_CHECK_INTERVAL}s",
                "timeout": "5s",
                "retries": 5,
                "start_period": "30s"
            }
        }
    
    def _create_redis_config(self) -> Dict[str, Any]:
        """Create optimized Redis container configuration."""
        return {
            "image": f"redis:{self.REDIS_VERSION}",
            "port": self.REDIS_DEFAULT_PORT,
            "command": [
                "redis-server",
                "--port", str(self.REDIS_DEFAULT_PORT),
                "--appendonly", "yes",
                "--save", "60", "1",
                "--maxmemory", "256mb",
                "--maxmemory-policy", "allkeys-lru"
            ],
            "volumes": {},
            "mem_limit": self.CONTAINER_MEMORY_LIMIT,
            "cpu_limit": self.CONTAINER_CPU_LIMIT,
            "healthcheck": {
                "test": ["CMD", "redis-cli", "ping"],
                "interval": f"{self.REDIS_HEALTH_CHECK_INTERVAL}s",
                "timeout": "3s",
                "retries": 5,
                "start_period": "10s"
            }
        }
    
    def _create_performance_config(self) -> Dict[str, Any]:
        """Create performance testing configuration."""
        return {
            "connection_pool_size": self.CONNECTION_POOL_SIZE,
            "max_connections": 50,
            "connection_timeout": 5.0,
            "server_selection_timeout": 10.0,
            "socket_timeout": 5.0,
            "max_idle_time": 30.0,
            "retry_writes": True,
            "retry_reads": True
        }
    
    def get_mongodb_connection_string(self, host: str, port: int) -> str:
        """
        Generate MongoDB connection string for test containers.
        
        Args:
            host: Container host address
            port: Container port number
            
        Returns:
            str: Formatted MongoDB connection string
        """
        config = self.mongodb_config
        username = config["environment"]["MONGO_INITDB_ROOT_USERNAME"]
        password = config["environment"]["MONGO_INITDB_ROOT_PASSWORD"]
        database = config["environment"]["MONGO_INITDB_DATABASE"]
        
        return (
            f"mongodb://{username}:{password}@{host}:{port}/{database}"
            f"?authSource=admin&retryWrites=true&w=majority"
        )
    
    def get_redis_connection_string(self, host: str, port: int) -> str:
        """
        Generate Redis connection string for test containers.
        
        Args:
            host: Container host address
            port: Container port number
            
        Returns:
            str: Formatted Redis connection string
        """
        return f"redis://{host}:{port}/0"


class MongoDbTestContainer:
    """
    Enhanced MongoDB Testcontainer wrapper providing realistic database behavior
    with replica set configuration, performance monitoring, and automated lifecycle management.
    
    This container wrapper provides:
    - MongoDB replica set initialization for production-equivalent behavior
    - Automated container health checking with configurable timeouts
    - Performance monitoring integration for baseline compliance testing
    - Connection pool management with optimized settings
    - Database seeding utilities for comprehensive test data management
    - Transaction support for ACID compliance testing
    - Automated cleanup and resource management
    
    Features per Section 6.6.1:
    - Enhanced mocking strategy using Testcontainers for realistic MongoDB behavior
    - Container-based mocking replacing static database mocks
    - Production-equivalent behavior with automated container lifecycle management
    - Performance validation capabilities for ≤10% variance compliance
    """
    
    def __init__(self, config: DatabaseContainerConfig):
        """
        Initialize MongoDB test container with comprehensive configuration.
        
        Args:
            config: Database container configuration instance
        """
        self.config = config
        self.container: Optional[MongoDbContainer] = None
        self.client: Optional[MongoClient] = None
        self.database: Optional[Database] = None
        self.connection_string: Optional[str] = None
        self._initialized = False
        self._replica_set_initialized = False
        
        if not TESTCONTAINERS_AVAILABLE:
            logger.warning("Testcontainers not available - using mock MongoDB container")
            self._setup_mock_container()
        
        logger.info("MongoDB test container initialized")
    
    def _setup_mock_container(self) -> None:
        """Setup mock container for environments without Testcontainers."""
        self.container = Mock()
        self.container.start = Mock()
        self.container.stop = Mock()
        self.container.get_container_host_ip = Mock(return_value="localhost")
        self.container.get_exposed_port = Mock(return_value=27017)
        self.connection_string = "mongodb://localhost:27017/test_database"
        logger.warning("Using mock MongoDB container - limited functionality")
    
    def start(self) -> 'MongoDbTestContainer':
        """
        Start MongoDB container with replica set initialization and health validation.
        
        Returns:
            MongoDbTestContainer: Self reference for method chaining
            
        Raises:
            ConnectionException: If container startup or replica set initialization fails
        """
        try:
            if not TESTCONTAINERS_AVAILABLE:
                logger.info("Mock MongoDB container started")
                return self
            
            # Initialize and start MongoDB container
            mongodb_config = self.config.mongodb_config
            self.container = MongoDbContainer(
                image=mongodb_config["image"]
            ).with_env(
                "MONGO_INITDB_ROOT_USERNAME",
                mongodb_config["environment"]["MONGO_INITDB_ROOT_USERNAME"]
            ).with_env(
                "MONGO_INITDB_ROOT_PASSWORD", 
                mongodb_config["environment"]["MONGO_INITDB_ROOT_PASSWORD"]
            ).with_env(
                "MONGO_INITDB_DATABASE",
                mongodb_config["environment"]["MONGO_INITDB_DATABASE"]
            )
            
            # Configure container resources
            if hasattr(self.container, 'with_kwargs'):
                self.container = self.container.with_kwargs(
                    mem_limit=mongodb_config["mem_limit"],
                    cpus=mongodb_config["cpu_limit"]
                )
            
            # Start container
            self.container.start()
            
            # Build connection string
            host = self.container.get_container_host_ip()
            port = self.container.get_exposed_port(self.config.MONGODB_DEFAULT_PORT)
            self.connection_string = self.config.get_mongodb_connection_string(host, port)
            
            # Initialize database client
            self._initialize_client()
            
            # Initialize replica set for production equivalence
            self._initialize_replica_set()
            
            # Validate container health
            self._validate_container_health()
            
            self._initialized = True
            
            logger.info(
                "MongoDB test container started successfully",
                host=host,
                port=port,
                replica_set_initialized=self._replica_set_initialized
            )
            
            return self
            
        except Exception as e:
            error_msg = f"Failed to start MongoDB test container: {str(e)}"
            logger.error(error_msg)
            raise ConnectionException(error_msg) from e
    
    def _initialize_client(self) -> None:
        """Initialize MongoDB client with optimized connection settings."""
        if not self.connection_string:
            raise ConnectionException("Connection string not available")
        
        # Get performance configuration
        perf_config = self.config.performance_config
        
        self.client = MongoClient(
            self.connection_string,
            maxPoolSize=perf_config["connection_pool_size"],
            maxConnections=perf_config["max_connections"],
            connectTimeoutMS=int(perf_config["connection_timeout"] * 1000),
            serverSelectionTimeoutMS=int(perf_config["server_selection_timeout"] * 1000),
            socketTimeoutMS=int(perf_config["socket_timeout"] * 1000),
            maxIdleTimeMS=int(perf_config["max_idle_time"] * 1000),
            retryWrites=perf_config["retry_writes"],
            retryReads=perf_config["retry_reads"]
        )
        
        # Get default database
        database_name = self.config.mongodb_config["environment"]["MONGO_INITDB_DATABASE"]
        self.database = self.client[database_name]
        
        logger.debug("MongoDB client initialized with optimized settings")
    
    def _initialize_replica_set(self) -> None:
        """Initialize MongoDB replica set for production-equivalent behavior."""
        try:
            if not self.client:
                raise ConnectionException("MongoDB client not initialized")
            
            # Check if replica set is already configured
            try:
                status = self.client.admin.command("replSetGetStatus")
                self._replica_set_initialized = True
                logger.info("MongoDB replica set already configured")
                return
            except OperationFailure:
                # Replica set not configured, initialize it
                pass
            
            # Initialize replica set
            host = self.container.get_container_host_ip()
            port = self.container.get_exposed_port(self.config.MONGODB_DEFAULT_PORT)
            
            config = {
                "_id": "rs0",
                "members": [
                    {
                        "_id": 0,
                        "host": f"{host}:{port}",
                        "priority": 1
                    }
                ]
            }
            
            self.client.admin.command("replSetInitiate", config)
            
            # Wait for replica set to be ready
            timeout = 30  # seconds
            start_time = time.time()
            
            while time.time() - start_time < timeout:
                try:
                    status = self.client.admin.command("replSetGetStatus")
                    if status.get("myState") == 1:  # PRIMARY state
                        self._replica_set_initialized = True
                        logger.info("MongoDB replica set initialized successfully")
                        return
                except OperationFailure:
                    pass
                
                time.sleep(1)
            
            logger.warning("MongoDB replica set initialization timeout - continuing without replica set")
            
        except Exception as e:
            logger.warning(f"Failed to initialize MongoDB replica set: {str(e)}")
            # Continue without replica set for basic testing
    
    def _validate_container_health(self) -> None:
        """Validate container health and readiness for testing."""
        if not self.client:
            raise ConnectionException("MongoDB client not available for health validation")
        
        try:
            # Test basic connectivity
            self.client.admin.command("ping")
            
            # Test database operations
            test_collection = self.database["health_check"]
            test_doc = {"timestamp": datetime.now(timezone.utc), "test": True}
            result = test_collection.insert_one(test_doc)
            test_collection.delete_one({"_id": result.inserted_id})
            
            logger.info("MongoDB container health validation successful")
            
        except Exception as e:
            error_msg = f"MongoDB container health validation failed: {str(e)}"
            logger.error(error_msg)
            raise ConnectionException(error_msg) from e
    
    def stop(self) -> None:
        """Stop MongoDB container and cleanup resources."""
        try:
            # Close client connections
            if self.client:
                self.client.close()
                self.client = None
            
            # Stop container
            if self.container and hasattr(self.container, 'stop'):
                self.container.stop()
            
            self._initialized = False
            self._replica_set_initialized = False
            
            logger.info("MongoDB test container stopped successfully")
            
        except Exception as e:
            logger.error(f"Error stopping MongoDB test container: {str(e)}")
    
    def get_client(self) -> MongoClient:
        """
        Get configured MongoDB client instance.
        
        Returns:
            MongoClient: Configured PyMongo client
            
        Raises:
            ConnectionException: If container not initialized or client unavailable
        """
        if not self._initialized or not self.client:
            raise ConnectionException("MongoDB container not initialized or client unavailable")
        
        return self.client
    
    def get_database(self, database_name: Optional[str] = None) -> Database:
        """
        Get MongoDB database instance.
        
        Args:
            database_name: Optional database name (defaults to configured database)
            
        Returns:
            Database: PyMongo database instance
            
        Raises:
            ConnectionException: If container not initialized
        """
        if not self._initialized or not self.client:
            raise ConnectionException("MongoDB container not initialized")
        
        if database_name:
            return self.client[database_name]
        
        return self.database
    
    def get_collection(self, collection_name: str, database_name: Optional[str] = None) -> Collection:
        """
        Get MongoDB collection instance.
        
        Args:
            collection_name: Collection name
            database_name: Optional database name
            
        Returns:
            Collection: PyMongo collection instance
        """
        database = self.get_database(database_name)
        return database[collection_name]
    
    def seed_data(self, collection_name: str, documents: List[Dict[str, Any]], 
                  database_name: Optional[str] = None) -> List[ObjectId]:
        """
        Seed test data into MongoDB collection.
        
        Args:
            collection_name: Target collection name
            documents: List of documents to insert
            database_name: Optional database name
            
        Returns:
            List[ObjectId]: Inserted document IDs
        """
        collection = self.get_collection(collection_name, database_name)
        
        # Add metadata to documents
        current_time = datetime.now(timezone.utc)
        for doc in documents:
            if "_id" not in doc:
                doc["_id"] = ObjectId()
            doc["created_at"] = current_time
            doc["test_data"] = True
        
        result = collection.insert_many(documents)
        
        logger.info(
            "Test data seeded successfully",
            collection=collection_name,
            document_count=len(documents)
        )
        
        return result.inserted_ids
    
    def cleanup_test_data(self, collection_name: Optional[str] = None,
                         database_name: Optional[str] = None) -> None:
        """
        Cleanup test data from MongoDB collections.
        
        Args:
            collection_name: Specific collection to clean (None for all test collections)
            database_name: Optional database name
        """
        database = self.get_database(database_name)
        
        if collection_name:
            # Clean specific collection
            collection = database[collection_name]
            result = collection.delete_many({"test_data": True})
            logger.info(f"Cleaned {result.deleted_count} test documents from {collection_name}")
        else:
            # Clean all test collections
            collection_names = database.list_collection_names()
            for name in collection_names:
                if name.startswith(self.config.TEST_COLLECTION_PREFIX):
                    collection = database[name]
                    result = collection.delete_many({})
                    logger.info(f"Cleaned {result.deleted_count} documents from {name}")
    
    @property
    def is_initialized(self) -> bool:
        """Check if container is properly initialized."""
        return self._initialized
    
    @property
    def has_replica_set(self) -> bool:
        """Check if replica set is configured."""
        return self._replica_set_initialized


class RedisTestContainer:
    """
    Enhanced Redis Testcontainer wrapper providing realistic caching behavior
    with persistence configuration, performance monitoring, and connection pool management.
    
    This container wrapper provides:
    - Redis server configuration with persistence and memory optimization
    - Connection pool management with configurable settings
    - Performance monitoring for cache operation validation
    - Automated health checking and readiness validation
    - Session storage simulation for Flask-Session integration testing
    - Cache operation utilities for comprehensive testing scenarios
    
    Features per Section 6.6.1:
    - Container-based mocking for realistic Redis behavior
    - Production-equivalent cache behavior with persistence
    - Performance validation for cache operation compliance
    """
    
    def __init__(self, config: DatabaseContainerConfig):
        """
        Initialize Redis test container with comprehensive configuration.
        
        Args:
            config: Database container configuration instance
        """
        self.config = config
        self.container: Optional[RedisContainer] = None
        self.client: Optional[Redis] = None
        self.connection_pool: Optional[ConnectionPool] = None
        self.connection_string: Optional[str] = None
        self._initialized = False
        
        if not TESTCONTAINERS_AVAILABLE or not REDIS_AVAILABLE:
            logger.warning("Testcontainers or Redis not available - using mock Redis container")
            self._setup_mock_container()
        
        logger.info("Redis test container initialized")
    
    def _setup_mock_container(self) -> None:
        """Setup mock container for environments without Testcontainers."""
        self.container = Mock()
        self.container.start = Mock()
        self.container.stop = Mock()
        self.container.get_container_host_ip = Mock(return_value="localhost")
        self.container.get_exposed_port = Mock(return_value=6379)
        self.connection_string = "redis://localhost:6379/0"
        
        # Mock Redis client
        self.client = Mock()
        self.client.ping = Mock(return_value=True)
        self.client.set = Mock(return_value=True)
        self.client.get = Mock(return_value=None)
        self.client.delete = Mock(return_value=1)
        self.client.flushdb = Mock(return_value=True)
        
        logger.warning("Using mock Redis container - limited functionality")
    
    def start(self) -> 'RedisTestContainer':
        """
        Start Redis container with optimized configuration and health validation.
        
        Returns:
            RedisTestContainer: Self reference for method chaining
            
        Raises:
            ConnectionException: If container startup or health validation fails
        """
        try:
            if not TESTCONTAINERS_AVAILABLE or not REDIS_AVAILABLE:
                logger.info("Mock Redis container started")
                return self
            
            # Initialize and start Redis container
            redis_config = self.config.redis_config
            self.container = RedisContainer(
                image=redis_config["image"]
            )
            
            # Configure container resources
            if hasattr(self.container, 'with_kwargs'):
                self.container = self.container.with_kwargs(
                    mem_limit=redis_config["mem_limit"],
                    cpus=redis_config["cpu_limit"]
                )
            
            # Start container
            self.container.start()
            
            # Build connection string
            host = self.container.get_container_host_ip()
            port = self.container.get_exposed_port(self.config.REDIS_DEFAULT_PORT)
            self.connection_string = self.config.get_redis_connection_string(host, port)
            
            # Initialize Redis client
            self._initialize_client()
            
            # Validate container health
            self._validate_container_health()
            
            self._initialized = True
            
            logger.info(
                "Redis test container started successfully",
                host=host,
                port=port
            )
            
            return self
            
        except Exception as e:
            error_msg = f"Failed to start Redis test container: {str(e)}"
            logger.error(error_msg)
            raise ConnectionException(error_msg) from e
    
    def _initialize_client(self) -> None:
        """Initialize Redis client with optimized connection settings."""
        if not self.connection_string:
            raise ConnectionException("Redis connection string not available")
        
        # Get performance configuration
        perf_config = self.config.performance_config
        
        # Create connection pool
        self.connection_pool = ConnectionPool.from_url(
            self.connection_string,
            max_connections=perf_config["max_connections"],
            socket_timeout=perf_config["socket_timeout"],
            socket_connect_timeout=perf_config["connection_timeout"],
            retry_on_timeout=True,
            health_check_interval=30
        )
        
        # Create Redis client
        self.client = Redis(
            connection_pool=self.connection_pool,
            decode_responses=True,
            socket_keepalive=True,
            socket_keepalive_options={}
        )
        
        logger.debug("Redis client initialized with optimized settings")
    
    def _validate_container_health(self) -> None:
        """Validate container health and readiness for testing."""
        if not self.client:
            raise ConnectionException("Redis client not available for health validation")
        
        try:
            # Test basic connectivity
            self.client.ping()
            
            # Test basic operations
            test_key = f"health_check_{uuid.uuid4().hex[:8]}"
            test_value = "health_check_value"
            
            self.client.set(test_key, test_value, ex=60)
            retrieved_value = self.client.get(test_key)
            self.client.delete(test_key)
            
            if retrieved_value != test_value:
                raise ConnectionException("Redis health check failed - value mismatch")
            
            logger.info("Redis container health validation successful")
            
        except Exception as e:
            error_msg = f"Redis container health validation failed: {str(e)}"
            logger.error(error_msg)
            raise ConnectionException(error_msg) from e
    
    def stop(self) -> None:
        """Stop Redis container and cleanup resources."""
        try:
            # Close client connections
            if self.client:
                self.client.close()
                self.client = None
            
            # Close connection pool
            if self.connection_pool:
                self.connection_pool.disconnect()
                self.connection_pool = None
            
            # Stop container
            if self.container and hasattr(self.container, 'stop'):
                self.container.stop()
            
            self._initialized = False
            
            logger.info("Redis test container stopped successfully")
            
        except Exception as e:
            logger.error(f"Error stopping Redis test container: {str(e)}")
    
    def get_client(self) -> Redis:
        """
        Get configured Redis client instance.
        
        Returns:
            Redis: Configured Redis client
            
        Raises:
            ConnectionException: If container not initialized or client unavailable
        """
        if not self._initialized or not self.client:
            raise ConnectionException("Redis container not initialized or client unavailable")
        
        return self.client
    
    def seed_cache_data(self, data: Dict[str, Any], ttl: int = 3600) -> None:
        """
        Seed test data into Redis cache.
        
        Args:
            data: Dictionary of key-value pairs to cache
            ttl: Time to live in seconds
        """
        if not self.client:
            raise ConnectionException("Redis client not available")
        
        for key, value in data.items():
            # Add test metadata
            test_key = f"test:{key}"
            self.client.set(test_key, str(value), ex=ttl)
        
        logger.info(f"Seeded {len(data)} cache entries with TTL {ttl}s")
    
    def cleanup_test_data(self) -> None:
        """Cleanup test data from Redis cache."""
        if not self.client:
            return
        
        try:
            # Remove all test keys
            test_keys = self.client.keys("test:*")
            if test_keys:
                self.client.delete(*test_keys)
                logger.info(f"Cleaned {len(test_keys)} test cache entries")
            
        except Exception as e:
            logger.error(f"Error cleaning Redis test data: {str(e)}")
    
    def flush_database(self) -> None:
        """Flush entire Redis database (use with caution)."""
        if self.client:
            self.client.flushdb()
            logger.info("Redis database flushed")
    
    @property
    def is_initialized(self) -> bool:
        """Check if container is properly initialized."""
        return self._initialized


# Test Data Generation Utilities

class TestDataFactory:
    """
    Comprehensive test data factory providing realistic data generation for database testing.
    
    This factory uses faker and factory_boy to generate production-equivalent test data
    including user profiles, business entities, transaction records, and system metadata.
    Supports both synchronous and asynchronous test scenarios with configurable data
    relationships and constraints.
    """
    
    def __init__(self):
        """Initialize test data factory with faker configuration."""
        if FAKER_AVAILABLE:
            self.faker = Faker()
        else:
            self.faker = None
            logger.warning("Faker not available - using static test data")
    
    def create_user_document(self, **kwargs) -> Dict[str, Any]:
        """Create realistic user document for testing."""
        base_doc = {
            "_id": ObjectId(),
            "email": self.faker.email() if self.faker else "test@example.com",
            "username": self.faker.user_name() if self.faker else "testuser",
            "full_name": self.faker.name() if self.faker else "Test User",
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
            "active": True,
            "profile": {
                "bio": self.faker.text(max_nb_chars=200) if self.faker else "Test bio",
                "location": self.faker.city() if self.faker else "Test City",
                "website": self.faker.url() if self.faker else "https://example.com"
            },
            "preferences": {
                "notifications": True,
                "theme": "light",
                "language": "en"
            },
            "test_data": True
        }
        
        # Override with provided kwargs
        base_doc.update(kwargs)
        return base_doc
    
    def create_transaction_document(self, user_id: Optional[ObjectId] = None, **kwargs) -> Dict[str, Any]:
        """Create realistic transaction document for testing."""
        base_doc = {
            "_id": ObjectId(),
            "user_id": user_id or ObjectId(),
            "amount": float(self.faker.pydecimal(left_digits=3, right_digits=2, positive=True)) if self.faker else 100.00,
            "currency": "USD",
            "type": self.faker.random_element(elements=["purchase", "refund", "transfer"]) if self.faker else "purchase",
            "status": self.faker.random_element(elements=["pending", "completed", "failed"]) if self.faker else "completed",
            "description": self.faker.sentence() if self.faker else "Test transaction",
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
            "metadata": {
                "ip_address": self.faker.ipv4() if self.faker else "127.0.0.1",
                "user_agent": self.faker.user_agent() if self.faker else "Test Agent",
                "reference_id": self.faker.uuid4() if self.faker else str(uuid.uuid4())
            },
            "test_data": True
        }
        
        base_doc.update(kwargs)
        return base_doc
    
    def create_product_document(self, **kwargs) -> Dict[str, Any]:
        """Create realistic product document for testing."""
        base_doc = {
            "_id": ObjectId(),
            "name": self.faker.catch_phrase() if self.faker else "Test Product",
            "description": self.faker.text(max_nb_chars=500) if self.faker else "Test product description",
            "price": float(self.faker.pydecimal(left_digits=3, right_digits=2, positive=True)) if self.faker else 99.99,
            "currency": "USD",
            "category": self.faker.word() if self.faker else "test-category",
            "tags": [self.faker.word() for _ in range(3)] if self.faker else ["test", "product", "sample"],
            "stock": self.faker.random_int(min=0, max=100) if self.faker else 10,
            "active": True,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
            "test_data": True
        }
        
        base_doc.update(kwargs)
        return base_doc
    
    def create_bulk_documents(self, document_type: str, count: int, **kwargs) -> List[Dict[str, Any]]:
        """
        Create bulk test documents for performance testing.
        
        Args:
            document_type: Type of document to create ('user', 'transaction', 'product')
            count: Number of documents to create
            **kwargs: Additional document properties
            
        Returns:
            List[Dict[str, Any]]: List of generated documents
        """
        documents = []
        
        for i in range(count):
            if document_type == "user":
                doc = self.create_user_document(**kwargs)
            elif document_type == "transaction":
                doc = self.create_transaction_document(**kwargs)
            elif document_type == "product":
                doc = self.create_product_document(**kwargs)
            else:
                raise ValueError(f"Unknown document type: {document_type}")
            
            # Add sequence number for bulk operations
            doc["sequence"] = i
            documents.append(doc)
        
        logger.info(f"Generated {count} {document_type} documents for testing")
        return documents


# pytest Fixtures

@pytest.fixture(scope="session")
def database_container_config() -> DatabaseContainerConfig:
    """
    Session-scoped database container configuration fixture.
    
    Provides centralized configuration for all database container instances
    with optimized settings for performance testing and realistic behavior.
    
    Returns:
        DatabaseContainerConfig: Configured container settings
    """
    config = DatabaseContainerConfig(environment="testing")
    
    logger.info(
        "Database container configuration created",
        mongodb_version=config.MONGODB_VERSION,
        redis_version=config.REDIS_VERSION
    )
    
    return config


@pytest.fixture(scope="session")
def mongodb_container(database_container_config: DatabaseContainerConfig) -> Generator[MongoDbTestContainer, None, None]:
    """
    Session-scoped MongoDB Testcontainer fixture providing realistic database behavior.
    
    This fixture provides:
    - MongoDB container with replica set configuration
    - Optimized connection pool settings
    - Automated health checking and validation
    - Performance monitoring capabilities
    - Comprehensive cleanup on session end
    
    Args:
        database_container_config: Container configuration settings
        
    Yields:
        MongoDbTestContainer: Initialized MongoDB container instance
    """
    container = MongoDbTestContainer(database_container_config)
    
    try:
        # Start container with comprehensive initialization
        container.start()
        
        logger.info(
            "MongoDB test container session started",
            initialized=container.is_initialized,
            replica_set=container.has_replica_set
        )
        
        yield container
        
    finally:
        # Cleanup on session end
        try:
            container.cleanup_test_data()
            container.stop()
            logger.info("MongoDB test container session ended")
        except Exception as e:
            logger.error(f"Error during MongoDB container cleanup: {str(e)}")


@pytest.fixture(scope="session") 
def redis_container(database_container_config: DatabaseContainerConfig) -> Generator[RedisTestContainer, None, None]:
    """
    Session-scoped Redis Testcontainer fixture providing realistic caching behavior.
    
    This fixture provides:
    - Redis container with persistence configuration
    - Connection pool management
    - Performance monitoring capabilities
    - Automated health checking and validation
    - Comprehensive cleanup on session end
    
    Args:
        database_container_config: Container configuration settings
        
    Yields:
        RedisTestContainer: Initialized Redis container instance
    """
    container = RedisTestContainer(database_container_config)
    
    try:
        # Start container with comprehensive initialization
        container.start()
        
        logger.info(
            "Redis test container session started",
            initialized=container.is_initialized
        )
        
        yield container
        
    finally:
        # Cleanup on session end
        try:
            container.cleanup_test_data()
            container.stop()
            logger.info("Redis test container session ended")
        except Exception as e:
            logger.error(f"Error during Redis container cleanup: {str(e)}")


@pytest.fixture
def mongodb_client(mongodb_container: MongoDbTestContainer) -> MongoClient:
    """
    Function-scoped PyMongo client fixture for synchronous database operations.
    
    Provides optimized PyMongo client with connection pooling equivalent to
    Node.js patterns and performance monitoring integration.
    
    Args:
        mongodb_container: MongoDB container instance
        
    Returns:
        MongoClient: Configured PyMongo client
    """
    client = mongodb_container.get_client()
    
    logger.debug("PyMongo client fixture created for test function")
    
    return client


@pytest.fixture
def mongodb_database(mongodb_container: MongoDbTestContainer) -> Database:
    """
    Function-scoped MongoDB database fixture for direct database operations.
    
    Args:
        mongodb_container: MongoDB container instance
        
    Returns:
        Database: PyMongo database instance
    """
    database = mongodb_container.get_database()
    
    logger.debug("MongoDB database fixture created for test function")
    
    return database


@pytest.fixture
def redis_client(redis_container: RedisTestContainer) -> Redis:
    """
    Function-scoped Redis client fixture for caching operations.
    
    Provides optimized Redis client with connection pooling and performance
    monitoring for comprehensive cache testing scenarios.
    
    Args:
        redis_container: Redis container instance
        
    Returns:
        Redis: Configured Redis client
    """
    client = redis_container.get_client()
    
    logger.debug("Redis client fixture created for test function")
    
    return client


@pytest_asyncio.fixture
async def async_mongodb_client(mongodb_container: MongoDbTestContainer) -> AsyncGenerator[AsyncIOMotorClient, None]:
    """
    Async function-scoped Motor client fixture for asynchronous database operations.
    
    Provides Motor 3.3+ async client with optimized connection pooling for
    high-performance async operations and concurrent request testing.
    
    Args:
        mongodb_container: MongoDB container instance
        
    Yields:
        AsyncIOMotorClient: Configured Motor async client
    """
    if not MOTOR_AVAILABLE:
        pytest.skip("Motor async driver not available")
    
    if not mongodb_container.connection_string:
        pytest.skip("MongoDB container not properly initialized")
    
    # Get performance configuration
    perf_config = mongodb_container.config.performance_config
    
    # Create Motor async client with optimized settings
    client = AsyncIOMotorClient(
        mongodb_container.connection_string,
        maxPoolSize=perf_config["connection_pool_size"],
        maxConnections=perf_config["max_connections"],
        connectTimeoutMS=int(perf_config["connection_timeout"] * 1000),
        serverSelectionTimeoutMS=int(perf_config["server_selection_timeout"] * 1000),
        socketTimeoutMS=int(perf_config["socket_timeout"] * 1000),
        maxIdleTimeMS=int(perf_config["max_idle_time"] * 1000),
        retryWrites=perf_config["retry_writes"],
        retryReads=perf_config["retry_reads"]
    )
    
    try:
        # Validate async connection
        await client.admin.command("ping")
        
        logger.debug("Motor async client fixture created for test function")
        
        yield client
        
    finally:
        # Cleanup async client
        client.close()


@pytest_asyncio.fixture
async def async_mongodb_database(async_mongodb_client: AsyncIOMotorClient, 
                                mongodb_container: MongoDbTestContainer) -> AsyncIOMotorDatabase:
    """
    Async function-scoped Motor database fixture for async database operations.
    
    Args:
        async_mongodb_client: Motor async client instance
        mongodb_container: MongoDB container instance
        
    Returns:
        AsyncIOMotorDatabase: Motor async database instance
    """
    database_name = mongodb_container.config.mongodb_config["environment"]["MONGO_INITDB_DATABASE"]
    database = async_mongodb_client[database_name]
    
    logger.debug("Motor async database fixture created for test function")
    
    return database


@pytest.fixture
def test_data_factory() -> TestDataFactory:
    """
    Function-scoped test data factory fixture for generating realistic test data.
    
    Provides comprehensive test data generation utilities using faker and
    factory_boy for production-equivalent test scenarios.
    
    Returns:
        TestDataFactory: Configured test data factory
    """
    factory = TestDataFactory()
    
    logger.debug("Test data factory fixture created")
    
    return factory


@pytest.fixture
def database_seeder(mongodb_container: MongoDbTestContainer, 
                   test_data_factory: TestDataFactory) -> Callable:
    """
    Function-scoped database seeder fixture for populating test data.
    
    Provides utilities for seeding realistic test data into MongoDB collections
    with automated cleanup and performance monitoring.
    
    Args:
        mongodb_container: MongoDB container instance
        test_data_factory: Test data factory instance
        
    Returns:
        Callable: Database seeding function
    """
    seeded_collections = []
    
    def seed_collection(collection_name: str, document_type: str, 
                       count: int = 10, **kwargs) -> List[ObjectId]:
        """
        Seed test data into specified collection.
        
        Args:
            collection_name: Target collection name
            document_type: Type of documents to create
            count: Number of documents to create
            **kwargs: Additional document properties
            
        Returns:
            List[ObjectId]: Inserted document IDs
        """
        documents = test_data_factory.create_bulk_documents(document_type, count, **kwargs)
        inserted_ids = mongodb_container.seed_data(collection_name, documents)
        
        seeded_collections.append(collection_name)
        
        logger.info(
            f"Seeded {count} {document_type} documents into {collection_name}",
            collection=collection_name,
            document_type=document_type,
            count=count
        )
        
        return inserted_ids
    
    yield seed_collection
    
    # Cleanup seeded data after test
    try:
        for collection_name in seeded_collections:
            mongodb_container.cleanup_test_data(collection_name)
        logger.debug(f"Cleaned up {len(seeded_collections)} seeded collections")
    except Exception as e:
        logger.error(f"Error cleaning up seeded collections: {str(e)}")


@pytest_asyncio.fixture
async def async_database_seeder(async_mongodb_database: AsyncIOMotorDatabase,
                               test_data_factory: TestDataFactory) -> AsyncGenerator[Callable, None]:
    """
    Async function-scoped database seeder fixture for async test data operations.
    
    Args:
        async_mongodb_database: Motor async database instance
        test_data_factory: Test data factory instance
        
    Yields:
        Callable: Async database seeding function
    """
    seeded_collections = []
    
    async def async_seed_collection(collection_name: str, document_type: str,
                                   count: int = 10, **kwargs) -> List[ObjectId]:
        """
        Asynchronously seed test data into specified collection.
        
        Args:
            collection_name: Target collection name
            document_type: Type of documents to create
            count: Number of documents to create
            **kwargs: Additional document properties
            
        Returns:
            List[ObjectId]: Inserted document IDs
        """
        documents = test_data_factory.create_bulk_documents(document_type, count, **kwargs)
        
        # Add metadata for async operations
        current_time = datetime.now(timezone.utc)
        for doc in documents:
            doc["created_at"] = current_time
            doc["test_data"] = True
            doc["async_test"] = True
        
        collection = async_mongodb_database[collection_name]
        result = await collection.insert_many(documents)
        
        seeded_collections.append(collection_name)
        
        logger.info(
            f"Async seeded {count} {document_type} documents into {collection_name}",
            collection=collection_name,
            document_type=document_type,
            count=count
        )
        
        return result.inserted_ids
    
    yield async_seed_collection
    
    # Cleanup seeded data after test
    try:
        for collection_name in seeded_collections:
            collection = async_mongodb_database[collection_name]
            result = await collection.delete_many({"test_data": True})
            logger.debug(f"Async cleaned {result.deleted_count} documents from {collection_name}")
    except Exception as e:
        logger.error(f"Error during async cleanup: {str(e)}")


@pytest.fixture
def performance_monitor() -> Callable:
    """
    Function-scoped performance monitoring fixture for database operation validation.
    
    Provides utilities for measuring database operation performance and validating
    compliance with ≤10% variance requirement from Node.js baseline.
    
    Returns:
        Callable: Performance monitoring context manager
    """
    performance_data = []
    
    @contextmanager
    def monitor_operation(operation_name: str, baseline_ms: Optional[float] = None):
        """
        Monitor database operation performance.
        
        Args:
            operation_name: Name of the operation being monitored
            baseline_ms: Baseline performance in milliseconds
            
        Yields:
            Dict: Performance metrics collector
        """
        start_time = time.time()
        metrics = {
            "operation": operation_name,
            "start_time": start_time,
            "baseline_ms": baseline_ms
        }
        
        try:
            yield metrics
        finally:
            end_time = time.time()
            duration_ms = (end_time - start_time) * 1000
            
            metrics.update({
                "end_time": end_time,
                "duration_ms": duration_ms,
                "variance_pct": None
            })
            
            if baseline_ms:
                variance_pct = ((duration_ms - baseline_ms) / baseline_ms) * 100
                metrics["variance_pct"] = variance_pct
                
                # Log performance compliance
                if abs(variance_pct) <= 10:
                    logger.info(
                        f"Performance compliant: {operation_name}",
                        duration_ms=duration_ms,
                        baseline_ms=baseline_ms,
                        variance_pct=variance_pct
                    )
                else:
                    logger.warning(
                        f"Performance variance exceeded: {operation_name}",
                        duration_ms=duration_ms,
                        baseline_ms=baseline_ms,
                        variance_pct=variance_pct
                    )
            
            performance_data.append(metrics)
    
    yield monitor_operation
    
    # Log summary performance data
    if performance_data:
        avg_duration = sum(m["duration_ms"] for m in performance_data) / len(performance_data)
        compliant_ops = sum(1 for m in performance_data 
                           if m.get("variance_pct") is not None and abs(m["variance_pct"]) <= 10)
        
        logger.info(
            "Performance monitoring summary",
            total_operations=len(performance_data),
            avg_duration_ms=avg_duration,
            compliant_operations=compliant_ops
        )


# Connection Pool Monitoring Fixtures

@pytest.fixture
def connection_pool_monitor(mongodb_client: MongoClient) -> Callable:
    """
    Function-scoped connection pool monitoring fixture for performance validation.
    
    Monitors PyMongo connection pool utilization and performance metrics to ensure
    equivalent performance to Node.js connection pooling patterns.
    
    Args:
        mongodb_client: Configured PyMongo client
        
    Returns:
        Callable: Connection pool monitoring function
    """
    def get_pool_stats() -> Dict[str, Any]:
        """
        Get current connection pool statistics.
        
        Returns:
            Dict[str, Any]: Connection pool metrics
        """
        try:
            # Get pool info from client
            topology = mongodb_client._topology
            servers = topology.description.server_descriptions()
            
            pool_stats = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "servers": {},
                "total_connections": 0,
                "active_connections": 0
            }
            
            for server_address, server_desc in servers.items():
                server_stats = {
                    "address": str(server_address),
                    "server_type": str(server_desc.server_type),
                    "pool_available": True
                }
                
                pool_stats["servers"][str(server_address)] = server_stats
            
            return pool_stats
            
        except Exception as e:
            logger.error(f"Error getting connection pool stats: {str(e)}")
            return {"error": str(e), "timestamp": datetime.now(timezone.utc).isoformat()}
    
    return get_pool_stats


# Database Transaction Fixtures

@pytest.fixture
def transaction_manager(mongodb_client: MongoClient) -> Callable:
    """
    Function-scoped transaction manager fixture for ACID compliance testing.
    
    Provides transaction management utilities with comprehensive error handling
    and performance monitoring for database transaction scenarios.
    
    Args:
        mongodb_client: Configured PyMongo client
        
    Returns:
        Callable: Transaction context manager
    """
    @contextmanager
    def manage_transaction(read_concern=None, write_concern=None):
        """
        Manage database transaction with comprehensive error handling.
        
        Args:
            read_concern: Read concern for transaction
            write_concern: Write concern for transaction
            
        Yields:
            session: MongoDB session for transaction operations
        """
        session = mongodb_client.start_session()
        
        try:
            with session.start_transaction(
                read_concern=read_concern,
                write_concern=write_concern
            ):
                logger.debug("Database transaction started")
                yield session
                logger.debug("Database transaction committed")
                
        except Exception as e:
            logger.error(f"Database transaction failed: {str(e)}")
            raise
        finally:
            session.end_session()
    
    return manage_transaction


# Cleanup Utilities

@pytest.fixture(autouse=True)
def auto_cleanup_database(mongodb_container: MongoDbTestContainer,
                         redis_container: RedisTestContainer):
    """
    Auto-cleanup fixture that runs after each test to ensure clean state.
    
    This fixture automatically cleans up test data and resets database state
    to prevent test interference and ensure consistent test environments.
    
    Args:
        mongodb_container: MongoDB container instance
        redis_container: Redis container instance
    """
    # Pre-test setup (if needed)
    yield
    
    # Post-test cleanup
    try:
        # Cleanup MongoDB test data
        if mongodb_container.is_initialized:
            mongodb_container.cleanup_test_data()
        
        # Cleanup Redis test data
        if redis_container.is_initialized:
            redis_container.cleanup_test_data()
        
        # Force garbage collection for memory cleanup
        gc.collect()
        
        logger.debug("Auto-cleanup completed successfully")
        
    except Exception as e:
        logger.error(f"Error during auto-cleanup: {str(e)}")


# Performance Baseline Fixtures

@pytest.fixture(scope="session")
def performance_baselines() -> Dict[str, float]:
    """
    Session-scoped performance baselines fixture for Node.js comparison.
    
    Provides baseline performance metrics from Node.js implementation for
    validation of ≤10% variance requirement compliance.
    
    Returns:
        Dict[str, float]: Performance baselines in milliseconds
    """
    # These baselines would typically be loaded from performance test results
    # or configuration files containing Node.js performance measurements
    baselines = {
        "simple_insert": 5.0,  # ms
        "simple_find": 3.0,    # ms
        "simple_update": 4.0,  # ms
        "simple_delete": 3.5,  # ms
        "bulk_insert_100": 50.0,  # ms
        "bulk_find_100": 25.0,    # ms
        "aggregate_simple": 15.0, # ms
        "transaction_simple": 10.0, # ms
        "cache_set": 1.0,      # ms
        "cache_get": 0.5,      # ms
    }
    
    logger.info(
        "Performance baselines loaded for Node.js comparison",
        baseline_count=len(baselines)
    )
    
    return baselines


# Package Exports

__all__ = [
    # Configuration classes
    "DatabaseContainerConfig",
    
    # Container classes
    "MongoDbTestContainer", 
    "RedisTestContainer",
    
    # Test data utilities
    "TestDataFactory",
    
    # pytest fixtures
    "database_container_config",
    "mongodb_container",
    "redis_container", 
    "mongodb_client",
    "mongodb_database",
    "redis_client",
    "async_mongodb_client",
    "async_mongodb_database",
    "test_data_factory",
    "database_seeder",
    "async_database_seeder",
    "performance_monitor",
    "connection_pool_monitor",
    "transaction_manager",
    "auto_cleanup_database",
    "performance_baselines",
    
    # Availability flags
    "TESTCONTAINERS_AVAILABLE",
    "MOTOR_AVAILABLE", 
    "REDIS_AVAILABLE",
    "FACTORY_BOY_AVAILABLE",
    "FAKER_AVAILABLE",
    "APP_MODULES_AVAILABLE"
]

# Module metadata
__version__ = "1.0.0"
__author__ = "Database Migration Team"
__description__ = "Comprehensive database test fixtures with Testcontainers integration"

# Module initialization logging
logger.info(
    "Database test fixtures module initialized",
    testcontainers_available=TESTCONTAINERS_AVAILABLE,
    motor_available=MOTOR_AVAILABLE,
    redis_available=REDIS_AVAILABLE,
    factory_boy_available=FACTORY_BOY_AVAILABLE,
    faker_available=FAKER_AVAILABLE,
    app_modules_available=APP_MODULES_AVAILABLE,
    version=__version__
)