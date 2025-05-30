"""
Database Test Fixtures with Testcontainers Integration

This module provides comprehensive database test fixtures using Testcontainers for realistic MongoDB and Redis
behavior, PyMongo 4.5+ and Motor 3.3+ driver integration, connection pooling configuration, and production-
equivalent database testing scenarios. Implements performance validation ensuring ≤10% variance from Node.js
baseline per Section 6.2.4 of the technical specification.

Key Features:
- Testcontainers MongoDB and Redis integration for production-equivalent testing per Section 6.6.1
- PyMongo 4.5+ synchronous database operation fixtures per Section 3.4.1
- Motor 3.3+ async database operation fixtures with pytest-asyncio configuration per Section 6.6.1
- Connection pooling management fixtures for performance testing per Section 6.2.4
- Database seeding utilities for comprehensive test data management per Section 6.6.1
- Performance monitoring integration for ≤10% variance validation per Section 0.1.1
- Thread-safe fixture management for parallel test execution per Section 6.6.1

Architecture Integration:
- Section 6.6.1: Enhanced mocking strategy using Testcontainers for realistic database behavior
- Section 3.4.1: PyMongo 4.5+ and Motor 3.3+ driver maintaining existing data patterns
- Section 6.2.4: Performance optimization with connection pooling and monitoring integration
- Section 3.4.3: Connection pool management equivalent to Node.js patterns
- Section 6.6.1: pytest-asyncio configuration for async database operations testing

Dependencies:
- testcontainers[mongodb,redis] ≥4.10.0 for dynamic container provisioning
- PyMongo 4.5+ for synchronous MongoDB operations with monitoring
- Motor 3.3+ for async MongoDB operations with connection pooling
- redis-py 5.0+ for Redis cache integration testing
- pytest-asyncio for async fixture management and testing support
- factory_boy for dynamic test data generation with realistic scenarios
"""

import asyncio
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from typing import Any, AsyncGenerator, Dict, Generator, List, Optional, Tuple, Union
from threading import Lock
import pytest
import pytest_asyncio
from unittest.mock import Mock, patch, MagicMock

# Testcontainers imports for dynamic container provisioning
from testcontainers.mongodb import MongoDbContainer
from testcontainers.redis import RedisContainer
from testcontainers.core.container import DockerContainer
from testcontainers.core.waiting_strategies import wait_for_logs

# Database driver imports
import pymongo
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
import motor.motor_asyncio
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
import redis
from redis import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

# BSON and ObjectId handling
from bson import ObjectId, json_util
from bson.errors import InvalidId

# Factory imports for test data generation
import factory
from factory import Factory, Faker, SubFactory, LazyAttribute, Iterator
from factory.fuzzy import FuzzyInteger, FuzzyText, FuzzyDateTime, FuzzyChoice

# Application imports - with fallback handling for development scenarios
try:
    from src.data import (
        DatabaseManager,
        DatabasePackageConfig,
        MongoDBClient,
        MongoDBConfig,
        MotorAsyncDatabase,
        create_mongodb_client,
        initialize_motor_client,
        get_motor_database,
        QueryResult,
        DEFAULT_CONNECTION_TIMEOUT_MS,
        DEFAULT_SERVER_SELECTION_TIMEOUT_MS,
        DEFAULT_SOCKET_TIMEOUT_MS,
        DEFAULT_MAX_POOL_SIZE,
        DEFAULT_MIN_POOL_SIZE,
        DEFAULT_MAX_IDLE_TIME_MS,
        DEFAULT_WAIT_QUEUE_TIMEOUT_MS
    )
    from src.config.settings import BaseConfig, TestingConfig
except ImportError as e:
    # Graceful fallback for development scenarios where modules may not exist yet
    logging.warning(f"Application imports not available: {e}")
    
    # Mock application classes for testing framework setup
    class DatabaseManager:
        def __init__(self, config=None): pass
        def initialize(self): pass
        def close(self): pass
    
    class DatabasePackageConfig:
        def __init__(self, **kwargs):
            self.mongodb_uri = kwargs.get('mongodb_uri', 'mongodb://localhost:27017')
            self.database_name = kwargs.get('database_name', 'test_db')
            self.max_pool_size = kwargs.get('max_pool_size', 50)
            self.min_pool_size = kwargs.get('min_pool_size', 5)
            self.enable_monitoring = kwargs.get('enable_monitoring', True)
    
    class MongoDBClient:
        def __init__(self, config): pass
        def initialize(self): pass
        def close(self): pass
    
    class MongoDBConfig:
        def __init__(self, **kwargs): pass
    
    class MotorAsyncDatabase:
        def __init__(self, client, database_name): pass
    
    DEFAULT_CONNECTION_TIMEOUT_MS = 30000
    DEFAULT_SERVER_SELECTION_TIMEOUT_MS = 30000
    DEFAULT_SOCKET_TIMEOUT_MS = 30000
    DEFAULT_MAX_POOL_SIZE = 50
    DEFAULT_MIN_POOL_SIZE = 5
    DEFAULT_MAX_IDLE_TIME_MS = 300000
    DEFAULT_WAIT_QUEUE_TIMEOUT_MS = 30000

# Configure structured logging for test fixtures
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global container management for fixture lifecycle
_container_registry: Dict[str, DockerContainer] = {}
_container_lock = Lock()

# Performance validation constants aligned with Node.js baseline requirements
PERFORMANCE_VARIANCE_THRESHOLD = 0.10  # ≤10% variance requirement per Section 0.1.1
NODEJS_BASELINE_RESPONSE_TIME_MS = 100  # Example baseline for validation
DATABASE_OPERATION_TIMEOUT_SECONDS = 30
CONTAINER_STARTUP_TIMEOUT_SECONDS = 120


@dataclass
class DatabaseContainerConfig:
    """
    Database container configuration for Testcontainers integration.
    
    Provides comprehensive configuration for MongoDB and Redis containers with production-
    equivalent settings including connection pooling, performance optimization, and monitoring
    integration for realistic testing scenarios.
    """
    
    # MongoDB container configuration
    mongodb_image: str = field(default="mongo:7.0")
    mongodb_port: int = field(default=27017)
    mongodb_username: str = field(default="testuser")
    mongodb_password: str = field(default="testpass")
    mongodb_database: str = field(default="test_database")
    mongodb_replica_set: bool = field(default=False)
    
    # Redis container configuration
    redis_image: str = field(default="redis:7.2-alpine")
    redis_port: int = field(default=6379)
    redis_password: Optional[str] = field(default=None)
    redis_max_memory: str = field(default="256mb")
    redis_max_memory_policy: str = field(default="allkeys-lru")
    
    # Container management configuration
    container_startup_timeout: int = field(default=CONTAINER_STARTUP_TIMEOUT_SECONDS)
    container_cleanup_timeout: int = field(default=30)
    container_logs_enabled: bool = field(default=True)
    
    # Performance testing configuration
    enable_performance_validation: bool = field(default=True)
    performance_variance_threshold: float = field(default=PERFORMANCE_VARIANCE_THRESHOLD)
    baseline_response_time_ms: float = field(default=NODEJS_BASELINE_RESPONSE_TIME_MS)
    
    # Connection pool testing configuration
    test_connection_pooling: bool = field(default=True)
    max_test_connections: int = field(default=20)
    connection_timeout_ms: int = field(default=DEFAULT_CONNECTION_TIMEOUT_MS)
    
    def get_mongodb_uri(self, host: str, port: int) -> str:
        """Generate MongoDB connection URI for container instance."""
        if self.mongodb_username and self.mongodb_password:
            auth_string = f"{self.mongodb_username}:{self.mongodb_password}@"
        else:
            auth_string = ""
        
        return f"mongodb://{auth_string}{host}:{port}/{self.mongodb_database}"
    
    def get_redis_uri(self, host: str, port: int) -> str:
        """Generate Redis connection URI for container instance."""
        if self.redis_password:
            return f"redis://:{self.redis_password}@{host}:{port}/0"
        else:
            return f"redis://{host}:{port}/0"


class MongoDbTestContainer(MongoDbContainer):
    """
    Enhanced MongoDB test container with production-equivalent configuration.
    
    Extends Testcontainers MongoDbContainer with comprehensive MongoDB configuration
    including authentication, connection pooling, performance optimization, and
    monitoring integration for realistic database testing scenarios.
    """
    
    def __init__(
        self, 
        image: str = "mongo:7.0",
        username: Optional[str] = None,
        password: Optional[str] = None,
        database: Optional[str] = None,
        **kwargs
    ):
        """
        Initialize MongoDB test container with comprehensive configuration.
        
        Args:
            image: MongoDB Docker image version
            username: Database authentication username
            password: Database authentication password
            database: Default database name
            **kwargs: Additional container configuration options
        """
        super().__init__(image=image, **kwargs)
        
        self.username = username
        self.password = password
        self.database = database or "test_database"
        
        # Configure MongoDB for production-equivalent behavior
        self.with_env("MONGO_INITDB_DATABASE", self.database)
        
        if username and password:
            self.with_env("MONGO_INITDB_ROOT_USERNAME", username)
            self.with_env("MONGO_INITDB_ROOT_PASSWORD", password)
        
        # Configure MongoDB performance settings for testing
        self.with_command([
            "--bind_ip_all",
            "--journal",
            "--storageEngine", "wiredTiger",
            "--wiredTigerCacheSizeGB", "0.5",
            "--wiredTigerCollectionBlockCompressor", "snappy",
            "--wiredTigerIndexPrefixCompression", "true"
        ])
        
        # Wait for MongoDB to be ready
        self.with_exposed_ports(27017)
        
        logger.info(
            "MongoDB test container configured",
            image=image,
            database=self.database,
            auth_enabled=bool(username and password)
        )
    
    def get_connection_url(self) -> str:
        """Get MongoDB connection URL for test client initialization."""
        host = self.get_container_host_ip()
        port = self.get_exposed_port(27017)
        
        if self.username and self.password:
            auth_string = f"{self.username}:{self.password}@"
        else:
            auth_string = ""
        
        connection_url = f"mongodb://{auth_string}{host}:{port}/{self.database}"
        
        logger.debug(
            "MongoDB connection URL generated",
            host=host,
            port=port,
            database=self.database,
            auth_enabled=bool(self.username and self.password)
        )
        
        return connection_url
    
    def get_pymongo_client(self, **client_options) -> MongoClient:
        """
        Create PyMongo client connected to test container.
        
        Args:
            **client_options: Additional PyMongo client configuration options
            
        Returns:
            Configured PyMongo MongoClient instance
        """
        connection_url = self.get_connection_url()
        
        # Default client options for testing with connection pooling
        default_options = {
            'maxPoolSize': DEFAULT_MAX_POOL_SIZE,
            'minPoolSize': DEFAULT_MIN_POOL_SIZE,
            'maxIdleTimeMS': DEFAULT_MAX_IDLE_TIME_MS,
            'waitQueueTimeoutMS': DEFAULT_WAIT_QUEUE_TIMEOUT_MS,
            'serverSelectionTimeoutMS': DEFAULT_SERVER_SELECTION_TIMEOUT_MS,
            'connectTimeoutMS': DEFAULT_CONNECTION_TIMEOUT_MS,
            'socketTimeoutMS': DEFAULT_SOCKET_TIMEOUT_MS,
            'retryWrites': True,
            'retryReads': True,
            'appName': 'TestContainer-PyMongo-Client'
        }
        
        # Merge with provided options
        final_options = {**default_options, **client_options}
        
        client = MongoClient(connection_url, **final_options)
        
        # Verify connection
        try:
            client.admin.command('ping')
            logger.info(
                "PyMongo test client connected successfully",
                connection_url=connection_url.split('@')[-1] if '@' in connection_url else connection_url,
                max_pool_size=final_options['maxPoolSize']
            )
        except Exception as e:
            logger.error(f"PyMongo test client connection failed: {e}")
            raise
        
        return client
    
    async def get_motor_client(self, **client_options) -> AsyncIOMotorClient:
        """
        Create Motor async client connected to test container.
        
        Args:
            **client_options: Additional Motor client configuration options
            
        Returns:
            Configured Motor AsyncIOMotorClient instance
        """
        connection_url = self.get_connection_url()
        
        # Default client options for async testing with connection pooling
        default_options = {
            'maxPoolSize': DEFAULT_MAX_POOL_SIZE,
            'minPoolSize': DEFAULT_MIN_POOL_SIZE,
            'maxIdleTimeMS': DEFAULT_MAX_IDLE_TIME_MS,
            'waitQueueTimeoutMS': DEFAULT_WAIT_QUEUE_TIMEOUT_MS,
            'serverSelectionTimeoutMS': DEFAULT_SERVER_SELECTION_TIMEOUT_MS,
            'connectTimeoutMS': DEFAULT_CONNECTION_TIMEOUT_MS,
            'socketTimeoutMS': DEFAULT_SOCKET_TIMEOUT_MS,
            'retryWrites': True,
            'retryReads': True,
            'appName': 'TestContainer-Motor-Client'
        }
        
        # Merge with provided options
        final_options = {**default_options, **client_options}
        
        client = AsyncIOMotorClient(connection_url, **final_options)
        
        # Verify async connection
        try:
            await client.admin.command('ping')
            logger.info(
                "Motor test client connected successfully",
                connection_url=connection_url.split('@')[-1] if '@' in connection_url else connection_url,
                max_pool_size=final_options['maxPoolSize']
            )
        except Exception as e:
            logger.error(f"Motor test client connection failed: {e}")
            raise
        
        return client


class RedisTestContainer(RedisContainer):
    """
    Enhanced Redis test container with production-equivalent configuration.
    
    Extends Testcontainers RedisContainer with comprehensive Redis configuration
    including authentication, memory management, persistence, and performance
    optimization for realistic cache and session testing scenarios.
    """
    
    def __init__(
        self,
        image: str = "redis:7.2-alpine",
        password: Optional[str] = None,
        max_memory: str = "256mb",
        max_memory_policy: str = "allkeys-lru",
        **kwargs
    ):
        """
        Initialize Redis test container with comprehensive configuration.
        
        Args:
            image: Redis Docker image version
            password: Redis authentication password
            max_memory: Maximum memory allocation for Redis instance
            max_memory_policy: Memory eviction policy for cache management
            **kwargs: Additional container configuration options
        """
        super().__init__(image=image, **kwargs)
        
        self.password = password
        self.max_memory = max_memory
        self.max_memory_policy = max_memory_policy
        
        # Configure Redis for production-equivalent behavior
        redis_config = [
            "--maxmemory", max_memory,
            "--maxmemory-policy", max_memory_policy,
            "--save", "900", "1",  # Persistence configuration
            "--appendonly", "yes",  # AOF persistence
            "--appendfsync", "everysec",  # AOF sync policy
            "--tcp-keepalive", "300",  # Connection keepalive
            "--timeout", "300"  # Client timeout
        ]
        
        if password:
            redis_config.extend(["--requirepass", password])
        
        self.with_command(redis_config)
        self.with_exposed_ports(6379)
        
        logger.info(
            "Redis test container configured",
            image=image,
            max_memory=max_memory,
            max_memory_policy=max_memory_policy,
            auth_enabled=bool(password)
        )
    
    def get_connection_url(self) -> str:
        """Get Redis connection URL for test client initialization."""
        host = self.get_container_host_ip()
        port = self.get_exposed_port(6379)
        
        if self.password:
            connection_url = f"redis://:{self.password}@{host}:{port}/0"
        else:
            connection_url = f"redis://{host}:{port}/0"
        
        logger.debug(
            "Redis connection URL generated",
            host=host,
            port=port,
            auth_enabled=bool(self.password)
        )
        
        return connection_url
    
    def get_redis_client(self, **client_options) -> Redis:
        """
        Create Redis client connected to test container.
        
        Args:
            **client_options: Additional Redis client configuration options
            
        Returns:
            Configured Redis client instance
        """
        host = self.get_container_host_ip()
        port = self.get_exposed_port(6379)
        
        # Default client options for testing with connection pooling
        default_options = {
            'host': host,
            'port': port,
            'db': 0,
            'password': self.password,
            'socket_timeout': 30,
            'socket_connect_timeout': 30,
            'socket_keepalive': True,
            'socket_keepalive_options': {},
            'connection_pool_kwargs': {
                'max_connections': 50,
                'retry_on_timeout': True
            },
            'decode_responses': True,
            'health_check_interval': 30
        }
        
        # Merge with provided options
        final_options = {**default_options, **client_options}
        
        client = Redis(**final_options)
        
        # Verify connection
        try:
            client.ping()
            logger.info(
                "Redis test client connected successfully",
                host=host,
                port=port,
                auth_enabled=bool(self.password)
            )
        except Exception as e:
            logger.error(f"Redis test client connection failed: {e}")
            raise
        
        return client


# =============================================================================
# Test Data Factories for Comprehensive Database Testing
# =============================================================================

class BaseTestObjectFactory(Factory):
    """
    Base factory for test object generation with realistic data patterns.
    
    Provides common factory configuration and utilities for generating
    test data that mirrors production document structures and data patterns
    used in the existing Node.js implementation.
    """
    
    class Meta:
        abstract = True
    
    # Common fields present in most database documents
    _id = factory.LazyFunction(lambda: ObjectId())
    created_at = factory.Faker('date_time_this_year', tzinfo=None)
    updated_at = factory.LazyAttribute(lambda obj: obj.created_at)
    version = FuzzyInteger(1, 5)
    
    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        """Override create method to return dict instead of model instance."""
        return {key: value for key, value in kwargs.items()}


class UserDocumentFactory(BaseTestObjectFactory):
    """
    Factory for generating realistic user document test data.
    
    Creates user documents that mirror the existing Node.js user schema
    with comprehensive profile information, authentication data, and
    realistic variation for thorough testing scenarios.
    """
    
    # User identification and authentication
    user_id = factory.LazyFunction(lambda: str(uuid.uuid4()))
    username = factory.Faker('user_name')
    email = factory.Faker('email')
    password_hash = factory.Faker('password', length=60, special_chars=True, digits=True, upper_case=True, lower_case=True)
    
    # User profile information
    first_name = factory.Faker('first_name')
    last_name = factory.Faker('last_name')
    full_name = factory.LazyAttribute(lambda obj: f"{obj.first_name} {obj.last_name}")
    date_of_birth = factory.Faker('date_of_birth', minimum_age=18, maximum_age=80)
    phone_number = factory.Faker('phone_number')
    
    # User preferences and settings
    timezone = factory.Faker('timezone')
    language = FuzzyChoice(['en', 'es', 'fr', 'de', 'it', 'pt'])
    theme = FuzzyChoice(['light', 'dark', 'auto'])
    notifications_enabled = factory.Faker('boolean', chance_of_getting_true=75)
    
    # User status and metadata
    status = FuzzyChoice(['active', 'inactive', 'pending', 'suspended'])
    email_verified = factory.Faker('boolean', chance_of_getting_true=85)
    phone_verified = factory.Faker('boolean', chance_of_getting_true=60)
    last_login = factory.Faker('date_time_this_month', tzinfo=None)
    login_count = FuzzyInteger(0, 1000)
    
    # Social and organizational data
    organization = factory.Faker('company')
    role = FuzzyChoice(['user', 'admin', 'moderator', 'viewer'])
    permissions = factory.LazyFunction(
        lambda: [f"permission_{i}" for i in range(factory.random.randint(1, 5))]
    )
    
    # Geographic information
    address = factory.SubFactory(
        'tests.fixtures.database_fixtures.AddressFactory'
    )
    
    # Audit and tracking fields
    created_by = factory.LazyFunction(lambda: str(ObjectId()))
    updated_by = factory.LazyAttribute(lambda obj: obj.created_by)
    source = FuzzyChoice(['web', 'mobile', 'api', 'admin'])


class AddressFactory(BaseTestObjectFactory):
    """Factory for generating realistic address data embedded in user documents."""
    
    street_address = factory.Faker('street_address')
    city = factory.Faker('city')
    state = factory.Faker('state')
    postal_code = factory.Faker('postcode')
    country = factory.Faker('country_code', representation='alpha-2')
    latitude = factory.Faker('latitude')
    longitude = factory.Faker('longitude')


class ProjectDocumentFactory(BaseTestObjectFactory):
    """
    Factory for generating realistic project document test data.
    
    Creates project documents representing typical business entities
    with comprehensive metadata, status tracking, and relationships
    for integration testing scenarios.
    """
    
    # Project identification
    project_id = factory.LazyFunction(lambda: str(uuid.uuid4()))
    name = factory.Faker('catch_phrase')
    slug = factory.LazyAttribute(lambda obj: obj.name.lower().replace(' ', '-'))
    description = factory.Faker('text', max_nb_chars=500)
    
    # Project categorization
    category = FuzzyChoice(['web', 'mobile', 'api', 'data', 'infrastructure'])
    tags = factory.LazyFunction(
        lambda: [factory.Faker('word').generate() for _ in range(factory.random.randint(1, 5))]
    )
    
    # Project status and timeline
    status = FuzzyChoice(['planning', 'active', 'completed', 'cancelled', 'on-hold'])
    priority = FuzzyChoice(['low', 'medium', 'high', 'critical'])
    start_date = factory.Faker('date_this_year')
    end_date = factory.LazyAttribute(
        lambda obj: factory.Faker('date_between', start_date=obj.start_date).generate()
    )
    
    # Project team and ownership
    owner_id = factory.LazyFunction(lambda: str(ObjectId()))
    team_members = factory.LazyFunction(
        lambda: [str(ObjectId()) for _ in range(factory.random.randint(2, 8))]
    )
    
    # Project metrics and progress
    progress_percentage = FuzzyInteger(0, 100)
    budget = FuzzyInteger(1000, 100000)
    currency = FuzzyChoice(['USD', 'EUR', 'GBP', 'CAD'])
    
    # Project configuration
    settings = factory.LazyFunction(
        lambda: {
            'notifications': factory.random.choice([True, False]),
            'public_visibility': factory.random.choice([True, False]),
            'collaboration_enabled': factory.random.choice([True, False]),
            'auto_archive_days': factory.random.randint(30, 365)
        }
    )


class SessionDocumentFactory(BaseTestObjectFactory):
    """
    Factory for generating realistic session document test data for Redis testing.
    
    Creates session documents that mirror Flask-Session patterns with
    comprehensive user context, authentication state, and session metadata
    for cache and session management testing.
    """
    
    # Session identification
    session_id = factory.LazyFunction(lambda: str(uuid.uuid4()))
    csrf_token = factory.LazyFunction(lambda: str(uuid.uuid4()))
    
    # User context
    user_id = factory.LazyFunction(lambda: str(ObjectId()))
    username = factory.Faker('user_name')
    
    # Authentication state
    authenticated = factory.Faker('boolean', chance_of_getting_true=90)
    auth_method = FuzzyChoice(['password', 'oauth', 'sso', 'api_key'])
    auth_timestamp = factory.Faker('date_time_this_hour', tzinfo=None)
    
    # Session metadata
    ip_address = factory.Faker('ipv4')
    user_agent = factory.Faker('user_agent')
    browser = FuzzyChoice(['Chrome', 'Firefox', 'Safari', 'Edge', 'Opera'])
    os = FuzzyChoice(['Windows', 'macOS', 'Linux', 'iOS', 'Android'])
    
    # Session activity tracking
    last_activity = factory.Faker('date_time_this_hour', tzinfo=None)
    page_views = FuzzyInteger(1, 50)
    actions_performed = FuzzyInteger(0, 20)
    
    # Session configuration
    session_timeout = FuzzyInteger(1800, 7200)  # 30 minutes to 2 hours
    remember_me = factory.Faker('boolean', chance_of_getting_true=30)
    
    # Geographic and location data
    timezone = factory.Faker('timezone')
    location = factory.SubFactory(AddressFactory)
    
    # Session security
    secure_connection = factory.Faker('boolean', chance_of_getting_true=95)
    two_factor_verified = factory.Faker('boolean', chance_of_getting_true=40)


# =============================================================================
# Database Fixture Utilities and Helper Functions
# =============================================================================

class DatabaseSeeder:
    """
    Database seeding utility for comprehensive test data management.
    
    Provides methods for populating test databases with realistic data sets,
    managing test data lifecycle, and ensuring consistent test environments
    across different testing scenarios and parallel test execution.
    """
    
    def __init__(self, mongodb_client: MongoClient, redis_client: Redis):
        """
        Initialize database seeder with client connections.
        
        Args:
            mongodb_client: Connected PyMongo client instance
            redis_client: Connected Redis client instance
        """
        self.mongodb_client = mongodb_client
        self.redis_client = redis_client
        self.database = mongodb_client.get_default_database()
        
        logger.info(
            "Database seeder initialized",
            database_name=self.database.name,
            mongodb_connected=True,
            redis_connected=True
        )
    
    def seed_users(self, count: int = 10) -> List[Dict[str, Any]]:
        """
        Seed user collection with realistic test data.
        
        Args:
            count: Number of user documents to create
            
        Returns:
            List of created user documents
        """
        users = UserDocumentFactory.create_batch(count)
        
        # Insert users into MongoDB
        result = self.database.users.insert_many(users)
        
        # Update documents with inserted IDs
        for user, inserted_id in zip(users, result.inserted_ids):
            user['_id'] = inserted_id
        
        logger.info(f"Seeded {count} user documents", collection="users")
        return users
    
    def seed_projects(self, count: int = 5, user_ids: Optional[List[ObjectId]] = None) -> List[Dict[str, Any]]:
        """
        Seed project collection with realistic test data linked to users.
        
        Args:
            count: Number of project documents to create
            user_ids: Optional list of user IDs to assign as project owners
            
        Returns:
            List of created project documents
        """
        projects = []
        
        for i in range(count):
            project = ProjectDocumentFactory.create()
            
            # Assign owner from provided user IDs if available
            if user_ids:
                project['owner_id'] = str(factory.random.choice(user_ids))
                
                # Assign team members from user IDs
                team_size = factory.random.randint(2, min(6, len(user_ids)))
                project['team_members'] = [
                    str(uid) for uid in factory.random.sample(user_ids, team_size)
                    if str(uid) != project['owner_id']
                ]
            
            projects.append(project)
        
        # Insert projects into MongoDB
        result = self.database.projects.insert_many(projects)
        
        # Update documents with inserted IDs
        for project, inserted_id in zip(projects, result.inserted_ids):
            project['_id'] = inserted_id
        
        logger.info(f"Seeded {count} project documents", collection="projects")
        return projects
    
    def seed_sessions(self, count: int = 20, user_ids: Optional[List[ObjectId]] = None) -> List[Dict[str, Any]]:
        """
        Seed Redis cache with realistic session data.
        
        Args:
            count: Number of session documents to create
            user_ids: Optional list of user IDs to assign to sessions
            
        Returns:
            List of created session documents
        """
        sessions = []
        
        for i in range(count):
            session = SessionDocumentFactory.create()
            
            # Assign user from provided user IDs if available
            if user_ids:
                session['user_id'] = str(factory.random.choice(user_ids))
            
            # Store session in Redis with TTL
            session_key = f"session:{session['session_id']}"
            session_data = json_util.dumps(session)
            ttl = session.get('session_timeout', 3600)
            
            self.redis_client.setex(session_key, ttl, session_data)
            sessions.append(session)
        
        logger.info(f"Seeded {count} session documents", cache="redis")
        return sessions
    
    def seed_cache_data(self, count: int = 50) -> Dict[str, Any]:
        """
        Seed Redis cache with various cached data patterns.
        
        Args:
            count: Number of cache entries to create
            
        Returns:
            Dictionary of created cache entries
        """
        cache_data = {}
        
        for i in range(count):
            # Generate various cache key patterns
            cache_patterns = [
                f"user:{factory.random.randint(1, 1000)}:profile",
                f"project:{factory.random.randint(1, 100)}:metadata",
                f"api:rate_limit:{factory.Faker('ipv4').generate()}",
                f"search:results:{factory.Faker('word').generate()}",
                f"config:feature_flags:{factory.Faker('word').generate()}"
            ]
            
            cache_key = factory.random.choice(cache_patterns)
            cache_value = {
                'data': factory.Faker('text', max_nb_chars=200).generate(),
                'timestamp': int(time.time()),
                'ttl': factory.random.randint(300, 3600),
                'version': factory.random.randint(1, 5)
            }
            
            # Store in Redis with random TTL
            ttl = cache_value['ttl']
            self.redis_client.setex(cache_key, ttl, json_util.dumps(cache_value))
            cache_data[cache_key] = cache_value
        
        logger.info(f"Seeded {count} cache entries", cache="redis")
        return cache_data
    
    def create_indexes(self) -> None:
        """Create database indexes for optimal query performance during testing."""
        # User collection indexes
        self.database.users.create_index([("email", 1)], unique=True)
        self.database.users.create_index([("username", 1)], unique=True)
        self.database.users.create_index([("user_id", 1)], unique=True)
        self.database.users.create_index([("status", 1)])
        self.database.users.create_index([("created_at", -1)])
        self.database.users.create_index([("last_login", -1)])
        
        # Project collection indexes
        self.database.projects.create_index([("project_id", 1)], unique=True)
        self.database.projects.create_index([("owner_id", 1)])
        self.database.projects.create_index([("status", 1)])
        self.database.projects.create_index([("category", 1)])
        self.database.projects.create_index([("created_at", -1)])
        self.database.projects.create_index([("tags", 1)])
        
        # Compound indexes for complex queries
        self.database.users.create_index([("status", 1), ("created_at", -1)])
        self.database.projects.create_index([("owner_id", 1), ("status", 1)])
        self.database.projects.create_index([("category", 1), ("priority", 1)])
        
        logger.info("Database indexes created for test collections")
    
    def cleanup_collections(self) -> None:
        """Clean up all test collections and cache data."""
        # Drop MongoDB collections
        collections_to_drop = ['users', 'projects', 'sessions', 'test_data']
        for collection_name in collections_to_drop:
            try:
                self.database.drop_collection(collection_name)
                logger.debug(f"Dropped collection: {collection_name}")
            except Exception as e:
                logger.warning(f"Failed to drop collection {collection_name}: {e}")
        
        # Clear Redis cache
        try:
            self.redis_client.flushdb()
            logger.debug("Cleared Redis cache")
        except Exception as e:
            logger.warning(f"Failed to clear Redis cache: {e}")
        
        logger.info("Database cleanup completed")


class PerformanceValidator:
    """
    Performance validation utility for ensuring ≤10% variance from Node.js baseline.
    
    Provides comprehensive performance measurement and comparison capabilities
    for database operations, cache performance, and connection pooling efficiency
    to validate migration success against baseline requirements.
    """
    
    def __init__(self, variance_threshold: float = PERFORMANCE_VARIANCE_THRESHOLD):
        """
        Initialize performance validator with variance threshold configuration.
        
        Args:
            variance_threshold: Maximum allowed variance from baseline (default: 0.10)
        """
        self.variance_threshold = variance_threshold
        self.baseline_metrics = {}
        self.performance_measurements = []
        
        logger.info(
            "Performance validator initialized",
            variance_threshold=variance_threshold
        )
    
    def measure_database_operation(
        self,
        operation_name: str,
        operation_func: callable,
        *args,
        **kwargs
    ) -> Tuple[Any, float]:
        """
        Measure database operation performance with timing and validation.
        
        Args:
            operation_name: Name of the database operation for tracking
            operation_func: Callable database operation to measure
            *args: Arguments for the operation function
            **kwargs: Keyword arguments for the operation function
            
        Returns:
            Tuple of (operation_result, execution_time_ms)
        """
        start_time = time.perf_counter()
        
        try:
            result = operation_func(*args, **kwargs)
            end_time = time.perf_counter()
            execution_time_ms = (end_time - start_time) * 1000
            
            # Record performance measurement
            measurement = {
                'operation': operation_name,
                'execution_time_ms': execution_time_ms,
                'timestamp': time.time(),
                'success': True,
                'error': None
            }
            
            self.performance_measurements.append(measurement)
            
            logger.debug(
                "Database operation measured",
                operation=operation_name,
                execution_time_ms=round(execution_time_ms, 2)
            )
            
            return result, execution_time_ms
            
        except Exception as e:
            end_time = time.perf_counter()
            execution_time_ms = (end_time - start_time) * 1000
            
            # Record failed measurement
            measurement = {
                'operation': operation_name,
                'execution_time_ms': execution_time_ms,
                'timestamp': time.time(),
                'success': False,
                'error': str(e)
            }
            
            self.performance_measurements.append(measurement)
            
            logger.error(
                "Database operation failed during measurement",
                operation=operation_name,
                execution_time_ms=round(execution_time_ms, 2),
                error=str(e)
            )
            
            raise
    
    def validate_performance_compliance(
        self,
        operation_name: str,
        baseline_time_ms: float,
        measured_time_ms: float
    ) -> bool:
        """
        Validate that measured performance meets variance threshold requirements.
        
        Args:
            operation_name: Name of the operation being validated
            baseline_time_ms: Node.js baseline execution time in milliseconds
            measured_time_ms: Python implementation execution time in milliseconds
            
        Returns:
            True if performance meets variance threshold, False otherwise
        """
        if baseline_time_ms <= 0:
            logger.warning(f"Invalid baseline time for {operation_name}: {baseline_time_ms}")
            return False
        
        variance = (measured_time_ms - baseline_time_ms) / baseline_time_ms
        variance_percentage = variance * 100
        
        compliant = abs(variance) <= self.variance_threshold
        
        validation_result = {
            'operation': operation_name,
            'baseline_time_ms': baseline_time_ms,
            'measured_time_ms': measured_time_ms,
            'variance': variance,
            'variance_percentage': variance_percentage,
            'threshold': self.variance_threshold,
            'compliant': compliant,
            'timestamp': time.time()
        }
        
        if compliant:
            logger.info(
                "Performance validation passed",
                operation=operation_name,
                variance_percentage=round(variance_percentage, 2),
                threshold_percentage=round(self.variance_threshold * 100, 2)
            )
        else:
            logger.warning(
                "Performance validation failed",
                operation=operation_name,
                variance_percentage=round(variance_percentage, 2),
                threshold_percentage=round(self.variance_threshold * 100, 2),
                measured_time_ms=round(measured_time_ms, 2),
                baseline_time_ms=round(baseline_time_ms, 2)
            )
        
        return compliant
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """
        Generate comprehensive performance measurement summary.
        
        Returns:
            Dictionary containing performance statistics and analysis
        """
        if not self.performance_measurements:
            return {
                'total_measurements': 0,
                'successful_measurements': 0,
                'failed_measurements': 0,
                'average_execution_time_ms': 0,
                'operations': {}
            }
        
        successful_measurements = [m for m in self.performance_measurements if m['success']]
        failed_measurements = [m for m in self.performance_measurements if not m['success']]
        
        # Group measurements by operation
        operations_summary = {}
        for measurement in self.performance_measurements:
            op_name = measurement['operation']
            if op_name not in operations_summary:
                operations_summary[op_name] = {
                    'count': 0,
                    'successful_count': 0,
                    'failed_count': 0,
                    'total_time_ms': 0,
                    'average_time_ms': 0,
                    'min_time_ms': float('inf'),
                    'max_time_ms': 0
                }
            
            op_summary = operations_summary[op_name]
            op_summary['count'] += 1
            op_summary['total_time_ms'] += measurement['execution_time_ms']
            
            if measurement['success']:
                op_summary['successful_count'] += 1
            else:
                op_summary['failed_count'] += 1
            
            op_summary['min_time_ms'] = min(op_summary['min_time_ms'], measurement['execution_time_ms'])
            op_summary['max_time_ms'] = max(op_summary['max_time_ms'], measurement['execution_time_ms'])
        
        # Calculate averages
        for op_summary in operations_summary.values():
            if op_summary['count'] > 0:
                op_summary['average_time_ms'] = op_summary['total_time_ms'] / op_summary['count']
            if op_summary['min_time_ms'] == float('inf'):
                op_summary['min_time_ms'] = 0
        
        # Overall statistics
        total_execution_time = sum(m['execution_time_ms'] for m in self.performance_measurements)
        average_execution_time = total_execution_time / len(self.performance_measurements)
        
        return {
            'total_measurements': len(self.performance_measurements),
            'successful_measurements': len(successful_measurements),
            'failed_measurements': len(failed_measurements),
            'average_execution_time_ms': round(average_execution_time, 2),
            'total_execution_time_ms': round(total_execution_time, 2),
            'operations': operations_summary,
            'measurement_period': {
                'start_time': min(m['timestamp'] for m in self.performance_measurements),
                'end_time': max(m['timestamp'] for m in self.performance_measurements)
            }
        }


# =============================================================================
# Core Database Fixtures with Testcontainers Integration
# =============================================================================

@pytest.fixture(scope="session")
def database_container_config() -> DatabaseContainerConfig:
    """
    Session-scoped fixture providing database container configuration.
    
    Returns:
        DatabaseContainerConfig instance with production-equivalent settings
    """
    config = DatabaseContainerConfig(
        mongodb_image="mongo:7.0",
        mongodb_username="testuser",
        mongodb_password="testpass123",
        mongodb_database="test_database",
        redis_image="redis:7.2-alpine",
        redis_password="redistest123",
        enable_performance_validation=True,
        performance_variance_threshold=PERFORMANCE_VARIANCE_THRESHOLD
    )
    
    logger.info(
        "Database container configuration created",
        mongodb_image=config.mongodb_image,
        redis_image=config.redis_image,
        performance_validation=config.enable_performance_validation
    )
    
    return config


@pytest.fixture(scope="session")
def mongodb_container(database_container_config: DatabaseContainerConfig) -> Generator[MongoDbTestContainer, None, None]:
    """
    Session-scoped fixture providing MongoDB Testcontainer instance.
    
    Creates and manages MongoDB container lifecycle with production-equivalent
    configuration for comprehensive database testing scenarios.
    
    Args:
        database_container_config: Container configuration settings
        
    Yields:
        MongoDbTestContainer instance with established connection
    """
    container_key = "mongodb_test_container"
    
    with _container_lock:
        if container_key in _container_registry:
            yield _container_registry[container_key]
            return
        
        container = MongoDbTestContainer(
            image=database_container_config.mongodb_image,
            username=database_container_config.mongodb_username,
            password=database_container_config.mongodb_password,
            database=database_container_config.mongodb_database
        )
        
        try:
            logger.info(
                "Starting MongoDB test container",
                image=database_container_config.mongodb_image,
                database=database_container_config.mongodb_database
            )
            
            container.start()
            
            # Wait for MongoDB to be fully ready
            container._wait_for_service_ready()
            
            # Verify container connectivity
            test_client = container.get_pymongo_client()
            test_client.admin.command('ping')
            test_client.close()
            
            _container_registry[container_key] = container
            
            logger.info(
                "MongoDB test container started successfully",
                host=container.get_container_host_ip(),
                port=container.get_exposed_port(27017),
                database=database_container_config.mongodb_database
            )
            
            yield container
            
        except Exception as e:
            logger.error(f"Failed to start MongoDB test container: {e}")
            try:
                container.stop()
            except:
                pass
            raise
        
        finally:
            # Cleanup on session end
            if container_key in _container_registry:
                try:
                    logger.info("Stopping MongoDB test container")
                    container.stop()
                    del _container_registry[container_key]
                    logger.info("MongoDB test container stopped successfully")
                except Exception as e:
                    logger.error(f"Error stopping MongoDB test container: {e}")


@pytest.fixture(scope="session")
def redis_container(database_container_config: DatabaseContainerConfig) -> Generator[RedisTestContainer, None, None]:
    """
    Session-scoped fixture providing Redis Testcontainer instance.
    
    Creates and manages Redis container lifecycle with production-equivalent
    configuration for comprehensive cache and session testing scenarios.
    
    Args:
        database_container_config: Container configuration settings
        
    Yields:
        RedisTestContainer instance with established connection
    """
    container_key = "redis_test_container"
    
    with _container_lock:
        if container_key in _container_registry:
            yield _container_registry[container_key]
            return
        
        container = RedisTestContainer(
            image=database_container_config.redis_image,
            password=database_container_config.redis_password,
            max_memory=database_container_config.redis_max_memory,
            max_memory_policy=database_container_config.redis_max_memory_policy
        )
        
        try:
            logger.info(
                "Starting Redis test container",
                image=database_container_config.redis_image,
                max_memory=database_container_config.redis_max_memory
            )
            
            container.start()
            
            # Wait for Redis to be fully ready
            time.sleep(2)  # Brief wait for Redis startup
            
            # Verify container connectivity
            test_client = container.get_redis_client()
            test_client.ping()
            test_client.close()
            
            _container_registry[container_key] = container
            
            logger.info(
                "Redis test container started successfully",
                host=container.get_container_host_ip(),
                port=container.get_exposed_port(6379),
                auth_enabled=bool(database_container_config.redis_password)
            )
            
            yield container
            
        except Exception as e:
            logger.error(f"Failed to start Redis test container: {e}")
            try:
                container.stop()
            except:
                pass
            raise
        
        finally:
            # Cleanup on session end
            if container_key in _container_registry:
                try:
                    logger.info("Stopping Redis test container")
                    container.stop()
                    del _container_registry[container_key]
                    logger.info("Redis test container stopped successfully")
                except Exception as e:
                    logger.error(f"Error stopping Redis test container: {e}")


@pytest.fixture(scope="function")
def pymongo_client(mongodb_container: MongoDbTestContainer) -> Generator[MongoClient, None, None]:
    """
    Function-scoped fixture providing PyMongo client connected to test container.
    
    Creates PyMongo client with production-equivalent connection pooling
    configuration for synchronous database operations testing.
    
    Args:
        mongodb_container: MongoDB test container instance
        
    Yields:
        Configured MongoClient instance with connection pooling
    """
    client = mongodb_container.get_pymongo_client()
    
    try:
        # Verify connection health
        client.admin.command('ping')
        
        logger.debug(
            "PyMongo test client created",
            database_name=client.get_default_database().name,
            max_pool_size=client.options.pool_options.max_pool_size
        )
        
        yield client
        
    finally:
        try:
            client.close()
            logger.debug("PyMongo test client closed")
        except Exception as e:
            logger.warning(f"Error closing PyMongo test client: {e}")


@pytest_asyncio.fixture(scope="function")
async def motor_client(mongodb_container: MongoDbTestContainer) -> AsyncGenerator[AsyncIOMotorClient, None]:
    """
    Function-scoped async fixture providing Motor client connected to test container.
    
    Creates Motor async client with production-equivalent connection pooling
    configuration for asynchronous database operations testing with pytest-asyncio.
    
    Args:
        mongodb_container: MongoDB test container instance
        
    Yields:
        Configured AsyncIOMotorClient instance with async connection pooling
    """
    client = await mongodb_container.get_motor_client()
    
    try:
        # Verify async connection health
        await client.admin.command('ping')
        
        logger.debug(
            "Motor test client created",
            database_name=client.get_default_database().name,
            max_pool_size=client.options.pool_options.max_pool_size
        )
        
        yield client
        
    finally:
        try:
            client.close()
            logger.debug("Motor test client closed")
        except Exception as e:
            logger.warning(f"Error closing Motor test client: {e}")


@pytest.fixture(scope="function")
def redis_client(redis_container: RedisTestContainer) -> Generator[Redis, None, None]:
    """
    Function-scoped fixture providing Redis client connected to test container.
    
    Creates Redis client with production-equivalent connection pooling
    configuration for cache and session management testing scenarios.
    
    Args:
        redis_container: Redis test container instance
        
    Yields:
        Configured Redis client instance with connection pooling
    """
    client = redis_container.get_redis_client()
    
    try:
        # Verify connection health
        client.ping()
        
        logger.debug(
            "Redis test client created",
            host=client.connection_pool.connection_kwargs['host'],
            port=client.connection_pool.connection_kwargs['port']
        )
        
        yield client
        
    finally:
        try:
            client.close()
            logger.debug("Redis test client closed")
        except Exception as e:
            logger.warning(f"Error closing Redis test client: {e}")


# =============================================================================
# Advanced Database Fixtures for Comprehensive Testing
# =============================================================================

@pytest.fixture(scope="function")
def database_manager(
    pymongo_client: MongoClient,
    redis_client: Redis,
    database_container_config: DatabaseContainerConfig
) -> Generator[DatabaseManager, None, None]:
    """
    Function-scoped fixture providing configured DatabaseManager instance.
    
    Creates DatabaseManager with Testcontainers-backed database connections
    for comprehensive application-level database testing scenarios.
    
    Args:
        pymongo_client: PyMongo client connected to test container
        redis_client: Redis client connected to test container
        database_container_config: Container configuration settings
        
    Yields:
        Configured DatabaseManager instance for application testing
    """
    # Create configuration for DatabaseManager
    mongodb_uri = f"mongodb://{database_container_config.mongodb_username}:{database_container_config.mongodb_password}@{pymongo_client.HOST}:{pymongo_client.PORT}/{database_container_config.mongodb_database}"
    
    config = DatabasePackageConfig(
        mongodb_uri=mongodb_uri,
        database_name=database_container_config.mongodb_database,
        max_pool_size=DEFAULT_MAX_POOL_SIZE,
        min_pool_size=DEFAULT_MIN_POOL_SIZE,
        enable_monitoring=database_container_config.enable_performance_validation
    )
    
    manager = DatabaseManager(config)
    
    try:
        # Initialize with existing connections would be ideal, but create new for isolation
        logger.debug(
            "Database manager created for testing",
            database_name=config.database_name,
            monitoring_enabled=config.enable_monitoring
        )
        
        yield manager
        
    finally:
        try:
            manager.close()
            logger.debug("Database manager closed")
        except Exception as e:
            logger.warning(f"Error closing database manager: {e}")


@pytest.fixture(scope="function")
def database_seeder(
    pymongo_client: MongoClient,
    redis_client: Redis
) -> Generator[DatabaseSeeder, None, None]:
    """
    Function-scoped fixture providing database seeding utility.
    
    Creates DatabaseSeeder for populating test databases with realistic
    data sets and managing test data lifecycle across testing scenarios.
    
    Args:
        pymongo_client: PyMongo client connected to test container
        redis_client: Redis client connected to test container
        
    Yields:
        DatabaseSeeder instance for test data management
    """
    seeder = DatabaseSeeder(pymongo_client, redis_client)
    
    try:
        # Setup initial database state
        seeder.create_indexes()
        
        logger.debug("Database seeder created and indexes established")
        
        yield seeder
        
    finally:
        try:
            # Clean up test data
            seeder.cleanup_collections()
            logger.debug("Database seeder cleanup completed")
        except Exception as e:
            logger.warning(f"Error during database seeder cleanup: {e}")


@pytest.fixture(scope="function")
def performance_validator(
    database_container_config: DatabaseContainerConfig
) -> Generator[PerformanceValidator, None, None]:
    """
    Function-scoped fixture providing performance validation utility.
    
    Creates PerformanceValidator for measuring database operation performance
    and validating compliance with ≤10% variance requirements from Node.js baseline.
    
    Args:
        database_container_config: Container configuration with performance settings
        
    Yields:
        PerformanceValidator instance for performance measurement and validation
    """
    validator = PerformanceValidator(
        variance_threshold=database_container_config.performance_variance_threshold
    )
    
    try:
        logger.debug(
            "Performance validator created",
            variance_threshold=database_container_config.performance_variance_threshold
        )
        
        yield validator
        
    finally:
        # Log performance summary
        summary = validator.get_performance_summary()
        logger.info(
            "Performance validation summary",
            total_measurements=summary['total_measurements'],
            successful_measurements=summary['successful_measurements'],
            failed_measurements=summary['failed_measurements'],
            average_execution_time_ms=summary['average_execution_time_ms']
        )


@pytest.fixture(scope="function")
def seeded_database(
    database_seeder: DatabaseSeeder
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Function-scoped fixture providing pre-seeded database for testing.
    
    Creates realistic test dataset with users, projects, sessions, and cache data
    for comprehensive integration testing scenarios without manual data setup.
    
    Args:
        database_seeder: Database seeding utility instance
        
    Returns:
        Dictionary containing all seeded data organized by entity type
    """
    # Seed users first to get user IDs for relationships
    users = database_seeder.seed_users(count=20)
    user_ids = [user['_id'] for user in users]
    
    # Seed projects with user relationships
    projects = database_seeder.seed_projects(count=10, user_ids=user_ids)
    
    # Seed sessions with user relationships
    sessions = database_seeder.seed_sessions(count=30, user_ids=user_ids)
    
    # Seed cache data
    cache_data = database_seeder.seed_cache_data(count=100)
    
    seeded_data = {
        'users': users,
        'projects': projects,
        'sessions': sessions,
        'cache_data': cache_data
    }
    
    logger.info(
        "Database seeded with comprehensive test data",
        users_count=len(users),
        projects_count=len(projects),
        sessions_count=len(sessions),
        cache_entries_count=len(cache_data)
    )
    
    return seeded_data


# =============================================================================
# Connection Pooling and Performance Testing Fixtures
# =============================================================================

@pytest.fixture(scope="function")
def connection_pool_tester(
    mongodb_container: MongoDbTestContainer,
    database_container_config: DatabaseContainerConfig
) -> Generator[callable, None, None]:
    """
    Function-scoped fixture providing connection pool testing utility.
    
    Creates utility function for testing PyMongo and Motor connection pool
    behavior under various load conditions to validate Node.js equivalent
    connection management patterns.
    
    Args:
        mongodb_container: MongoDB test container instance
        database_container_config: Container configuration settings
        
    Yields:
        Callable function for connection pool testing scenarios
    """
    def test_connection_pool(
        max_connections: int = 20,
        concurrent_operations: int = 10,
        operation_duration_ms: int = 100
    ) -> Dict[str, Any]:
        """
        Test connection pool behavior under concurrent load.
        
        Args:
            max_connections: Maximum connections to test
            concurrent_operations: Number of concurrent operations
            operation_duration_ms: Duration of each operation in milliseconds
            
        Returns:
            Dictionary containing connection pool performance metrics
        """
        import threading
        import concurrent.futures
        
        results = {
            'successful_connections': 0,
            'failed_connections': 0,
            'connection_times': [],
            'operation_times': [],
            'pool_exhaustion_events': 0,
            'concurrent_connections_peak': 0
        }
        
        def connection_test_operation():
            try:
                start_time = time.perf_counter()
                
                # Create connection with limited pool size
                client = mongodb_container.get_pymongo_client(
                    maxPoolSize=max_connections,
                    minPoolSize=2,
                    waitQueueTimeoutMS=5000
                )
                
                connection_time = time.perf_counter() - start_time
                results['connection_times'].append(connection_time * 1000)
                
                # Perform database operation
                op_start_time = time.perf_counter()
                client.admin.command('ping')
                time.sleep(operation_duration_ms / 1000)  # Simulate operation duration
                op_end_time = time.perf_counter()
                
                operation_time = (op_end_time - op_start_time) * 1000
                results['operation_times'].append(operation_time)
                
                client.close()
                results['successful_connections'] += 1
                
            except Exception as e:
                results['failed_connections'] += 1
                if "pool" in str(e).lower() or "timeout" in str(e).lower():
                    results['pool_exhaustion_events'] += 1
                logger.debug(f"Connection test operation failed: {e}")
        
        # Execute concurrent operations
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrent_operations) as executor:
            futures = [
                executor.submit(connection_test_operation)
                for _ in range(concurrent_operations)
            ]
            
            # Wait for all operations to complete
            concurrent.futures.wait(futures, timeout=60)
        
        # Calculate statistics
        if results['connection_times']:
            results['avg_connection_time_ms'] = sum(results['connection_times']) / len(results['connection_times'])
            results['max_connection_time_ms'] = max(results['connection_times'])
            results['min_connection_time_ms'] = min(results['connection_times'])
        
        if results['operation_times']:
            results['avg_operation_time_ms'] = sum(results['operation_times']) / len(results['operation_times'])
            results['max_operation_time_ms'] = max(results['operation_times'])
            results['min_operation_time_ms'] = min(results['operation_times'])
        
        results['total_operations'] = concurrent_operations
        results['success_rate'] = results['successful_connections'] / concurrent_operations if concurrent_operations > 0 else 0
        
        logger.info(
            "Connection pool test completed",
            max_connections=max_connections,
            concurrent_operations=concurrent_operations,
            successful_connections=results['successful_connections'],
            failed_connections=results['failed_connections'],
            success_rate=results['success_rate']
        )
        
        return results
    
    yield test_connection_pool


@pytest_asyncio.fixture(scope="function")
async def async_connection_pool_tester(
    mongodb_container: MongoDbTestContainer,
    database_container_config: DatabaseContainerConfig
) -> AsyncGenerator[callable, None]:
    """
    Function-scoped async fixture providing Motor connection pool testing utility.
    
    Creates utility function for testing Motor async connection pool behavior
    under various concurrent load conditions to validate async database
    operations performance equivalent to Node.js patterns.
    
    Args:
        mongodb_container: MongoDB test container instance
        database_container_config: Container configuration settings
        
    Yields:
        Callable async function for Motor connection pool testing scenarios
    """
    async def test_async_connection_pool(
        max_connections: int = 20,
        concurrent_operations: int = 10,
        operation_duration_ms: int = 100
    ) -> Dict[str, Any]:
        """
        Test Motor async connection pool behavior under concurrent load.
        
        Args:
            max_connections: Maximum connections to test
            concurrent_operations: Number of concurrent operations
            operation_duration_ms: Duration of each operation in milliseconds
            
        Returns:
            Dictionary containing async connection pool performance metrics
        """
        results = {
            'successful_connections': 0,
            'failed_connections': 0,
            'connection_times': [],
            'operation_times': [],
            'pool_exhaustion_events': 0,
            'async_operations_completed': 0
        }
        
        async def async_connection_test_operation():
            try:
                start_time = time.perf_counter()
                
                # Create async connection with limited pool size
                client = await mongodb_container.get_motor_client(
                    maxPoolSize=max_connections,
                    minPoolSize=2,
                    waitQueueTimeoutMS=5000
                )
                
                connection_time = time.perf_counter() - start_time
                results['connection_times'].append(connection_time * 1000)
                
                # Perform async database operation
                op_start_time = time.perf_counter()
                await client.admin.command('ping')
                await asyncio.sleep(operation_duration_ms / 1000)  # Simulate async operation
                op_end_time = time.perf_counter()
                
                operation_time = (op_end_time - op_start_time) * 1000
                results['operation_times'].append(operation_time)
                
                client.close()
                results['successful_connections'] += 1
                results['async_operations_completed'] += 1
                
            except Exception as e:
                results['failed_connections'] += 1
                if "pool" in str(e).lower() or "timeout" in str(e).lower():
                    results['pool_exhaustion_events'] += 1
                logger.debug(f"Async connection test operation failed: {e}")
        
        # Execute concurrent async operations
        tasks = [
            async_connection_test_operation()
            for _ in range(concurrent_operations)
        ]
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        # Calculate statistics
        if results['connection_times']:
            results['avg_connection_time_ms'] = sum(results['connection_times']) / len(results['connection_times'])
            results['max_connection_time_ms'] = max(results['connection_times'])
            results['min_connection_time_ms'] = min(results['connection_times'])
        
        if results['operation_times']:
            results['avg_operation_time_ms'] = sum(results['operation_times']) / len(results['operation_times'])
            results['max_operation_time_ms'] = max(results['operation_times'])
            results['min_operation_time_ms'] = min(results['operation_times'])
        
        results['total_async_operations'] = concurrent_operations
        results['async_success_rate'] = results['successful_connections'] / concurrent_operations if concurrent_operations > 0 else 0
        
        logger.info(
            "Async connection pool test completed",
            max_connections=max_connections,
            concurrent_operations=concurrent_operations,
            successful_connections=results['successful_connections'],
            failed_connections=results['failed_connections'],
            async_success_rate=results['async_success_rate']
        )
        
        return results
    
    yield test_async_connection_pool


# =============================================================================
# Comprehensive Test Scenario Fixtures
# =============================================================================

@pytest.fixture(scope="function")
def comprehensive_database_environment(
    pymongo_client: MongoClient,
    motor_client: AsyncIOMotorClient,
    redis_client: Redis,
    database_seeder: DatabaseSeeder,
    performance_validator: PerformanceValidator,
    seeded_database: Dict[str, List[Dict[str, Any]]]
) -> Dict[str, Any]:
    """
    Function-scoped fixture providing comprehensive database testing environment.
    
    Creates complete testing environment with all database clients, seeded data,
    performance validation utilities, and monitoring capabilities for end-to-end
    database testing scenarios across synchronous and asynchronous operations.
    
    Args:
        pymongo_client: PyMongo synchronous client
        motor_client: Motor async client
        redis_client: Redis cache client
        database_seeder: Database seeding utility
        performance_validator: Performance validation utility
        seeded_database: Pre-seeded test data
        
    Returns:
        Dictionary containing complete database testing environment
    """
    environment = {
        'clients': {
            'pymongo': pymongo_client,
            'motor': motor_client,
            'redis': redis_client
        },
        'utilities': {
            'seeder': database_seeder,
            'performance_validator': performance_validator
        },
        'data': seeded_database,
        'databases': {
            'mongodb': pymongo_client.get_default_database(),
            'motor_db': motor_client.get_default_database()
        },
        'collections': {
            'users': pymongo_client.get_default_database().users,
            'projects': pymongo_client.get_default_database().projects
        },
        'environment_info': {
            'mongodb_version': pymongo_client.server_info()['version'],
            'redis_version': redis_client.info()['redis_version'],
            'total_users': len(seeded_database['users']),
            'total_projects': len(seeded_database['projects']),
            'total_sessions': len(seeded_database['sessions']),
            'total_cache_entries': len(seeded_database['cache_data'])
        }
    }
    
    logger.info(
        "Comprehensive database environment created",
        mongodb_version=environment['environment_info']['mongodb_version'],
        redis_version=environment['environment_info']['redis_version'],
        total_data_entities=sum([
            environment['environment_info']['total_users'],
            environment['environment_info']['total_projects'],
            environment['environment_info']['total_sessions'],
            environment['environment_info']['total_cache_entries']
        ])
    )
    
    return environment


# Export all fixtures for easy import in test modules
__all__ = [
    # Container configuration and management
    'DatabaseContainerConfig',
    'MongoDbTestContainer',
    'RedisTestContainer',
    'database_container_config',
    'mongodb_container',
    'redis_container',
    
    # Database client fixtures
    'pymongo_client',
    'motor_client',
    'redis_client',
    
    # Application-level fixtures
    'database_manager',
    'database_seeder',
    'performance_validator',
    'seeded_database',
    
    # Performance and connection testing fixtures
    'connection_pool_tester',
    'async_connection_pool_tester',
    
    # Comprehensive testing environment
    'comprehensive_database_environment',
    
    # Test data factories
    'BaseTestObjectFactory',
    'UserDocumentFactory',
    'AddressFactory',
    'ProjectDocumentFactory',
    'SessionDocumentFactory',
    
    # Utilities
    'DatabaseSeeder',
    'PerformanceValidator'
]