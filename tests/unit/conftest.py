"""
Global pytest Configuration and Fixture Definitions

This module provides comprehensive test infrastructure for Flask application testing including
pytest 7.4+ configuration, Flask test client setup, Testcontainers integration for realistic
MongoDB and Redis instances, authentication fixtures for JWT and Auth0 mock responses, and
shared testing utilities for all unit test modules.

The configuration implements enterprise-grade testing patterns per Section 6.6.1 with
comprehensive external service mocking, dynamic test object generation using factory_boy,
and pytest-asyncio configuration for Motor async database operations testing.

Key Features:
- pytest 7.4+ framework with extensive plugin ecosystem support per Section 6.6.1
- Flask application testing with pytest-flask integration per Section 6.6.1
- Testcontainers for realistic MongoDB and Redis test instances per Section 6.6.1
- Authentication testing fixtures for JWT and Auth0 mock responses per Section 6.6.1
- pytest-mock integration for external service mocking per Section 6.6.1
- factory_boy integration for dynamic test object generation per Section 6.6.1
- pytest-asyncio for asynchronous database operations testing per Section 6.6.1
- Comprehensive test isolation and cleanup patterns per Section 6.6.1
- Performance monitoring integration ensuring ≤10% variance compliance per Section 0.1.1

Architecture Integration:
- Section 6.6.1: pytest fixture configuration for Flask application testing
- Section 6.6.1: Testcontainers integration for MongoDB and Redis testing
- Section 6.6.1: Flask test client fixtures with application factory pattern
- Section 6.6.1: Authentication fixtures for JWT token generation and validation testing
- Section 6.6.1: pytest-mock integration for external service mocking
- Section 6.6.1: factory_boy integration for dynamic test object generation
- Section 6.6.1: pytest-asyncio for asynchronous database operations testing

Testing Standards:
- Unit test coverage target: 95% per Section 6.6.3 for core business logic
- API layer coverage: 100% per Section 6.6.3 for critical requirement
- Authentication module coverage: 95% per Section 6.6.3 for security compliance
- Integration test reliability: ≥99% success rate per Section 6.6.3
- Performance variance: ≤10% from Node.js baseline per Section 0.1.1

Dependencies:
- pytest 7.4+: Primary testing framework with extensive plugin ecosystem
- pytest-flask: Flask-specific testing patterns and fixtures
- pytest-mock: Comprehensive external service simulation
- pytest-asyncio: Asynchronous database operations testing
- testcontainers[mongodb,redis] ≥4.10.0: Realistic database and cache testing
- factory_boy: Dynamic test object generation with varied scenarios
- pytest-cov: Real-time coverage reporting and threshold enforcement
- pytest-xdist: Parallel test execution for optimized performance

Author: Flask Migration Team
Version: 1.0.0
Coverage Target: 95% core business logic, 100% API layer per Section 6.6.3
"""

import os
import sys
import asyncio
import logging
import tempfile
import time
import warnings
from typing import Dict, Any, Optional, List, Union, Generator, AsyncGenerator
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch
import gc

# pytest core imports
import pytest
import pytest_asyncio
from pytest_mock import MockerFixture

# Flask testing imports
from flask import Flask, testing
from flask.testing import FlaskClient

# Testcontainers imports for realistic database and cache testing
from testcontainers.mongodb import MongoDbContainer
from testcontainers.redis import RedisContainer
from testcontainers.core.generic import DockerContainer
from testcontainers.core.waiting_strategies import LogMessageWaitStrategy

# Database and cache client imports
import pymongo
from pymongo import MongoClient
from motor.motor_asyncio import AsyncIOMotorClient
import redis
from redis.asyncio import Redis as AsyncRedis

# Authentication and JWT testing imports
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# Factory and data generation imports
import factory
from factory import Faker, LazyFunction, SubFactory, fuzzy
from faker import Factory as FakerFactory

# Application imports
from src.app import create_app, FlaskApplicationFactory, cleanup_application
from src.config.settings import (
    BaseConfig, 
    DevelopmentConfig, 
    TestingConfig,
    create_config_for_environment
)
from src.auth.authentication import JWTManager, User
from src.data.database import DatabaseManager
from src.cache.redis_client import CacheManager

# Test fixtures from dedicated modules
from tests.fixtures.database_fixtures import (
    mongodb_container_config,
    redis_container_config,
    create_test_database_client,
    create_test_motor_client,
    create_test_redis_client
)
from tests.fixtures.auth_fixtures import (
    create_test_jwt_token,
    create_mock_auth0_client,
    create_test_user,
    mock_jwt_validation
)

# Configure test logging to reduce noise during test execution
logging.getLogger('testcontainers').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('requests').setLevel(logging.WARNING)
logging.getLogger('docker').setLevel(logging.WARNING)

# Suppress specific warnings during testing
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=PendingDeprecationWarning)
warnings.filterwarnings("ignore", message=".*unclosed.*", category=ResourceWarning)

# Configure faker for deterministic test data generation
fake = FakerFactory.create()
fake.seed_instance(42)  # Deterministic test data for reproducible tests


# ============================================================================
# pytest Configuration
# ============================================================================

def pytest_configure(config):
    """
    Configure pytest environment for Flask application testing.
    
    Sets up test markers, configures asyncio policies, initializes test
    databases, and establishes comprehensive test isolation patterns.
    """
    # Register custom test markers for test categorization
    config.addinivalue_line(
        "markers",
        "unit: Unit tests for individual components and functions"
    )
    config.addinivalue_line(
        "markers", 
        "integration: Integration tests for service interactions"
    )
    config.addinivalue_line(
        "markers",
        "auth: Authentication and authorization testing"
    )
    config.addinivalue_line(
        "markers",
        "database: Database operation and connection testing"
    )
    config.addinivalue_line(
        "markers",
        "cache: Redis caching and session management testing"
    )
    config.addinivalue_line(
        "markers",
        "api: Flask API endpoint testing"
    )
    config.addinivalue_line(
        "markers",
        "performance: Performance validation and baseline comparison"
    )
    config.addinivalue_line(
        "markers",
        "security: Security vulnerability and compliance testing"
    )
    config.addinivalue_line(
        "markers",
        "mock: External service mocking and simulation"
    )
    config.addinivalue_line(
        "markers",
        "slow: Long-running tests requiring extended execution time"
    )
    
    # Configure asyncio event loop policy for pytest-asyncio
    if sys.platform.startswith('win'):
        # Windows-specific event loop policy
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    else:
        # Unix-specific event loop policy for optimal performance
        try:
            import uvloop
            asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        except ImportError:
            # Fallback to default event loop policy
            asyncio.set_event_loop_policy(asyncio.DefaultEventLoopPolicy())
    
    # Set environment variables for testing
    os.environ.setdefault('FLASK_ENV', 'testing')
    os.environ.setdefault('TESTING', 'true')
    os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-testing-only')
    os.environ.setdefault('WTF_CSRF_ENABLED', 'false')  # Disable CSRF for testing
    
    # Configure test database and cache URLs (will be overridden by containers)
    os.environ.setdefault('MONGODB_URI', 'mongodb://localhost:27017/test_db')
    os.environ.setdefault('REDIS_URL', 'redis://localhost:6379/1')
    
    # Disable external service integrations during testing
    os.environ.setdefault('AUTH0_DOMAIN', 'test-domain.auth0.com')
    os.environ.setdefault('AUTH0_AUDIENCE', 'test-audience')
    os.environ.setdefault('AUTH0_CLIENT_ID', 'test-client-id')
    os.environ.setdefault('AUTH0_CLIENT_SECRET', 'test-client-secret')
    
    # Configure test-specific logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )


def pytest_collection_modifyitems(config, items):
    """
    Modify collected test items for optimized execution order.
    
    Prioritizes fast unit tests before slower integration tests,
    groups tests by markers for efficient resource utilization,
    and configures parallel execution patterns.
    """
    # Separate tests by execution time and complexity
    unit_tests = []
    integration_tests = []
    slow_tests = []
    auth_tests = []
    database_tests = []
    
    for item in items:
        if 'slow' in item.keywords:
            slow_tests.append(item)
        elif 'integration' in item.keywords:
            integration_tests.append(item)
        elif 'auth' in item.keywords:
            auth_tests.append(item)
        elif 'database' in item.keywords:
            database_tests.append(item)
        else:
            unit_tests.append(item)
    
    # Reorder tests for optimal execution: unit -> auth -> database -> integration -> slow
    items[:] = unit_tests + auth_tests + database_tests + integration_tests + slow_tests


def pytest_sessionstart(session):
    """
    Initialize pytest session with comprehensive test environment setup.
    
    Configures global test containers, initializes shared test resources,
    and establishes baseline performance metrics for comparison testing.
    """
    print("\n" + "="*80)
    print("INITIALIZING COMPREHENSIVE FLASK APPLICATION TEST SUITE")
    print("="*80)
    print(f"pytest version: {pytest.__version__}")
    print(f"Python version: {sys.version}")
    print(f"Flask environment: {os.getenv('FLASK_ENV', 'unknown')}")
    print(f"Test execution time: {datetime.now().isoformat()}")
    print("="*80 + "\n")


def pytest_sessionfinish(session, exitstatus):
    """
    Clean up pytest session resources and generate test summary.
    
    Performs comprehensive cleanup of test containers, generates
    coverage reports, and validates test execution metrics.
    """
    print("\n" + "="*80)
    print("FLASK APPLICATION TEST SUITE EXECUTION COMPLETED")
    print("="*80)
    print(f"Exit status: {exitstatus}")
    print(f"Test completion time: {datetime.now().isoformat()}")
    
    # Force garbage collection to clean up test resources
    gc.collect()
    
    if exitstatus == 0:
        print("✅ All tests passed successfully!")
    else:
        print("❌ Some tests failed. Check output above for details.")
    
    print("="*80 + "\n")


# ============================================================================
# Application Factory and Configuration Fixtures
# ============================================================================

@pytest.fixture(scope='session')
def testing_config():
    """
    Create testing configuration for Flask application.
    
    Returns:
        TestingConfig: Configuration instance optimized for testing
    """
    return create_config_for_environment('testing')


@pytest.fixture(scope='session')
def app_factory():
    """
    Create Flask application factory for test session.
    
    Returns:
        FlaskApplicationFactory: Application factory instance
    """
    return FlaskApplicationFactory()


@pytest.fixture(scope='function')
def app(testing_config, mongodb_container, redis_container):
    """
    Create Flask application instance for testing with real database containers.
    
    This fixture provides a fully configured Flask application with:
    - Testcontainers for realistic MongoDB and Redis behavior
    - Comprehensive authentication system mocking
    - Performance monitoring integration
    - Complete error handling and middleware pipeline
    
    Args:
        testing_config: Testing configuration instance
        mongodb_container: MongoDB Testcontainer instance
        redis_container: Redis Testcontainer instance
        
    Returns:
        Flask: Configured Flask application for testing
    """
    # Configure application with container connection strings
    config_overrides = {
        'TESTING': True,
        'WTF_CSRF_ENABLED': False,
        'MONGODB_URI': mongodb_container.get_connection_url(),
        'REDIS_URL': redis_container.get_connection_url(),
        'SECRET_KEY': 'test-secret-key-for-testing-only',
        'JWT_SECRET_KEY': 'test-jwt-secret-key',
        'AUTH0_DOMAIN': 'test-domain.auth0.com',
        'AUTH0_AUDIENCE': 'test-audience',
        'AUTH0_CLIENT_ID': 'test-client-id',
        'AUTH0_CLIENT_SECRET': 'test-client-secret',
        'RATELIMIT_ENABLED': False,  # Disable rate limiting for testing
        'TALISMAN_ENABLED': False,   # Disable security headers for testing
        'CORS_ENABLED': True,
        'MONITORING_ENABLED': False  # Disable monitoring for testing
    }
    
    # Create Flask application with testing configuration
    app = create_app(
        config_name='testing',
        **config_overrides
    )
    
    # Establish application context for testing
    with app.app_context():
        yield app
    
    # Cleanup application resources
    try:
        cleanup_application(app)
    except Exception as e:
        print(f"Warning: Application cleanup error: {e}")


@pytest.fixture(scope='function')
def client(app):
    """
    Create Flask test client for HTTP endpoint testing.
    
    Args:
        app: Flask application instance
        
    Returns:
        FlaskClient: Test client for HTTP request simulation
    """
    return app.test_client()


@pytest.fixture(scope='function')
def runner(app):
    """
    Create Flask CLI test runner for command testing.
    
    Args:
        app: Flask application instance
        
    Returns:
        FlaskCliRunner: CLI test runner for command simulation
    """
    return app.test_cli_runner()


# ============================================================================
# Testcontainers Integration Fixtures
# ============================================================================

@pytest.fixture(scope='session')
def mongodb_container():
    """
    Create MongoDB Testcontainer for realistic database testing.
    
    Provides production-equivalent MongoDB behavior with automated
    container lifecycle management, connection pooling validation,
    and performance monitoring integration.
    
    Returns:
        MongoDbContainer: MongoDB container instance with connection details
    """
    # Configure MongoDB container with production-equivalent settings
    container = MongoDbContainer(
        image="mongo:7.0-jammy",
        port=27017
    )
    
    # Configure container with optimized settings for testing
    container.with_env("MONGO_INITDB_ROOT_USERNAME", "testuser")
    container.with_env("MONGO_INITDB_ROOT_PASSWORD", "testpass")
    container.with_env("MONGO_INITDB_DATABASE", "test_database")
    
    # Configure wait strategy for container readiness
    container.with_wait_strategy(
        LogMessageWaitStrategy("waiting for connections on port")
    )
    
    try:
        # Start container and wait for readiness
        container.start()
        
        # Validate container connectivity
        connection_url = container.get_connection_url()
        client = MongoClient(connection_url)
        
        # Verify database connectivity
        client.admin.command('ping')
        client.close()
        
        print(f"✅ MongoDB container started: {connection_url}")
        yield container
        
    finally:
        # Cleanup container resources
        try:
            container.stop()
            print("✅ MongoDB container stopped successfully")
        except Exception as e:
            print(f"Warning: MongoDB container cleanup error: {e}")


@pytest.fixture(scope='session')
def redis_container():
    """
    Create Redis Testcontainer for realistic caching and session testing.
    
    Provides production-equivalent Redis behavior with automated
    container lifecycle management, session management validation,
    and cache performance optimization testing.
    
    Returns:
        RedisContainer: Redis container instance with connection details
    """
    # Configure Redis container with production-equivalent settings
    container = RedisContainer(
        image="redis:7-alpine",
        port=6379
    )
    
    # Configure Redis with testing optimizations
    container.with_command("redis-server --appendonly yes --maxmemory 256mb")
    
    try:
        # Start container and wait for readiness
        container.start()
        
        # Validate container connectivity
        connection_url = container.get_connection_url()
        client = redis.from_url(connection_url)
        
        # Verify Redis connectivity
        client.ping()
        client.close()
        
        print(f"✅ Redis container started: {connection_url}")
        yield container
        
    finally:
        # Cleanup container resources
        try:
            container.stop()
            print("✅ Redis container stopped successfully")
        except Exception as e:
            print(f"Warning: Redis container cleanup error: {e}")


# ============================================================================
# Database Connection Fixtures
# ============================================================================

@pytest.fixture(scope='function')
def mongodb_client(mongodb_container):
    """
    Create PyMongo client for synchronous database operations testing.
    
    Args:
        mongodb_container: MongoDB Testcontainer instance
        
    Returns:
        MongoClient: Configured PyMongo client with connection pooling
    """
    connection_url = mongodb_container.get_connection_url()
    
    client = MongoClient(
        connection_url,
        maxPoolSize=10,
        minPoolSize=1,
        maxIdleTimeMS=30000,
        waitQueueTimeoutMS=5000,
        serverSelectionTimeoutMS=5000,
        connectTimeoutMS=10000,
        socketTimeoutMS=20000
    )
    
    try:
        # Verify connectivity
        client.admin.command('ping')
        yield client
    finally:
        client.close()


@pytest.fixture(scope='function')
async def motor_client(mongodb_container):
    """
    Create Motor async client for asynchronous database operations testing.
    
    Args:
        mongodb_container: MongoDB Testcontainer instance
        
    Returns:
        AsyncIOMotorClient: Configured Motor client for async operations
    """
    connection_url = mongodb_container.get_connection_url()
    
    client = AsyncIOMotorClient(
        connection_url,
        maxPoolSize=10,
        minPoolSize=1,
        maxIdleTimeMS=30000,
        waitQueueTimeoutMS=5000,
        serverSelectionTimeoutMS=5000,
        connectTimeoutMS=10000,
        socketTimeoutMS=20000
    )
    
    try:
        # Verify async connectivity
        await client.admin.command('ping')
        yield client
    finally:
        client.close()


@pytest.fixture(scope='function')
def redis_client(redis_container):
    """
    Create Redis client for caching and session management testing.
    
    Args:
        redis_container: Redis Testcontainer instance
        
    Returns:
        redis.Redis: Configured Redis client with connection pooling
    """
    connection_url = redis_container.get_connection_url()
    
    client = redis.from_url(
        connection_url,
        max_connections=10,
        retry_on_timeout=True,
        socket_timeout=5,
        socket_connect_timeout=5,
        health_check_interval=30
    )
    
    try:
        # Verify connectivity
        client.ping()
        
        # Clear any existing test data
        client.flushdb()
        
        yield client
    finally:
        # Cleanup test data
        try:
            client.flushdb()
            client.close()
        except Exception:
            pass


@pytest.fixture(scope='function')
async def async_redis_client(redis_container):
    """
    Create async Redis client for asynchronous caching operations testing.
    
    Args:
        redis_container: Redis Testcontainer instance
        
    Returns:
        redis.asyncio.Redis: Configured async Redis client
    """
    connection_url = redis_container.get_connection_url()
    
    client = AsyncRedis.from_url(
        connection_url,
        max_connections=10,
        retry_on_timeout=True,
        socket_timeout=5,
        socket_connect_timeout=5,
        health_check_interval=30
    )
    
    try:
        # Verify async connectivity
        await client.ping()
        
        # Clear any existing test data
        await client.flushdb()
        
        yield client
    finally:
        # Cleanup test data
        try:
            await client.flushdb()
            await client.close()
        except Exception:
            pass


# ============================================================================
# Authentication and JWT Fixtures
# ============================================================================

@pytest.fixture(scope='session')
def rsa_keypair():
    """
    Generate RSA keypair for JWT token signing and validation testing.
    
    Returns:
        tuple: (private_key, public_key) for JWT operations
    """
    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Extract public key
    public_key = private_key.public_key()
    
    return private_key, public_key


@pytest.fixture(scope='session')
def jwt_private_key(rsa_keypair):
    """
    Get RSA private key for JWT token signing.
    
    Returns:
        RSAPrivateKey: Private key for JWT signing
    """
    private_key, _ = rsa_keypair
    return private_key


@pytest.fixture(scope='session')
def jwt_public_key(rsa_keypair):
    """
    Get RSA public key for JWT token validation.
    
    Returns:
        RSAPublicKey: Public key for JWT validation
    """
    _, public_key = rsa_keypair
    return public_key


@pytest.fixture(scope='session')
def jwt_secret_key():
    """
    Generate JWT secret key for HMAC-based token operations.
    
    Returns:
        str: Secret key for JWT HMAC operations
    """
    return 'test-jwt-secret-key-for-testing-only'


@pytest.fixture(scope='function')
def mock_auth0_client(mocker: MockerFixture):
    """
    Create comprehensive Auth0 client mock for authentication testing.
    
    Args:
        mocker: pytest-mock fixture for mocking external services
        
    Returns:
        Mock: Configured Auth0 client mock with realistic responses
    """
    # Create Auth0 client mock
    auth0_mock = mocker.Mock()
    
    # Mock user info endpoint
    auth0_mock.users.get.return_value = {
        'user_id': 'auth0|test_user_id',
        'email': 'test@example.com',
        'name': 'Test User',
        'picture': 'https://example.com/avatar.jpg',
        'email_verified': True,
        'created_at': '2023-01-01T00:00:00.000Z',
        'updated_at': '2023-01-01T00:00:00.000Z',
        'user_metadata': {},
        'app_metadata': {
            'roles': ['user'],
            'permissions': ['read:profile']
        }
    }
    
    # Mock user list endpoint
    auth0_mock.users.list.return_value = {
        'users': [auth0_mock.users.get.return_value],
        'total': 1,
        'length': 1,
        'start': 0,
        'limit': 50
    }
    
    # Mock token introspection
    auth0_mock.oauth.introspect_token.return_value = {
        'active': True,
        'client_id': 'test-client-id',
        'username': 'test@example.com',
        'scope': 'read:profile write:profile',
        'exp': int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
        'iat': int(datetime.now(timezone.utc).timestamp()),
        'sub': 'auth0|test_user_id',
        'aud': 'test-audience'
    }
    
    return auth0_mock


@pytest.fixture(scope='function')
def valid_jwt_token(jwt_secret_key):
    """
    Generate valid JWT token for authentication testing.
    
    Args:
        jwt_secret_key: Secret key for token signing
        
    Returns:
        str: Valid JWT token with test claims
    """
    # Define token payload with comprehensive claims
    payload = {
        'sub': 'auth0|test_user_id',
        'iss': 'https://test-domain.auth0.com/',
        'aud': 'test-audience',
        'iat': int(datetime.now(timezone.utc).timestamp()),
        'exp': int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
        'azp': 'test-client-id',
        'scope': 'read:profile write:profile',
        'permissions': ['read:profile', 'write:profile'],
        'email': 'test@example.com',
        'email_verified': True,
        'name': 'Test User',
        'picture': 'https://example.com/avatar.jpg',
        'user_metadata': {},
        'app_metadata': {
            'roles': ['user'],
            'permissions': ['read:profile']
        }
    }
    
    # Generate JWT token
    token = jwt.encode(
        payload,
        jwt_secret_key,
        algorithm='HS256'
    )
    
    return token


@pytest.fixture(scope='function')
def expired_jwt_token(jwt_secret_key):
    """
    Generate expired JWT token for negative testing scenarios.
    
    Args:
        jwt_secret_key: Secret key for token signing
        
    Returns:
        str: Expired JWT token for testing
    """
    # Define expired token payload
    payload = {
        'sub': 'auth0|test_user_id',
        'iss': 'https://test-domain.auth0.com/',
        'aud': 'test-audience',
        'iat': int((datetime.now(timezone.utc) - timedelta(hours=2)).timestamp()),
        'exp': int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp()),
        'azp': 'test-client-id',
        'scope': 'read:profile',
        'email': 'test@example.com',
        'name': 'Test User'
    }
    
    # Generate expired JWT token
    token = jwt.encode(
        payload,
        jwt_secret_key,
        algorithm='HS256'
    )
    
    return token


@pytest.fixture(scope='function')
def invalid_jwt_token():
    """
    Generate invalid JWT token for negative testing scenarios.
    
    Returns:
        str: Invalid JWT token for error testing
    """
    return 'invalid.jwt.token.for.testing'


@pytest.fixture(scope='function')
def test_user_data():
    """
    Generate test user data for authentication testing.
    
    Returns:
        dict: User data for testing scenarios
    """
    return {
        'user_id': 'auth0|test_user_id',
        'email': 'test@example.com',
        'name': 'Test User',
        'picture': 'https://example.com/avatar.jpg',
        'email_verified': True,
        'created_at': datetime.now(timezone.utc).isoformat(),
        'updated_at': datetime.now(timezone.utc).isoformat(),
        'user_metadata': {
            'first_login': True,
            'preferences': {
                'theme': 'light',
                'language': 'en'
            }
        },
        'app_metadata': {
            'roles': ['user'],
            'permissions': ['read:profile', 'write:profile'],
            'tier': 'standard'
        }
    }


# ============================================================================
# Factory Boy Integration Fixtures
# ============================================================================

class UserFactory(factory.Factory):
    """
    Factory for generating test user objects with realistic data.
    
    Implements dynamic test object generation using factory_boy per
    Section 6.6.1 enhanced mocking strategy with realistic data patterns.
    """
    
    class Meta:
        model = dict
    
    user_id = factory.Sequence(lambda n: f'auth0|user_{n:06d}')
    email = factory.Faker('email')
    name = factory.Faker('name')
    picture = factory.Faker('image_url')
    email_verified = factory.Faker('boolean', chance_of_getting_true=80)
    created_at = factory.LazyFunction(lambda: datetime.now(timezone.utc).isoformat())
    updated_at = factory.LazyFunction(lambda: datetime.now(timezone.utc).isoformat())
    
    user_metadata = factory.LazyFunction(lambda: {
        'first_login': fake.boolean(),
        'preferences': {
            'theme': fake.random_element(['light', 'dark']),
            'language': fake.random_element(['en', 'es', 'fr', 'de']),
            'timezone': fake.timezone()
        }
    })
    
    app_metadata = factory.LazyFunction(lambda: {
        'roles': [fake.random_element(['user', 'admin', 'moderator'])],
        'permissions': fake.random_elements(
            ['read:profile', 'write:profile', 'read:admin', 'write:admin'],
            length=fake.random_int(1, 3),
            unique=True
        ),
        'tier': fake.random_element(['free', 'standard', 'premium'])
    })


class DatabaseDocumentFactory(factory.Factory):
    """
    Factory for generating test database documents with realistic data.
    
    Provides comprehensive test data generation for MongoDB document
    testing with varied scenarios and edge cases per Section 6.6.1.
    """
    
    class Meta:
        model = dict
    
    _id = factory.LazyFunction(lambda: fake.uuid4())
    created_at = factory.LazyFunction(lambda: datetime.now(timezone.utc))
    updated_at = factory.LazyFunction(lambda: datetime.now(timezone.utc))
    version = factory.Sequence(lambda n: n)
    
    title = factory.Faker('sentence', nb_words=4)
    description = factory.Faker('paragraph', nb_sentences=3)
    tags = factory.LazyFunction(lambda: fake.words(nb=fake.random_int(1, 5)))
    
    metadata = factory.LazyFunction(lambda: {
        'category': fake.word(),
        'priority': fake.random_element(['low', 'medium', 'high']),
        'status': fake.random_element(['active', 'inactive', 'pending']),
        'numeric_value': fake.random_number(digits=4),
        'boolean_flag': fake.boolean()
    })


@pytest.fixture(scope='function')
def user_factory():
    """
    Provide UserFactory for dynamic test user generation.
    
    Returns:
        UserFactory: Factory for generating test users
    """
    return UserFactory


@pytest.fixture(scope='function')
def document_factory():
    """
    Provide DocumentFactory for dynamic test document generation.
    
    Returns:
        DatabaseDocumentFactory: Factory for generating test documents
    """
    return DatabaseDocumentFactory


# ============================================================================
# Mock External Services Fixtures
# ============================================================================

@pytest.fixture(scope='function')
def mock_requests(mocker: MockerFixture):
    """
    Mock requests library for external HTTP service testing.
    
    Args:
        mocker: pytest-mock fixture
        
    Returns:
        Mock: Configured requests mock with realistic responses
    """
    requests_mock = mocker.patch('requests.get')
    requests_mock.return_value.status_code = 200
    requests_mock.return_value.json.return_value = {
        'status': 'success',
        'data': {'message': 'Mock response'},
        'timestamp': datetime.now(timezone.utc).isoformat()
    }
    requests_mock.return_value.headers = {
        'Content-Type': 'application/json',
        'X-Request-ID': fake.uuid4()
    }
    
    return requests_mock


@pytest.fixture(scope='function')
def mock_httpx(mocker: MockerFixture):
    """
    Mock httpx library for async HTTP service testing.
    
    Args:
        mocker: pytest-mock fixture
        
    Returns:
        Mock: Configured httpx mock with async responses
    """
    httpx_mock = mocker.patch('httpx.AsyncClient')
    
    # Configure async response mock
    async_response_mock = mocker.AsyncMock()
    async_response_mock.status_code = 200
    async_response_mock.json.return_value = {
        'status': 'success',
        'data': {'message': 'Mock async response'},
        'timestamp': datetime.now(timezone.utc).isoformat()
    }
    async_response_mock.headers = {
        'Content-Type': 'application/json',
        'X-Request-ID': fake.uuid4()
    }
    
    httpx_mock.return_value.__aenter__.return_value.get.return_value = async_response_mock
    httpx_mock.return_value.__aenter__.return_value.post.return_value = async_response_mock
    
    return httpx_mock


@pytest.fixture(scope='function')
def mock_aws_s3(mocker: MockerFixture):
    """
    Mock AWS S3 service for file storage testing.
    
    Args:
        mocker: pytest-mock fixture
        
    Returns:
        Mock: Configured S3 client mock
    """
    s3_mock = mocker.patch('boto3.client')
    
    # Configure S3 operation mocks
    s3_client_mock = mocker.Mock()
    s3_client_mock.upload_file.return_value = None
    s3_client_mock.download_file.return_value = None
    s3_client_mock.delete_object.return_value = {'DeleteMarker': True}
    s3_client_mock.head_object.return_value = {
        'ContentLength': 1024,
        'LastModified': datetime.now(timezone.utc),
        'ContentType': 'application/octet-stream'
    }
    s3_client_mock.list_objects_v2.return_value = {
        'Contents': [
            {
                'Key': 'test-file.txt',
                'LastModified': datetime.now(timezone.utc),
                'Size': 1024
            }
        ],
        'KeyCount': 1
    }
    
    s3_mock.return_value = s3_client_mock
    return s3_client_mock


# ============================================================================
# Performance and Monitoring Fixtures
# ============================================================================

@pytest.fixture(scope='function')
def performance_monitor():
    """
    Create performance monitoring context for test execution timing.
    
    Measures test execution time and validates against performance
    thresholds ensuring ≤10% variance compliance per Section 0.1.1.
    
    Returns:
        dict: Performance monitoring context
    """
    class PerformanceMonitor:
        def __init__(self):
            self.start_time = None
            self.end_time = None
            self.metrics = {}
        
        def start(self):
            self.start_time = time.perf_counter()
            return self
        
        def stop(self):
            self.end_time = time.perf_counter()
            return self
        
        def duration(self):
            if self.start_time and self.end_time:
                return self.end_time - self.start_time
            return 0
        
        def add_metric(self, name: str, value: Union[int, float]):
            self.metrics[name] = value
        
        def get_metrics(self) -> Dict[str, Any]:
            return {
                'duration_seconds': self.duration(),
                'start_time': self.start_time,
                'end_time': self.end_time,
                **self.metrics
            }
    
    return PerformanceMonitor()


@pytest.fixture(scope='function')
def cleanup_test_data():
    """
    Provide test data cleanup utilities for maintaining test isolation.
    
    Returns:
        callable: Cleanup function for test data management
    """
    cleanup_tasks = []
    
    def register_cleanup(cleanup_func):
        """Register cleanup function for execution after test."""
        cleanup_tasks.append(cleanup_func)
    
    def execute_cleanup():
        """Execute all registered cleanup functions."""
        for cleanup_func in cleanup_tasks:
            try:
                cleanup_func()
            except Exception as e:
                print(f"Warning: Cleanup function failed: {e}")
    
    yield register_cleanup
    
    # Execute cleanup after test completion
    execute_cleanup()


# ============================================================================
# Async Testing Configuration
# ============================================================================

@pytest.fixture(scope='session')
def event_loop():
    """
    Create event loop for async testing with pytest-asyncio.
    
    Configures optimized event loop for Motor async database operations
    and external service async communications per Section 6.6.1.
    
    Returns:
        asyncio.AbstractEventLoop: Event loop for async testing
    """
    if sys.platform.startswith('win'):
        # Windows-specific event loop policy
        loop = asyncio.ProactorEventLoop()
    else:
        # Unix-specific event loop policy for optimal performance
        try:
            import uvloop
            loop = uvloop.new_event_loop()
        except ImportError:
            loop = asyncio.new_event_loop()
    
    yield loop
    loop.close()


# ============================================================================
# Test Environment Validation
# ============================================================================

@pytest.fixture(scope='session', autouse=True)
def validate_test_environment():
    """
    Validate test environment setup and dependencies.
    
    Ensures all required dependencies are available and properly
    configured for comprehensive test execution.
    """
    # Validate critical dependencies
    required_modules = [
        'pytest',
        'pytest_flask',
        'pytest_mock',
        'pytest_asyncio',
        'testcontainers',
        'pymongo',
        'motor',
        'redis',
        'jwt',
        'factory',
        'flask'
    ]
    
    missing_modules = []
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing_modules.append(module)
    
    if missing_modules:
        pytest.fail(
            f"Missing required test dependencies: {', '.join(missing_modules)}\n"
            "Please install missing dependencies and try again."
        )
    
    # Validate environment variables
    required_env_vars = ['FLASK_ENV', 'SECRET_KEY']
    missing_env_vars = [var for var in required_env_vars if not os.getenv(var)]
    
    if missing_env_vars:
        print(f"Warning: Missing environment variables: {', '.join(missing_env_vars)}")
        print("Some tests may fail without proper environment configuration.")
    
    print("✅ Test environment validation completed successfully")
    return True


# Export public fixtures for test modules
__all__ = [
    # Application fixtures
    'app',
    'client',
    'runner',
    'testing_config',
    
    # Container fixtures
    'mongodb_container',
    'redis_container',
    
    # Database fixtures
    'mongodb_client',
    'motor_client',
    'redis_client',
    'async_redis_client',
    
    # Authentication fixtures
    'valid_jwt_token',
    'expired_jwt_token',
    'invalid_jwt_token',
    'mock_auth0_client',
    'test_user_data',
    'jwt_secret_key',
    
    # Factory fixtures
    'user_factory',
    'document_factory',
    
    # Mock service fixtures
    'mock_requests',
    'mock_httpx',
    'mock_aws_s3',
    
    # Utility fixtures
    'performance_monitor',
    'cleanup_test_data'
]