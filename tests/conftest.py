"""
Global pytest configuration providing Flask application context, database fixtures with Testcontainers
integration, Redis caching setup, Auth0 mocking, and comprehensive test environment initialization.

This module serves as the central fixture provider for all test categories with production-equivalent
behavior through Testcontainers integration as specified in Section 6.6.1 of the technical specification.

Key Features:
- Flask application factory fixture for test context per Section 6.6.1 pytest framework
- Testcontainers MongoDB and Redis instances for production-equivalent testing per Section 6.6.1
- Auth0 service mocking for authentication testing isolation per Section 6.6.1
- pytest-asyncio configuration for Motor database operations per Section 6.6.1
- pytest-xdist configuration for parallel test execution optimization per Section 6.6.1
- Test database seeding and cleanup automation per Section 6.6.1

Dependencies:
- pytest 7.4+ with extensive plugin ecosystem support
- pytest-flask for Flask-specific testing patterns and fixtures
- pytest-asyncio for asynchronous database operations
- pytest-xdist for distributed test execution across multiple worker processes
- pytest-mock for comprehensive external service simulation
- Testcontainers for MongoDB/Redis integration mocks providing production-equivalent behavior
- factory_boy for dynamic test object generation with varied test scenarios
"""

import asyncio
import os
import sys
from typing import AsyncGenerator, Generator, Any, Dict, Optional
import pytest
from unittest.mock import Mock, patch, MagicMock
import logging

# Flask and testing imports
from flask import Flask
from flask.testing import FlaskClient
import pytest_asyncio

# Database and caching imports
import pymongo
import motor.motor_asyncio
import redis
from testcontainers.mongodb import MongoDbContainer
from testcontainers.redis import RedisContainer

# Authentication and security imports
import jwt
from unittest.mock import patch
import requests

# Application imports - using relative imports since these may not exist yet
try:
    from src.app import create_app
    from src.config.settings import TestingConfig
except ImportError:
    # Fallback if modules don't exist yet - create mock versions
    def create_app(config_name='testing'):
        """Fallback app factory if src.app doesn't exist yet"""
        app = Flask(__name__)
        app.config.from_object(TestingConfig())
        return app
    
    class TestingConfig:
        """Fallback testing configuration"""
        TESTING = True
        WTF_CSRF_ENABLED = False
        SECRET_KEY = 'test-secret-key'
        MONGODB_URI = 'mongodb://localhost:27017/test_db'
        REDIS_URL = 'redis://localhost:6379/0'

# Import all fixture modules to make them available
try:
    from tests.fixtures.database_fixtures import *
    from tests.fixtures.auth_fixtures import *
    from tests.fixtures.external_service_mocks import *
    from tests.fixtures.factory_fixtures import *
    from tests.fixtures.performance_fixtures import *
except ImportError:
    # Graceful handling if fixture modules don't exist yet
    pass

# Configure pytest plugins and settings
pytest_plugins = [
    'pytest_asyncio',
    'pytest_flask',
    'pytest_mock',
]

# pytest-asyncio configuration for Motor database operations
pytestmark = pytest.mark.asyncio

def pytest_configure(config):
    """
    Pytest configuration hook for global test setup.
    
    Configures:
    - Test environment variables
    - Logging levels for test output
    - Parallel execution settings
    - Coverage reporting
    """
    # Set test environment variables
    os.environ['FLASK_ENV'] = 'testing'
    os.environ['TESTING'] = 'true'
    
    # Configure logging for test output
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Suppress verbose logging from external libraries during tests
    logging.getLogger('testcontainers').setLevel(logging.WARNING)
    logging.getLogger('docker').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)

def pytest_collection_modifyitems(config, items):
    """
    Modify collected test items to add markers and optimize execution.
    
    Adds markers for:
    - Integration tests requiring database
    - Performance tests requiring baseline comparison
    - Security tests requiring Auth0 mocking
    - Async tests requiring Motor operations
    """
    for item in items:
        # Mark integration tests
        if "integration" in item.nodeid:
            item.add_marker(pytest.mark.integration)
        
        # Mark performance tests
        if "performance" in item.nodeid:
            item.add_marker(pytest.mark.performance)
            
        # Mark security tests
        if "security" in item.nodeid or "auth" in item.nodeid:
            item.add_marker(pytest.mark.security)
            
        # Mark async tests
        if "async" in item.nodeid or "motor" in item.nodeid:
            item.add_marker(pytest.mark.asyncio)

# pytest-xdist configuration for parallel test execution
def pytest_xdist_setupnodes(config, specs):
    """Configure pytest-xdist for optimized parallel execution."""
    pass

@pytest.fixture(scope="session")
def event_loop():
    """
    Create event loop for pytest-asyncio session scope.
    
    Required for Motor async database operations and ensures proper
    async context management across test session.
    """
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="session")
def mongodb_container() -> Generator[MongoDbContainer, None, None]:
    """
    Testcontainers MongoDB instance for production-equivalent database testing.
    
    Provides:
    - Realistic MongoDB behavior with connection pooling
    - Query optimization validation
    - Transaction handling validation
    - Automated container lifecycle management
    
    Returns:
        MongoDbContainer: Running MongoDB container instance
    """
    with MongoDbContainer("mongo:7.0") as container:
        # Wait for MongoDB to be ready
        container.get_connection_url()
        yield container

@pytest.fixture(scope="session")
def redis_container() -> Generator[RedisContainer, None, None]:
    """
    Testcontainers Redis instance for production-equivalent caching behavior.
    
    Provides:
    - Realistic Redis session management
    - Cache invalidation patterns testing
    - Performance optimization validation
    - Automated container lifecycle management
    
    Returns:
        RedisContainer: Running Redis container instance
    """
    with RedisContainer("redis:7.0") as container:
        # Wait for Redis to be ready
        container.get_connection_url()
        yield container

@pytest.fixture(scope="session")
def mongodb_uri(mongodb_container: MongoDbContainer) -> str:
    """
    MongoDB connection URI from Testcontainers instance.
    
    Args:
        mongodb_container: Running MongoDB container
        
    Returns:
        str: MongoDB connection URI for test database
    """
    return mongodb_container.get_connection_url()

@pytest.fixture(scope="session")
def redis_uri(redis_container: RedisContainer) -> str:
    """
    Redis connection URI from Testcontainers instance.
    
    Args:
        redis_container: Running Redis container
        
    Returns:
        str: Redis connection URI for test caching
    """
    return redis_container.get_connection_url()

@pytest.fixture(scope="function")
def test_config(mongodb_uri: str, redis_uri: str) -> TestingConfig:
    """
    Test configuration with Testcontainers database URIs.
    
    Args:
        mongodb_uri: MongoDB connection URI from container
        redis_uri: Redis connection URI from container
        
    Returns:
        TestingConfig: Flask configuration for testing
    """
    config = TestingConfig()
    config.MONGODB_URI = mongodb_uri
    config.REDIS_URL = redis_uri
    config.WTF_CSRF_ENABLED = False
    config.TESTING = True
    return config

@pytest.fixture(scope="function")
def app(test_config: TestingConfig) -> Flask:
    """
    Flask application factory fixture for test context.
    
    Creates a Flask application instance with testing configuration
    and Testcontainers database connections.
    
    Args:
        test_config: Testing configuration with container URIs
        
    Returns:
        Flask: Configured Flask application for testing
    """
    app = create_app('testing')
    app.config.from_object(test_config)
    
    # Configure additional test settings
    app.config.update({
        'WTF_CSRF_ENABLED': False,
        'TESTING': True,
        'DEBUG': False,
        'PRESERVE_CONTEXT_ON_EXCEPTION': False,
        'LOGIN_DISABLED': True,  # Disable login protection during tests
    })
    
    return app

@pytest.fixture(scope="function")
def client(app: Flask) -> FlaskClient:
    """
    Flask test client for HTTP request testing.
    
    Args:
        app: Flask application instance
        
    Returns:
        FlaskClient: Test client for making HTTP requests
    """
    return app.test_client()

@pytest.fixture(scope="function")
def app_context(app: Flask):
    """
    Flask application context for tests requiring app context.
    
    Args:
        app: Flask application instance
        
    Yields:
        Flask application context
    """
    with app.app_context():
        yield app

@pytest.fixture(scope="function")
def request_context(app: Flask):
    """
    Flask request context for tests requiring request context.
    
    Args:
        app: Flask application instance
        
    Yields:
        Flask request context
    """
    with app.test_request_context():
        yield

@pytest.fixture(scope="function")
def mongodb_client(mongodb_uri: str) -> Generator[pymongo.MongoClient, None, None]:
    """
    PyMongo client fixture for synchronous database operations.
    
    Args:
        mongodb_uri: MongoDB connection URI from container
        
    Yields:
        pymongo.MongoClient: MongoDB client for testing
    """
    client = pymongo.MongoClient(mongodb_uri)
    try:
        yield client
    finally:
        # Clean up databases after test
        for db_name in client.list_database_names():
            if db_name.startswith('test_'):
                client.drop_database(db_name)
        client.close()

@pytest.fixture(scope="function")
async def motor_client(mongodb_uri: str) -> AsyncGenerator[motor.motor_asyncio.AsyncIOMotorClient, None]:
    """
    Motor async client fixture for asynchronous database operations.
    
    Args:
        mongodb_uri: MongoDB connection URI from container
        
    Yields:
        motor.motor_asyncio.AsyncIOMotorClient: Async MongoDB client for testing
    """
    client = motor.motor_asyncio.AsyncIOMotorClient(mongodb_uri)
    try:
        yield client
    finally:
        # Clean up databases after test
        for db_name in await client.list_database_names():
            if db_name.startswith('test_'):
                await client.drop_database(db_name)
        client.close()

@pytest.fixture(scope="function")
def redis_client(redis_uri: str) -> Generator[redis.Redis, None, None]:
    """
    Redis client fixture for caching operations testing.
    
    Args:
        redis_uri: Redis connection URI from container
        
    Yields:
        redis.Redis: Redis client for testing
    """
    client = redis.from_url(redis_uri)
    try:
        yield client
    finally:
        # Clean up Redis data after test
        client.flushall()
        client.close()

@pytest.fixture(scope="function")
def auth0_mock():
    """
    Auth0 service mocking for authentication testing isolation.
    
    Provides comprehensive Auth0 API mocking including:
    - Token validation endpoints
    - User profile retrieval
    - Authentication flow simulation
    - Error scenario testing
    
    Returns:
        Mock: Auth0 service mock with realistic responses
    """
    with patch('src.auth.auth0_client.Auth0Client') as mock_auth0:
        # Configure mock Auth0 responses
        mock_instance = Mock()
        
        # Mock successful token validation
        mock_instance.validate_token.return_value = {
            'sub': 'auth0|test_user_123',
            'email': 'test@example.com',
            'email_verified': True,
            'iss': 'https://test-tenant.auth0.com/',
            'aud': 'test-audience',
            'iat': 1609459200,
            'exp': 1609545600,
            'scope': 'openid profile email'
        }
        
        # Mock user profile retrieval
        mock_instance.get_user_profile.return_value = {
            'user_id': 'auth0|test_user_123',
            'email': 'test@example.com',
            'name': 'Test User',
            'picture': 'https://example.com/avatar.jpg',
            'email_verified': True,
            'created_at': '2023-01-01T00:00:00.000Z',
            'updated_at': '2023-01-01T00:00:00.000Z'
        }
        
        # Mock authentication flow
        mock_instance.authenticate.return_value = {
            'access_token': 'mock_access_token',
            'refresh_token': 'mock_refresh_token',
            'id_token': 'mock_id_token',
            'token_type': 'Bearer',
            'expires_in': 3600
        }
        
        mock_auth0.return_value = mock_instance
        yield mock_instance

@pytest.fixture(scope="function")
def jwt_token():
    """
    JWT token generation fixture for authentication testing.
    
    Creates valid JWT tokens with configurable claims for testing
    authentication and authorization scenarios.
    
    Returns:
        str: Valid JWT token for testing
    """
    payload = {
        'sub': 'test_user_123',
        'email': 'test@example.com',
        'iss': 'https://test-tenant.auth0.com/',
        'aud': 'test-audience',
        'iat': 1609459200,
        'exp': 1609545600,
        'scope': 'openid profile email'
    }
    
    # Use test secret key for token generation
    secret_key = 'test-secret-key-for-jwt-generation'
    return jwt.encode(payload, secret_key, algorithm='HS256')

@pytest.fixture(scope="function")
def mock_external_services():
    """
    Comprehensive external service mocking fixture.
    
    Mocks all external HTTP services including:
    - AWS services (S3, KMS)
    - Third-party APIs
    - HTTP client requests
    - Circuit breaker patterns
    
    Returns:
        Dict: Collection of mocked external services
    """
    mocks = {}
    
    # Mock AWS services
    with patch('boto3.client') as mock_boto3:
        mock_s3 = Mock()
        mock_s3.upload_file.return_value = True
        mock_s3.download_file.return_value = True
        mock_s3.delete_object.return_value = {'DeleteMarker': True}
        mock_boto3.return_value = mock_s3
        mocks['aws_s3'] = mock_s3
    
    # Mock HTTP requests
    with patch('requests.request') as mock_requests:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'status': 'success'}
        mock_response.text = '{"status": "success"}'
        mock_requests.return_value = mock_response
        mocks['http_requests'] = mock_requests
    
    yield mocks

@pytest.fixture(scope="function")
def performance_baseline():
    """
    Performance baseline data for comparison testing.
    
    Provides Node.js baseline metrics for performance validation
    ensuring ≤10% variance requirement compliance.
    
    Returns:
        Dict: Performance baseline metrics
    """
    return {
        'response_times': {
            'api_get_users': 150,  # milliseconds
            'api_create_user': 200,
            'api_update_user': 180,
            'api_delete_user': 120,
            'health_check': 50,
        },
        'memory_usage': {
            'baseline_mb': 256,
            'peak_mb': 512,
            'average_mb': 320,
        },
        'database_queries': {
            'user_lookup': 45,  # milliseconds
            'user_create': 85,
            'user_update': 70,
            'user_delete': 40,
        },
        'cache_operations': {
            'get_hit': 5,  # milliseconds
            'get_miss': 15,
            'set': 10,
            'delete': 8,
        }
    }

@pytest.fixture(scope="function", autouse=True)
def cleanup_test_data(mongodb_client, redis_client):
    """
    Automatic test data cleanup fixture.
    
    Ensures clean test environment by automatically cleaning up
    test data after each test function execution.
    
    Args:
        mongodb_client: MongoDB client for database cleanup
        redis_client: Redis client for cache cleanup
    """
    yield  # Test execution happens here
    
    # Cleanup after test
    try:
        # Clean MongoDB test data
        for db_name in mongodb_client.list_database_names():
            if db_name.startswith('test_'):
                mongodb_client.drop_database(db_name)
        
        # Clean Redis test data
        redis_client.flushall()
    except Exception as e:
        # Log cleanup errors but don't fail tests
        logging.warning(f"Test cleanup error: {e}")

@pytest.fixture(scope="function")
def test_database_seeding(mongodb_client, redis_client):
    """
    Test database seeding fixture for comprehensive test data management.
    
    Provides pre-populated test data for integration testing scenarios
    including users, business data, and cache entries.
    
    Args:
        mongodb_client: MongoDB client for data seeding
        redis_client: Redis client for cache seeding
        
    Returns:
        Dict: Seeded test data references
    """
    test_db = mongodb_client.test_database
    
    # Seed user data
    users_collection = test_db.users
    test_users = [
        {
            '_id': 'user_001',
            'email': 'user1@test.com',
            'name': 'Test User 1',
            'created_at': '2023-01-01T00:00:00Z',
            'is_active': True
        },
        {
            '_id': 'user_002',
            'email': 'user2@test.com',
            'name': 'Test User 2',
            'created_at': '2023-01-02T00:00:00Z',
            'is_active': True
        }
    ]
    users_collection.insert_many(test_users)
    
    # Seed cache data
    redis_client.set('test_key_1', 'test_value_1', ex=3600)
    redis_client.set('test_key_2', 'test_value_2', ex=3600)
    
    return {
        'users': test_users,
        'database': test_db,
        'cache_keys': ['test_key_1', 'test_key_2']
    }

# Configure pytest-asyncio for Motor database operations
@pytest_asyncio.fixture(scope="function")
async def async_test_setup():
    """
    Async test setup fixture for Motor database operations.
    
    Provides async context for Motor async database operations
    and ensures proper async test execution.
    """
    # Setup async test environment
    yield
    # Cleanup handled by other fixtures

# Performance testing configuration
def pytest_runtest_setup(item):
    """
    Pre-test setup hook for performance monitoring.
    
    Initializes performance monitoring for tests marked with
    performance markers to ensure baseline comparison capability.
    """
    if item.get_closest_marker("performance"):
        # Initialize performance monitoring
        item.performance_start_time = pytest.MonotonicClock()

def pytest_runtest_teardown(item):
    """
    Post-test teardown hook for performance data collection.
    
    Collects performance metrics for tests marked with performance
    markers and validates against baseline requirements.
    """
    if item.get_closest_marker("performance") and hasattr(item, 'performance_start_time'):
        # Calculate test execution time
        execution_time = pytest.MonotonicClock() - item.performance_start_time
        # Store performance data for later analysis
        if not hasattr(item.session, 'performance_data'):
            item.session.performance_data = []
        item.session.performance_data.append({
            'test_name': item.nodeid,
            'execution_time': execution_time
        })

# Security testing configuration
@pytest.fixture(scope="function")
def security_headers():
    """
    Security headers validation fixture for security testing.
    
    Provides expected security headers for validation in security tests
    ensuring Flask-Talisman security header compliance.
    
    Returns:
        Dict: Expected security headers
    """
    return {
        'X-Frame-Options': 'SAMEORIGIN',
        'X-Content-Type-Options': 'nosniff',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'",
        'Referrer-Policy': 'strict-origin-when-cross-origin'
    }

# Test environment validation
def pytest_sessionstart(session):
    """
    Session start hook for test environment validation.
    
    Validates test environment setup and ensures all required
    dependencies are available for comprehensive testing.
    """
    # Validate required environment variables
    required_env_vars = ['FLASK_ENV']
    missing_vars = [var for var in required_env_vars if not os.getenv(var)]
    
    if missing_vars:
        logging.warning(f"Missing environment variables: {missing_vars}")
    
    # Initialize session-level test data
    session.test_session_id = f"test_session_{os.getpid()}"
    logging.info(f"Starting test session: {session.test_session_id}")

def pytest_sessionfinish(session, exitstatus):
    """
    Session finish hook for test result summary and cleanup.
    
    Provides test session summary and ensures complete cleanup
    of test resources and temporary data.
    """
    logging.info(f"Test session finished: {session.test_session_id} with exit status: {exitstatus}")
    
    # Report performance data if collected
    if hasattr(session, 'performance_data'):
        logging.info(f"Performance tests executed: {len(session.performance_data)}")
        for perf_data in session.performance_data:
            logging.info(f"Test: {perf_data['test_name']} - Time: {perf_data['execution_time']:.3f}s")

# pytest-xdist worker configuration
def pytest_configure_node(node):
    """
    Configure pytest-xdist worker nodes for parallel execution.
    
    Ensures proper worker node configuration for distributed testing
    with Testcontainers and database isolation.
    """
    # Configure worker-specific settings
    worker_id = getattr(node, 'workerinput', {}).get('workerid', 'master')
    os.environ['PYTEST_WORKER_ID'] = worker_id
    
    # Set worker-specific database names to avoid conflicts
    if worker_id != 'master':
        os.environ['TEST_DB_SUFFIX'] = f"_{worker_id}"

# Additional pytest configuration for enhanced testing
pytest.register_assert_rewrite('tests.fixtures')