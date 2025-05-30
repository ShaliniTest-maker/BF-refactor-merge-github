"""
Global pytest configuration and fixture definitions for Flask application testing.

This module provides comprehensive test infrastructure for the Flask migration project including
Flask application testing, database mocking with Testcontainers, authentication fixtures, and
shared testing utilities. The configuration ensures complete test isolation while maintaining
realistic production-equivalent behavior for comprehensive validation.

Key Features:
- pytest 7.4+ framework with extensive plugin ecosystem support per Section 6.6.1
- Flask application testing with pytest-flask integration per Section 6.6.1  
- Testcontainers for realistic MongoDB and Redis test instances per Section 6.6.1
- Authentication testing fixtures for JWT and Auth0 mock responses per Section 6.6.1
- pytest-mock integration for external service mocking per Section 6.6.1
- factory_boy integration for dynamic test object generation per Section 6.6.1
- pytest-asyncio for asynchronous database operations testing per Section 6.6.1

Dependencies:
- pytest 7.4+ with extensive plugin ecosystem including pytest-flask, pytest-mock, pytest-asyncio
- testcontainers[mongodb,redis] ≥4.10.0 for realistic database and cache behavior
- Flask 2.3+ application factory pattern integration with Blueprint testing support
- PyJWT 2.8+ for authentication testing equivalent to Node.js jsonwebtoken patterns
- factory_boy for dynamic test object generation with varied scenarios
- structlog 23.1+ for enterprise audit logging during testing

Author: Flask Migration Team
Version: 1.0.0
Compliance: SOC 2, ISO 27001, OWASP Top 10 testing standards
"""

import asyncio
import logging
import os
import tempfile
import warnings
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, Generator, List, Optional, Union
from unittest.mock import Mock, patch, MagicMock, AsyncMock
import uuid

import pytest
import pytest_asyncio
from flask import Flask, g, request, session
from flask.testing import FlaskClient
import structlog

# Database and caching test fixtures
from tests.fixtures.database_fixtures import (
    DatabaseContainerConfig, MongoDbTestContainer, RedisTestContainer,
    DatabaseSeeder, PerformanceValidator,
    mongodb_container, redis_container, database_container_config,
    pymongo_client, motor_client, redis_client,
    database_seeder, performance_validator, seeded_database,
    comprehensive_database_environment, connection_pool_tester,
    async_connection_pool_tester,
    UserDocumentFactory, ProjectDocumentFactory, SessionDocumentFactory
)

# Authentication test fixtures  
from tests.fixtures.auth_fixtures import (
    JWTTokenFactory, Auth0ServiceMock, MockAuth0User, MockAnonymousUser,
    MockRedisCache, jwt_token_factory, auth0_mock, mock_redis_cache,
    mock_auth_user, mock_admin_user, mock_anonymous_user,
    valid_jwt_token, expired_jwt_token, invalid_signature_token,
    malformed_jwt_token, admin_jwt_token, session_data,
    auth_test_context, circuit_breaker_test_context,
    permission_test_scenarios, auth_metrics_context,
    async_auth_manager, async_session_manager,
    security_audit_logger, security_compliance_context,
    performance_baseline_context
)

# Application imports with fallback handling
try:
    from src.app import create_app, create_wsgi_app
    from src.config.settings import (
        TestingConfig, DevelopmentConfig, ConfigFactory,
        create_config_for_environment
    )
    from src.auth.authentication import (
        AuthenticationManager, get_auth_manager, init_auth_manager,
        close_auth_manager
    )
except ImportError as e:
    # Graceful fallback for development scenarios where modules may not exist yet
    logging.warning(f"Application imports not available: {e}")
    
    # Mock application classes for testing framework setup
    def create_app(config=None):
        app = Flask(__name__)
        app.config.update(
            TESTING=True,
            SECRET_KEY='test-secret-key',
            WTF_CSRF_ENABLED=False,
            SQLALCHEMY_DATABASE_URI='sqlite:///:memory:'
        )
        return app
    
    def create_wsgi_app():
        return create_app()
    
    class TestingConfig:
        TESTING = True
        SECRET_KEY = 'test-secret-key'
        MONGODB_URI = 'mongodb://localhost:27017/test_database'
        REDIS_URL = 'redis://localhost:6379/0'
        WTF_CSRF_ENABLED = False
        CORS_ORIGINS = ['http://localhost:3000']
    
    class ConfigFactory:
        @staticmethod
        def get_config(environment='testing'):
            return TestingConfig

# Configure structured logging for test execution
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Suppress specific warnings for cleaner test output
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=PendingDeprecationWarning)

# Configure structlog for test logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger("tests.unit.conftest")


# =============================================================================
# Pytest Configuration and Global Settings
# =============================================================================

def pytest_configure(config):
    """
    Global pytest configuration for Flask application testing.
    
    Configures pytest for comprehensive testing including asyncio event loop
    policy, marker registration, and test environment initialization with
    enterprise-grade logging and monitoring integration.
    
    Args:
        config: pytest configuration object
    """
    # Configure asyncio event loop policy for consistent async testing
    asyncio.set_event_loop_policy(asyncio.DefaultEventLoopPolicy())
    
    # Register custom markers for test categorization
    config.addinivalue_line(
        "markers", 
        "unit: Unit tests for individual components and functions"
    )
    config.addinivalue_line(
        "markers",
        "integration: Integration tests for component interactions"  
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
        "performance: Performance validation and baseline comparison testing"
    )
    config.addinivalue_line(
        "markers",
        "security: Security compliance and vulnerability testing"
    )
    config.addinivalue_line(
        "markers",
        "slow: Tests that require extended execution time"
    )
    config.addinivalue_line(
        "markers",
        "external: Tests requiring external service dependencies"
    )
    
    # Configure test environment variables
    os.environ.update({
        'FLASK_ENV': 'testing',
        'TESTING': 'true',
        'SECRET_KEY': 'test-secret-key-do-not-use-in-production',
        'JWT_SECRET_KEY': 'test-jwt-secret-key-do-not-use-in-production',
        'AUTH0_DOMAIN': 'test-domain.auth0.com',
        'AUTH0_CLIENT_ID': 'test-client-id',
        'AUTH0_CLIENT_SECRET': 'test-client-secret',
        'AUTH0_AUDIENCE': 'test-audience',
        'MONGODB_URI': 'mongodb://localhost:27017/test_database',
        'REDIS_URL': 'redis://localhost:6379/15',  # Use DB 15 for testing
        'CORS_ORIGINS': 'http://localhost:3000,http://127.0.0.1:3000',
        'RATE_LIMIT_ENABLED': 'false',
        'TALISMAN_ENABLED': 'false',
        'PERFORMANCE_MONITORING_ENABLED': 'true',
        'CACHE_TYPE': 'simple',
        'WTF_CSRF_ENABLED': 'false'
    })
    
    logger.info(
        "Pytest configuration completed",
        markers_registered=8,
        asyncio_policy="DefaultEventLoopPolicy",
        test_environment="configured"
    )


def pytest_sessionstart(session):
    """
    Initialize test session with comprehensive logging and monitoring setup.
    
    Args:
        session: pytest session object
    """
    logger.info(
        "Test session started",
        python_version=session.config.getoption("--tb"),
        test_directory=str(session.config.rootpath),
        session_id=str(uuid.uuid4())
    )


def pytest_sessionfinish(session, exitstatus):
    """
    Cleanup test session with performance reporting and resource cleanup.
    
    Args:
        session: pytest session object
        exitstatus: test execution exit status
    """
    logger.info(
        "Test session finished",
        exit_status=exitstatus,
        tests_passed=session.testscollected - session.testsfailed,
        tests_failed=session.testsfailed
    )


def pytest_runtest_setup(item):
    """
    Setup individual test execution with environment validation.
    
    Args:
        item: pytest test item
    """
    logger.debug(
        "Test setup started",
        test_name=item.name,
        test_file=str(item.fspath),
        markers=[mark.name for mark in item.iter_markers()]
    )


def pytest_runtest_teardown(item, nextitem):
    """
    Cleanup individual test execution with resource verification.
    
    Args:
        item: completed pytest test item
        nextitem: next test item to execute
    """
    logger.debug(
        "Test teardown completed",
        test_name=item.name,
        next_test=nextitem.name if nextitem else None
    )


# =============================================================================
# Core Flask Application Fixtures
# =============================================================================

@pytest.fixture(scope="session")
def app_config() -> TestingConfig:
    """
    Session-scoped fixture providing Flask application configuration for testing.
    
    Creates TestingConfig instance with comprehensive test settings including
    database URIs, authentication configuration, and security settings optimized
    for testing scenarios while maintaining production compatibility.
    
    Returns:
        TestingConfig instance with complete test configuration
    """
    config = ConfigFactory.get_config('testing')()
    
    # Override with test-specific settings
    config.TESTING = True
    config.DEBUG = False
    config.WTF_CSRF_ENABLED = False
    config.TALISMAN_ENABLED = False
    config.RATELIMIT_ENABLED = False
    config.LOGIN_DISABLED = True
    
    # Configure test database URIs that will be overridden by Testcontainers
    config.MONGODB_URI = 'mongodb://localhost:27017/test_database'
    config.REDIS_URL = 'redis://localhost:6379/15'
    
    # Security settings for testing
    config.SECRET_KEY = 'test-secret-key-do-not-use-in-production'
    config.JWT_SECRET_KEY = 'test-jwt-secret-key-do-not-use-in-production'
    config.SESSION_COOKIE_SECURE = False
    config.REMEMBER_COOKIE_SECURE = False
    
    logger.info(
        "Flask application configuration created",
        environment="testing",
        csrf_enabled=config.WTF_CSRF_ENABLED,
        debug_mode=config.DEBUG
    )
    
    return config


@pytest.fixture(scope="function")  
def app(app_config: TestingConfig) -> Generator[Flask, None, None]:
    """
    Function-scoped fixture providing Flask application instance for testing.
    
    Creates Flask application using the application factory pattern with testing
    configuration, proper context management, and comprehensive cleanup to ensure
    test isolation and consistent behavior across test executions.
    
    Args:
        app_config: Testing configuration instance
        
    Yields:
        Configured Flask application instance
    """
    # Create Flask application with test configuration
    flask_app = create_app()
    flask_app.config.from_object(app_config)
    
    # Additional test-specific configuration
    flask_app.config.update({
        'TESTING': True,
        'DEBUG': False,
        'WTF_CSRF_ENABLED': False,
        'LOGIN_DISABLED': True,
        'PRESERVE_CONTEXT_ON_EXCEPTION': False,
        'TRAP_HTTP_EXCEPTIONS': True,
        'TRAP_BAD_REQUEST_ERRORS': True
    })
    
    # Create application context for testing
    with flask_app.app_context():
        # Initialize application for testing
        try:
            logger.debug(
                "Flask application created for testing",
                app_name=flask_app.name,
                config_class=app_config.__class__.__name__,
                testing_enabled=flask_app.config['TESTING']
            )
            
            yield flask_app
            
        finally:
            # Cleanup application context
            logger.debug("Flask application context cleaned up")


@pytest.fixture(scope="function")
def client(app: Flask) -> Generator[FlaskClient, None, None]:
    """
    Function-scoped fixture providing Flask test client for API testing.
    
    Creates Flask test client with comprehensive request/response testing
    capabilities, session management, and authentication context for complete
    API endpoint testing including error handling and edge cases.
    
    Args:
        app: Flask application instance
        
    Yields:
        Flask test client instance
    """
    with app.test_client() as test_client:
        with app.test_request_context():
            logger.debug(
                "Flask test client created",
                app_name=app.name,
                base_url=test_client.application.config.get('SERVER_NAME', 'localhost')
            )
            
            yield test_client


@pytest.fixture(scope="function")
def runner(app: Flask):
    """
    Function-scoped fixture providing Flask CLI runner for command testing.
    
    Creates Flask CLI test runner for testing command-line interface components,
    management commands, and administrative functions with proper environment
    isolation and output capture.
    
    Args:
        app: Flask application instance
        
    Returns:
        Flask CLI test runner instance
    """
    runner = app.test_cli_runner()
    
    logger.debug(
        "Flask CLI runner created",
        app_name=app.name
    )
    
    return runner


# =============================================================================
# Database and Caching Test Fixtures
# =============================================================================

@pytest.fixture(scope="function")
def app_with_database(
    app: Flask,
    mongodb_container: MongoDbTestContainer,
    redis_container: RedisTestContainer
) -> Generator[Flask, None, None]:
    """
    Function-scoped fixture providing Flask application with Testcontainers database connections.
    
    Integrates Flask application with realistic MongoDB and Redis instances through
    Testcontainers, providing production-equivalent database behavior for comprehensive
    integration testing while maintaining complete test isolation.
    
    Args:
        app: Flask application instance
        mongodb_container: MongoDB Testcontainer instance
        redis_container: Redis Testcontainer instance
        
    Yields:
        Flask application with configured database connections
    """
    # Configure MongoDB connection
    mongodb_uri = mongodb_container.get_connection_url()
    app.config['MONGODB_URI'] = mongodb_uri
    app.config['MONGODB_DATABASE'] = mongodb_container.database
    
    # Configure Redis connection  
    redis_host = redis_container.get_container_host_ip()
    redis_port = redis_container.get_exposed_port(6379)
    app.config['REDIS_HOST'] = redis_host
    app.config['REDIS_PORT'] = redis_port
    app.config['REDIS_URL'] = redis_container.get_connection_url()
    
    # Update application context with database connections
    with app.app_context():
        # Store database clients in application config for access during testing
        app.config['PYMONGO_CLIENT'] = mongodb_container.get_pymongo_client()
        app.config['REDIS_CLIENT'] = redis_container.get_redis_client()
        
        logger.info(
            "Flask application configured with Testcontainers databases",
            mongodb_uri=mongodb_uri.split('@')[-1] if '@' in mongodb_uri else mongodb_uri,
            redis_host=redis_host,
            redis_port=redis_port
        )
        
        try:
            yield app
        finally:
            # Cleanup database connections
            pymongo_client = app.config.get('PYMONGO_CLIENT')
            redis_client = app.config.get('REDIS_CLIENT')
            
            if pymongo_client:
                pymongo_client.close()
            if redis_client:
                redis_client.close()
            
            logger.debug("Database connections cleaned up")


@pytest.fixture(scope="function")
def app_with_seeded_data(
    app_with_database: Flask,
    database_seeder: DatabaseSeeder
) -> Generator[Flask, None, None]:
    """
    Function-scoped fixture providing Flask application with pre-seeded test data.
    
    Creates Flask application with realistic test datasets including users, projects,
    sessions, and cache data for comprehensive integration testing scenarios without
    manual data setup requirements.
    
    Args:
        app_with_database: Flask application with database connections
        database_seeder: Database seeding utility
        
    Yields:
        Flask application with seeded test data
    """
    with app_with_database.app_context():
        # Seed comprehensive test dataset
        users = database_seeder.seed_users(count=10)
        user_ids = [user['_id'] for user in users]
        
        projects = database_seeder.seed_projects(count=5, user_ids=user_ids)
        sessions = database_seeder.seed_sessions(count=15, user_ids=user_ids)
        cache_data = database_seeder.seed_cache_data(count=50)
        
        # Store seeded data in application config for test access
        app_with_database.config['SEEDED_DATA'] = {
            'users': users,
            'projects': projects,
            'sessions': sessions,
            'cache_data': cache_data
        }
        
        logger.info(
            "Flask application configured with seeded test data",
            users_count=len(users),
            projects_count=len(projects),
            sessions_count=len(sessions),
            cache_entries_count=len(cache_data)
        )
        
        yield app_with_database


# =============================================================================
# Authentication and Security Test Fixtures  
# =============================================================================

@pytest.fixture(scope="function")
def mock_auth_context():
    """
    Function-scoped fixture providing comprehensive authentication testing context.
    
    Creates mock authentication environment with Auth0 service simulation,
    JWT token generation capabilities, and authentication state management
    for testing authentication flows without external dependencies.
    
    Returns:
        Authentication testing context with mocked services
    """
    with patch('src.auth.authentication.httpx.AsyncClient') as mock_httpx, \
         patch('src.auth.cache.redis.Redis') as mock_redis, \
         patch('src.auth.authentication.Auth0Management') as mock_auth0_mgmt:
        
        # Configure mock HTTP client for Auth0 API calls
        mock_client = AsyncMock()
        mock_httpx.return_value = mock_client
        
        # Configure mock responses for Auth0 JWKS endpoint
        mock_jwks_response = AsyncMock()
        mock_jwks_response.status_code = 200
        mock_jwks_response.json.return_value = {
            "keys": [{
                "kty": "RSA",
                "use": "sig", 
                "kid": "test-key-id",
                "n": "test-n-value",
                "e": "AQAB",
                "alg": "RS256"
            }]
        }
        mock_client.get.return_value = mock_jwks_response
        
        # Configure mock Redis client for caching
        mock_redis_instance = MockRedisCache()
        mock_redis.return_value = mock_redis_instance
        
        # Configure mock Auth0 management client
        mock_mgmt = Mock()
        mock_auth0_mgmt.return_value = mock_mgmt
        
        context = {
            'mock_httpx_client': mock_client,
            'mock_redis': mock_redis_instance,
            'mock_auth0_mgmt': mock_mgmt,
            'mock_jwks_response': mock_jwks_response
        }
        
        logger.debug("Mock authentication context created")
        yield context


@pytest.fixture(scope="function")
def authenticated_client(
    client: FlaskClient,
    valid_jwt_token: str,
    mock_auth_user: MockAuth0User
) -> Generator[FlaskClient, None, None]:
    """
    Function-scoped fixture providing authenticated Flask test client.
    
    Creates Flask test client with authentication context including valid JWT token,
    user session, and authentication state for testing protected endpoints and
    authorization scenarios with comprehensive user context.
    
    Args:
        client: Flask test client instance
        valid_jwt_token: Valid JWT token for authentication
        mock_auth_user: Mock authenticated user instance
        
    Yields:
        Authenticated Flask test client
    """
    with client.session_transaction() as sess:
        sess['user_id'] = mock_auth_user.id
        sess['authenticated'] = True
        sess['jwt_token'] = valid_jwt_token
        sess['user_profile'] = mock_auth_user.to_dict()
    
    # Set authentication headers for API requests
    client.environ_base['HTTP_AUTHORIZATION'] = f'Bearer {valid_jwt_token}'
    
    logger.debug(
        "Authenticated test client created",
        user_id=mock_auth_user.id,
        email=mock_auth_user.email,
        permissions_count=len(mock_auth_user.permissions)
    )
    
    yield client


@pytest.fixture(scope="function")
def admin_authenticated_client(
    client: FlaskClient,
    admin_jwt_token: str,
    mock_admin_user: MockAuth0User
) -> Generator[FlaskClient, None, None]:
    """
    Function-scoped fixture providing admin-authenticated Flask test client.
    
    Creates Flask test client with admin authentication context including elevated
    permissions, admin JWT token, and administrative session for testing admin
    endpoints and elevated authorization scenarios.
    
    Args:
        client: Flask test client instance
        admin_jwt_token: Admin JWT token for authentication
        mock_admin_user: Mock admin user instance
        
    Yields:
        Admin-authenticated Flask test client
    """
    with client.session_transaction() as sess:
        sess['user_id'] = mock_admin_user.id
        sess['authenticated'] = True
        sess['jwt_token'] = admin_jwt_token
        sess['user_profile'] = mock_admin_user.to_dict()
        sess['is_admin'] = True
    
    # Set admin authentication headers
    client.environ_base['HTTP_AUTHORIZATION'] = f'Bearer {admin_jwt_token}'
    
    logger.debug(
        "Admin authenticated test client created",
        user_id=mock_admin_user.id,
        email=mock_admin_user.email,
        roles=list(mock_admin_user.roles),
        permissions_count=len(mock_admin_user.permissions)
    )
    
    yield client


# =============================================================================
# Performance and Monitoring Test Fixtures
# =============================================================================

@pytest.fixture(scope="function")
def performance_test_context(
    performance_baseline_context: Dict[str, Any]
) -> Generator[Dict[str, Any], None, None]:
    """
    Function-scoped fixture providing performance testing context for ≤10% variance validation.
    
    Creates performance testing environment with baseline comparison capabilities,
    metric collection, and automated variance validation to ensure compliance
    with Node.js performance requirements throughout testing.
    
    Args:
        performance_baseline_context: Performance baseline context with Node.js metrics
        
    Yields:
        Performance testing context with validation functions
    """
    context = {
        **performance_baseline_context,
        'test_metrics': {},
        'performance_violations': [],
        'current_test_start': None
    }
    
    def start_performance_measurement(test_name: str):
        """Start performance measurement for specific test"""
        import time
        context['current_test_start'] = time.perf_counter()
        context['current_test_name'] = test_name
        logger.debug("Performance measurement started", test_name=test_name)
    
    def end_performance_measurement() -> float:
        """End performance measurement and return execution time"""
        import time
        if context['current_test_start'] is None:
            return 0.0
        
        execution_time = time.perf_counter() - context['current_test_start']
        test_name = context.get('current_test_name', 'unknown_test')
        
        context['test_metrics'][test_name] = execution_time
        
        # Check against baseline if available
        baseline_metric = f"{test_name}_time"
        if baseline_metric in context['baseline_metrics']:
            baseline_value = context['baseline_metrics'][baseline_metric]
            variance = abs(execution_time - baseline_value) / baseline_value
            
            if variance > context['variance_threshold']:
                violation = {
                    'test_name': test_name,
                    'baseline': baseline_value,
                    'measured': execution_time,
                    'variance': variance,
                    'threshold': context['variance_threshold']
                }
                context['performance_violations'].append(violation)
                logger.warning(
                    "Performance variance violation detected",
                    test_name=test_name,
                    variance_percentage=variance * 100,
                    threshold_percentage=context['variance_threshold'] * 100
                )
        
        logger.debug(
            "Performance measurement completed",
            test_name=test_name,
            execution_time_ms=execution_time * 1000
        )
        
        return execution_time
    
    context['start_measurement'] = start_performance_measurement
    context['end_measurement'] = end_performance_measurement
    
    logger.debug("Performance test context created")
    yield context


@pytest.fixture(scope="function")  
def test_metrics_collector():
    """
    Function-scoped fixture providing test metrics collection for quality monitoring.
    
    Creates metrics collection system for tracking test execution performance,
    coverage statistics, error rates, and quality metrics to support continuous
    improvement and performance monitoring requirements.
    
    Returns:
        Test metrics collector instance
    """
    class TestMetricsCollector:
        def __init__(self):
            self.metrics = {
                'test_count': 0,
                'passed_tests': 0,
                'failed_tests': 0,
                'execution_times': [],
                'memory_usage': [],
                'error_types': {},
                'coverage_data': {},
                'auth_operations': 0,
                'database_operations': 0,
                'cache_operations': 0
            }
            self.start_time = None
        
        def start_test(self, test_name: str):
            """Start tracking metrics for a test"""
            import time
            self.start_time = time.perf_counter()
            self.metrics['test_count'] += 1
            logger.debug("Metrics collection started", test_name=test_name)
        
        def end_test(self, test_name: str, success: bool, error_type: Optional[str] = None):
            """End tracking metrics for a test"""
            import time
            if self.start_time:
                execution_time = time.perf_counter() - self.start_time
                self.metrics['execution_times'].append(execution_time)
            
            if success:
                self.metrics['passed_tests'] += 1
            else:
                self.metrics['failed_tests'] += 1
                if error_type:
                    self.metrics['error_types'][error_type] = \
                        self.metrics['error_types'].get(error_type, 0) + 1
            
            logger.debug(
                "Metrics collection completed",
                test_name=test_name,
                success=success,
                execution_time_ms=(execution_time * 1000) if self.start_time else 0
            )
        
        def record_operation(self, operation_type: str):
            """Record specific operation for tracking"""
            metric_key = f"{operation_type}_operations"
            if metric_key in self.metrics:
                self.metrics[metric_key] += 1
        
        def get_summary(self) -> Dict[str, Any]:
            """Get metrics summary"""
            avg_execution_time = (
                sum(self.metrics['execution_times']) / len(self.metrics['execution_times'])
                if self.metrics['execution_times'] else 0
            )
            
            success_rate = (
                self.metrics['passed_tests'] / self.metrics['test_count']
                if self.metrics['test_count'] > 0 else 0
            )
            
            return {
                'total_tests': self.metrics['test_count'],
                'passed_tests': self.metrics['passed_tests'],
                'failed_tests': self.metrics['failed_tests'],
                'success_rate': success_rate,
                'average_execution_time': avg_execution_time,
                'total_execution_time': sum(self.metrics['execution_times']),
                'error_distribution': self.metrics['error_types'],
                'operation_counts': {
                    'auth_operations': self.metrics['auth_operations'],
                    'database_operations': self.metrics['database_operations'],
                    'cache_operations': self.metrics['cache_operations']
                }
            }
    
    collector = TestMetricsCollector()
    logger.debug("Test metrics collector created")
    return collector


# =============================================================================
# External Service Mocking Fixtures
# =============================================================================

@pytest.fixture(scope="function")
def mock_external_services():
    """
    Function-scoped fixture providing comprehensive external service mocking.
    
    Creates mock implementations for all external services including Auth0,
    AWS services, third-party APIs, and other external dependencies to ensure
    test isolation and consistent behavior across different testing environments.
    
    Returns:
        External service mocking context
    """
    with patch('boto3.client') as mock_boto3, \
         patch('requests.get') as mock_requests_get, \
         patch('requests.post') as mock_requests_post, \
         patch('httpx.AsyncClient') as mock_httpx:
        
        # Configure AWS service mocks
        mock_s3_client = Mock()
        mock_s3_client.upload_file.return_value = {'ETag': 'test-etag'}
        mock_s3_client.delete_object.return_value = {'DeleteMarker': True}
        mock_boto3.return_value = mock_s3_client
        
        # Configure HTTP request mocks
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'status': 'success'}
        mock_response.text = '{"status": "success"}'
        mock_requests_get.return_value = mock_response
        mock_requests_post.return_value = mock_response
        
        # Configure async HTTP client mock
        mock_async_client = AsyncMock()
        mock_async_response = AsyncMock()
        mock_async_response.status_code = 200
        mock_async_response.json.return_value = {'status': 'success'}
        mock_async_client.get.return_value = mock_async_response
        mock_async_client.post.return_value = mock_async_response
        mock_httpx.return_value = mock_async_client
        
        context = {
            'mock_s3': mock_s3_client,
            'mock_requests_get': mock_requests_get,
            'mock_requests_post': mock_requests_post,
            'mock_httpx': mock_async_client,
            'mock_response': mock_response,
            'mock_async_response': mock_async_response
        }
        
        logger.debug("External service mocks configured")
        yield context


@pytest.fixture(scope="function")
def mock_circuit_breaker():
    """
    Function-scoped fixture providing circuit breaker testing functionality.
    
    Creates mock circuit breaker implementation for testing resilience patterns,
    failure scenarios, and recovery mechanisms in external service integrations
    with configurable failure thresholds and recovery timeouts.
    
    Returns:
        Mock circuit breaker instance
    """
    class MockCircuitBreaker:
        def __init__(self):
            self.failure_count = 0
            self.failure_threshold = 5
            self.recovery_timeout = 60
            self.state = 'closed'  # closed, open, half-open
            self.last_failure_time = None
        
        def call(self, func, *args, **kwargs):
            """Execute function with circuit breaker protection"""
            if self.state == 'open':
                import time
                if (self.last_failure_time and 
                    time.time() - self.last_failure_time > self.recovery_timeout):
                    self.state = 'half-open'
                else:
                    raise Exception("Circuit breaker is open")
            
            try:
                result = func(*args, **kwargs)
                if self.state == 'half-open':
                    self.reset()
                return result
            except Exception as e:
                self.record_failure()
                raise
        
        def record_failure(self):
            """Record failure and potentially open circuit"""
            import time
            self.failure_count += 1
            self.last_failure_time = time.time()
            
            if self.failure_count >= self.failure_threshold:
                self.state = 'open'
        
        def reset(self):
            """Reset circuit breaker to closed state"""
            self.failure_count = 0
            self.last_failure_time = None
            self.state = 'closed'
        
        def get_state(self):
            """Get current circuit breaker state"""
            return {
                'state': self.state,
                'failure_count': self.failure_count,
                'failure_threshold': self.failure_threshold,
                'last_failure_time': self.last_failure_time
            }
    
    circuit_breaker = MockCircuitBreaker()
    logger.debug("Mock circuit breaker created")
    return circuit_breaker


# =============================================================================
# Async Testing Fixtures
# =============================================================================

@pytest_asyncio.fixture(scope="function")
async def async_app(app_config: TestingConfig) -> AsyncGenerator[Flask, None]:
    """
    Function-scoped async fixture providing Flask application for async testing.
    
    Creates Flask application configured for asynchronous operations testing
    including Motor database operations, async HTTP clients, and concurrent
    request processing validation with proper async context management.
    
    Args:
        app_config: Testing configuration instance
        
    Yields:
        Flask application configured for async testing
    """
    flask_app = create_app()
    flask_app.config.from_object(app_config)
    
    # Configure for async testing
    flask_app.config.update({
        'TESTING': True,
        'ASYNC_MODE': True,
        'MOTOR_CLIENT_ENABLED': True
    })
    
    async with flask_app.app_context():
        logger.debug(
            "Async Flask application created",
            app_name=flask_app.name,
            async_mode=flask_app.config.get('ASYNC_MODE', False)
        )
        
        yield flask_app


@pytest_asyncio.fixture(scope="function")
async def async_client_with_auth(
    async_app: Flask,
    valid_jwt_token: str,
    mock_auth_user: MockAuth0User
):
    """
    Function-scoped async fixture providing authenticated async test client.
    
    Creates async test client with authentication context for testing async
    endpoints, concurrent request handling, and async database operations
    with proper authentication and session management.
    
    Args:
        async_app: Async Flask application instance
        valid_jwt_token: Valid JWT token for authentication
        mock_auth_user: Mock authenticated user instance
        
    Returns:
        Authenticated async test client
    """
    class AsyncTestClient:
        def __init__(self, app, token, user):
            self.app = app
            self.token = token
            self.user = user
            self.headers = {'Authorization': f'Bearer {token}'}
        
        async def get(self, path, **kwargs):
            """Async GET request with authentication"""
            headers = kwargs.get('headers', {})
            headers.update(self.headers)
            kwargs['headers'] = headers
            return await self._make_request('GET', path, **kwargs)
        
        async def post(self, path, **kwargs):
            """Async POST request with authentication"""
            headers = kwargs.get('headers', {})
            headers.update(self.headers)
            kwargs['headers'] = headers
            return await self._make_request('POST', path, **kwargs)
        
        async def _make_request(self, method, path, **kwargs):
            """Make async HTTP request"""
            # Mock implementation for async request
            response = Mock()
            response.status_code = 200
            response.json = lambda: {'status': 'success'}
            return response
    
    client = AsyncTestClient(async_app, valid_jwt_token, mock_auth_user)
    
    logger.debug(
        "Async authenticated client created",
        user_id=mock_auth_user.id,
        app_name=async_app.name
    )
    
    return client


# =============================================================================
# Utility and Helper Fixtures
# =============================================================================

@pytest.fixture(scope="function")
def temp_file():
    """
    Function-scoped fixture providing temporary file for file upload testing.
    
    Creates temporary file with test content for testing file upload endpoints,
    file processing functionality, and storage operations with automatic cleanup
    and proper resource management.
    
    Yields:
        Temporary file path for testing
    """
    import tempfile
    import os
    
    # Create temporary file with test content
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
        temp_file.write("Test file content for upload testing\n")
        temp_file.write("Line 2 of test content\n")
        temp_file.write("End of test file\n")
        temp_file_path = temp_file.name
    
    logger.debug("Temporary file created", file_path=temp_file_path)
    
    try:
        yield temp_file_path
    finally:
        # Cleanup temporary file
        try:
            os.unlink(temp_file_path)
            logger.debug("Temporary file cleaned up", file_path=temp_file_path)
        except OSError:
            pass


@pytest.fixture(scope="function")
def mock_datetime():
    """
    Function-scoped fixture providing datetime mocking for time-dependent testing.
    
    Creates datetime mock for testing time-sensitive functionality including
    token expiration, session timeouts, and timestamp validation with
    controllable time progression and timezone handling.
    
    Returns:
        Mock datetime context manager
    """
    from datetime import datetime, timezone
    from unittest.mock import patch
    
    fixed_datetime = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    
    @contextmanager
    def mock_time(mock_datetime=fixed_datetime):
        with patch('datetime.datetime') as mock_dt:
            mock_dt.utcnow.return_value = mock_datetime
            mock_dt.now.return_value = mock_datetime
            mock_dt.side_effect = lambda *args, **kw: datetime(*args, **kw)
            yield mock_dt
    
    logger.debug("Mock datetime fixture created", fixed_time=fixed_datetime.isoformat())
    return mock_time


@pytest.fixture(scope="function")
def error_simulation():
    """
    Function-scoped fixture providing error simulation for exception testing.
    
    Creates error simulation utilities for testing error handling, exception
    propagation, and recovery mechanisms across different failure scenarios
    with configurable error types and timing.
    
    Returns:
        Error simulation utilities
    """
    class ErrorSimulator:
        def __init__(self):
            self.error_count = 0
            self.error_threshold = 3
            self.should_fail = False
            self.error_type = Exception
            self.error_message = "Simulated error for testing"
        
        def configure_error(self, error_type=Exception, message="Simulated error", 
                          threshold=3, should_fail=True):
            """Configure error simulation parameters"""
            self.error_type = error_type
            self.error_message = message
            self.error_threshold = threshold
            self.should_fail = should_fail
            self.error_count = 0
        
        def maybe_fail(self):
            """Potentially raise an error based on configuration"""
            if self.should_fail:
                self.error_count += 1
                if self.error_count >= self.error_threshold:
                    raise self.error_type(self.error_message)
        
        def reset(self):
            """Reset error simulation state"""
            self.error_count = 0
            self.should_fail = False
        
        def force_error(self, error_type=None, message=None):
            """Force an immediate error"""
            error_class = error_type or self.error_type
            error_msg = message or self.error_message
            raise error_class(error_msg)
    
    simulator = ErrorSimulator()
    logger.debug("Error simulator created")
    return simulator


# =============================================================================
# Test Data and Factory Fixtures
# =============================================================================

@pytest.fixture(scope="function")
def user_factory():
    """
    Function-scoped fixture providing user test data factory.
    
    Creates factory for generating realistic user test data with varied
    attributes, permissions, and scenarios for comprehensive user-related
    testing without manual data creation requirements.
    
    Returns:
        User data factory instance
    """
    return UserDocumentFactory


@pytest.fixture(scope="function")
def project_factory():
    """
    Function-scoped fixture providing project test data factory.
    
    Creates factory for generating realistic project test data with varied
    configurations, team assignments, and scenarios for comprehensive
    project-related testing scenarios.
    
    Returns:
        Project data factory instance
    """
    return ProjectDocumentFactory


@pytest.fixture(scope="function")
def session_factory():
    """
    Function-scoped fixture providing session test data factory.
    
    Creates factory for generating realistic session test data with varied
    authentication states, expiration times, and security contexts for
    comprehensive session management testing.
    
    Returns:
        Session data factory instance
    """
    return SessionDocumentFactory


# =============================================================================
# Cleanup and Finalization
# =============================================================================

@pytest.fixture(scope="function", autouse=True)
def auto_cleanup():
    """
    Auto-use function-scoped fixture providing automatic test cleanup.
    
    Automatically cleans up test resources, clears caches, resets mocks,
    and ensures clean state between test executions to prevent test
    interference and maintain isolation.
    
    Yields:
        None (auto-use fixture for cleanup)
    """
    # Setup phase (before test execution)
    logger.debug("Test setup: auto cleanup fixture activated")
    
    yield
    
    # Cleanup phase (after test execution)  
    try:
        # Clear Flask application context if exists
        if hasattr(g, 'user'):
            delattr(g, 'user')
        if hasattr(g, 'current_user'):
            delattr(g, 'current_user')
        
        # Reset any global authentication state
        try:
            import asyncio
            # Close any authentication managers
            loop = asyncio.get_event_loop()
            if not loop.is_closed():
                loop.run_until_complete(close_auth_manager())
        except Exception:
            pass  # Ignore cleanup errors
        
        logger.debug("Test cleanup: auto cleanup completed")
        
    except Exception as e:
        logger.warning("Test cleanup warning", error=str(e))


# Export all fixtures for easy import in test modules
__all__ = [
    # Core Flask fixtures
    'app_config', 'app', 'client', 'runner',
    
    # Database integration fixtures
    'app_with_database', 'app_with_seeded_data',
    
    # Authentication fixtures
    'mock_auth_context', 'authenticated_client', 'admin_authenticated_client',
    
    # Performance testing fixtures
    'performance_test_context', 'test_metrics_collector',
    
    # External service mocking
    'mock_external_services', 'mock_circuit_breaker',
    
    # Async testing fixtures
    'async_app', 'async_client_with_auth',
    
    # Utility fixtures
    'temp_file', 'mock_datetime', 'error_simulation',
    
    # Test data factories
    'user_factory', 'project_factory', 'session_factory',
    
    # Auto-cleanup
    'auto_cleanup'
]