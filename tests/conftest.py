"""
Global pytest Configuration and Fixtures

This module provides comprehensive Flask application context, database fixtures with Testcontainers 
integration, Redis caching setup, Auth0 mocking, and production-equivalent test environment 
initialization for the Node.js to Python migration project.

Key Components:
- Flask application factory fixture for test context per Section 6.6.1 pytest framework
- Testcontainers integration for realistic MongoDB and Redis behavior per Section 6.6.1 enhanced mocking strategy
- Auth0 service mocking for authentication testing isolation per Section 6.6.1 external service mocking
- Production-equivalent test environment setup per Section 6.6.1 test environment architecture
- Pytest-asyncio configuration for Motor database operations per Section 6.6.1 async testing
- Pytest-xdist configuration for parallel test execution optimization per Section 6.6.1 performance optimization
- Test database seeding and cleanup automation per Section 6.6.1 test data management

Architecture Integration:
- Section 6.6.1: Enhanced mocking strategy using Testcontainers for realistic database behavior
- Section 6.6.1: pytest-asyncio for asynchronous database operations and external service calls
- Section 6.6.1: pytest-xdist for distributed test execution across unit and integration test suites
- Section 6.6.1: Comprehensive test organization structure for Flask testing
- Section 6.6.1: Production-equivalent test environment setup through Testcontainers
- Section 6.6.1: External service mocking including Auth0, AWS, and third-party APIs
- Section 6.6.1: Test data management with dynamic test object generation

Performance Requirements:
- ≤10% variance from Node.js baseline per Section 0.1.1 performance variance requirement
- Performance validation integration per Section 6.6.1 performance optimization
- Parallel test execution optimization per Section 6.6.1 pytest-xdist configuration
- Production-equivalent behavior through Testcontainers per Section 6.6.1

Dependencies:
- pytest 7.4+ with extensive plugin ecosystem support
- pytest-flask for Flask-specific testing patterns and fixtures
- pytest-asyncio for async testing with Motor database operations
- pytest-xdist for parallel test execution optimization
- pytest-mock for comprehensive external service simulation
- pytest-cov for real-time coverage reporting and threshold enforcement
- testcontainers[mongodb,redis] ≥4.10.0 for realistic database behavior
- factory_boy for dynamic test object generation

Author: Flask Migration Team
Version: 1.0.0
Coverage Target: 95% per Section 6.6.3 quality metrics
"""

import asyncio
import logging
import os
import sys
import tempfile
import time
import uuid
from contextlib import contextmanager, asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, AsyncGenerator
from unittest.mock import Mock, patch, MagicMock, AsyncMock

import pytest
import pytest_asyncio
from flask import Flask, g, request, session
from flask.testing import FlaskClient
from flask_login import AnonymousUserMixin

# Configure pytest-asyncio for Motor database operations
pytest_plugins = ('pytest_asyncio',)

# Import application modules with fallback handling for development scenarios
try:
    from src.app import create_app
    from src.config.settings import TestingConfig, get_config, ConfigFactory
except ImportError as e:
    logging.warning(f"Application imports not available: {e}")
    
    # Fallback implementations for isolated testing
    class TestingConfig:
        TESTING = True
        SECRET_KEY = 'test-secret-key'
        WTF_CSRF_ENABLED = False
        MONGODB_URI = 'mongodb://localhost:27017/test_database'
        REDIS_URL = 'redis://localhost:6379/15'
        
    def create_app(config=None):
        """Fallback Flask application factory"""
        app = Flask(__name__)
        app.config.from_object(TestingConfig)
        return app
    
    def get_config():
        return TestingConfig()

# Import test fixtures with proper error handling
try:
    from tests.fixtures.database_fixtures import (
        DatabaseContainerConfig,
        MongoDbTestContainer,
        RedisTestContainer,
        database_container_config,
        mongodb_container,
        redis_container,
        pymongo_client,
        motor_client,
        redis_client,
        database_seeder,
        performance_validator,
        seeded_database,
        comprehensive_database_environment,
        DatabaseSeeder,
        PerformanceValidator
    )
    
    from tests.fixtures.auth_fixtures import (
        JWTTokenFactory,
        Auth0ServiceMock,
        MockAuth0User,
        MockAnonymousUser,
        MockRedisCache,
        jwt_token_factory,
        auth0_mock,
        mock_redis_cache,
        mock_auth_user,
        mock_admin_user,
        mock_anonymous_user,
        valid_jwt_token,
        expired_jwt_token,
        invalid_signature_token,
        admin_jwt_token,
        auth_test_context,
        security_audit_logger,
        performance_baseline_context
    )
    
    FIXTURES_AVAILABLE = True
    
except ImportError as e:
    logging.warning(f"Test fixtures not available: {e}")
    FIXTURES_AVAILABLE = False

# Configure structured logging for test execution
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# =============================================================================
# Pytest Configuration and Collection Customization
# =============================================================================

def pytest_configure(config):
    """
    Configure pytest with custom markers and settings for comprehensive testing.
    
    This function sets up pytest configuration including custom markers for test
    categorization, performance thresholds, and integration with CI/CD pipeline
    requirements per Section 6.6.1 testing approach.
    
    Args:
        config: Pytest configuration object
    """
    # Register custom markers for test categorization
    config.addinivalue_line(
        "markers", 
        "unit: Unit tests with isolated component testing"
    )
    config.addinivalue_line(
        "markers", 
        "integration: Integration tests with external service dependencies"
    )
    config.addinivalue_line(
        "markers", 
        "e2e: End-to-end tests with complete workflow validation"
    )
    config.addinivalue_line(
        "markers", 
        "performance: Performance tests with ≤10% variance validation"
    )
    config.addinivalue_line(
        "markers", 
        "security: Security tests with authentication and authorization validation"
    )
    config.addinivalue_line(
        "markers", 
        "database: Database tests with MongoDB and Redis integration"
    )
    config.addinivalue_line(
        "markers", 
        "auth: Authentication tests with Auth0 service mocking"
    )
    config.addinivalue_line(
        "markers", 
        "async_test: Async tests with Motor database operations"
    )
    config.addinivalue_line(
        "markers", 
        "slow: Slow tests requiring extended execution time"
    )
    config.addinivalue_line(
        "markers", 
        "testcontainers: Tests requiring Testcontainers for realistic service behavior"
    )
    
    # Configure pytest-asyncio for Motor async database operations
    config.option.asyncio_mode = "auto"
    
    # Configure parallel execution with pytest-xdist optimization
    if hasattr(config.option, 'numprocesses') and config.option.numprocesses:
        logger.info(
            "Pytest-xdist parallel execution enabled",
            num_processes=config.option.numprocesses
        )
    
    logger.info("Pytest configuration completed with custom markers and async support")


def pytest_collection_modifyitems(config, items):
    """
    Modify test collection to add automatic markers and optimize execution order.
    
    This function automatically categorizes tests based on file paths and function
    names, optimizes test execution order for performance, and configures proper
    test isolation per Section 6.6.1 test organization structure.
    
    Args:
        config: Pytest configuration object
        items: List of collected test items
    """
    for item in items:
        # Auto-mark tests based on file location
        test_file_path = str(item.fspath)
        
        if "/unit/" in test_file_path:
            item.add_marker(pytest.mark.unit)
        elif "/integration/" in test_file_path:
            item.add_marker(pytest.mark.integration)
        elif "/e2e/" in test_file_path:
            item.add_marker(pytest.mark.e2e)
        
        # Auto-mark based on test function names
        test_name = item.name.lower()
        
        if "performance" in test_name or "baseline" in test_name:
            item.add_marker(pytest.mark.performance)
        
        if "auth" in test_name or "login" in test_name or "token" in test_name:
            item.add_marker(pytest.mark.auth)
        
        if "database" in test_name or "mongo" in test_name or "redis" in test_name:
            item.add_marker(pytest.mark.database)
        
        if "async" in test_name or "motor" in test_name:
            item.add_marker(pytest.mark.async_test)
        
        if "security" in test_name or "permission" in test_name or "authorization" in test_name:
            item.add_marker(pytest.mark.security)
        
        if "container" in test_name or "testcontainer" in test_name:
            item.add_marker(pytest.mark.testcontainers)
        
        # Mark slow tests for optional exclusion
        if ("load" in test_name or "stress" in test_name or 
            "concurrent" in test_name or "bulk" in test_name):
            item.add_marker(pytest.mark.slow)
    
    logger.info(f"Test collection modified with automatic markers for {len(items)} test items")


def pytest_runtest_setup(item):
    """
    Set up individual test execution with proper isolation and context.
    
    This function ensures proper test isolation, validates test prerequisites,
    and configures test-specific context per Section 6.6.1 test environment
    management requirements.
    
    Args:
        item: Test item being executed
    """
    # Skip Testcontainers tests if Docker is not available
    if item.get_closest_marker("testcontainers"):
        try:
            import docker
            client = docker.from_env()
            client.ping()
        except Exception:
            pytest.skip("Docker not available for Testcontainers tests")
    
    # Skip async tests if pytest-asyncio is not properly configured
    if item.get_closest_marker("async_test"):
        if not hasattr(pytest, 'fixture') or not hasattr(pytest, 'mark'):
            pytest.skip("Async testing environment not properly configured")
    
    logger.debug(f"Test setup completed for: {item.name}")


def pytest_runtest_teardown(item, nextitem):
    """
    Clean up after individual test execution to ensure isolation.
    
    This function performs test cleanup including cache clearing, database
    cleanup, and resource deallocation per Section 6.6.1 test data management
    requirements.
    
    Args:
        item: Completed test item
        nextitem: Next test item to be executed
    """
    # Clear any test-specific globals or caches
    if hasattr(g, '_test_context'):
        delattr(g, '_test_context')
    
    logger.debug(f"Test teardown completed for: {item.name}")


# =============================================================================
# Core Flask Application Fixtures
# =============================================================================

@pytest.fixture(scope="session")
def app_config():
    """
    Session-scoped fixture providing test configuration.
    
    Creates comprehensive test configuration with optimized settings for
    testing including disabled CSRF, test database connections, and
    enhanced debugging per Section 6.6.1 Flask testing patterns.
    
    Returns:
        TestingConfig instance with comprehensive test settings
    """
    config = TestingConfig()
    
    # Override configuration for testing optimization
    config.TESTING = True
    config.DEBUG = True
    config.WTF_CSRF_ENABLED = False
    config.RATELIMIT_ENABLED = False
    config.TALISMAN_ENABLED = False
    config.SESSION_COOKIE_SECURE = False
    config.REMEMBER_COOKIE_SECURE = False
    
    # Database configuration for testing
    config.MONGODB_URI = os.getenv('MONGODB_TEST_URI', 'mongodb://localhost:27017/test_database')
    config.REDIS_URL = os.getenv('REDIS_TEST_URL', 'redis://localhost:6379/15')
    
    # Testing-specific optimizations
    config.CACHE_TYPE = 'null'  # Disable caching for testing
    config.PERFORMANCE_MONITORING_ENABLED = False
    config.HEALTH_CHECK_ENABLED = False
    
    logger.info("Test configuration created with optimized settings")
    return config


@pytest.fixture(scope="session")
def flask_app(app_config):
    """
    Session-scoped fixture providing Flask application instance for testing.
    
    Creates Flask application using the factory pattern with test configuration
    and comprehensive extension initialization per Section 6.6.1 Flask application
    factory fixture requirements.
    
    Args:
        app_config: Test configuration instance
        
    Returns:
        Configured Flask application instance for testing
    """
    app = create_app()
    app.config.from_object(app_config)
    
    # Configure test-specific settings
    app.config['TESTING'] = True
    app.config['SERVER_NAME'] = 'localhost:5000'
    
    # Create application context for testing
    with app.app_context():
        # Initialize any test-specific setup
        logger.info("Flask application created for testing", app_name=app.config.get('APP_NAME', 'Flask App'))
        yield app
    
    logger.info("Flask application context closed")


@pytest.fixture(scope="function")
def client(flask_app):
    """
    Function-scoped fixture providing Flask test client.
    
    Creates Flask test client with proper context management for HTTP request
    testing per Section 6.6.1 Flask testing patterns and API endpoint validation.
    
    Args:
        flask_app: Flask application instance
        
    Returns:
        Flask test client for HTTP request simulation
    """
    with flask_app.test_client() as test_client:
        with flask_app.app_context():
            logger.debug("Flask test client created")
            yield test_client
    
    logger.debug("Flask test client context closed")


@pytest.fixture(scope="function")
def app_context(flask_app):
    """
    Function-scoped fixture providing Flask application context.
    
    Creates Flask application context for testing components that require
    application context access per Section 6.6.1 Flask testing requirements.
    
    Args:
        flask_app: Flask application instance
        
    Yields:
        Flask application context manager
    """
    with flask_app.app_context():
        logger.debug("Flask application context established")
        yield flask_app
    
    logger.debug("Flask application context closed")


@pytest.fixture(scope="function")
def request_context(flask_app):
    """
    Function-scoped fixture providing Flask request context.
    
    Creates Flask request context for testing components that require request
    context access including session, g object, and request-specific data
    per Section 6.6.1 Flask testing patterns.
    
    Args:
        flask_app: Flask application instance
        
    Yields:
        Flask request context manager
    """
    with flask_app.test_request_context('/'):
        logger.debug("Flask request context established")
        yield flask_app
    
    logger.debug("Flask request context closed")


# =============================================================================
# Database and Cache Fixtures Integration
# =============================================================================

if FIXTURES_AVAILABLE:
    
    @pytest.fixture(scope="function")
    def test_database_environment(
        pymongo_client,
        motor_client,
        redis_client,
        database_seeder,
        performance_validator
    ):
        """
        Function-scoped fixture providing complete database testing environment.
        
        Integrates Testcontainers-backed database connections with seeding utilities
        and performance validation for comprehensive database testing per Section 6.6.1
        Testcontainers integration requirements.
        
        Args:
            pymongo_client: PyMongo synchronous client
            motor_client: Motor async client  
            redis_client: Redis cache client
            database_seeder: Database seeding utility
            performance_validator: Performance validation utility
            
        Returns:
            Dictionary containing complete database testing environment
        """
        environment = {
            'pymongo_client': pymongo_client,
            'motor_client': motor_client,
            'redis_client': redis_client,
            'database_seeder': database_seeder,
            'performance_validator': performance_validator,
            'database': pymongo_client.get_default_database(),
            'collections': {
                'users': pymongo_client.get_default_database().users,
                'projects': pymongo_client.get_default_database().projects,
                'sessions': pymongo_client.get_default_database().sessions
            }
        }
        
        logger.info(
            "Complete database testing environment created",
            mongodb_available=environment['pymongo_client'] is not None,
            redis_available=environment['redis_client'] is not None,
            seeder_available=environment['database_seeder'] is not None
        )
        
        return environment

else:
    
    @pytest.fixture(scope="function")  
    def test_database_environment():
        """Fallback database environment for isolated testing"""
        logger.warning("Database fixtures not available, using fallback environment")
        return {
            'pymongo_client': None,
            'motor_client': None,
            'redis_client': None,
            'database_seeder': None,
            'performance_validator': None,
            'database': None,
            'collections': {}
        }


# =============================================================================
# Authentication and Authorization Fixtures Integration
# =============================================================================

if FIXTURES_AVAILABLE:
    
    @pytest.fixture(scope="function")
    def auth_test_environment(
        jwt_token_factory,
        auth0_mock,
        mock_redis_cache,
        mock_auth_user,
        mock_admin_user,
        mock_anonymous_user,
        security_audit_logger
    ):
        """
        Function-scoped fixture providing complete authentication testing environment.
        
        Integrates Auth0 service mocking, JWT token management, and user fixtures
        for comprehensive authentication testing per Section 6.6.1 Auth0 service
        mocking requirements.
        
        Args:
            jwt_token_factory: JWT token generation utility
            auth0_mock: Auth0 service mock
            mock_redis_cache: Redis cache mock
            mock_auth_user: Standard authenticated user
            mock_admin_user: Admin user with elevated permissions
            mock_anonymous_user: Anonymous user for unauthenticated testing
            security_audit_logger: Security audit logging utility
            
        Returns:
            Dictionary containing complete authentication testing environment
        """
        environment = {
            'jwt_factory': jwt_token_factory,
            'auth0_mock': auth0_mock,
            'cache': mock_redis_cache,
            'users': {
                'authenticated': mock_auth_user,
                'admin': mock_admin_user,
                'anonymous': mock_anonymous_user
            },
            'audit_logger': security_audit_logger,
            'tokens': {
                'valid': jwt_token_factory.create_valid_token(
                    user_id=mock_auth_user.id,
                    email=mock_auth_user.email,
                    permissions=list(mock_auth_user.permissions),
                    roles=list(mock_auth_user.roles)
                ),
                'admin': jwt_token_factory.create_valid_token(
                    user_id=mock_admin_user.id,
                    email=mock_admin_user.email,
                    permissions=list(mock_admin_user.permissions),
                    roles=list(mock_admin_user.roles)
                ),
                'expired': jwt_token_factory.create_expired_token(
                    user_id=mock_auth_user.id,
                    email=mock_auth_user.email
                ),
                'invalid_signature': jwt_token_factory.create_invalid_signature_token(
                    user_id=mock_auth_user.id,
                    email=mock_auth_user.email
                )
            }
        }
        
        logger.info(
            "Complete authentication testing environment created",
            auth0_mock_users=len(auth0_mock.users),
            jwt_tokens_generated=len(environment['tokens']),
            user_types_available=len(environment['users'])
        )
        
        return environment

else:
    
    @pytest.fixture(scope="function")
    def auth_test_environment():
        """Fallback authentication environment for isolated testing"""
        logger.warning("Authentication fixtures not available, using fallback environment")
        return {
            'jwt_factory': None,
            'auth0_mock': None,
            'cache': None,
            'users': {
                'authenticated': None,
                'admin': None,
                'anonymous': None
            },
            'audit_logger': None,
            'tokens': {}
        }


# =============================================================================
# Performance and Monitoring Fixtures
# =============================================================================

@pytest.fixture(scope="function")
def performance_monitoring():
    """
    Function-scoped fixture providing performance monitoring for ≤10% variance validation.
    
    Creates performance monitoring context for tracking response times, memory usage,
    and throughput metrics to ensure compliance with Node.js baseline requirements
    per Section 0.1.1 performance variance requirement.
    
    Returns:
        Performance monitoring context with measurement utilities
    """
    monitoring_context = {
        'measurements': [],
        'baseline_metrics': {
            'auth_request_time': 0.15,  # 150ms Node.js baseline
            'database_query_time': 0.05,  # 50ms Node.js baseline
            'cache_operation_time': 0.01,  # 10ms Node.js baseline
            'api_response_time': 0.20,  # 200ms Node.js baseline
        },
        'variance_threshold': 0.10,  # ≤10% variance requirement
        'performance_violations': []
    }
    
    def measure_operation(operation_name: str, baseline_name: str = None):
        """Context manager for measuring operation performance"""
        @contextmanager
        def measurement_context():
            start_time = time.perf_counter()
            try:
                yield
            finally:
                end_time = time.perf_counter()
                duration = end_time - start_time
                
                measurement = {
                    'operation': operation_name,
                    'duration': duration,
                    'timestamp': time.time()
                }
                monitoring_context['measurements'].append(measurement)
                
                # Validate against baseline if provided
                if baseline_name and baseline_name in monitoring_context['baseline_metrics']:
                    baseline_value = monitoring_context['baseline_metrics'][baseline_name]
                    variance = abs(duration - baseline_value) / baseline_value
                    
                    if variance > monitoring_context['variance_threshold']:
                        violation = {
                            'operation': operation_name,
                            'measured': duration,
                            'baseline': baseline_value,
                            'variance': variance,
                            'threshold': monitoring_context['variance_threshold'],
                            'timestamp': time.time()
                        }
                        monitoring_context['performance_violations'].append(violation)
                        logger.warning(
                            "Performance variance violation detected",
                            operation=operation_name,
                            variance_percentage=round(variance * 100, 2),
                            threshold_percentage=round(monitoring_context['variance_threshold'] * 100, 2)
                        )
        
        return measurement_context()
    
    def get_performance_summary():
        """Get comprehensive performance measurement summary"""
        return {
            'total_measurements': len(monitoring_context['measurements']),
            'performance_violations': len(monitoring_context['performance_violations']),
            'average_duration': (
                sum(m['duration'] for m in monitoring_context['measurements']) / 
                len(monitoring_context['measurements'])
                if monitoring_context['measurements'] else 0
            ),
            'violations': monitoring_context['performance_violations'],
            'compliant': len(monitoring_context['performance_violations']) == 0
        }
    
    monitoring_context['measure_operation'] = measure_operation
    monitoring_context['get_performance_summary'] = get_performance_summary
    
    logger.info(
        "Performance monitoring context created",
        variance_threshold=monitoring_context['variance_threshold'],
        baseline_metrics_count=len(monitoring_context['baseline_metrics'])
    )
    
    return monitoring_context


@pytest.fixture(scope="function")
def test_metrics_collector():
    """
    Function-scoped fixture providing test metrics collection for CI/CD integration.
    
    Creates comprehensive metrics collection for test execution including coverage,
    performance, security validation, and quality metrics per Section 6.6.1
    test automation requirements.
    
    Returns:
        Test metrics collector with aggregation utilities
    """
    metrics = {
        'test_execution': {
            'started_at': time.time(),
            'total_tests': 0,
            'passed_tests': 0,
            'failed_tests': 0,
            'skipped_tests': 0
        },
        'coverage_metrics': {
            'line_coverage': 0.0,
            'branch_coverage': 0.0,
            'function_coverage': 0.0
        },
        'performance_metrics': {
            'test_execution_time': 0.0,
            'database_operations': 0,
            'cache_operations': 0,
            'api_requests': 0
        },
        'security_metrics': {
            'auth_tests': 0,
            'permission_tests': 0,
            'security_violations': 0
        },
        'quality_metrics': {
            'code_quality_score': 0.0,
            'maintainability_index': 0.0,
            'technical_debt_ratio': 0.0
        }
    }
    
    def record_test_result(test_name: str, status: str, duration: float = 0.0):
        """Record individual test result"""
        metrics['test_execution']['total_tests'] += 1
        
        if status == 'passed':
            metrics['test_execution']['passed_tests'] += 1
        elif status == 'failed':
            metrics['test_execution']['failed_tests'] += 1
        elif status == 'skipped':
            metrics['test_execution']['skipped_tests'] += 1
        
        metrics['performance_metrics']['test_execution_time'] += duration
        
        logger.debug(f"Test result recorded: {test_name} - {status}")
    
    def record_database_operation():
        """Record database operation for metrics"""
        metrics['performance_metrics']['database_operations'] += 1
    
    def record_cache_operation():
        """Record cache operation for metrics"""  
        metrics['performance_metrics']['cache_operations'] += 1
    
    def record_api_request():
        """Record API request for metrics"""
        metrics['performance_metrics']['api_requests'] += 1
    
    def record_security_test(test_type: str):
        """Record security test execution"""
        if test_type == 'auth':
            metrics['security_metrics']['auth_tests'] += 1
        elif test_type == 'permission':
            metrics['security_metrics']['permission_tests'] += 1
    
    def record_security_violation():
        """Record security violation"""
        metrics['security_metrics']['security_violations'] += 1
    
    def get_final_metrics():
        """Get final test execution metrics"""
        execution_time = time.time() - metrics['test_execution']['started_at']
        
        final_metrics = {
            **metrics,
            'execution_summary': {
                'total_execution_time': execution_time,
                'tests_per_second': (
                    metrics['test_execution']['total_tests'] / execution_time
                    if execution_time > 0 else 0
                ),
                'success_rate': (
                    metrics['test_execution']['passed_tests'] / 
                    metrics['test_execution']['total_tests']
                    if metrics['test_execution']['total_tests'] > 0 else 0
                )
            }
        }
        
        return final_metrics
    
    # Attach utility functions to metrics context
    metrics['record_test_result'] = record_test_result
    metrics['record_database_operation'] = record_database_operation
    metrics['record_cache_operation'] = record_cache_operation
    metrics['record_api_request'] = record_api_request
    metrics['record_security_test'] = record_security_test
    metrics['record_security_violation'] = record_security_violation
    metrics['get_final_metrics'] = get_final_metrics
    
    logger.info("Test metrics collector initialized")
    return metrics


# =============================================================================
# External Service Mocking Fixtures
# =============================================================================

@pytest.fixture(scope="function")
def mock_external_services():
    """
    Function-scoped fixture providing comprehensive external service mocking.
    
    Creates mock implementations for AWS services, third-party APIs, and enterprise
    service integrations per Section 6.6.1 external service mocking requirements.
    
    Returns:
        Dictionary containing all mocked external service implementations
    """
    services = {}
    
    # Mock AWS S3 service
    with patch('boto3.client') as mock_boto3:
        mock_s3 = Mock()
        mock_s3.upload_file.return_value = {'ETag': '"mock-etag"'}
        mock_s3.download_file.return_value = None
        mock_s3.delete_object.return_value = {'DeleteMarker': True}
        mock_s3.list_objects_v2.return_value = {
            'Contents': [
                {'Key': 'test-file.txt', 'Size': 1024}
            ]
        }
        mock_boto3.return_value = mock_s3
        services['aws_s3'] = mock_s3
        
        logger.debug("AWS S3 service mocked")
    
    # Mock HTTP client for external API calls
    with patch('httpx.AsyncClient') as mock_httpx:
        mock_client = AsyncMock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'status': 'success', 'data': {}}
        mock_response.text = '{"status": "success"}'
        mock_client.get.return_value = mock_response
        mock_client.post.return_value = mock_response
        mock_client.put.return_value = mock_response
        mock_client.delete.return_value = mock_response
        mock_httpx.return_value.__aenter__.return_value = mock_client
        services['http_client'] = mock_client
        
        logger.debug("HTTP client service mocked")
    
    # Mock email service
    mock_email = Mock()
    mock_email.send_email.return_value = {'MessageId': 'mock-message-id'}
    services['email_service'] = mock_email
    
    # Mock notification service
    mock_notifications = Mock()
    mock_notifications.send_notification.return_value = {'id': 'mock-notification-id'}
    services['notification_service'] = mock_notifications
    
    # Mock payment service
    mock_payment = Mock()
    mock_payment.process_payment.return_value = {
        'transaction_id': 'mock-txn-id',
        'status': 'completed'
    }
    services['payment_service'] = mock_payment
    
    logger.info(
        "External services mocked",
        services_mocked=list(services.keys()),
        aws_available=bool(services.get('aws_s3')),
        http_client_available=bool(services.get('http_client'))
    )
    
    return services


@pytest.fixture(scope="function")
def mock_circuit_breakers():
    """
    Function-scoped fixture providing circuit breaker testing utilities.
    
    Creates mock circuit breaker implementations for testing resilience patterns
    and failure handling scenarios per Section 6.6.1 circuit breaker testing.
    
    Returns:
        Dictionary containing circuit breaker mocks for different services
    """
    circuit_breakers = {}
    
    # Auth0 circuit breaker mock
    auth0_cb = Mock()
    auth0_cb.state = 'closed'
    auth0_cb.failure_count = 0
    auth0_cb.last_failure_time = None
    
    def auth0_call(func, *args, **kwargs):
        if auth0_cb.state == 'open':
            raise Exception("Circuit breaker is open")
        
        try:
            result = func(*args, **kwargs)
            auth0_cb.failure_count = 0
            return result
        except Exception as e:
            auth0_cb.failure_count += 1
            auth0_cb.last_failure_time = time.time()
            
            if auth0_cb.failure_count >= 5:
                auth0_cb.state = 'open'
            
            raise e
    
    auth0_cb.call = auth0_call
    circuit_breakers['auth0'] = auth0_cb
    
    # Database circuit breaker mock
    db_cb = Mock()
    db_cb.state = 'closed'
    db_cb.failure_count = 0
    db_cb.last_failure_time = None
    
    def db_call(func, *args, **kwargs):
        if db_cb.state == 'open':
            raise Exception("Database circuit breaker is open")
        
        try:
            result = func(*args, **kwargs)
            db_cb.failure_count = 0
            return result
        except Exception as e:
            db_cb.failure_count += 1
            db_cb.last_failure_time = time.time()
            
            if db_cb.failure_count >= 3:
                db_cb.state = 'open'
            
            raise e
    
    db_cb.call = db_call
    circuit_breakers['database'] = db_cb
    
    # External API circuit breaker mock
    api_cb = Mock()
    api_cb.state = 'closed'
    api_cb.failure_count = 0
    api_cb.last_failure_time = None
    
    def api_call(func, *args, **kwargs):
        if api_cb.state == 'open':
            raise Exception("External API circuit breaker is open")
        
        try:
            result = func(*args, **kwargs)
            api_cb.failure_count = 0
            return result
        except Exception as e:
            api_cb.failure_count += 1
            api_cb.last_failure_time = time.time()
            
            if api_cb.failure_count >= 5:
                api_cb.state = 'open'
            
            raise e
    
    api_cb.call = api_call
    circuit_breakers['external_api'] = api_cb
    
    logger.info(
        "Circuit breaker mocks created",
        circuit_breakers=list(circuit_breakers.keys())
    )
    
    return circuit_breakers


# =============================================================================
# Comprehensive Test Environment Fixtures
# =============================================================================

@pytest.fixture(scope="function")
def comprehensive_test_environment(
    flask_app,
    client,
    test_database_environment,
    auth_test_environment,
    performance_monitoring,
    test_metrics_collector,
    mock_external_services,
    mock_circuit_breakers
):
    """
    Function-scoped fixture providing complete testing environment.
    
    Integrates all testing components including Flask application, database
    connections, authentication mocking, performance monitoring, and external
    service mocking for comprehensive end-to-end testing per Section 6.6.1
    comprehensive test environment requirements.
    
    Args:
        flask_app: Flask application instance
        client: Flask test client
        test_database_environment: Database testing environment
        auth_test_environment: Authentication testing environment
        performance_monitoring: Performance monitoring context
        test_metrics_collector: Test metrics collection utilities
        mock_external_services: External service mocks
        mock_circuit_breakers: Circuit breaker testing utilities
        
    Returns:
        Comprehensive testing environment with all components integrated
    """
    environment = {
        'app': flask_app,
        'client': client,
        'database': test_database_environment,
        'auth': auth_test_environment,
        'performance': performance_monitoring,
        'metrics': test_metrics_collector,
        'external_services': mock_external_services,
        'circuit_breakers': mock_circuit_breakers,
        'config': {
            'testing_mode': True,
            'performance_validation_enabled': True,
            'security_testing_enabled': True,
            'database_integration_enabled': bool(test_database_environment.get('pymongo_client')),
            'auth_mocking_enabled': bool(auth_test_environment.get('auth0_mock')),
            'external_services_mocked': True,
            'circuit_breaker_testing_enabled': True
        }
    }
    
    # Initialize environment state
    start_time = time.time()
    environment['session_info'] = {
        'session_id': str(uuid.uuid4()),
        'started_at': start_time,
        'started_at_iso': datetime.utcnow().isoformat()
    }
    
    logger.info(
        "Comprehensive test environment initialized",
        session_id=environment['session_info']['session_id'],
        flask_app_available=bool(environment['app']),
        database_available=environment['config']['database_integration_enabled'],
        auth_available=environment['config']['auth_mocking_enabled'],
        external_services_available=environment['config']['external_services_mocked'],
        performance_monitoring_available=environment['config']['performance_validation_enabled']
    )
    
    yield environment
    
    # Environment cleanup and final metrics collection
    end_time = time.time()
    execution_time = end_time - start_time
    
    final_metrics = environment['metrics']['get_final_metrics']()
    performance_summary = environment['performance']['get_performance_summary']()
    
    logger.info(
        "Comprehensive test environment session completed",
        session_id=environment['session_info']['session_id'],
        execution_time=round(execution_time, 3),
        total_tests=final_metrics['test_execution']['total_tests'],
        performance_violations=performance_summary['performance_violations'],
        performance_compliant=performance_summary['compliant']
    )


# =============================================================================
# Async Testing Configuration for Motor Database Operations
# =============================================================================

@pytest_asyncio.fixture(scope="function")
async def async_test_environment(comprehensive_test_environment):
    """
    Function-scoped async fixture providing async testing environment.
    
    Creates async testing environment for Motor database operations and async
    service integrations per Section 6.6.1 pytest-asyncio configuration requirements.
    
    Args:
        comprehensive_test_environment: Complete testing environment
        
    Returns:
        Async testing environment with Motor client and async utilities
    """
    async_env = {
        'motor_client': comprehensive_test_environment['database'].get('motor_client'),
        'async_database': None,
        'async_cache': None,
        'async_auth': None
    }
    
    # Initialize async database if Motor client is available
    if async_env['motor_client']:
        async_env['async_database'] = async_env['motor_client'].get_default_database()
        
        # Test async connection
        try:
            await async_env['motor_client'].admin.command('ping')
            logger.debug("Async database connection validated")
        except Exception as e:
            logger.warning(f"Async database connection failed: {e}")
    
    # Mock async cache operations
    class AsyncCacheMock:
        def __init__(self):
            self.data = {}
        
        async def get(self, key: str):
            return self.data.get(key)
        
        async def set(self, key: str, value: str, ttl: int = None):
            self.data[key] = value
            return True
        
        async def delete(self, key: str):
            return self.data.pop(key, None) is not None
    
    async_env['async_cache'] = AsyncCacheMock()
    
    # Mock async authentication operations
    class AsyncAuthMock:
        async def validate_token(self, token: str):
            return {'valid': True, 'user_id': 'test_user'}
        
        async def get_user_permissions(self, user_id: str):
            return ['read:profile', 'update:profile']
    
    async_env['async_auth'] = AsyncAuthMock()
    
    logger.info(
        "Async test environment created",
        motor_available=bool(async_env['motor_client']),
        async_cache_available=bool(async_env['async_cache']),
        async_auth_available=bool(async_env['async_auth'])
    )
    
    yield async_env
    
    # Async cleanup
    if async_env['motor_client']:
        async_env['motor_client'].close()
        logger.debug("Async database connection closed")


# =============================================================================
# Test Data Management and Cleanup Utilities
# =============================================================================

@pytest.fixture(scope="function", autouse=True)
def test_data_cleanup():
    """
    Function-scoped auto-use fixture providing automatic test data cleanup.
    
    Ensures test isolation by automatically cleaning up test data, clearing
    caches, and resetting state between tests per Section 6.6.1 test data
    management requirements.
    
    Yields:
        Cleanup context manager for test execution
    """
    # Pre-test setup
    test_id = str(uuid.uuid4())
    logger.debug(f"Test data cleanup initialized for test: {test_id}")
    
    yield test_id
    
    # Post-test cleanup
    try:
        # Clear any global test state
        if hasattr(g, '_test_data'):
            delattr(g, '_test_data')
        
        # Clear session data
        with Flask(__name__).test_request_context():
            session.clear()
        
        logger.debug(f"Test data cleanup completed for test: {test_id}")
        
    except Exception as e:
        logger.warning(f"Test data cleanup failed for test {test_id}: {e}")


@pytest.fixture(scope="session", autouse=True)
def test_session_management():
    """
    Session-scoped auto-use fixture providing test session management.
    
    Manages the overall test session including setup, monitoring, and cleanup
    for comprehensive test execution tracking per Section 6.6.1 test automation
    requirements.
    
    Yields:
        Test session context for the entire test run
    """
    # Session setup
    session_id = str(uuid.uuid4())
    start_time = time.time()
    
    logger.info(
        "Test session started",
        session_id=session_id,
        pytest_version=pytest.__version__,
        python_version=sys.version.split()[0]
    )
    
    session_context = {
        'session_id': session_id,
        'start_time': start_time,
        'tests_executed': 0,
        'tests_passed': 0,
        'tests_failed': 0,
        'tests_skipped': 0
    }
    
    yield session_context
    
    # Session cleanup and reporting
    end_time = time.time()
    execution_time = end_time - start_time
    
    logger.info(
        "Test session completed",
        session_id=session_id,
        execution_time=round(execution_time, 3),
        tests_executed=session_context['tests_executed'],
        tests_passed=session_context['tests_passed'],
        tests_failed=session_context['tests_failed'],
        tests_skipped=session_context['tests_skipped']
    )


# =============================================================================
# Utility Functions for Test Configuration
# =============================================================================

def skip_if_no_docker():
    """Skip test if Docker is not available for Testcontainers"""
    try:
        import docker
        client = docker.from_env()
        client.ping()
        return False
    except:
        return True


def skip_if_no_redis():
    """Skip test if Redis is not available"""
    try:
        import redis
        r = redis.Redis(host='localhost', port=6379, db=15)
        r.ping()
        return False
    except:
        return True


def skip_if_no_mongodb():
    """Skip test if MongoDB is not available"""
    try:
        import pymongo
        client = pymongo.MongoClient('mongodb://localhost:27017', serverSelectionTimeoutMS=1000)
        client.admin.command('ping')
        return False
    except:
        return True


# Export key fixtures and utilities for easy import
__all__ = [
    # Core Flask fixtures
    'flask_app',
    'client', 
    'app_context',
    'request_context',
    
    # Environment fixtures
    'comprehensive_test_environment',
    'test_database_environment',
    'auth_test_environment',
    'async_test_environment',
    
    # Monitoring and metrics
    'performance_monitoring',
    'test_metrics_collector',
    
    # External service mocking
    'mock_external_services',
    'mock_circuit_breakers',
    
    # Utility functions
    'skip_if_no_docker',
    'skip_if_no_redis',
    'skip_if_no_mongodb'
]