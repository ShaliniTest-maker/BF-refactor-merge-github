"""
Test Fixtures Package Initialization

Centralized fixture imports and shared configuration constants for comprehensive test suite
supporting Node.js to Python Flask migration testing requirements per Section 6.6.1.

This module provides:
- Centralized fixture imports from all fixture modules for easy access across test suites
- Shared test configuration constants for pytest 7.4+ framework integration
- Common factory_boy and Testcontainers configuration values per Section 6.6.1
- Pytest-Flask integration patterns for comprehensive Flask application testing
- Performance validation constants supporting ≤10% variance requirement per Section 0.3.2
- Test environment configuration for static analysis and security testing integration

Package Structure:
- database_fixtures: MongoDB, Redis, PyMongo, Motor, connection pooling fixtures
- auth_fixtures: Auth0, JWT, Flask-Login, session management fixtures
- external_service_mocks: AWS, HTTP client, circuit breaker, third-party API mocks
- factory_fixtures: factory_boy patterns, pydantic validation, dynamic test data generation

Features:
- pytest 7.4+ framework with extensive plugin ecosystem support per Section 6.6.1
- Test organization structure with fixture-based data per Section 6.6.1
- factory_boy integration for dynamic test object generation per Section 6.6.1
- Testcontainers integration for realistic service behavior per Section 6.6.1
- Enhanced mocking strategy with production-equivalent behavior per Section 6.6.1
- Comprehensive fixture strategy for authentication, database, and external services
- pytest-flask integration for Flask-specific testing patterns and fixtures

Dependencies:
- pytest 7.4+ with extensive plugin ecosystem
- pytest-flask for Flask application testing patterns
- pytest-asyncio for async testing support with Motor
- pytest-mock for comprehensive external service simulation
- factory_boy for dynamic test object generation
- testcontainers for production-equivalent service behavior
- PyJWT 2.8+ for JWT token processing
- boto3 1.28+ for AWS service testing
- redis-py 5.0+ for cache testing

Author: Flask Migration Team
Version: 1.0.0
Compliance: pytest 7.4+, Section 6.6.1 Testing Strategy
"""

import os
import sys
from typing import Dict, List, Any, Optional, Union

# Core testing framework imports
import pytest
import pytest_asyncio

# Configuration for shared test constants and fixture patterns
from dataclasses import dataclass, field
from pathlib import Path

# =============================================================================
# Shared Test Configuration Constants
# =============================================================================

# Performance validation constants per Section 0.3.2
PERFORMANCE_VARIANCE_THRESHOLD = 0.10  # ≤10% variance requirement
NODEJS_BASELINE_RESPONSE_TIME_MS = 100  # Example baseline for validation
DATABASE_OPERATION_TIMEOUT_SECONDS = 30
CONTAINER_STARTUP_TIMEOUT_SECONDS = 120

# Test environment configuration per Section 6.6.1
TEST_DATABASE_NAME = "test_database"
TEST_REDIS_DB = 0
TEST_SESSION_TIMEOUT = 3600
TEST_JWT_EXPIRATION = 3600

# Testcontainers configuration per Section 6.6.1
MONGODB_TEST_IMAGE = "mongo:7.0"
REDIS_TEST_IMAGE = "redis:7.2-alpine"
CONTAINER_NETWORK_NAME = "test-network"

# factory_boy configuration per Section 6.6.1
FACTORY_DEFAULT_STRATEGY = 'create'
FACTORY_TEST_DATA_BATCH_SIZE = 10
FACTORY_PERFORMANCE_TEST_SIZE = 1000

# pytest-flask configuration per Section 6.6.1
FLASK_TESTING_CONFIG = {
    'TESTING': True,
    'DEBUG': True,
    'WTF_CSRF_ENABLED': False,
    'LOGIN_DISABLED': False,
    'SECRET_KEY': 'test-secret-key-for-flask-testing'
}

# Static analysis integration per Section 6.6.1
COVERAGE_THRESHOLD = 90  # Minimum coverage percentage
FLAKE8_MAX_LINE_LENGTH = 88
MYPY_STRICT_MODE = True

# Security testing configuration per Section 6.6.1
SECURITY_TEST_CONFIG = {
    'bandit_skip_tests': [],  # List of bandit tests to skip
    'safety_ignore_vulnerabilities': [],  # List of CVEs to ignore for testing
    'jwt_test_algorithms': ['RS256', 'HS256'],  # JWT algorithms for testing
    'auth0_test_domain': 'test-domain.auth0.com'
}


@dataclass
class SharedTestConfig:
    """
    Shared test configuration class providing centralized access to test constants.
    
    This configuration class consolidates all shared test constants and provides
    type-safe access to configuration values across the test suite. Supports
    pytest 7.4+ framework integration and comprehensive testing strategy per
    Section 6.6.1 requirements.
    """
    
    # Performance testing configuration
    performance_variance_threshold: float = field(default=PERFORMANCE_VARIANCE_THRESHOLD)
    nodejs_baseline_response_time_ms: float = field(default=NODEJS_BASELINE_RESPONSE_TIME_MS)
    database_operation_timeout: int = field(default=DATABASE_OPERATION_TIMEOUT_SECONDS)
    container_startup_timeout: int = field(default=CONTAINER_STARTUP_TIMEOUT_SECONDS)
    
    # Database testing configuration
    test_database_name: str = field(default=TEST_DATABASE_NAME)
    test_redis_db: int = field(default=TEST_REDIS_DB)
    mongodb_test_image: str = field(default=MONGODB_TEST_IMAGE)
    redis_test_image: str = field(default=REDIS_TEST_IMAGE)
    
    # Authentication testing configuration
    test_session_timeout: int = field(default=TEST_SESSION_TIMEOUT)
    test_jwt_expiration: int = field(default=TEST_JWT_EXPIRATION)
    flask_testing_config: Dict[str, Any] = field(default_factory=lambda: FLASK_TESTING_CONFIG.copy())
    security_test_config: Dict[str, Any] = field(default_factory=lambda: SECURITY_TEST_CONFIG.copy())
    
    # Factory testing configuration
    factory_default_strategy: str = field(default=FACTORY_DEFAULT_STRATEGY)
    factory_test_data_batch_size: int = field(default=FACTORY_TEST_DATA_BATCH_SIZE)
    factory_performance_test_size: int = field(default=FACTORY_PERFORMANCE_TEST_SIZE)
    
    # Quality assurance configuration
    coverage_threshold: int = field(default=COVERAGE_THRESHOLD)
    flake8_max_line_length: int = field(default=FLAKE8_MAX_LINE_LENGTH)
    mypy_strict_mode: bool = field(default=MYPY_STRICT_MODE)
    
    def get_flask_app_config(self) -> Dict[str, Any]:
        """Get Flask application configuration for testing."""
        return self.flask_testing_config.copy()
    
    def get_database_config(self) -> Dict[str, Any]:
        """Get database configuration for testing."""
        return {
            'database_name': self.test_database_name,
            'redis_db': self.test_redis_db,
            'mongodb_image': self.mongodb_test_image,
            'redis_image': self.redis_test_image,
            'operation_timeout': self.database_operation_timeout
        }
    
    def get_performance_config(self) -> Dict[str, Any]:
        """Get performance testing configuration."""
        return {
            'variance_threshold': self.performance_variance_threshold,
            'baseline_response_time_ms': self.nodejs_baseline_response_time_ms,
            'timeout_seconds': self.database_operation_timeout
        }
    
    def get_security_config(self) -> Dict[str, Any]:
        """Get security testing configuration."""
        return self.security_test_config.copy()


# Global shared test configuration instance
shared_test_config = SharedTestConfig()


# =============================================================================
# Database Fixtures Imports
# =============================================================================

# Import all database fixtures from database_fixtures module
try:
    from .database_fixtures import (
        # Container configuration and management
        DatabaseContainerConfig,
        MongoDbTestContainer,
        RedisTestContainer,
        database_container_config,
        mongodb_container,
        redis_container,
        
        # Database client fixtures
        pymongo_client,
        motor_client,
        redis_client,
        
        # Application-level fixtures
        database_manager,
        database_seeder,
        performance_validator,
        seeded_database,
        
        # Performance and connection testing fixtures
        connection_pool_tester,
        async_connection_pool_tester,
        
        # Comprehensive testing environment
        comprehensive_database_environment,
        
        # Test data factories
        BaseTestObjectFactory,
        UserDocumentFactory,
        AddressFactory,
        ProjectDocumentFactory,
        SessionDocumentFactory,
        
        # Utilities
        DatabaseSeeder,
        PerformanceValidator
    )
    
    DATABASE_FIXTURES_AVAILABLE = True
    
except ImportError as e:
    DATABASE_FIXTURES_AVAILABLE = False
    print(f"Warning: Database fixtures not available: {e}")


# =============================================================================
# Authentication Fixtures Imports
# =============================================================================

# Import all authentication fixtures from auth_fixtures module
try:
    from .auth_fixtures import (
        # Mock user objects for Flask-Login integration
        MockAuth0User,
        MockAnonymousUser,
        
        # JWT token generation and validation
        JWTTokenFactory,
        
        # Auth0 service mocking fixtures
        mock_auth0_client,
        mock_auth0_management_client,
        mock_auth0_user_info,
        mock_auth0_jwks,
        
        # Flask-Login fixtures
        flask_login_manager,
        authenticated_user,
        anonymous_user,
        user_session,
        
        # JWT validation fixtures
        jwt_token_factory,
        valid_jwt_token,
        expired_jwt_token,
        invalid_jwt_token,
        jwt_public_key,
        
        # Session management fixtures
        session_manager,
        redis_session_store,
        distributed_session,
        
        # Security context fixtures
        security_context,
        permission_validator,
        role_manager,
        
        # Authentication cache fixtures
        auth_cache,
        permission_cache,
        user_cache
    )
    
    AUTH_FIXTURES_AVAILABLE = True
    
except ImportError as e:
    AUTH_FIXTURES_AVAILABLE = False
    print(f"Warning: Authentication fixtures not available: {e}")


# =============================================================================
# External Service Mock Fixtures Imports
# =============================================================================

# Import all external service mock fixtures from external_service_mocks module
try:
    from .external_service_mocks import (
        # AWS service mocks
        mock_s3_client,
        mock_s3_bucket,
        mock_kms_client,
        mock_sts_client,
        mock_cloudwatch_client,
        
        # HTTP client mocks
        mock_requests_client,
        mock_httpx_client,
        mock_http_response,
        mock_async_http_response,
        
        # Circuit breaker mocks
        mock_circuit_breaker,
        circuit_breaker_config,
        circuit_breaker_manager,
        
        # Third-party API mocks
        mock_external_api_client,
        mock_webhook_handler,
        mock_file_processing_service,
        
        # Service health monitoring mocks
        mock_health_check_manager,
        mock_service_registry,
        
        # Performance monitoring mocks
        mock_performance_monitor,
        mock_metrics_collector,
        
        # Configuration and utility mocks
        external_service_config,
        mock_retry_handler,
        mock_timeout_handler
    )
    
    EXTERNAL_SERVICE_FIXTURES_AVAILABLE = True
    
except ImportError as e:
    EXTERNAL_SERVICE_FIXTURES_AVAILABLE = False
    print(f"Warning: External service fixtures not available: {e}")


# =============================================================================
# Factory Fixtures Imports
# =============================================================================

# Import all factory fixtures from factory_fixtures module
try:
    from .factory_fixtures import (
        # Base factory classes
        BaseTestModelFactory,
        BusinessModelFactory,
        DataModelFactory,
        
        # User and authentication factories
        UserFactory,
        UserProfileFactory,
        OrganizationFactory,
        UserSessionFactory,
        
        # Business model factories
        ProductFactory,
        OrderFactory,
        OrderItemFactory,
        PaymentTransactionFactory,
        
        # Geographic and contact factories
        AddressFactory as FactoryAddressFactory,  # Rename to avoid conflict
        ContactInfoFactory,
        
        # File and system factories
        FileUploadFactory,
        FileMetadataFactory,
        SystemConfigurationFactory,
        
        # API and pagination factories
        PaginationParamsFactory,
        ApiResponseFactory,
        PaginatedResponseFactory,
        
        # Performance testing factories
        PerformanceTestDataFactory,
        LoadTestDataFactory,
        
        # Edge case and validation factories
        EdgeCaseDataFactory,
        ValidationTestFactory,
        
        # Complex scenario factories
        IntegrationTestScenarioFactory,
        EndToEndTestDataFactory,
        
        # Factory utilities
        FactoryRegistry,
        TestDataManager,
        ValidationTestHelper
    )
    
    FACTORY_FIXTURES_AVAILABLE = True
    
except ImportError as e:
    FACTORY_FIXTURES_AVAILABLE = False
    print(f"Warning: Factory fixtures not available: {e}")


# =============================================================================
# Fixture Availability and Status Reporting
# =============================================================================

# Create fixture availability status for debugging and development
FIXTURE_AVAILABILITY_STATUS = {
    'database_fixtures': DATABASE_FIXTURES_AVAILABLE,
    'auth_fixtures': AUTH_FIXTURES_AVAILABLE,
    'external_service_fixtures': EXTERNAL_SERVICE_FIXTURES_AVAILABLE,
    'factory_fixtures': FACTORY_FIXTURES_AVAILABLE
}

# Count of available fixture modules
AVAILABLE_FIXTURE_MODULES = sum(FIXTURE_AVAILABILITY_STATUS.values())
TOTAL_FIXTURE_MODULES = len(FIXTURE_AVAILABILITY_STATUS)


def get_fixture_availability_report() -> Dict[str, Any]:
    """
    Generate comprehensive fixture availability report for debugging.
    
    Returns:
        Dictionary containing fixture availability status and statistics
    """
    return {
        'availability_status': FIXTURE_AVAILABILITY_STATUS,
        'available_modules': AVAILABLE_FIXTURE_MODULES,
        'total_modules': TOTAL_FIXTURE_MODULES,
        'availability_percentage': (AVAILABLE_FIXTURE_MODULES / TOTAL_FIXTURE_MODULES) * 100,
        'missing_modules': [
            module for module, available in FIXTURE_AVAILABILITY_STATUS.items()
            if not available
        ],
        'config': {
            'performance_variance_threshold': PERFORMANCE_VARIANCE_THRESHOLD,
            'test_database_name': TEST_DATABASE_NAME,
            'mongodb_image': MONGODB_TEST_IMAGE,
            'redis_image': REDIS_TEST_IMAGE,
            'coverage_threshold': COVERAGE_THRESHOLD
        }
    }


def validate_fixture_environment() -> bool:
    """
    Validate that the fixture environment is properly configured.
    
    Returns:
        True if all critical fixtures are available, False otherwise
    """
    critical_fixtures = ['database_fixtures', 'auth_fixtures']
    critical_available = all(
        FIXTURE_AVAILABILITY_STATUS.get(fixture, False)
        for fixture in critical_fixtures
    )
    
    if not critical_available:
        missing_critical = [
            fixture for fixture in critical_fixtures
            if not FIXTURE_AVAILABILITY_STATUS.get(fixture, False)
        ]
        print(f"Critical fixtures missing: {missing_critical}")
    
    return critical_available


# =============================================================================
# Pytest Integration and Configuration
# =============================================================================

# Pytest plugin configuration for comprehensive testing support
pytest_plugins = [
    'pytest_asyncio',  # Async testing support for Motor
    'pytest_mock',     # Enhanced mocking capabilities
    'pytest_flask',    # Flask application testing
    'pytest_xdist',    # Parallel test execution per Section 6.6.1
    'pytest_cov',      # Coverage reporting
]

# Configure pytest collection and execution settings
def pytest_configure(config):
    """Configure pytest for comprehensive testing per Section 6.6.1."""
    # Add custom markers for test organization
    config.addinivalue_line(
        "markers", "database: marks tests as requiring database fixtures"
    )
    config.addinivalue_line(
        "markers", "auth: marks tests as requiring authentication fixtures"
    )
    config.addinivalue_line(
        "markers", "external_service: marks tests as requiring external service mocks"
    )
    config.addinivalue_line(
        "markers", "factory: marks tests as requiring factory fixtures"
    )
    config.addinivalue_line(
        "markers", "performance: marks tests as performance validation tests"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "e2e: marks tests as end-to-end tests"
    )
    config.addinivalue_line(
        "markers", "security: marks tests as security validation tests"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection for enhanced organization per Section 6.6.1."""
    for item in items:
        # Auto-mark tests based on fixture usage
        if 'database' in item.fixturenames:
            item.add_marker(pytest.mark.database)
        if 'auth' in item.fixturenames or 'jwt' in item.fixturenames:
            item.add_marker(pytest.mark.auth)
        if 'mock' in item.fixturenames:
            item.add_marker(pytest.mark.external_service)
        if 'factory' in item.fixturenames:
            item.add_marker(pytest.mark.factory)
        
        # Mark performance tests based on function name patterns
        if 'performance' in item.name.lower() or 'benchmark' in item.name.lower():
            item.add_marker(pytest.mark.performance)
        
        # Mark integration tests based on path
        if 'integration' in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        
        # Mark end-to-end tests based on path
        if 'e2e' in str(item.fspath):
            item.add_marker(pytest.mark.e2e)


# =============================================================================
# Public API and Exports
# =============================================================================

# Export shared configuration for easy access
__all__ = [
    # Shared configuration
    'shared_test_config',
    'SharedTestConfig',
    'PERFORMANCE_VARIANCE_THRESHOLD',
    'TEST_DATABASE_NAME',
    'TEST_REDIS_DB',
    'MONGODB_TEST_IMAGE',
    'REDIS_TEST_IMAGE',
    'FLASK_TESTING_CONFIG',
    'SECURITY_TEST_CONFIG',
    
    # Fixture availability and utilities
    'get_fixture_availability_report',
    'validate_fixture_environment',
    'FIXTURE_AVAILABILITY_STATUS',
    
    # Database fixtures (if available)
    *([
        'DatabaseContainerConfig',
        'MongoDbTestContainer',
        'RedisTestContainer',
        'database_container_config',
        'mongodb_container',
        'redis_container',
        'pymongo_client',
        'motor_client',
        'redis_client',
        'database_manager',
        'database_seeder',
        'performance_validator',
        'seeded_database',
        'connection_pool_tester',
        'async_connection_pool_tester',
        'comprehensive_database_environment',
        'BaseTestObjectFactory',
        'UserDocumentFactory',
        'AddressFactory',
        'ProjectDocumentFactory',
        'SessionDocumentFactory',
        'DatabaseSeeder',
        'PerformanceValidator'
    ] if DATABASE_FIXTURES_AVAILABLE else []),
    
    # Authentication fixtures (if available)
    *([
        'MockAuth0User',
        'MockAnonymousUser',
        'JWTTokenFactory',
        'mock_auth0_client',
        'mock_auth0_management_client',
        'mock_auth0_user_info',
        'mock_auth0_jwks',
        'flask_login_manager',
        'authenticated_user',
        'anonymous_user',
        'user_session',
        'jwt_token_factory',
        'valid_jwt_token',
        'expired_jwt_token',
        'invalid_jwt_token',
        'jwt_public_key',
        'session_manager',
        'redis_session_store',
        'distributed_session',
        'security_context',
        'permission_validator',
        'role_manager',
        'auth_cache',
        'permission_cache',
        'user_cache'
    ] if AUTH_FIXTURES_AVAILABLE else []),
    
    # External service fixtures (if available)
    *([
        'mock_s3_client',
        'mock_s3_bucket',
        'mock_kms_client',
        'mock_sts_client',
        'mock_cloudwatch_client',
        'mock_requests_client',
        'mock_httpx_client',
        'mock_http_response',
        'mock_async_http_response',
        'mock_circuit_breaker',
        'circuit_breaker_config',
        'circuit_breaker_manager',
        'mock_external_api_client',
        'mock_webhook_handler',
        'mock_file_processing_service',
        'mock_health_check_manager',
        'mock_service_registry',
        'mock_performance_monitor',
        'mock_metrics_collector',
        'external_service_config',
        'mock_retry_handler',
        'mock_timeout_handler'
    ] if EXTERNAL_SERVICE_FIXTURES_AVAILABLE else []),
    
    # Factory fixtures (if available)
    *([
        'BaseTestModelFactory',
        'BusinessModelFactory',
        'DataModelFactory',
        'UserFactory',
        'UserProfileFactory',
        'OrganizationFactory',
        'UserSessionFactory',
        'ProductFactory',
        'OrderFactory',
        'OrderItemFactory',
        'PaymentTransactionFactory',
        'FactoryAddressFactory',
        'ContactInfoFactory',
        'FileUploadFactory',
        'FileMetadataFactory',
        'SystemConfigurationFactory',
        'PaginationParamsFactory',
        'ApiResponseFactory',
        'PaginatedResponseFactory',
        'PerformanceTestDataFactory',
        'LoadTestDataFactory',
        'EdgeCaseDataFactory',
        'ValidationTestFactory',
        'IntegrationTestScenarioFactory',
        'EndToEndTestDataFactory',
        'FactoryRegistry',
        'TestDataManager',
        'ValidationTestHelper'
    ] if FACTORY_FIXTURES_AVAILABLE else [])
]

# Print fixture availability report for development debugging
if __name__ == "__main__":
    import pprint
    print("Test Fixtures Package Initialization Report:")
    print("=" * 50)
    pprint.pprint(get_fixture_availability_report())
    print("\nFixture environment validation:", validate_fixture_environment())