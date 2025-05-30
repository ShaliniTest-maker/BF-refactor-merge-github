"""
Test-specific configuration management for Flask application testing.

This module provides isolated test settings, database connection strings for
Testcontainers, mock service endpoints, and environment-specific test parameters.
Ensures complete test isolation and production behavior simulation per Section 6.6.1.

Key Features:
- Test environment configuration isolation per Section 6.6.1
- Testcontainers integration configuration per Section 6.6.1  
- Mock service configuration for external dependencies per Section 6.6.1
- Production parity configuration for realistic testing per Section 6.6.1
- Test-specific JWT settings for authentication testing per Section 6.6.1
- Environment isolation parameters per Section 6.6.1 test data management
"""

import os
import tempfile
from datetime import timedelta
from typing import Dict, Any, Optional, List
from unittest.mock import Mock
import secrets
import pytest


class TestConfig:
    """
    Base test configuration class providing shared test settings.
    
    Implements test environment configuration isolation per Section 6.6.1
    test environment management with production parity validation.
    """
    
    # Flask Core Settings
    TESTING = True
    DEBUG = False
    SECRET_KEY = "test-secret-key-for-testing-only"
    WTF_CSRF_ENABLED = False
    
    # Environment Configuration
    ENV = "testing"
    FLASK_ENV = "testing"
    
    # Application Security Settings
    SESSION_COOKIE_SECURE = False  # Allow HTTP in test environment
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    
    # Rate Limiting - Disabled for Testing
    RATELIMIT_ENABLED = False
    RATELIMIT_STORAGE_URL = "memory://"
    
    # CORS Configuration - Permissive for Testing
    CORS_ORIGINS = ["*"]
    CORS_ALLOW_HEADERS = ["*"]
    CORS_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
    
    # Logging Configuration
    LOG_LEVEL = "INFO"
    LOG_FORMAT = "json"
    STRUCTURED_LOGGING = True
    
    # Test Data Management
    TEST_DATA_CLEANUP = True
    TEST_ISOLATION_ENABLED = True
    
    @classmethod
    def get_test_database_url(cls, container_port: int) -> str:
        """
        Generate MongoDB connection string for Testcontainers integration.
        
        Args:
            container_port: Port number from MongoDB Testcontainer
            
        Returns:
            MongoDB connection string for test container
        """
        return f"mongodb://localhost:{container_port}/test_database"
    
    @classmethod
    def get_test_redis_url(cls, container_port: int) -> str:
        """
        Generate Redis connection string for Testcontainers integration.
        
        Args:
            container_port: Port number from Redis Testcontainer
            
        Returns:
            Redis connection string for test container
        """
        return f"redis://localhost:{container_port}/0"


class TestContainersConfig(TestConfig):
    """
    Configuration for Testcontainers integration per Section 6.6.1.
    
    Provides dynamic service provisioning with realistic MongoDB and Redis
    instances for integration testing with production-equivalent behavior.
    """
    
    # Testcontainers Settings
    TESTCONTAINERS_ENABLED = True
    
    # MongoDB Testcontainer Configuration
    MONGODB_IMAGE = "mongo:7.0"
    MONGODB_PORT = 27017
    MONGODB_CONTAINER_NAME = "test-mongodb"
    MONGODB_WAIT_TIMEOUT = 60
    MONGODB_ENVIRONMENT = {
        "MONGO_INITDB_ROOT_USERNAME": "test_admin",
        "MONGO_INITDB_ROOT_PASSWORD": "test_password",
        "MONGO_INITDB_DATABASE": "test_database"
    }
    
    # Redis Testcontainer Configuration  
    REDIS_IMAGE = "redis:7.2-alpine"
    REDIS_PORT = 6379
    REDIS_CONTAINER_NAME = "test-redis"
    REDIS_WAIT_TIMEOUT = 30
    REDIS_COMMAND = ["redis-server", "--appendonly", "yes"]
    
    # Container Resource Limits
    CONTAINER_MEMORY_LIMIT = "512m"
    CONTAINER_CPU_LIMIT = "1"
    
    # Production Parity Settings
    MONGODB_CONNECTION_POOL_SIZE = 50
    MONGODB_WAIT_QUEUE_TIMEOUT = 30000
    MONGODB_SERVER_SELECTION_TIMEOUT = 10000
    
    REDIS_CONNECTION_POOL_SIZE = 50
    REDIS_SOCKET_TIMEOUT = 30.0
    REDIS_SOCKET_CONNECT_TIMEOUT = 10.0
    REDIS_RETRY_ON_TIMEOUT = True
    
    @classmethod
    def get_mongodb_config(cls, container_port: int) -> Dict[str, Any]:
        """
        Generate complete MongoDB configuration for testing.
        
        Args:
            container_port: Port from MongoDB Testcontainer
            
        Returns:
            Dictionary containing MongoDB connection configuration
        """
        return {
            "host": "localhost",
            "port": container_port,
            "database": "test_database",
            "username": "test_admin", 
            "password": "test_password",
            "authSource": "admin",
            "maxPoolSize": cls.MONGODB_CONNECTION_POOL_SIZE,
            "waitQueueTimeoutMS": cls.MONGODB_WAIT_QUEUE_TIMEOUT,
            "serverSelectionTimeoutMS": cls.MONGODB_SERVER_SELECTION_TIMEOUT,
            "connectTimeoutMS": 10000,
            "socketTimeoutMS": 30000,
            "retryWrites": True,
            "retryReads": True
        }
    
    @classmethod  
    def get_redis_config(cls, container_port: int) -> Dict[str, Any]:
        """
        Generate complete Redis configuration for testing.
        
        Args:
            container_port: Port from Redis Testcontainer
            
        Returns:
            Dictionary containing Redis connection configuration
        """
        return {
            "host": "localhost",
            "port": container_port,
            "db": 0,
            "max_connections": cls.REDIS_CONNECTION_POOL_SIZE,
            "socket_timeout": cls.REDIS_SOCKET_TIMEOUT,
            "socket_connect_timeout": cls.REDIS_SOCKET_CONNECT_TIMEOUT,
            "retry_on_timeout": cls.REDIS_RETRY_ON_TIMEOUT,
            "decode_responses": True,
            "encoding": "utf-8"
        }


class MockServiceConfig(TestConfig):
    """
    Mock service configuration for external dependencies per Section 6.6.1.
    
    Provides comprehensive mocking of Auth0 authentication endpoints, AWS services,
    and third-party APIs using pytest-mock for test isolation and reliability.
    """
    
    # Mock Service Endpoints
    MOCK_SERVICES_ENABLED = True
    
    # Auth0 Mock Configuration
    AUTH0_DOMAIN = "test-domain.auth0.com"
    AUTH0_CLIENT_ID = "test_client_id_12345"
    AUTH0_CLIENT_SECRET = "test_client_secret_67890" 
    AUTH0_AUDIENCE = "test-api-audience"
    AUTH0_ALGORITHMS = ["HS256", "RS256"]
    
    # Mock Auth0 Endpoints
    AUTH0_MOCK_ENDPOINTS = {
        "token": "https://test-domain.auth0.com/oauth/token",
        "userinfo": "https://test-domain.auth0.com/userinfo",
        "jwks": "https://test-domain.auth0.com/.well-known/jwks.json",
        "logout": "https://test-domain.auth0.com/v2/logout"
    }
    
    # AWS Mock Configuration
    AWS_REGION = "us-east-1"
    AWS_ACCESS_KEY_ID = "test_access_key"
    AWS_SECRET_ACCESS_KEY = "test_secret_key"
    AWS_SESSION_TOKEN = "test_session_token"
    
    # S3 Mock Settings
    S3_BUCKET_NAME = "test-bucket"
    S3_MOCK_ENDPOINT = "http://localhost:9000"  # Minio mock endpoint
    S3_USE_SSL = False
    
    # Third-party API Mock Endpoints
    EXTERNAL_API_MOCKS = {
        "payment_service": "http://localhost:8001/mock/payment",
        "notification_service": "http://localhost:8002/mock/notification", 
        "analytics_service": "http://localhost:8003/mock/analytics"
    }
    
    # Circuit Breaker Mock Settings
    CIRCUIT_BREAKER_FAIL_MAX = 3
    CIRCUIT_BREAKER_RESET_TIMEOUT = 30
    CIRCUIT_BREAKER_ENABLED = False  # Disabled for testing
    
    @classmethod
    def get_mock_auth0_token(cls) -> str:
        """
        Generate mock Auth0 JWT token for testing.
        
        Returns:
            Mock JWT token string for authentication testing
        """
        return "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ0ZXN0LWRvbWFpbi5hdXRoMC5jb20iLCJzdWIiOiJ0ZXN0X3VzZXJfaWQiLCJhdWQiOiJ0ZXN0LWFwaS1hdWRpZW5jZSIsImV4cCI6OTk5OTk5OTk5OSwiaWF0IjoxNjAwMDAwMDAwfQ.test_signature"
    
    @classmethod
    def get_mock_user_payload(cls) -> Dict[str, Any]:
        """
        Generate mock user payload for authentication testing.
        
        Returns:
            Dictionary containing mock user data
        """
        return {
            "sub": "test_user_id_12345",
            "email": "test.user@example.com",
            "email_verified": True,
            "name": "Test User",
            "nickname": "testuser",
            "picture": "https://example.com/avatar.jpg",
            "updated_at": "2023-01-01T00:00:00.000Z",
            "roles": ["user", "admin"],
            "permissions": ["read:profile", "write:profile"]
        }


class JWTTestConfig(TestConfig):
    """
    Test-specific JWT settings for authentication testing per Section 6.6.1.
    
    Provides JWT token generation and validation configuration for business
    logic testing without external dependencies.
    """
    
    # JWT Configuration
    JWT_SECRET_KEY = "test-jwt-secret-key-for-testing-only"
    JWT_ALGORITHM = "HS256"
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=7)
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ["access", "refresh"]
    
    # Token Validation Settings
    JWT_VERIFY_SIGNATURE = True
    JWT_VERIFY_EXPIRATION = True
    JWT_VERIFY_AUDIENCE = False  # Disabled for test flexibility
    JWT_VERIFY_ISSUER = False    # Disabled for test flexibility
    JWT_REQUIRE_CLAIMS = ["sub", "iat", "exp"]
    
    # Test Token Settings
    JWT_TEST_ISSUER = "test-flask-app"
    JWT_TEST_AUDIENCE = "test-api"
    JWT_TEST_SUBJECT = "test_user_12345"
    
    @classmethod
    def generate_test_token(cls, payload: Optional[Dict[str, Any]] = None) -> str:
        """
        Generate test JWT token with custom payload.
        
        Args:
            payload: Optional custom claims to include in token
            
        Returns:
            JWT token string for testing
        """
        import jwt
        from datetime import datetime, timezone
        
        default_payload = {
            "sub": cls.JWT_TEST_SUBJECT,
            "iss": cls.JWT_TEST_ISSUER,
            "aud": cls.JWT_TEST_AUDIENCE,
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + cls.JWT_ACCESS_TOKEN_EXPIRES,
            "email": "test.user@example.com",
            "roles": ["user"]
        }
        
        if payload:
            default_payload.update(payload)
            
        return jwt.encode(default_payload, cls.JWT_SECRET_KEY, algorithm=cls.JWT_ALGORITHM)
    
    @classmethod
    def generate_expired_token(cls) -> str:
        """
        Generate expired JWT token for testing token validation.
        
        Returns:
            Expired JWT token string
        """
        import jwt
        from datetime import datetime, timezone, timedelta
        
        payload = {
            "sub": cls.JWT_TEST_SUBJECT,
            "iss": cls.JWT_TEST_ISSUER,
            "aud": cls.JWT_TEST_AUDIENCE,
            "iat": datetime.now(timezone.utc) - timedelta(hours=2),
            "exp": datetime.now(timezone.utc) - timedelta(hours=1),
            "email": "test.user@example.com"
        }
        
        return jwt.encode(payload, cls.JWT_SECRET_KEY, algorithm=cls.JWT_ALGORITHM)


class EnvironmentIsolationConfig(TestConfig):
    """
    Environment isolation parameters per Section 6.6.1 test data management.
    
    Ensures complete test isolation with separate test databases, automated
    cleanup, and data isolation between test runs.
    """
    
    # Test Isolation Settings
    ISOLATION_LEVEL = "complete"
    AUTO_CLEANUP_ENABLED = True
    PARALLEL_TEST_SUPPORT = True
    
    # Database Isolation
    USE_TEMPORARY_DATABASE = True
    DATABASE_ISOLATION_STRATEGY = "per_test_class"
    CLEANUP_DATABASE_ON_TEARDOWN = True
    
    # Session Isolation
    USE_TEMPORARY_SESSIONS = True
    SESSION_ISOLATION_STRATEGY = "per_test"
    CLEANUP_SESSIONS_ON_TEARDOWN = True
    
    # File System Isolation
    USE_TEMPORARY_DIRECTORIES = True
    TEMP_DIR_PREFIX = "flask_test_"
    CLEANUP_TEMP_FILES = True
    
    # Cache Isolation
    USE_SEPARATE_CACHE_NAMESPACE = True
    CACHE_NAMESPACE_PREFIX = "test_"
    FLUSH_CACHE_ON_SETUP = True
    
    # External Service Isolation
    MOCK_ALL_EXTERNAL_SERVICES = True
    NETWORK_ISOLATION_ENABLED = True
    PREVENT_EXTERNAL_CALLS = True
    
    @classmethod
    def get_test_database_name(cls, test_name: str) -> str:
        """
        Generate unique test database name for isolation.
        
        Args:
            test_name: Name of the test function or class
            
        Returns:
            Unique database name for test isolation
        """
        safe_name = test_name.replace(".", "_").replace("::", "_")
        return f"test_db_{safe_name}_{secrets.token_hex(8)}"
    
    @classmethod
    def get_test_cache_namespace(cls, test_name: str) -> str:
        """
        Generate unique cache namespace for test isolation.
        
        Args:
            test_name: Name of the test function or class
            
        Returns:
            Unique cache namespace for test isolation
        """
        safe_name = test_name.replace(".", "_").replace("::", "_")
        return f"{cls.CACHE_NAMESPACE_PREFIX}{safe_name}_{secrets.token_hex(4)}"
    
    @classmethod
    def create_temp_directory(cls) -> str:
        """
        Create temporary directory for test file isolation.
        
        Returns:
            Path to temporary directory
        """
        return tempfile.mkdtemp(prefix=cls.TEMP_DIR_PREFIX)


class PerformanceTestConfig(TestConfig):
    """
    Performance testing configuration for ≤10% variance validation.
    
    Provides performance baseline comparison settings and monitoring
    configuration to ensure Node.js migration compliance.
    """
    
    # Performance Testing Settings
    PERFORMANCE_TESTING_ENABLED = True
    BASELINE_COMPARISON_ENABLED = True
    PERFORMANCE_VARIANCE_THRESHOLD = 0.10  # 10% variance limit
    
    # Benchmark Settings
    BENCHMARK_ITERATIONS = 100
    BENCHMARK_WARMUP_ITERATIONS = 10
    BENCHMARK_TIMEOUT_SECONDS = 300
    
    # Load Testing Configuration
    LOAD_TEST_USERS = 50
    LOAD_TEST_DURATION = 60  # seconds
    LOAD_TEST_RAMP_UP_TIME = 10  # seconds
    
    # Performance Metrics Collection
    COLLECT_RESPONSE_TIMES = True
    COLLECT_MEMORY_USAGE = True
    COLLECT_CPU_UTILIZATION = True
    COLLECT_DATABASE_METRICS = True
    
    # Baseline Data
    NODEJS_BASELINE_RESPONSE_TIME = 100  # milliseconds
    NODEJS_BASELINE_MEMORY_USAGE = 256  # MB
    NODEJS_BASELINE_CPU_USAGE = 15     # percentage
    
    @classmethod
    def calculate_variance(cls, current_value: float, baseline_value: float) -> float:
        """
        Calculate performance variance percentage.
        
        Args:
            current_value: Current measured value
            baseline_value: Baseline Node.js value
            
        Returns:
            Variance percentage (positive for increase, negative for decrease)
        """
        if baseline_value == 0:
            return 0.0
        return ((current_value - baseline_value) / baseline_value) * 100
    
    @classmethod
    def is_within_variance_threshold(cls, current_value: float, baseline_value: float) -> bool:
        """
        Check if performance metric is within acceptable variance.
        
        Args:
            current_value: Current measured value
            baseline_value: Baseline Node.js value
            
        Returns:
            True if within threshold, False otherwise
        """
        variance = abs(cls.calculate_variance(current_value, baseline_value))
        return variance <= (cls.PERFORMANCE_VARIANCE_THRESHOLD * 100)


# Configuration Factory Function
def get_test_config(config_type: str = "default") -> TestConfig:
    """
    Factory function to retrieve appropriate test configuration.
    
    Args:
        config_type: Type of test configuration to return
                    Options: 'default', 'testcontainers', 'mock_services', 
                            'jwt', 'isolation', 'performance'
    
    Returns:
        Test configuration class instance
        
    Raises:
        ValueError: If config_type is not recognized
    """
    config_mapping = {
        "default": TestConfig,
        "testcontainers": TestContainersConfig,
        "mock_services": MockServiceConfig,
        "jwt": JWTTestConfig,
        "isolation": EnvironmentIsolationConfig,
        "performance": PerformanceTestConfig
    }
    
    if config_type not in config_mapping:
        raise ValueError(f"Unknown config type: {config_type}. "
                        f"Available types: {list(config_mapping.keys())}")
    
    return config_mapping[config_type]()


# Pytest Configuration Helpers
@pytest.fixture(scope="session")
def test_config():
    """Pytest fixture providing default test configuration."""
    return get_test_config("default")


@pytest.fixture(scope="session")
def testcontainers_config():
    """Pytest fixture providing Testcontainers configuration."""
    return get_test_config("testcontainers")


@pytest.fixture(scope="session") 
def mock_services_config():
    """Pytest fixture providing mock services configuration."""
    return get_test_config("mock_services")


@pytest.fixture(scope="function")
def jwt_config():
    """Pytest fixture providing JWT testing configuration."""
    return get_test_config("jwt")


@pytest.fixture(scope="function")
def isolation_config():
    """Pytest fixture providing environment isolation configuration."""
    return get_test_config("isolation")


@pytest.fixture(scope="session")
def performance_config():
    """Pytest fixture providing performance testing configuration."""
    return get_test_config("performance")


# Environment Variable Overrides for Testing
TEST_ENV_OVERRIDES = {
    "FLASK_ENV": "testing",
    "TESTING": "true",
    "DATABASE_URL": "mongodb://localhost:27017/test_database",
    "REDIS_URL": "redis://localhost:6379/0",
    "JWT_SECRET_KEY": "test-jwt-secret",
    "AUTH0_DOMAIN": "test-domain.auth0.com",
    "AUTH0_CLIENT_ID": "test_client_id",
    "AUTH0_CLIENT_SECRET": "test_client_secret",
    "AWS_ACCESS_KEY_ID": "test_access_key",
    "AWS_SECRET_ACCESS_KEY": "test_secret_key",
    "S3_BUCKET_NAME": "test-bucket",
    "LOG_LEVEL": "INFO",
    "RATELIMIT_ENABLED": "false",
    "CIRCUIT_BREAKER_ENABLED": "false",
    "PERFORMANCE_TESTING": "true"
}


def apply_test_env_overrides():
    """
    Apply test environment variable overrides.
    
    Should be called at the beginning of test sessions to ensure
    proper test environment configuration.
    """
    for key, value in TEST_ENV_OVERRIDES.items():
        os.environ[key] = value


def cleanup_test_env_overrides():
    """
    Remove test environment variable overrides.
    
    Should be called at the end of test sessions to clean up
    environment state.
    """
    for key in TEST_ENV_OVERRIDES:
        os.environ.pop(key, None)


# Export main configuration classes
__all__ = [
    "TestConfig",
    "TestContainersConfig", 
    "MockServiceConfig",
    "JWTTestConfig",
    "EnvironmentIsolationConfig",
    "PerformanceTestConfig",
    "get_test_config",
    "apply_test_env_overrides",
    "cleanup_test_env_overrides",
    "TEST_ENV_OVERRIDES"
]