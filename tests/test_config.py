"""
Test Configuration Management Module

This module provides comprehensive test-specific configuration classes for Flask application testing
with Testcontainers integration, external service mocking, and production parity validation.
Implements isolated test environments as specified in Section 6.6.1 of the technical specification.

Key Features:
- Test-specific Flask configuration classes for complete environment isolation
- Testcontainers integration for MongoDB and Redis with production-equivalent behavior
- Mock service endpoint configuration for external dependency testing
- JWT authentication testing configuration with secure token generation
- Performance testing configuration ensuring ≤10% variance requirement compliance
- Production parity configuration for realistic testing behavior simulation

Architecture Integration:
- Section 6.6.1: Test environment management with pytest framework and Testcontainers
- Section 6.6.1: Container integration providing production-equivalent testing behavior
- Section 6.6.1: External service mocking for Auth0, AWS, and third-party API integration
- Section 6.6.1: Test data management with automated seeding and cleanup

Author: Flask Migration Team
Version: 1.0.0
Dependencies: pytest 7.4+, testcontainers 4.10+, PyJWT 2.8+, redis-py 5.0+, PyMongo 4.5+
"""

import os
import secrets
import tempfile
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Type, Union
from pathlib import Path

# Test framework imports
import pytest
from unittest.mock import Mock, MagicMock

# JWT and security imports for test authentication
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Testcontainers imports for production-equivalent testing
from testcontainers.mongodb import MongoDbContainer
from testcontainers.redis import RedisContainer

# Import base configuration classes for inheritance
from src.config.settings import BaseConfig, TestingConfig, ConfigFactory


class TestBaseConfig(BaseConfig):
    """
    Base test configuration class providing fundamental test settings.
    
    Extends BaseConfig with test-specific overrides for security, session management,
    and external service integration while maintaining production behavior patterns.
    """
    
    # Test Environment Identification
    TESTING = True
    FLASK_ENV = 'testing'
    DEBUG = False
    
    # Test Security Configuration (relaxed for testing)
    WTF_CSRF_ENABLED = False
    TALISMAN_ENABLED = False
    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_SECURE = False
    
    # Test Rate Limiting (disabled for fast test execution)
    RATELIMIT_ENABLED = False
    
    # Test Performance Monitoring
    PERFORMANCE_MONITORING_ENABLED = True
    PERFORMANCE_VARIANCE_THRESHOLD = 15.0  # Relaxed for testing environment
    NODEJS_BASELINE_MONITORING = False
    
    # Test Logging Configuration
    LOG_LEVEL = 'WARNING'
    STRUCTURED_LOGGING_ENABLED = False
    
    # Test File Upload Configuration
    UPLOAD_FOLDER = tempfile.mkdtemp(prefix='test_uploads_')
    MAX_FILE_SIZE = 1 * 1024 * 1024  # 1MB for faster testing
    
    # Test Cache Configuration
    CACHE_TYPE = 'null'  # Disable caching by default for testing
    CACHE_DEFAULT_TIMEOUT = 30  # Short timeout for testing
    
    # Test Session Configuration
    SESSION_TYPE = 'null'  # Disable persistent sessions by default
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=5)
    
    # Test Feature Flags
    FEATURE_FLAGS_ENABLED = True
    MIGRATION_ENABLED = True
    HEALTH_CHECK_ENABLED = False  # Disabled for unit tests
    
    @classmethod
    def get_environment_name(cls) -> str:
        """Get test environment name."""
        return 'testing'


class TestContainersConfig(TestBaseConfig):
    """
    Testcontainers integration configuration providing production-equivalent database behavior.
    
    Implements dynamic MongoDB and Redis container provisioning as specified in Section 6.6.1
    for realistic database integration testing with automated container lifecycle management.
    """
    
    # Container Configuration
    TESTCONTAINERS_ENABLED = True
    TESTCONTAINERS_MONGODB_VERSION = os.getenv('TEST_MONGODB_VERSION', 'mongo:7.0')
    TESTCONTAINERS_REDIS_VERSION = os.getenv('TEST_REDIS_VERSION', 'redis:7.0')
    
    # Dynamic Container Configuration (populated by fixtures)
    MONGODB_CONTAINER_URI = None
    REDIS_CONTAINER_URI = None
    
    # Container Lifecycle Management
    CONTAINER_STARTUP_TIMEOUT = int(os.getenv('CONTAINER_STARTUP_TIMEOUT', '60'))
    CONTAINER_SHUTDOWN_TIMEOUT = int(os.getenv('CONTAINER_SHUTDOWN_TIMEOUT', '30'))
    CONTAINER_HEALTH_CHECK_INTERVAL = int(os.getenv('CONTAINER_HEALTH_CHECK_INTERVAL', '5'))
    
    # Production Parity Database Configuration
    MONGODB_CONNECTION_POOL_SIZE = 10
    MONGODB_MAX_IDLE_TIME_MS = 30000
    MONGODB_SERVER_SELECTION_TIMEOUT_MS = 5000
    MONGODB_SOCKET_TIMEOUT_MS = 10000
    MONGODB_CONNECT_TIMEOUT_MS = 5000
    
    # Production Parity Redis Configuration
    REDIS_CONNECTION_POOL_MAX_CONNECTIONS = 20
    REDIS_CONNECTION_POOL_RETRY_ON_TIMEOUT = True
    REDIS_SOCKET_TIMEOUT = 10
    REDIS_SOCKET_CONNECT_TIMEOUT = 10
    REDIS_SOCKET_KEEPALIVE = True
    REDIS_SOCKET_KEEPALIVE_OPTIONS = {
        'TCP_KEEPIDLE': 1,
        'TCP_KEEPINTVL': 3,
        'TCP_KEEPCNT': 5
    }
    
    # Database Test Isolation Configuration
    TEST_DATABASE_PREFIX = 'test_'
    TEST_COLLECTION_PREFIX = 'test_'
    TEST_REDIS_DB_OFFSET = 10  # Use Redis DB 10+ for testing
    
    # Container Resource Limits
    CONTAINER_MEMORY_LIMIT = '512m'
    CONTAINER_CPU_LIMIT = '0.5'
    CONTAINER_TMPFS_SIZE = '100m'
    
    @classmethod
    def create_mongodb_container(cls) -> MongoDbContainer:
        """
        Create and configure MongoDB Testcontainer instance.
        
        Returns:
            MongoDbContainer: Configured MongoDB container for testing
        """
        container = MongoDbContainer(cls.TESTCONTAINERS_MONGODB_VERSION)
        
        # Configure container resource limits
        container.with_mem_limit(cls.CONTAINER_MEMORY_LIMIT)
        container.with_tmpfs({'/tmp': f'size={cls.CONTAINER_TMPFS_SIZE}'})
        
        # Configure MongoDB-specific settings
        container.with_env('MONGO_INITDB_ROOT_USERNAME', 'test_admin')
        container.with_env('MONGO_INITDB_ROOT_PASSWORD', 'test_password')
        
        return container
    
    @classmethod
    def create_redis_container(cls) -> RedisContainer:
        """
        Create and configure Redis Testcontainer instance.
        
        Returns:
            RedisContainer: Configured Redis container for testing
        """
        container = RedisContainer(cls.TESTCONTAINERS_REDIS_VERSION)
        
        # Configure container resource limits
        container.with_mem_limit(cls.CONTAINER_MEMORY_LIMIT)
        container.with_tmpfs({'/tmp': f'size={cls.CONTAINER_TMPFS_SIZE}'})
        
        # Configure Redis-specific settings
        container.with_env('REDIS_PASSWORD', 'test_redis_password')
        
        return container
    
    @classmethod
    def get_test_database_name(cls, base_name: str = 'test_db') -> str:
        """
        Generate unique test database name with worker isolation.
        
        Args:
            base_name: Base database name
            
        Returns:
            str: Unique test database name
        """
        worker_id = os.getenv('PYTEST_WORKER_ID', 'master')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return f"{cls.TEST_DATABASE_PREFIX}{base_name}_{worker_id}_{timestamp}"
    
    @classmethod
    def get_test_redis_db(cls, base_db: int = 0) -> int:
        """
        Calculate test Redis database number with worker isolation.
        
        Args:
            base_db: Base Redis database number
            
        Returns:
            int: Isolated test Redis database number
        """
        worker_id = os.getenv('PYTEST_WORKER_ID', 'master')
        worker_offset = hash(worker_id) % 5  # Support up to 5 workers
        return cls.TEST_REDIS_DB_OFFSET + base_db + worker_offset


class MockServiceConfig(TestBaseConfig):
    """
    Mock service configuration for external dependency testing isolation.
    
    Provides comprehensive mock service endpoints for Auth0, AWS services, and third-party
    APIs as specified in Section 6.6.1 external service mocking requirements.
    """
    
    # Mock Service Enablement
    MOCK_EXTERNAL_SERVICES = True
    MOCK_AUTH0_ENABLED = True
    MOCK_AWS_ENABLED = True
    MOCK_HTTP_CLIENTS = True
    
    # Mock Auth0 Configuration
    MOCK_AUTH0_DOMAIN = 'test-tenant.auth0.com'
    MOCK_AUTH0_CLIENT_ID = 'test_client_id_12345'
    MOCK_AUTH0_CLIENT_SECRET = 'test_client_secret_67890'
    MOCK_AUTH0_AUDIENCE = 'test-api-audience'
    MOCK_AUTH0_SCOPE = 'openid profile email read:users'
    
    # Mock AWS Configuration
    MOCK_AWS_ACCESS_KEY_ID = 'AKIATEST12345EXAMPLE'
    MOCK_AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    MOCK_AWS_DEFAULT_REGION = 'us-east-1'
    MOCK_AWS_S3_BUCKET = 'test-application-bucket'
    MOCK_AWS_S3_ENDPOINT = 'https://mock-s3.example.com'
    
    # Mock HTTP Service Endpoints
    MOCK_HTTP_ENDPOINTS = {
        'auth0_token': f'https://{MOCK_AUTH0_DOMAIN}/oauth/token',
        'auth0_userinfo': f'https://{MOCK_AUTH0_DOMAIN}/userinfo',
        'auth0_jwks': f'https://{MOCK_AUTH0_DOMAIN}/.well-known/jwks.json',
        'aws_s3_api': MOCK_AWS_S3_ENDPOINT,
        'external_api_v1': 'https://mock-external-api.example.com/v1',
        'webhook_endpoint': 'https://mock-webhook.example.com/webhooks'
    }
    
    # Mock Service Response Templates
    MOCK_AUTH0_USER_PROFILE = {
        'user_id': 'auth0|test_user_123',
        'email': 'test@example.com',
        'name': 'Test User',
        'picture': 'https://example.com/avatar.jpg',
        'email_verified': True,
        'created_at': '2023-01-01T00:00:00.000Z',
        'updated_at': '2023-01-01T00:00:00.000Z'
    }
    
    MOCK_AUTH0_TOKEN_RESPONSE = {
        'access_token': 'mock_access_token_12345',
        'refresh_token': 'mock_refresh_token_67890',
        'id_token': 'mock_id_token_abcdef',
        'token_type': 'Bearer',
        'expires_in': 3600,
        'scope': MOCK_AUTH0_SCOPE
    }
    
    MOCK_AWS_S3_RESPONSES = {
        'upload_success': {
            'ETag': '"mock-etag-12345"',
            'VersionId': 'mock-version-id',
            'Location': f'{MOCK_AWS_S3_ENDPOINT}/test-application-bucket/test-file.txt'
        },
        'download_success': {
            'Body': b'mock file content',
            'ContentLength': 17,
            'ContentType': 'text/plain',
            'ETag': '"mock-etag-12345"'
        }
    }
    
    # Circuit Breaker Configuration for Mock Services
    MOCK_CIRCUIT_BREAKER_ENABLED = True
    MOCK_CIRCUIT_BREAKER_FAILURE_THRESHOLD = 5
    MOCK_CIRCUIT_BREAKER_RECOVERY_TIMEOUT = 30
    MOCK_CIRCUIT_BREAKER_EXPECTED_EXCEPTION = Exception
    
    @classmethod
    def get_mock_auth0_endpoints(cls) -> Dict[str, str]:
        """
        Get Auth0 mock service endpoints.
        
        Returns:
            Dict[str, str]: Auth0 mock endpoint configuration
        """
        return {
            'domain': cls.MOCK_AUTH0_DOMAIN,
            'token_endpoint': cls.MOCK_HTTP_ENDPOINTS['auth0_token'],
            'userinfo_endpoint': cls.MOCK_HTTP_ENDPOINTS['auth0_userinfo'],
            'jwks_endpoint': cls.MOCK_HTTP_ENDPOINTS['auth0_jwks'],
            'client_id': cls.MOCK_AUTH0_CLIENT_ID,
            'audience': cls.MOCK_AUTH0_AUDIENCE
        }
    
    @classmethod
    def get_mock_aws_config(cls) -> Dict[str, str]:
        """
        Get AWS mock service configuration.
        
        Returns:
            Dict[str, str]: AWS mock service configuration
        """
        return {
            'aws_access_key_id': cls.MOCK_AWS_ACCESS_KEY_ID,
            'aws_secret_access_key': cls.MOCK_AWS_SECRET_ACCESS_KEY,
            'region_name': cls.MOCK_AWS_DEFAULT_REGION,
            'endpoint_url': cls.MOCK_AWS_S3_ENDPOINT,
            'bucket_name': cls.MOCK_AWS_S3_BUCKET
        }


class JWTTestConfig(TestBaseConfig):
    """
    JWT authentication testing configuration with secure token generation.
    
    Provides comprehensive JWT testing capabilities including token generation, validation,
    and Auth0 integration testing as specified in Section 6.6.1 authentication testing requirements.
    """
    
    # JWT Test Configuration
    JWT_TEST_ENABLED = True
    JWT_ALGORITHM = 'HS256'
    JWT_TEST_SECRET_KEY = 'test-jwt-secret-key-for-testing-only'
    JWT_TEST_AUDIENCE = 'test-api-audience'
    JWT_TEST_ISSUER = 'https://test-tenant.auth0.com/'
    JWT_EXPIRATION_DELTA = timedelta(hours=1)
    JWT_REFRESH_EXPIRATION_DELTA = timedelta(days=7)
    
    # RSA Key Pair for Advanced JWT Testing
    JWT_RSA_PRIVATE_KEY = None
    JWT_RSA_PUBLIC_KEY = None
    JWT_RSA_ALGORITHM = 'RS256'
    
    # JWT Claims Templates
    JWT_TEST_CLAIMS_STANDARD = {
        'sub': 'test_user_123',
        'email': 'test@example.com',
        'iss': JWT_TEST_ISSUER,
        'aud': JWT_TEST_AUDIENCE,
        'scope': 'openid profile email'
    }
    
    JWT_TEST_CLAIMS_ADMIN = {
        'sub': 'admin_user_456',
        'email': 'admin@example.com',
        'iss': JWT_TEST_ISSUER,
        'aud': JWT_TEST_AUDIENCE,
        'scope': 'openid profile email admin:read admin:write',
        'permissions': ['read:users', 'write:users', 'delete:users']
    }
    
    JWT_TEST_CLAIMS_LIMITED = {
        'sub': 'limited_user_789',
        'email': 'limited@example.com',
        'iss': JWT_TEST_ISSUER,
        'aud': JWT_TEST_AUDIENCE,
        'scope': 'openid profile'
    }
    
    @classmethod
    def generate_rsa_keypair(cls) -> tuple:
        """
        Generate RSA key pair for advanced JWT testing.
        
        Returns:
            tuple: (private_key, public_key) as PEM-encoded strings
        """
        if cls.JWT_RSA_PRIVATE_KEY and cls.JWT_RSA_PUBLIC_KEY:
            return cls.JWT_RSA_PRIVATE_KEY, cls.JWT_RSA_PUBLIC_KEY
        
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Get public key
        public_key = private_key.public_key()
        
        # Serialize to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        # Cache the keys
        cls.JWT_RSA_PRIVATE_KEY = private_pem
        cls.JWT_RSA_PUBLIC_KEY = public_pem
        
        return private_pem, public_pem
    
    @classmethod
    def create_test_token(cls, claims: Optional[Dict[str, Any]] = None, 
                         algorithm: str = None, secret: str = None,
                         expires_delta: timedelta = None) -> str:
        """
        Create JWT test token with specified claims.
        
        Args:
            claims: Custom JWT claims (defaults to standard test claims)
            algorithm: JWT algorithm (defaults to HS256)
            secret: JWT secret key (defaults to test secret)
            expires_delta: Token expiration time (defaults to 1 hour)
            
        Returns:
            str: Encoded JWT token for testing
        """
        # Use default values if not provided
        claims = claims or cls.JWT_TEST_CLAIMS_STANDARD.copy()
        algorithm = algorithm or cls.JWT_ALGORITHM
        secret = secret or cls.JWT_TEST_SECRET_KEY
        expires_delta = expires_delta or cls.JWT_EXPIRATION_DELTA
        
        # Add timestamp claims
        now = datetime.utcnow()
        claims.update({
            'iat': now,
            'exp': now + expires_delta,
            'nbf': now
        })
        
        # Handle RSA algorithm
        if algorithm.startswith('RS'):
            private_key, _ = cls.generate_rsa_keypair()
            secret = private_key
        
        return jwt.encode(claims, secret, algorithm=algorithm)
    
    @classmethod
    def create_expired_token(cls, claims: Optional[Dict[str, Any]] = None) -> str:
        """
        Create expired JWT token for testing token validation.
        
        Args:
            claims: Custom JWT claims
            
        Returns:
            str: Expired JWT token for testing
        """
        claims = claims or cls.JWT_TEST_CLAIMS_STANDARD.copy()
        
        # Set expiration in the past
        now = datetime.utcnow()
        claims.update({
            'iat': now - timedelta(hours=2),
            'exp': now - timedelta(hours=1),
            'nbf': now - timedelta(hours=2)
        })
        
        return jwt.encode(claims, cls.JWT_TEST_SECRET_KEY, algorithm=cls.JWT_ALGORITHM)
    
    @classmethod
    def create_invalid_signature_token(cls, claims: Optional[Dict[str, Any]] = None) -> str:
        """
        Create JWT token with invalid signature for testing.
        
        Args:
            claims: Custom JWT claims
            
        Returns:
            str: JWT token with invalid signature
        """
        claims = claims or cls.JWT_TEST_CLAIMS_STANDARD.copy()
        
        # Add timestamp claims
        now = datetime.utcnow()
        claims.update({
            'iat': now,
            'exp': now + cls.JWT_EXPIRATION_DELTA,
            'nbf': now
        })
        
        # Use wrong secret key
        wrong_secret = 'wrong-secret-key-for-invalid-signature'
        return jwt.encode(claims, wrong_secret, algorithm=cls.JWT_ALGORITHM)


class PerformanceTestConfig(TestBaseConfig):
    """
    Performance testing configuration ensuring ≤10% variance requirement compliance.
    
    Implements performance baseline comparison and monitoring capabilities as specified
    in Section 6.6.1 performance testing requirements with Node.js baseline validation.
    """
    
    # Performance Testing Configuration
    PERFORMANCE_TESTING_ENABLED = True
    PERFORMANCE_BASELINE_ENABLED = True
    PERFORMANCE_VARIANCE_THRESHOLD = 10.0  # ≤10% variance requirement
    PERFORMANCE_COMPARISON_ENABLED = True
    
    # Node.js Baseline Metrics (from original implementation)
    NODEJS_BASELINE_METRICS = {
        'response_times': {
            'api_get_users': 150,  # milliseconds
            'api_create_user': 200,
            'api_update_user': 180,
            'api_delete_user': 120,
            'api_list_users': 100,
            'health_check': 50,
            'auth_login': 180,
            'auth_logout': 80,
            'file_upload': 300,
            'database_query': 75
        },
        'memory_usage': {
            'baseline_mb': 256,
            'peak_mb': 512,
            'average_mb': 320,
            'startup_mb': 180
        },
        'throughput': {
            'requests_per_second': 1000,
            'concurrent_users': 100,
            'database_ops_per_second': 500
        },
        'database_performance': {
            'user_lookup': 45,  # milliseconds
            'user_create': 85,
            'user_update': 70,
            'user_delete': 40,
            'bulk_operations': 200,
            'index_queries': 25
        },
        'cache_performance': {
            'get_hit': 5,  # milliseconds
            'get_miss': 15,
            'set': 10,
            'delete': 8,
            'bulk_get': 20,
            'pipeline_operations': 30
        }
    }
    
    # Performance Test Configuration
    PERFORMANCE_TEST_DURATION = int(os.getenv('PERFORMANCE_TEST_DURATION', '60'))  # seconds
    PERFORMANCE_TEST_USERS = int(os.getenv('PERFORMANCE_TEST_USERS', '50'))
    PERFORMANCE_TEST_SPAWN_RATE = int(os.getenv('PERFORMANCE_TEST_SPAWN_RATE', '5'))
    PERFORMANCE_TEST_HOST = os.getenv('PERFORMANCE_TEST_HOST', 'http://localhost:5000')
    
    # Performance Monitoring Configuration
    PERFORMANCE_METRICS_COLLECTION = True
    PERFORMANCE_METRICS_INTERVAL = 1  # seconds
    PERFORMANCE_METRICS_RETENTION = 3600  # seconds
    
    # Load Testing Scenarios
    LOAD_TEST_SCENARIOS = {
        'light_load': {
            'users': 10,
            'spawn_rate': 2,
            'duration': 30
        },
        'normal_load': {
            'users': 50,
            'spawn_rate': 5,
            'duration': 60
        },
        'heavy_load': {
            'users': 100,
            'spawn_rate': 10,
            'duration': 120
        },
        'stress_test': {
            'users': 200,
            'spawn_rate': 20,
            'duration': 300
        }
    }
    
    @classmethod
    def calculate_variance_percentage(cls, baseline: float, measured: float) -> float:
        """
        Calculate performance variance percentage.
        
        Args:
            baseline: Node.js baseline metric value
            measured: Python implementation measured value
            
        Returns:
            float: Variance percentage (positive = slower, negative = faster)
        """
        if baseline == 0:
            return 0.0
        return ((measured - baseline) / baseline) * 100
    
    @classmethod
    def is_within_variance_threshold(cls, baseline: float, measured: float) -> bool:
        """
        Check if measured performance is within acceptable variance.
        
        Args:
            baseline: Node.js baseline metric value
            measured: Python implementation measured value
            
        Returns:
            bool: True if within ≤10% variance threshold
        """
        variance = cls.calculate_variance_percentage(baseline, measured)
        return abs(variance) <= cls.PERFORMANCE_VARIANCE_THRESHOLD
    
    @classmethod
    def get_performance_thresholds(cls, metric_category: str) -> Dict[str, float]:
        """
        Get performance thresholds for metric category.
        
        Args:
            metric_category: Category of metrics (response_times, memory_usage, etc.)
            
        Returns:
            Dict[str, float]: Performance thresholds with variance applied
        """
        if metric_category not in cls.NODEJS_BASELINE_METRICS:
            return {}
        
        baseline_metrics = cls.NODEJS_BASELINE_METRICS[metric_category]
        thresholds = {}
        
        for metric_name, baseline_value in baseline_metrics.items():
            # Calculate acceptable maximum (baseline + 10%)
            max_threshold = baseline_value * (1 + cls.PERFORMANCE_VARIANCE_THRESHOLD / 100)
            thresholds[f"{metric_name}_max"] = max_threshold
            
            # Store baseline for comparison
            thresholds[f"{metric_name}_baseline"] = baseline_value
        
        return thresholds


class TestEnvironmentIsolationConfig(TestBaseConfig):
    """
    Test environment isolation configuration ensuring complete test data separation.
    
    Implements comprehensive test isolation parameters as specified in Section 6.6.1
    test data management with automated seeding and cleanup capabilities.
    """
    
    # Environment Isolation Configuration
    TEST_ISOLATION_ENABLED = True
    TEST_DATA_ISOLATION = True
    TEST_CLEANUP_ENABLED = True
    TEST_SEEDING_ENABLED = True
    
    # Worker Process Isolation
    PYTEST_WORKER_ISOLATION = True
    PYTEST_WORKER_ID = os.getenv('PYTEST_WORKER_ID', 'master')
    PYTEST_SESSION_ID = None  # Set dynamically during test execution
    
    # Database Isolation Configuration
    TEST_DATABASE_ISOLATION = True
    TEST_DATABASE_AUTO_CLEANUP = True
    TEST_DATABASE_SEED_DATA = True
    TEST_DATABASE_TRANSACTION_ISOLATION = True
    
    # Cache Isolation Configuration
    TEST_CACHE_ISOLATION = True
    TEST_CACHE_AUTO_CLEANUP = True
    TEST_CACHE_NAMESPACE_PREFIX = f'test_{PYTEST_WORKER_ID}_'
    
    # File System Isolation
    TEST_UPLOAD_ISOLATION = True
    TEST_UPLOAD_AUTO_CLEANUP = True
    TEST_UPLOAD_DIRECTORY = tempfile.mkdtemp(prefix=f'test_uploads_{PYTEST_WORKER_ID}_')
    
    # External Service Isolation
    TEST_EXTERNAL_SERVICE_ISOLATION = True
    TEST_MOCK_ALL_EXTERNAL_CALLS = True
    TEST_EXTERNAL_SERVICE_TIMEOUT = 5  # seconds
    
    # Test Data Seeding Configuration
    TEST_SEED_USERS = [
        {
            'user_id': 'test_user_001',
            'email': 'testuser1@example.com',
            'name': 'Test User One',
            'role': 'user',
            'is_active': True,
            'created_at': '2023-01-01T00:00:00Z'
        },
        {
            'user_id': 'test_user_002',
            'email': 'testuser2@example.com',
            'name': 'Test User Two',
            'role': 'admin',
            'is_active': True,
            'created_at': '2023-01-02T00:00:00Z'
        },
        {
            'user_id': 'test_user_003',
            'email': 'testuser3@example.com',
            'name': 'Test User Three',
            'role': 'user',
            'is_active': False,
            'created_at': '2023-01-03T00:00:00Z'
        }
    ]
    
    TEST_SEED_CACHE_DATA = {
        'test_key_1': 'test_value_1',
        'test_key_2': {'nested': 'object', 'count': 42},
        'test_key_3': ['list', 'of', 'values'],
        'test_session_data': {
            'user_id': 'test_user_001',
            'session_token': 'test_session_token_123'
        }
    }
    
    # Cleanup Configuration
    CLEANUP_TIMEOUT = 30  # seconds
    CLEANUP_RETRY_COUNT = 3
    CLEANUP_RETRY_DELAY = 1  # seconds
    
    @classmethod
    def get_isolated_database_name(cls, base_name: str) -> str:
        """
        Generate isolated database name for test execution.
        
        Args:
            base_name: Base database name
            
        Returns:
            str: Isolated database name with worker and session identifiers
        """
        session_id = cls.PYTEST_SESSION_ID or datetime.now().strftime('%Y%m%d_%H%M%S')
        return f"test_{base_name}_{cls.PYTEST_WORKER_ID}_{session_id}"
    
    @classmethod
    def get_isolated_cache_key(cls, base_key: str) -> str:
        """
        Generate isolated cache key for test execution.
        
        Args:
            base_key: Base cache key
            
        Returns:
            str: Isolated cache key with namespace prefix
        """
        return f"{cls.TEST_CACHE_NAMESPACE_PREFIX}{base_key}"
    
    @classmethod
    def get_isolated_upload_path(cls, filename: str) -> str:
        """
        Generate isolated upload file path for test execution.
        
        Args:
            filename: Original filename
            
        Returns:
            str: Isolated file path in test upload directory
        """
        return os.path.join(cls.TEST_UPLOAD_DIRECTORY, filename)


class IntegratedTestConfig(TestContainersConfig, MockServiceConfig, JWTTestConfig,
                          PerformanceTestConfig, TestEnvironmentIsolationConfig):
    """
    Comprehensive integrated test configuration combining all test capabilities.
    
    Provides complete test environment setup with Testcontainers integration,
    mock services, JWT authentication, performance testing, and environment isolation
    as specified in Section 6.6.1 comprehensive test environment requirements.
    """
    
    # Integrated Configuration Metadata
    CONFIG_NAME = 'integrated_test'
    CONFIG_VERSION = '1.0.0'
    CONFIG_DESCRIPTION = 'Comprehensive test configuration with full integration capabilities'
    
    # Feature Enablement Matrix
    FEATURE_MATRIX = {
        'testcontainers': True,
        'mock_services': True,
        'jwt_testing': True,
        'performance_testing': True,
        'environment_isolation': True,
        'production_parity': True
    }
    
    # Configuration Validation
    CONFIGURATION_VALIDATION_ENABLED = True
    CONFIGURATION_VALIDATION_STRICT = True
    
    @classmethod
    def validate_configuration(cls) -> bool:
        """
        Validate integrated test configuration for completeness and correctness.
        
        Returns:
            bool: True if configuration is valid
            
        Raises:
            ValueError: If configuration validation fails
        """
        # Validate required environment variables
        required_vars = ['FLASK_ENV']
        missing_vars = [var for var in required_vars if not os.getenv(var)]
        if missing_vars and cls.CONFIGURATION_VALIDATION_STRICT:
            raise ValueError(f"Missing required environment variables: {missing_vars}")
        
        # Validate Testcontainers configuration
        if cls.TESTCONTAINERS_ENABLED:
            if not cls.TESTCONTAINERS_MONGODB_VERSION:
                raise ValueError("MongoDB container version must be specified")
            if not cls.TESTCONTAINERS_REDIS_VERSION:
                raise ValueError("Redis container version must be specified")
        
        # Validate JWT configuration
        if cls.JWT_TEST_ENABLED:
            if not cls.JWT_TEST_SECRET_KEY:
                raise ValueError("JWT test secret key must be specified")
            if not cls.JWT_TEST_AUDIENCE:
                raise ValueError("JWT test audience must be specified")
        
        # Validate performance testing configuration
        if cls.PERFORMANCE_TESTING_ENABLED:
            if cls.PERFORMANCE_VARIANCE_THRESHOLD <= 0:
                raise ValueError("Performance variance threshold must be positive")
        
        return True
    
    @classmethod
    def get_configuration_summary(cls) -> Dict[str, Any]:
        """
        Get comprehensive configuration summary for debugging and validation.
        
        Returns:
            Dict[str, Any]: Configuration summary with enabled features
        """
        return {
            'config_name': cls.CONFIG_NAME,
            'config_version': cls.CONFIG_VERSION,
            'environment': cls.get_environment_name(),
            'features_enabled': cls.FEATURE_MATRIX,
            'testcontainers': {
                'enabled': cls.TESTCONTAINERS_ENABLED,
                'mongodb_version': cls.TESTCONTAINERS_MONGODB_VERSION,
                'redis_version': cls.TESTCONTAINERS_REDIS_VERSION
            },
            'mock_services': {
                'enabled': cls.MOCK_EXTERNAL_SERVICES,
                'auth0_enabled': cls.MOCK_AUTH0_ENABLED,
                'aws_enabled': cls.MOCK_AWS_ENABLED
            },
            'jwt_testing': {
                'enabled': cls.JWT_TEST_ENABLED,
                'algorithm': cls.JWT_ALGORITHM,
                'audience': cls.JWT_TEST_AUDIENCE
            },
            'performance_testing': {
                'enabled': cls.PERFORMANCE_TESTING_ENABLED,
                'variance_threshold': cls.PERFORMANCE_VARIANCE_THRESHOLD,
                'baseline_enabled': cls.PERFORMANCE_BASELINE_ENABLED
            },
            'isolation': {
                'worker_id': cls.PYTEST_WORKER_ID,
                'database_isolation': cls.TEST_DATABASE_ISOLATION,
                'cache_isolation': cls.TEST_CACHE_ISOLATION
            }
        }


class TestConfigFactory:
    """
    Test configuration factory for creating environment-specific test configurations.
    
    Provides centralized test configuration management with support for different
    testing scenarios and environment-specific overrides.
    """
    
    _test_configs: Dict[str, Type[TestBaseConfig]] = {
        'base': TestBaseConfig,
        'containers': TestContainersConfig,
        'mocks': MockServiceConfig,
        'jwt': JWTTestConfig,
        'performance': PerformanceTestConfig,
        'isolation': TestEnvironmentIsolationConfig,
        'integrated': IntegratedTestConfig
    }
    
    @classmethod
    def get_test_config(cls, config_type: str = 'integrated') -> Type[TestBaseConfig]:
        """
        Get test configuration class for specified type.
        
        Args:
            config_type: Test configuration type
            
        Returns:
            Type[TestBaseConfig]: Test configuration class
            
        Raises:
            ValueError: If configuration type is not supported
        """
        if config_type not in cls._test_configs:
            raise ValueError(
                f"Unsupported test configuration type: {config_type}. "
                f"Supported types: {list(cls._test_configs.keys())}"
            )
        
        return cls._test_configs[config_type]
    
    @classmethod
    def create_test_config(cls, config_type: str = 'integrated') -> TestBaseConfig:
        """
        Create test configuration instance for specified type.
        
        Args:
            config_type: Test configuration type
            
        Returns:
            TestBaseConfig: Test configuration instance
        """
        config_class = cls.get_test_config(config_type)
        config_instance = config_class()
        
        # Validate configuration if validation is enabled
        if hasattr(config_instance, 'validate_configuration'):
            config_instance.validate_configuration()
        
        return config_instance
    
    @classmethod
    def get_available_configs(cls) -> List[str]:
        """
        Get list of available test configuration types.
        
        Returns:
            List[str]: Available test configuration types
        """
        return list(cls._test_configs.keys())


def create_test_config(config_type: str = 'integrated') -> TestBaseConfig:
    """
    Create test configuration instance with validation.
    
    Args:
        config_type: Test configuration type
        
    Returns:
        TestBaseConfig: Validated test configuration instance
        
    Raises:
        ValueError: If configuration type is unsupported or validation fails
    """
    return TestConfigFactory.create_test_config(config_type)


def get_testcontainers_config() -> TestContainersConfig:
    """
    Get Testcontainers-specific configuration instance.
    
    Returns:
        TestContainersConfig: Testcontainers configuration for production-equivalent testing
    """
    return TestContainersConfig()


def get_mock_service_config() -> MockServiceConfig:
    """
    Get mock service configuration instance for external dependency testing.
    
    Returns:
        MockServiceConfig: Mock service configuration for isolated testing
    """
    return MockServiceConfig()


def get_jwt_test_config() -> JWTTestConfig:
    """
    Get JWT authentication testing configuration instance.
    
    Returns:
        JWTTestConfig: JWT testing configuration for authentication scenarios
    """
    return JWTTestConfig()


def get_performance_test_config() -> PerformanceTestConfig:
    """
    Get performance testing configuration instance.
    
    Returns:
        PerformanceTestConfig: Performance testing configuration with baseline comparison
    """
    return PerformanceTestConfig()


def get_isolation_test_config() -> TestEnvironmentIsolationConfig:
    """
    Get test environment isolation configuration instance.
    
    Returns:
        TestEnvironmentIsolationConfig: Environment isolation configuration for test data management
    """
    return TestEnvironmentIsolationConfig()


# Export all test configuration classes and factory functions
__all__ = [
    # Base test configuration classes
    'TestBaseConfig',
    'TestContainersConfig',
    'MockServiceConfig',
    'JWTTestConfig',
    'PerformanceTestConfig',
    'TestEnvironmentIsolationConfig',
    'IntegratedTestConfig',
    
    # Factory classes and functions
    'TestConfigFactory',
    'create_test_config',
    'get_testcontainers_config',
    'get_mock_service_config',
    'get_jwt_test_config',
    'get_performance_test_config',
    'get_isolation_test_config'
]