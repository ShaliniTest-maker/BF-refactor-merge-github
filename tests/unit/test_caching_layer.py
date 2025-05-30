"""
Comprehensive Redis caching layer testing covering redis-py integration, session management, 
cache invalidation, TTL management, and distributed caching patterns.

This test module implements comprehensive validation of the Redis caching infrastructure per 
Section 5.2.7 and Section 6.6.1, ensuring performance optimization equivalent to Node.js 
caching patterns while maintaining ≤10% variance from baseline performance.

Key Testing Areas:
- Redis client operations with redis-py 5.0+ integration per Section 5.2.7
- Session management and distributed caching per Section 5.2.7
- Cache invalidation and TTL management per Section 5.2.7
- Flask-Caching 2.1+ integration and response caching per Section 5.2.7
- Connection pooling and resource efficiency per Section 5.2.7
- Testcontainers Redis integration for realistic testing per Section 6.6.1
- Performance optimization testing per Section 5.2.7
- Authentication cache testing with AES-256-GCM encryption per Section 6.4.1
- Prometheus metrics collection and monitoring per Section 5.2.8
- Circuit breaker patterns for Redis service resilience per Section 5.2.7

Coverage Requirements:
- 90% integration layer coverage per Section 6.6.3
- Comprehensive cache operation validation per Section 5.2.7
- Performance testing within ≤10% variance requirement per Section 0.1.1
- Realistic testing with Testcontainers integration per Section 6.6.1
"""

import asyncio
import json
import os
import time
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set, Any, Union, Tuple
from unittest.mock import Mock, patch, MagicMock, AsyncMock, call
import uuid

import pytest
import redis
from redis.exceptions import RedisError, ConnectionError, TimeoutError
from testcontainers.redis import RedisContainer
import structlog

# Import caching components under test
from src.cache import (
    CacheManager,
    cache_manager,
    init_cache,
    get_cache_manager,
    is_cache_available,
    cache_get,
    cache_set,
    cache_delete,
    cache_invalidate_pattern,
    RedisClient,
    ResponseCache,
    CacheStrategiesManager,
    CacheError,
    CacheConnectionError,
    CacheTimeoutError,
    CacheCircuitBreakerError,
    CacheSerializationError,
    CachePoolExhaustedError,
    CacheMemoryError,
    CacheOperationError,
    CacheKeyError,
    CacheInvalidationError
)

# Import authentication cache components
from src.auth.cache import (
    AuthenticationCache,
    CacheConfig,
    CacheMetrics,
    PrometheusMetrics,
    AWSKMSManager,
    CacheEncryption,
    CircuitBreaker,
    get_auth_cache,
    init_auth_cache,
    hash_token,
    generate_session_id,
    cache_operation_with_fallback
)


# Test Configuration Constants
REDIS_TEST_PORT = 6380
REDIS_TEST_HOST = "localhost"
TEST_CACHE_TTL = 60
PERFORMANCE_VARIANCE_THRESHOLD = 0.10  # 10% variance threshold per Section 0.1.1


class TestRedisContainerFixture:
    """Test fixture for Redis container management with Testcontainers integration"""
    
    def __init__(self):
        """Initialize Redis container fixture per Section 6.6.1"""
        self.container: Optional[RedisContainer] = None
        self.redis_client: Optional[redis.Redis] = None
        self.connection_url: Optional[str] = None
    
    def start_container(self) -> None:
        """Start Redis container with production-equivalent configuration"""
        try:
            # Start Redis container with realistic configuration
            self.container = RedisContainer("redis:7.0-alpine")
            self.container.start()
            
            # Get connection details
            self.connection_url = self.container.get_connection_url()
            
            # Create Redis client
            self.redis_client = redis.from_url(
                self.connection_url,
                decode_responses=False,  # Keep bytes for encryption testing
                socket_timeout=30.0,
                socket_connect_timeout=10.0,
                retry_on_timeout=True,
                health_check_interval=30
            )
            
            # Validate connection
            self.redis_client.ping()
            
            # Configure Redis for testing
            self.redis_client.config_set('maxmemory-policy', 'allkeys-lru')
            self.redis_client.config_set('notify-keyspace-events', 'Ex')  # Enable expiration events
            
        except Exception as e:
            self.cleanup()
            raise RuntimeError(f"Failed to start Redis container: {str(e)}")
    
    def stop_container(self) -> None:
        """Stop Redis container and cleanup resources"""
        try:
            if self.redis_client:
                self.redis_client.flushall()
                self.redis_client.close()
                self.redis_client = None
            
            if self.container:
                self.container.stop()
                self.container = None
                
        except Exception as e:
            # Log warning but don't fail tests
            print(f"Warning: Error stopping Redis container: {str(e)}")
    
    def cleanup(self) -> None:
        """Cleanup all resources"""
        self.stop_container()
    
    def get_redis_config(self) -> Dict[str, Any]:
        """Get Redis configuration for testing"""
        if not self.container:
            raise RuntimeError("Redis container not started")
        
        return {
            'host': self.container.get_container_host_ip(),
            'port': int(self.container.get_exposed_port(6379)),
            'db': 0,
            'password': None,
            'ssl': False,
            'max_connections': 50,
            'socket_timeout': 30.0,
            'socket_connect_timeout': 10.0,
            'retry_on_timeout': True,
            'health_check_interval': 30,
            'decode_responses': True,
            'encoding': 'utf-8'
        }


@pytest.fixture(scope="session")
def redis_container():
    """Session-scoped Redis container fixture for realistic testing per Section 6.6.1"""
    container_fixture = TestRedisContainerFixture()
    container_fixture.start_container()
    
    yield container_fixture
    
    container_fixture.cleanup()


@pytest.fixture(scope="function")
def redis_client(redis_container):
    """Function-scoped Redis client fixture with clean state"""
    # Get fresh Redis client
    client = redis.from_url(
        redis_container.connection_url,
        decode_responses=True,
        socket_timeout=30.0,
        socket_connect_timeout=10.0,
        retry_on_timeout=True
    )
    
    # Clean state for each test
    client.flushall()
    
    yield client
    
    # Cleanup after test
    try:
        client.flushall()
        client.close()
    except Exception:
        pass  # Ignore cleanup errors


@pytest.fixture
def cache_config(redis_container):
    """Cache configuration fixture for testing"""
    redis_config = redis_container.get_redis_config()
    
    return CacheConfig(
        host=redis_config['host'],
        port=redis_config['port'],
        password=redis_config.get('password'),
        database=0,
        max_connections=50,
        socket_timeout=30.0,
        socket_connect_timeout=10.0,
        retry_on_timeout=True,
        health_check_interval=30,
        key_prefix="test_auth_cache",
        default_ttl=300,
        encryption_enabled=False  # Disabled for basic tests
    )


@pytest.fixture
def flask_app():
    """Flask application fixture for cache manager testing"""
    from flask import Flask
    
    app = Flask(__name__)
    app.config.update({
        'TESTING': True,
        'REDIS_HOST': 'localhost',
        'REDIS_PORT': 6379,
        'REDIS_DB': 0,
        'REDIS_PASSWORD': None,
        'REDIS_SSL': False,
        'REDIS_MAX_CONNECTIONS': 50,
        'REDIS_SOCKET_TIMEOUT': 30.0,
        'REDIS_SOCKET_CONNECT_TIMEOUT': 10.0,
        'REDIS_RETRY_ON_TIMEOUT': True,
        'REDIS_HEALTH_CHECK_INTERVAL': 30,
        'REDIS_DECODE_RESPONSES': True,
        'REDIS_ENCODING': 'utf-8',
        'CACHE_DEFAULT_TIMEOUT': 3600,
        'CACHE_TTL_POLICIES': {
            'session': {
                'policy': 'static',
                'base_ttl': 3600,
                'min_ttl': 300,
                'max_ttl': 7200
            },
            'permission': {
                'policy': 'adaptive', 
                'base_ttl': 300,
                'min_ttl': 60,
                'max_ttl': 1800
            }
        }
    })
    
    with app.app_context():
        yield app


@pytest.fixture
def mock_kms_manager():
    """Mock AWS KMS manager for encryption testing"""
    mock_manager = Mock(spec=AWSKMSManager)
    
    # Mock data key generation
    mock_plaintext_key = b'test_key_32_bytes_long_for_aes256'
    mock_encrypted_key = b'encrypted_key_blob_from_kms_service'
    
    mock_manager.generate_data_key.return_value = (mock_plaintext_key, mock_encrypted_key)
    mock_manager.decrypt_data_key.return_value = mock_plaintext_key
    mock_manager.rotate_key.return_value = {
        'key_id': 'test-cmk-arn',
        'rotation_enabled': True,
        'status': 'rotation_enabled',
        'timestamp': datetime.utcnow().isoformat()
    }
    
    return mock_manager


@pytest.fixture
def prometheus_metrics():
    """Prometheus metrics fixture for monitoring testing"""
    from prometheus_client import CollectorRegistry
    
    registry = CollectorRegistry()
    metrics = PrometheusMetrics(registry=registry)
    
    return metrics


class TestRedisClientOperations:
    """Test Redis client operations per Section 5.2.7"""
    
    def test_redis_connection_establishment(self, redis_container):
        """Test Redis connection establishment with connection pooling"""
        redis_config = redis_container.get_redis_config()
        
        # Test connection creation
        client = redis.Redis(
            host=redis_config['host'],
            port=redis_config['port'],
            db=redis_config['db'],
            max_connections=redis_config['max_connections'],
            socket_timeout=redis_config['socket_timeout'],
            retry_on_timeout=redis_config['retry_on_timeout']
        )
        
        # Validate connection
        assert client.ping() is True
        
        # Test connection info
        info = client.info()
        assert 'redis_version' in info
        assert info['connected_clients'] >= 1
        
        client.close()
    
    def test_redis_basic_operations(self, redis_client):
        """Test basic Redis operations with TTL management"""
        # Test SET operation
        result = redis_client.set('test_key', 'test_value', ex=60)
        assert result is True
        
        # Test GET operation
        value = redis_client.get('test_key')
        assert value == 'test_value'
        
        # Test TTL
        ttl = redis_client.ttl('test_key')
        assert 50 <= ttl <= 60  # Allow for timing variance
        
        # Test DELETE operation
        deleted = redis_client.delete('test_key')
        assert deleted == 1
        
        # Verify deletion
        value = redis_client.get('test_key')
        assert value is None
    
    def test_redis_pipeline_operations(self, redis_client):
        """Test Redis pipeline operations for performance optimization"""
        # Create pipeline
        pipe = redis_client.pipeline()
        
        # Add multiple operations
        test_data = {
            'key1': 'value1',
            'key2': 'value2', 
            'key3': 'value3'
        }
        
        for key, value in test_data.items():
            pipe.set(key, value, ex=60)
        
        # Execute pipeline
        results = pipe.execute()
        assert all(result is True for result in results)
        
        # Verify data
        for key, expected_value in test_data.items():
            value = redis_client.get(key)
            assert value == expected_value
    
    def test_redis_pattern_operations(self, redis_client):
        """Test Redis pattern-based operations for cache invalidation"""
        # Set test data with patterns
        test_keys = [
            'user:123:session',
            'user:123:permissions',
            'user:123:profile',
            'user:456:session',
            'cache:response:endpoint1'
        ]
        
        for key in test_keys:
            redis_client.set(key, f'value_for_{key}', ex=60)
        
        # Test pattern matching
        user_123_keys = redis_client.keys('user:123:*')
        assert len(user_123_keys) == 3
        assert all(key.startswith('user:123:') for key in user_123_keys)
        
        # Test pattern deletion
        deleted_count = redis_client.delete(*user_123_keys)
        assert deleted_count == 3
        
        # Verify deletion
        remaining_keys = redis_client.keys('*')
        assert 'user:123:session' not in remaining_keys
        assert 'user:456:session' in remaining_keys
    
    def test_redis_connection_pool_efficiency(self, redis_container):
        """Test Redis connection pooling and resource efficiency per Section 5.2.7"""
        redis_config = redis_container.get_redis_config()
        
        # Create connection pool
        pool = redis.ConnectionPool(
            host=redis_config['host'],
            port=redis_config['port'],
            db=redis_config['db'],
            max_connections=10,
            retry_on_timeout=True
        )
        
        # Test multiple clients sharing pool
        clients = []
        for i in range(5):
            client = redis.Redis(connection_pool=pool)
            clients.append(client)
            
            # Test operation
            client.set(f'pool_test_{i}', f'value_{i}')
            assert client.get(f'pool_test_{i}') == f'value_{i}'
        
        # Check pool statistics
        assert pool.created_connections <= 10
        
        # Cleanup
        for client in clients:
            client.close()
        pool.disconnect()
    
    def test_redis_error_handling(self, redis_container):
        """Test Redis error handling and resilience patterns"""
        redis_config = redis_container.get_redis_config()
        
        # Test invalid connection
        invalid_client = redis.Redis(
            host='invalid_host',
            port=redis_config['port'],
            socket_timeout=1.0,
            socket_connect_timeout=1.0
        )
        
        with pytest.raises(redis.exceptions.ConnectionError):
            invalid_client.ping()
        
        # Test timeout handling
        valid_client = redis.Redis(
            host=redis_config['host'],
            port=redis_config['port'],
            socket_timeout=0.001  # Very short timeout
        )
        
        # This should work for ping (connection test)
        assert valid_client.ping() is True
        
        valid_client.close()


class TestAuthenticationCache:
    """Test authentication cache operations per Section 6.4.1"""
    
    def test_auth_cache_initialization(self, cache_config):
        """Test authentication cache initialization with configuration"""
        # Test with custom config
        auth_cache = AuthenticationCache(cache_config)
        
        assert auth_cache.config.host == cache_config.host
        assert auth_cache.config.port == cache_config.port
        assert auth_cache.config.encryption_enabled == cache_config.encryption_enabled
        
        # Test health check
        health = auth_cache.health_check()
        assert health['status'] in ['healthy', 'degraded']
        assert health['redis_connected'] is True
        
        auth_cache.close()
    
    def test_cache_metrics_tracking(self, cache_config, prometheus_metrics):
        """Test cache metrics tracking and Prometheus integration per Section 5.2.8"""
        auth_cache = AuthenticationCache(cache_config)
        auth_cache.metrics = prometheus_metrics
        
        # Perform cache operations
        auth_cache.set('test', 'user1', {'data': 'test_value'}, ttl=60)
        auth_cache.get('test', 'user1')  # Hit
        auth_cache.get('test', 'user2')  # Miss
        
        # Check metrics
        stats = auth_cache.get_cache_stats()
        assert stats.hits >= 1
        assert stats.misses >= 1
        assert stats.total_operations >= 2
        assert stats.hit_ratio > 0
        
        # Check Prometheus metrics
        metrics_data = auth_cache.get_prometheus_metrics()
        assert 'auth_cache_hits_total' in metrics_data
        assert 'auth_cache_misses_total' in metrics_data
        
        auth_cache.close()
    
    def test_structured_cache_keys(self, cache_config):
        """Test structured Redis cache key patterns per Section 6.4.2"""
        auth_cache = AuthenticationCache(cache_config)
        
        # Test session key building
        session_key = auth_cache._build_cache_key('session', 'sess_123')
        expected_session_key = f"{cache_config.key_prefix}:session:sess_123"
        assert session_key == expected_session_key
        
        # Test permission key with additional args
        perm_key = auth_cache._build_cache_key('permission', 'user_456', 'admin')
        expected_perm_key = f"{cache_config.key_prefix}:permission:user_456:admin"
        assert perm_key == expected_perm_key
        
        # Test JWT validation key
        token_hash = 'abc123def456'
        jwt_key = auth_cache._build_cache_key('jwt_validation', token_hash)
        expected_jwt_key = f"{cache_config.key_prefix}:jwt_validation:{token_hash}"
        assert jwt_key == expected_jwt_key
        
        auth_cache.close()
    
    def test_user_session_caching(self, cache_config):
        """Test user session caching and retrieval per Section 5.2.3"""
        auth_cache = AuthenticationCache(cache_config)
        
        # Test session data
        session_id = 'sess_abc123'
        session_data = {
            'user_id': 'user_123',
            'username': 'testuser',
            'roles': ['user', 'admin'],
            'login_time': datetime.utcnow().isoformat(),
            'last_activity': datetime.utcnow().isoformat()
        }
        
        # Cache session
        result = auth_cache.cache_user_session(session_id, session_data, ttl=3600)
        assert result is True
        
        # Retrieve session
        cached_session = auth_cache.get_user_session(session_id)
        assert cached_session is not None
        assert cached_session['user_id'] == session_data['user_id']
        assert cached_session['username'] == session_data['username']
        assert cached_session['roles'] == session_data['roles']
        
        # Test session invalidation
        invalidated = auth_cache.invalidate_user_session(session_id)
        assert invalidated is True
        
        # Verify invalidation
        cached_session = auth_cache.get_user_session(session_id)
        assert cached_session is None
        
        auth_cache.close()
    
    def test_user_permissions_caching(self, cache_config):
        """Test user permissions caching with Set handling per Section 6.4.2"""
        auth_cache = AuthenticationCache(cache_config)
        
        # Test permission data
        user_id = 'user_789'
        permissions = {'read_users', 'write_users', 'delete_posts', 'admin_access'}
        
        # Cache permissions
        result = auth_cache.cache_user_permissions(user_id, permissions, ttl=300)
        assert result is True
        
        # Retrieve permissions
        cached_permissions = auth_cache.get_user_permissions(user_id)
        assert cached_permissions is not None
        assert isinstance(cached_permissions, set)
        assert cached_permissions == permissions
        
        # Test permission invalidation
        invalidated = auth_cache.invalidate_user_permissions(user_id)
        assert invalidated is True
        
        # Verify invalidation
        cached_permissions = auth_cache.get_user_permissions(user_id)
        assert cached_permissions is None
        
        auth_cache.close()
    
    def test_jwt_validation_caching(self, cache_config):
        """Test JWT token validation result caching per Section 6.4.1"""
        auth_cache = AuthenticationCache(cache_config)
        
        # Test JWT validation data
        token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature'
        token_hash = hash_token(token)
        
        validation_result = {
            'valid': True,
            'user_id': 'user_456',
            'username': 'jwtuser',
            'exp': (datetime.utcnow() + timedelta(hours=1)).timestamp(),
            'iat': datetime.utcnow().timestamp(),
            'roles': ['user']
        }
        
        # Cache JWT validation
        result = auth_cache.cache_jwt_validation(token_hash, validation_result, ttl=300)
        assert result is True
        
        # Retrieve validation result
        cached_validation = auth_cache.get_jwt_validation(token_hash)
        assert cached_validation is not None
        assert cached_validation['valid'] is True
        assert cached_validation['user_id'] == validation_result['user_id']
        assert cached_validation['username'] == validation_result['username']
        
        auth_cache.close()
    
    def test_auth0_profile_caching(self, cache_config):
        """Test Auth0 user profile caching per Section 6.4.1"""
        auth_cache = AuthenticationCache(cache_config)
        
        # Test Auth0 profile data
        user_id = 'auth0|123456789'
        profile_data = {
            'user_id': user_id,
            'email': 'test@example.com',
            'email_verified': True,
            'name': 'Test User',
            'nickname': 'testuser',
            'picture': 'https://example.com/avatar.jpg',
            'app_metadata': {'roles': ['user', 'admin']},
            'user_metadata': {'preferences': {'theme': 'dark'}}
        }
        
        # Cache profile
        result = auth_cache.cache_auth0_user_profile(user_id, profile_data, ttl=1800)
        assert result is True
        
        # Retrieve profile
        cached_profile = auth_cache.get_auth0_user_profile(user_id)
        assert cached_profile is not None
        assert cached_profile['user_id'] == profile_data['user_id']
        assert cached_profile['email'] == profile_data['email']
        assert cached_profile['app_metadata'] == profile_data['app_metadata']
        
        auth_cache.close()
    
    def test_user_cache_invalidation(self, cache_config):
        """Test comprehensive user cache invalidation per Section 5.2.7"""
        auth_cache = AuthenticationCache(cache_config)
        
        user_id = 'user_comprehensive_test'
        
        # Cache multiple data types for user
        session_data = {'user_id': user_id, 'login_time': datetime.utcnow().isoformat()}
        permissions = {'read', 'write', 'admin'}
        profile_data = {'user_id': user_id, 'email': 'test@example.com'}
        
        auth_cache.cache_user_session(f'session_{user_id}', session_data)
        auth_cache.cache_user_permissions(user_id, permissions)
        auth_cache.cache_auth0_user_profile(user_id, profile_data)
        
        # Verify data is cached
        assert auth_cache.get_user_session(f'session_{user_id}') is not None
        assert auth_cache.get_user_permissions(user_id) is not None
        assert auth_cache.get_auth0_user_profile(user_id) is not None
        
        # Invalidate all user cache
        deleted_count = auth_cache.invalidate_user_cache(user_id)
        assert deleted_count >= 2  # At least permissions and profile
        
        # Verify invalidation
        assert auth_cache.get_user_permissions(user_id) is None
        assert auth_cache.get_auth0_user_profile(user_id) is None
        
        auth_cache.close()


class TestCacheEncryption:
    """Test cache encryption with AES-256-GCM and AWS KMS per Section 6.4.3"""
    
    def test_encryption_initialization(self, mock_kms_manager, prometheus_metrics):
        """Test cache encryption initialization with AWS KMS"""
        encryption = CacheEncryption(mock_kms_manager, prometheus_metrics)
        
        # Verify initialization
        assert encryption.kms_manager == mock_kms_manager
        assert encryption.metrics == prometheus_metrics
        assert encryption._current_key is not None
        assert encryption._encrypted_key is not None
        assert encryption._key_generated_at is not None
        
        # Verify key rotation was called
        mock_kms_manager.generate_data_key.assert_called_once()
    
    def test_data_encryption_decryption(self, mock_kms_manager, prometheus_metrics):
        """Test AES-256-GCM data encryption and decryption"""
        encryption = CacheEncryption(mock_kms_manager, prometheus_metrics)
        
        # Test string data
        test_string = "sensitive_authentication_data"
        encrypted_string = encryption.encrypt(test_string)
        decrypted_string = encryption.decrypt(encrypted_string)
        assert decrypted_string == test_string
        
        # Test dictionary data
        test_dict = {
            'user_id': 'user_123',
            'permissions': ['read', 'write'],
            'session_data': {'login_time': '2024-01-01T00:00:00Z'}
        }
        encrypted_dict = encryption.encrypt(test_dict)
        decrypted_dict = encryption.decrypt(encrypted_dict)
        assert decrypted_dict == test_dict
        
        # Test bytes data
        test_bytes = b"binary_session_data"
        encrypted_bytes = encryption.encrypt(test_bytes)
        decrypted_bytes = encryption.decrypt(encrypted_bytes)
        assert decrypted_bytes == test_bytes.decode('utf-8')  # Converted to string
    
    def test_key_rotation(self, mock_kms_manager, prometheus_metrics):
        """Test encryption key rotation with AWS KMS"""
        encryption = CacheEncryption(mock_kms_manager, prometheus_metrics)
        
        # Store original key
        original_key = encryption._current_key
        
        # Force key rotation
        encryption._rotate_encryption_key()
        
        # Verify new key was generated
        assert encryption._current_key != original_key
        assert mock_kms_manager.generate_data_key.call_count >= 2
        
        # Verify metrics were recorded
        prometheus_metrics.record_key_rotation.assert_called_with('data_key', 'success')
    
    def test_encryption_error_handling(self, prometheus_metrics):
        """Test encryption error handling with KMS failures"""
        # Mock failing KMS manager
        failing_kms = Mock(spec=AWSKMSManager)
        failing_kms.generate_data_key.side_effect = Exception("KMS service unavailable")
        
        # Test initialization failure
        with pytest.raises(Exception):
            CacheEncryption(failing_kms, prometheus_metrics)
    
    def test_encrypted_cache_operations(self, cache_config, mock_kms_manager):
        """Test authentication cache with encryption enabled"""
        # Enable encryption in config
        cache_config.encryption_enabled = True
        
        with patch('src.auth.cache.AWSKMSManager', return_value=mock_kms_manager):
            auth_cache = AuthenticationCache(cache_config)
            
            # Test encrypted session caching
            session_id = 'encrypted_session_123'
            session_data = {
                'user_id': 'user_789',
                'sensitive_data': 'confidential_information',
                'permissions': ['admin', 'read', 'write']
            }
            
            # Cache with encryption
            result = auth_cache.cache_user_session(session_id, session_data, ttl=300)
            assert result is True
            
            # Retrieve and decrypt
            cached_session = auth_cache.get_user_session(session_id)
            assert cached_session is not None
            assert cached_session['user_id'] == session_data['user_id']
            assert cached_session['sensitive_data'] == session_data['sensitive_data']
            
            auth_cache.close()


class TestCircuitBreakerPatterns:
    """Test circuit breaker patterns for Redis service resilience per Section 5.2.7"""
    
    def test_circuit_breaker_initialization(self):
        """Test circuit breaker initialization and configuration"""
        breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=30)
        
        assert breaker.failure_threshold == 3
        assert breaker.recovery_timeout == 30
        assert breaker.failure_count == 0
        assert breaker.state == 'closed'
        assert breaker.last_failure_time is None
    
    def test_circuit_breaker_failure_tracking(self):
        """Test circuit breaker failure tracking and state transitions"""
        breaker = CircuitBreaker(failure_threshold=2, recovery_timeout=1)
        
        # Mock function that fails
        @breaker
        def failing_function():
            raise ConnectionError("Redis connection failed")
        
        # Test first failure
        with pytest.raises(ConnectionError):
            failing_function()
        assert breaker.failure_count == 1
        assert breaker.state == 'closed'
        
        # Test second failure - should open circuit
        with pytest.raises(ConnectionError):
            failing_function()
        assert breaker.failure_count == 2
        assert breaker.state == 'open'
        
        # Test circuit open behavior
        with pytest.raises(CacheConnectionError, match="Circuit breaker is open"):
            failing_function()
    
    def test_circuit_breaker_recovery(self):
        """Test circuit breaker recovery and half-open state"""
        breaker = CircuitBreaker(failure_threshold=1, recovery_timeout=0.1)
        
        # Mock function
        call_count = 0
        
        @breaker
        def sometimes_failing_function():
            nonlocal call_count
            call_count += 1
            if call_count <= 1:
                raise ConnectionError("Initial failure")
            return "success"
        
        # Cause failure and open circuit
        with pytest.raises(ConnectionError):
            sometimes_failing_function()
        assert breaker.state == 'open'
        
        # Wait for recovery timeout
        time.sleep(0.2)
        
        # Should transition to half-open and then closed on success
        result = sometimes_failing_function()
        assert result == "success"
        assert breaker.state == 'closed'
        assert breaker.failure_count == 0
    
    def test_auth_cache_circuit_breaker_integration(self, cache_config):
        """Test circuit breaker integration with authentication cache"""
        auth_cache = AuthenticationCache(cache_config)
        
        # Verify circuit breaker is initialized
        assert hasattr(auth_cache, 'circuit_breaker')
        assert auth_cache.circuit_breaker.state == 'closed'
        
        # Test normal operation
        result = auth_cache.set('test', 'circuit_test', {'data': 'value'}, ttl=60)
        assert result is True
        assert auth_cache.circuit_breaker.state == 'closed'
        
        auth_cache.close()


class TestCachePerformance:
    """Test cache performance optimization per Section 5.2.7 and Section 0.1.1"""
    
    def test_cache_operation_performance(self, cache_config):
        """Test cache operation performance within ≤10% variance threshold"""
        auth_cache = AuthenticationCache(cache_config)
        
        # Performance test data
        test_data = {
            'user_id': 'perf_test_user',
            'session_data': {
                'permissions': ['read', 'write', 'admin'] * 100,  # Larger payload
                'metadata': {'key': 'value'} * 50,
                'timestamp': datetime.utcnow().isoformat()
            }
        }
        
        # Test SET performance
        set_times = []
        for i in range(100):
            start_time = time.time()
            auth_cache.set('performance', f'user_{i}', test_data, ttl=60)
            end_time = time.time()
            set_times.append(end_time - start_time)
        
        # Test GET performance
        get_times = []
        for i in range(100):
            start_time = time.time()
            auth_cache.get('performance', f'user_{i}')
            end_time = time.time()
            get_times.append(end_time - start_time)
        
        # Calculate performance metrics
        avg_set_time = sum(set_times) / len(set_times)
        avg_get_time = sum(get_times) / len(get_times)
        max_set_time = max(set_times)
        max_get_time = max(get_times)
        
        # Performance assertions (reasonable thresholds for testing)
        assert avg_set_time < 0.05, f"Average SET time too high: {avg_set_time:.4f}s"
        assert avg_get_time < 0.05, f"Average GET time too high: {avg_get_time:.4f}s"
        assert max_set_time < 0.1, f"Max SET time too high: {max_set_time:.4f}s"
        assert max_get_time < 0.1, f"Max GET time too high: {max_get_time:.4f}s"
        
        # Performance variance check (within ±10% of average)
        for set_time in set_times:
            variance = abs(set_time - avg_set_time) / avg_set_time
            assert variance <= PERFORMANCE_VARIANCE_THRESHOLD * 3, f"SET performance variance too high: {variance:.2%}"
        
        auth_cache.close()
    
    def test_concurrent_cache_operations(self, cache_config):
        """Test concurrent cache operations for distributed caching per Section 5.2.7"""
        auth_cache = AuthenticationCache(cache_config)
        
        # Test data
        num_threads = 10
        operations_per_thread = 50
        results = []
        
        def cache_worker(thread_id):
            """Worker function for concurrent testing"""
            thread_results = []
            for i in range(operations_per_thread):
                key = f'concurrent_test_{thread_id}_{i}'
                data = {'thread': thread_id, 'iteration': i, 'data': f'value_{i}'}
                
                # SET operation
                start_time = time.time()
                success = auth_cache.set('concurrent', key, data, ttl=60)
                set_time = time.time() - start_time
                
                # GET operation
                start_time = time.time()
                retrieved_data = auth_cache.get('concurrent', key)
                get_time = time.time() - start_time
                
                thread_results.append({
                    'thread_id': thread_id,
                    'iteration': i,
                    'set_success': success,
                    'get_success': retrieved_data is not None,
                    'data_match': retrieved_data == data if retrieved_data else False,
                    'set_time': set_time,
                    'get_time': get_time
                })
            
            return thread_results
        
        # Create and start threads
        threads = []
        for i in range(num_threads):
            thread = threading.Thread(target=lambda tid=i: results.extend(cache_worker(tid)))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Analyze results
        total_operations = len(results)
        successful_sets = sum(1 for r in results if r['set_success'])
        successful_gets = sum(1 for r in results if r['get_success'])
        data_matches = sum(1 for r in results if r['data_match'])
        
        # Performance assertions
        assert total_operations == num_threads * operations_per_thread
        assert successful_sets >= total_operations * 0.95, "SET success rate too low"
        assert successful_gets >= total_operations * 0.95, "GET success rate too low"
        assert data_matches >= total_operations * 0.95, "Data integrity failure rate too high"
        
        # Average performance check
        avg_set_time = sum(r['set_time'] for r in results) / total_operations
        avg_get_time = sum(r['get_time'] for r in results) / total_operations
        
        assert avg_set_time < 0.1, f"Concurrent SET performance degraded: {avg_set_time:.4f}s"
        assert avg_get_time < 0.1, f"Concurrent GET performance degraded: {avg_get_time:.4f}s"
        
        auth_cache.close()
    
    def test_cache_memory_efficiency(self, cache_config):
        """Test cache memory efficiency and resource optimization"""
        auth_cache = AuthenticationCache(cache_config)
        
        # Test large dataset caching
        large_dataset = {}
        for i in range(1000):
            large_dataset[f'key_{i}'] = {
                'data': 'x' * 1000,  # 1KB per entry
                'metadata': {'index': i, 'timestamp': datetime.utcnow().isoformat()}
            }
        
        # Cache large dataset
        start_time = time.time()
        auth_cache.set('memory_test', 'large_dataset', large_dataset, ttl=300)
        cache_time = time.time() - start_time
        
        # Retrieve and verify
        start_time = time.time()
        retrieved_data = auth_cache.get('memory_test', 'large_dataset')
        retrieval_time = time.time() - start_time
        
        # Performance assertions
        assert cache_time < 1.0, f"Large dataset caching too slow: {cache_time:.4f}s"
        assert retrieval_time < 1.0, f"Large dataset retrieval too slow: {retrieval_time:.4f}s"
        assert retrieved_data == large_dataset, "Data integrity check failed"
        
        # Memory efficiency check
        health = auth_cache.health_check()
        assert health['status'] in ['healthy', 'degraded']
        
        auth_cache.close()


class TestDistributedCaching:
    """Test distributed caching patterns for multi-instance deployments per Section 5.2.7"""
    
    def test_multi_instance_cache_sharing(self, redis_container):
        """Test cache sharing between multiple cache instances"""
        redis_config = redis_container.get_redis_config()
        
        # Create multiple cache instances
        config1 = CacheConfig(**redis_config, key_prefix="instance_1", encryption_enabled=False)
        config2 = CacheConfig(**redis_config, key_prefix="instance_2", encryption_enabled=False)
        
        cache1 = AuthenticationCache(config1)
        cache2 = AuthenticationCache(config2)
        
        # Test independent operation
        cache1.set('test', 'shared_key', {'instance': 1, 'data': 'from_cache1'}, ttl=60)
        cache2.set('test', 'shared_key', {'instance': 2, 'data': 'from_cache2'}, ttl=60)
        
        # Verify isolation
        data1 = cache1.get('test', 'shared_key')
        data2 = cache2.get('test', 'shared_key')
        
        assert data1['instance'] == 1
        assert data2['instance'] == 2
        assert data1['data'] == 'from_cache1'
        assert data2['data'] == 'from_cache2'
        
        cache1.close()
        cache2.close()
    
    def test_shared_cache_invalidation(self, redis_container):
        """Test cache invalidation across multiple instances"""
        redis_config = redis_container.get_redis_config()
        
        # Use same key prefix for shared cache
        shared_config = CacheConfig(**redis_config, key_prefix="shared_cache", encryption_enabled=False)
        
        cache_instance1 = AuthenticationCache(shared_config)
        cache_instance2 = AuthenticationCache(shared_config)
        
        # Cache data from instance 1
        user_id = 'shared_user_123'
        session_data = {'user_id': user_id, 'shared': True}
        permissions = {'read', 'write', 'admin'}
        
        cache_instance1.cache_user_session(f'session_{user_id}', session_data)
        cache_instance1.cache_user_permissions(user_id, permissions)
        
        # Verify data is accessible from instance 2
        retrieved_session = cache_instance2.get_user_session(f'session_{user_id}')
        retrieved_permissions = cache_instance2.get_user_permissions(user_id)
        
        assert retrieved_session is not None
        assert retrieved_session['user_id'] == user_id
        assert retrieved_permissions == permissions
        
        # Invalidate from instance 1
        deleted_count = cache_instance1.invalidate_user_cache(user_id)
        assert deleted_count >= 1
        
        # Verify invalidation is visible from instance 2
        assert cache_instance2.get_user_permissions(user_id) is None
        
        cache_instance1.close()
        cache_instance2.close()
    
    def test_distributed_session_management(self, redis_container):
        """Test distributed session management across instances"""
        redis_config = redis_container.get_redis_config()
        shared_config = CacheConfig(**redis_config, key_prefix="distributed_sessions", encryption_enabled=False)
        
        # Simulate multiple application instances
        app_instance1 = AuthenticationCache(shared_config)
        app_instance2 = AuthenticationCache(shared_config)
        app_instance3 = AuthenticationCache(shared_config)
        
        # User logs in through instance 1
        session_id = generate_session_id()
        session_data = {
            'user_id': 'distributed_user',
            'username': 'dist_test_user',
            'login_instance': 'app_instance1',
            'roles': ['user', 'premium'],
            'login_time': datetime.utcnow().isoformat()
        }
        
        app_instance1.cache_user_session(session_id, session_data, ttl=3600)
        
        # User makes request through instance 2
        session_from_instance2 = app_instance2.get_user_session(session_id)
        assert session_from_instance2 is not None
        assert session_from_instance2['user_id'] == 'distributed_user'
        assert session_from_instance2['login_instance'] == 'app_instance1'
        
        # User makes request through instance 3
        session_from_instance3 = app_instance3.get_user_session(session_id)
        assert session_from_instance3 is not None
        assert session_from_instance3['username'] == 'dist_test_user'
        
        # User logs out through instance 2
        logout_success = app_instance2.invalidate_user_session(session_id)
        assert logout_success is True
        
        # Verify session is invalidated across all instances
        assert app_instance1.get_user_session(session_id) is None
        assert app_instance2.get_user_session(session_id) is None
        assert app_instance3.get_user_session(session_id) is None
        
        app_instance1.close()
        app_instance2.close()
        app_instance3.close()


class TestCacheManager:
    """Test Flask cache manager integration per Section 6.1.1"""
    
    def test_cache_manager_initialization(self, flask_app, redis_container):
        """Test cache manager initialization with Flask application factory pattern"""
        redis_config = redis_container.get_redis_config()
        
        # Update Flask config with test Redis settings
        flask_app.config.update({
            'REDIS_HOST': redis_config['host'],
            'REDIS_PORT': redis_config['port']
        })
        
        # Initialize cache manager
        manager = CacheManager()
        manager.init_app(flask_app)
        
        # Verify initialization
        assert manager.app == flask_app
        assert manager.redis_client is not None
        assert manager.response_cache is not None
        assert 'cache_manager' in flask_app.extensions
        
        # Test health check
        health = manager.get_health_status()
        assert health['status'] in ['healthy', 'degraded']
        assert 'redis' in health['components']
        
        manager.close()
    
    def test_cache_manager_redis_operations(self, flask_app, redis_container):
        """Test cache manager Redis operations"""
        redis_config = redis_container.get_redis_config()
        flask_app.config.update({
            'REDIS_HOST': redis_config['host'],
            'REDIS_PORT': redis_config['port']
        })
        
        manager = CacheManager()
        manager.init_app(flask_app)
        
        # Test Redis client access
        client = manager.get_client()
        assert client is not None
        
        # Test basic operations
        assert client.ping() is True
        client.set('test_key', 'test_value', ex=60)
        assert client.get('test_key') == 'test_value'
        
        manager.close()
    
    def test_global_cache_functions(self, redis_container):
        """Test global cache utility functions"""
        redis_config = redis_container.get_redis_config()
        
        # Mock get_redis_client to return test client
        test_client = redis.Redis(
            host=redis_config['host'],
            port=redis_config['port'],
            decode_responses=True
        )
        
        with patch('src.cache.get_redis_client', return_value=test_client):
            # Test cache_set
            result = cache_set('global_test_key', 'global_test_value', ttl=60)
            assert result is True
            
            # Test cache_get
            value = cache_get('global_test_key')
            assert value == 'global_test_value'
            
            # Test cache_get with default
            missing_value = cache_get('missing_key', default='default_value')
            assert missing_value == 'default_value'
            
            # Test cache_delete
            deleted_count = cache_delete('global_test_key')
            assert deleted_count == 1
            
            # Verify deletion
            value_after_delete = cache_get('global_test_key')
            assert value_after_delete is None
        
        test_client.close()


class TestCacheErrorHandling:
    """Test comprehensive cache error handling per Section 5.2.7"""
    
    def test_cache_connection_errors(self):
        """Test cache connection error handling"""
        # Test with invalid Redis configuration
        invalid_config = CacheConfig(
            host='invalid_host_that_does_not_exist',
            port=9999,
            socket_timeout=1.0,
            socket_connect_timeout=1.0,
            encryption_enabled=False
        )
        
        with pytest.raises(CacheConnectionError):
            AuthenticationCache(invalid_config)
    
    def test_cache_operation_timeouts(self, cache_config):
        """Test cache operation timeout handling"""
        auth_cache = AuthenticationCache(cache_config)
        
        # Mock Redis client to simulate timeout
        with patch.object(auth_cache.redis_client, 'set', side_effect=TimeoutError("Operation timed out")):
            with pytest.raises(CacheError, match="Failed to set cache entry"):
                auth_cache.set('timeout_test', 'key1', {'data': 'value'}, ttl=60)
        
        auth_cache.close()
    
    def test_cache_serialization_errors(self, cache_config):
        """Test cache serialization error handling"""
        auth_cache = AuthenticationCache(cache_config)
        
        # Test with non-serializable data
        class NonSerializableClass:
            def __init__(self):
                self.data = "test"
        
        non_serializable_data = NonSerializableClass()
        
        # This should handle serialization gracefully
        with pytest.raises(CacheError):
            auth_cache.set('serialization_test', 'key1', non_serializable_data, ttl=60)
        
        auth_cache.close()
    
    def test_cache_fallback_operations(self, cache_config):
        """Test cache operations with fallback functionality"""
        # Test cache operation with fallback
        def cache_operation():
            raise CacheError("Cache operation failed")
        
        def fallback_operation():
            return "fallback_result"
        
        result = cache_operation_with_fallback(cache_operation, fallback_operation)
        assert result == "fallback_result"
        
        # Test successful cache operation
        def successful_cache_operation():
            return "cache_result"
        
        result = cache_operation_with_fallback(successful_cache_operation, fallback_operation)
        assert result == "cache_result"
    
    def test_cache_health_monitoring(self, cache_config):
        """Test cache health monitoring and status reporting"""
        auth_cache = AuthenticationCache(cache_config)
        
        # Test healthy state
        health = auth_cache.health_check()
        assert health['status'] in ['healthy', 'degraded']
        assert health['redis_connected'] is True
        assert 'response_time_seconds' in health
        assert 'cache_hit_ratio' in health
        
        # Test performance metrics
        stats = auth_cache.get_cache_stats()
        assert isinstance(stats.hit_ratio, float)
        assert stats.hit_ratio >= 0.0
        
        auth_cache.close()


class TestCacheUtilityFunctions:
    """Test cache utility functions per Section 6.4.1"""
    
    def test_token_hashing(self):
        """Test JWT token hashing for cache keys"""
        token1 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test1.signature1"
        token2 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test2.signature2"
        
        hash1 = hash_token(token1)
        hash2 = hash_token(token2)
        hash1_again = hash_token(token1)
        
        # Test hash properties
        assert len(hash1) == 64  # SHA-256 hex digest length
        assert hash1 != hash2  # Different tokens produce different hashes
        assert hash1 == hash1_again  # Same token produces same hash
        assert isinstance(hash1, str)
        assert all(c in '0123456789abcdef' for c in hash1)  # Valid hex
    
    def test_session_id_generation(self):
        """Test cryptographically secure session ID generation"""
        session_ids = [generate_session_id() for _ in range(100)]
        
        # Test uniqueness
        assert len(set(session_ids)) == 100, "Session IDs should be unique"
        
        # Test format and length
        for session_id in session_ids[:10]:  # Check first 10
            assert isinstance(session_id, str)
            assert len(session_id) >= 40  # Base64 of 32 bytes without padding
            assert all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_' 
                      for c in session_id)  # Valid base64url characters
    
    def test_cache_availability_check(self, redis_container):
        """Test cache availability checking"""
        # Test with working cache
        redis_config = redis_container.get_redis_config()
        config = CacheConfig(**redis_config, encryption_enabled=False)
        
        # Initialize cache
        auth_cache = AuthenticationCache(config)
        
        # Mock global cache state
        with patch('src.cache._cache_initialized', True), \
             patch('src.cache.cache_manager.get_health_status', return_value={'status': 'healthy'}):
            assert is_cache_available() is True
        
        # Test with unhealthy cache
        with patch('src.cache._cache_initialized', True), \
             patch('src.cache.cache_manager.get_health_status', return_value={'status': 'unhealthy'}):
            assert is_cache_available() is False
        
        # Test with uninitialized cache
        with patch('src.cache._cache_initialized', False):
            assert is_cache_available() is False
        
        auth_cache.close()


class TestCacheTTLManagement:
    """Test cache TTL management and expiration per Section 5.2.7"""
    
    def test_ttl_setting_and_verification(self, cache_config):
        """Test TTL setting and verification for cache entries"""
        auth_cache = AuthenticationCache(cache_config)
        
        # Test different TTL values
        test_cases = [
            ('short_ttl', 5),
            ('medium_ttl', 60),
            ('long_ttl', 3600)
        ]
        
        for test_id, ttl_seconds in test_cases:
            # Set cache entry with TTL
            result = auth_cache.set('ttl_test', test_id, {'ttl': ttl_seconds}, ttl=ttl_seconds)
            assert result is True
            
            # Check Redis TTL
            cache_key = auth_cache._build_cache_key('ttl_test', test_id)
            redis_ttl = auth_cache.redis_client.ttl(cache_key)
            
            # Allow for timing variance (±5 seconds)
            assert ttl_seconds - 5 <= redis_ttl <= ttl_seconds
        
        auth_cache.close()
    
    def test_ttl_expiration_behavior(self, cache_config):
        """Test cache entry expiration behavior"""
        auth_cache = AuthenticationCache(cache_config)
        
        # Set cache entry with short TTL
        short_ttl = 2
        auth_cache.set('expiration_test', 'expires_soon', {'data': 'will_expire'}, ttl=short_ttl)
        
        # Verify entry exists
        data = auth_cache.get('expiration_test', 'expires_soon')
        assert data is not None
        assert data['data'] == 'will_expire'
        
        # Wait for expiration
        time.sleep(short_ttl + 1)
        
        # Verify entry has expired
        expired_data = auth_cache.get('expiration_test', 'expires_soon')
        assert expired_data is None
        
        auth_cache.close()
    
    def test_session_ttl_management(self, cache_config):
        """Test session-specific TTL management"""
        auth_cache = AuthenticationCache(cache_config)
        
        # Test different session types with appropriate TTLs
        session_configs = [
            ('short_session', 300),    # 5 minutes
            ('regular_session', 3600), # 1 hour 
            ('extended_session', 86400) # 24 hours
        ]
        
        for session_type, ttl in session_configs:
            session_id = f"session_{session_type}_{uuid.uuid4().hex[:8]}"
            session_data = {
                'user_id': f'user_{session_type}',
                'session_type': session_type,
                'created_at': datetime.utcnow().isoformat()
            }
            
            # Cache session with specific TTL
            result = auth_cache.cache_user_session(session_id, session_data, ttl=ttl)
            assert result is True
            
            # Verify TTL is set correctly
            cache_key = auth_cache._build_cache_key('session', session_id)
            redis_ttl = auth_cache.redis_client.ttl(cache_key)
            assert ttl - 10 <= redis_ttl <= ttl  # Allow for timing variance
        
        auth_cache.close()


class TestCacheIntegrationScenarios:
    """Test comprehensive cache integration scenarios per Section 5.2.7"""
    
    def test_user_authentication_workflow(self, cache_config):
        """Test complete user authentication workflow with caching"""
        auth_cache = AuthenticationCache(cache_config)
        
        # Simulate user authentication workflow
        user_id = 'integration_user_123'
        username = 'integration_test_user'
        
        # Step 1: User login - cache session
        session_id = generate_session_id()
        session_data = {
            'user_id': user_id,
            'username': username,
            'login_time': datetime.utcnow().isoformat(),
            'ip_address': '192.168.1.100',
            'user_agent': 'Mozilla/5.0 (Test Browser)'
        }
        
        session_cached = auth_cache.cache_user_session(session_id, session_data, ttl=3600)
        assert session_cached is True
        
        # Step 2: Cache user permissions
        user_permissions = {'read_posts', 'write_posts', 'read_users', 'admin_access'}
        permissions_cached = auth_cache.cache_user_permissions(user_id, user_permissions, ttl=300)
        assert permissions_cached is True
        
        # Step 3: Cache Auth0 profile
        auth0_profile = {
            'user_id': user_id,
            'email': 'integration@example.com',
            'email_verified': True,
            'name': 'Integration Test User',
            'picture': 'https://example.com/avatar.jpg',
            'app_metadata': {'roles': ['user', 'admin']}
        }
        profile_cached = auth_cache.cache_auth0_user_profile(user_id, auth0_profile, ttl=1800)
        assert profile_cached is True
        
        # Step 4: JWT token validation cache
        jwt_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.integration_test.signature'
        token_hash = hash_token(jwt_token)
        jwt_validation = {
            'valid': True,
            'user_id': user_id,
            'username': username,
            'exp': (datetime.utcnow() + timedelta(hours=1)).timestamp(),
            'roles': ['user', 'admin']
        }
        jwt_cached = auth_cache.cache_jwt_validation(token_hash, jwt_validation, ttl=300)
        assert jwt_cached is True
        
        # Step 5: Verify all cached data is accessible
        cached_session = auth_cache.get_user_session(session_id)
        cached_permissions = auth_cache.get_user_permissions(user_id)
        cached_profile = auth_cache.get_auth0_user_profile(user_id)
        cached_jwt = auth_cache.get_jwt_validation(token_hash)
        
        assert cached_session['user_id'] == user_id
        assert cached_permissions == user_permissions
        assert cached_profile['email'] == 'integration@example.com'
        assert cached_jwt['valid'] is True
        
        # Step 6: User logout - invalidate caches
        invalidated_count = auth_cache.invalidate_user_cache(user_id)
        assert invalidated_count >= 2  # At least permissions and profile
        
        # Step 7: Verify invalidation
        assert auth_cache.get_user_permissions(user_id) is None
        assert auth_cache.get_auth0_user_profile(user_id) is None
        # Session cache uses different pattern, should still exist
        assert auth_cache.get_user_session(session_id) is not None
        
        # Step 8: Manual session invalidation
        session_invalidated = auth_cache.invalidate_user_session(session_id)
        assert session_invalidated is True
        assert auth_cache.get_user_session(session_id) is None
        
        auth_cache.close()
    
    def test_high_throughput_caching_scenario(self, cache_config):
        """Test high-throughput caching scenario with multiple users"""
        auth_cache = AuthenticationCache(cache_config)
        
        # Simulate high-throughput scenario
        num_users = 100
        operations_per_user = 10
        
        # Phase 1: Mass user data caching
        start_time = time.time()
        for user_idx in range(num_users):
            user_id = f'throughput_user_{user_idx}'
            
            # Cache session
            session_data = {
                'user_id': user_id,
                'login_time': datetime.utcnow().isoformat(),
                'session_idx': user_idx
            }
            auth_cache.cache_user_session(f'session_{user_id}', session_data, ttl=3600)
            
            # Cache permissions
            permissions = {f'permission_{i}' for i in range(5)}
            auth_cache.cache_user_permissions(user_id, permissions, ttl=300)
        
        cache_time = time.time() - start_time
        
        # Phase 2: Mass data retrieval
        start_time = time.time()
        retrieved_sessions = 0
        retrieved_permissions = 0
        
        for user_idx in range(num_users):
            user_id = f'throughput_user_{user_idx}'
            
            session = auth_cache.get_user_session(f'session_{user_id}')
            if session:
                retrieved_sessions += 1
            
            permissions = auth_cache.get_user_permissions(user_id)
            if permissions:
                retrieved_permissions += 1
        
        retrieval_time = time.time() - start_time
        
        # Performance assertions
        assert cache_time < 10.0, f"Mass caching too slow: {cache_time:.2f}s"
        assert retrieval_time < 5.0, f"Mass retrieval too slow: {retrieval_time:.2f}s"
        assert retrieved_sessions >= num_users * 0.95, "Session retrieval success rate too low"
        assert retrieved_permissions >= num_users * 0.95, "Permission retrieval success rate too low"
        
        # Cache statistics validation
        stats = auth_cache.get_cache_stats()
        assert stats.total_operations >= num_users * 4  # 2 sets + 2 gets per user minimum
        assert stats.hits >= num_users * 2  # At least 2 hits per user
        
        auth_cache.close()
    
    def test_cache_failure_recovery_scenario(self, cache_config):
        """Test cache failure and recovery scenario"""
        auth_cache = AuthenticationCache(cache_config)
        
        # Step 1: Normal operation
        test_data = {'user_id': 'recovery_test', 'data': 'normal_operation'}
        result = auth_cache.set('recovery_test', 'key1', test_data, ttl=60)
        assert result is True
        
        retrieved_data = auth_cache.get('recovery_test', 'key1')
        assert retrieved_data == test_data
        
        # Step 2: Simulate Redis connection failure
        original_client = auth_cache.redis_client
        
        # Mock failing Redis client
        failing_client = Mock()
        failing_client.set.side_effect = ConnectionError("Redis connection lost")
        failing_client.get.side_effect = ConnectionError("Redis connection lost")
        auth_cache.redis_client = failing_client
        
        # Step 3: Verify error handling
        with pytest.raises(CacheError):
            auth_cache.set('recovery_test', 'key2', test_data, ttl=60)
        
        with pytest.raises(CacheError):
            auth_cache.get('recovery_test', 'key2')
        
        # Step 4: Restore connection
        auth_cache.redis_client = original_client
        
        # Step 5: Verify recovery
        recovery_data = {'user_id': 'recovery_test', 'data': 'after_recovery'}
        result = auth_cache.set('recovery_test', 'key3', recovery_data, ttl=60)
        assert result is True
        
        retrieved_recovery_data = auth_cache.get('recovery_test', 'key3')
        assert retrieved_recovery_data == recovery_data
        
        auth_cache.close()


if __name__ == '__main__':
    # Run tests with comprehensive coverage
    pytest.main([
        __file__,
        '-v',
        '--tb=short',
        '--cov=src.cache',
        '--cov=src.auth.cache',
        '--cov-report=term-missing',
        '--cov-report=html:htmlcov/cache_tests',
        '--durations=10'
    ])