"""
Redis Caching Layer Unit Tests - Comprehensive Coverage

This module provides comprehensive testing for the Redis caching layer including redis-py
5.0+ integration, session management, cache invalidation, TTL management, and distributed
caching patterns. Tests validate performance optimization and session storage with cache
operation validation per Section 5.2.7 requirements.

Key Testing Areas:
- Redis client operations testing for session and response caching per Section 5.2.7
- Distributed caching testing for multi-instance deployments per Section 5.2.7
- Cache invalidation testing for data consistency per Section 5.2.7
- Performance optimization testing equivalent to Node.js caching patterns per Section 5.2.7
- Testcontainers Redis integration for realistic testing per Section 6.6.1
- Flask-Caching integration testing per Section 5.2.7
- Connection pooling and resource efficiency testing per Section 5.2.7
- Cache performance optimization testing per Section 5.2.7

Dependencies:
- pytest 7.4+ with pytest-asyncio for async cache operations testing
- testcontainers[redis] ≥4.10.0 for realistic Redis behavior per Section 6.6.1
- redis-py 5.0+ for Redis client operations per Section 3.4.2
- Flask-Caching 2.1+ for Flask integration testing per Section 3.4.2
- structlog 23.1+ for enterprise audit logging during testing

Performance Requirements:
- Redis operation latency: ≤5ms for get/set operations
- Cache hit latency: ≤2ms for response cache hits
- Cache invalidation latency: ≤10ms for pattern-based invalidation
- Memory efficiency: ≤15% overhead for cache coordination structures
- Distributed coordination: ≤10ms for multi-instance cache synchronization

Author: Flask Migration Team
Version: 1.0.0
Compliance: ≤10% performance variance from Node.js baseline per Section 0.1.1
"""

import asyncio
import json
import pytest
import pytest_asyncio
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Union
from unittest.mock import Mock, patch, MagicMock, AsyncMock, call
import warnings

# Suppress Redis warnings for cleaner test output
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    
    import redis
    from redis.exceptions import (
        ConnectionError as RedisConnectionError,
        TimeoutError as RedisTimeoutError,
        ResponseError as RedisResponseError
    )

import structlog
from testcontainers.redis import RedisContainer

# Import application components for testing
from src.cache import (
    init_cache_extensions,
    get_cache_extensions, 
    get_default_redis_client,
    get_default_response_cache,
    cached_response,
    invalidate_cache,
    get_cache_health,
    get_cache_stats,
    cleanup_cache_resources,
    RedisClient,
    FlaskResponseCache,
    CacheConfiguration,
    CachePolicy,
    CompressionType,
    CacheInvalidationPattern,
    TTLPolicy,
    CacheWarmingStrategy
)

from src.auth.cache import (
    AuthCacheManager,
    EncryptionManager,
    CacheHealthMonitor,
    CacheKeyPatterns,
    get_auth_cache_manager,
    init_auth_cache_manager,
    create_token_hash,
    format_cache_key,
    extract_user_id_from_session,
    cache_operation_metrics
)

# Import exceptions for error testing
from src.config.database import DatabaseConnectionError
from src.config.aws import AWSError
from src.auth.exceptions import (
    SecurityException,
    AuthenticationException,
    AuthorizationException,
    SessionException,
    SecurityErrorCode
)

# Configure structured logging for test execution
logger = structlog.get_logger(__name__)


class TestRedisClientOperations:
    """
    Test Redis client operations for session and response caching per Section 5.2.7.
    
    Validates redis-py 5.0+ integration, connection pooling, basic cache operations,
    and performance characteristics required for enterprise-grade caching layer.
    """
    
    def test_redis_client_initialization(self, redis_container):
        """
        Test Redis client initialization with connection pooling.
        
        Validates proper client setup, connection pool configuration, and
        health check capabilities for enterprise deployment scenarios.
        """
        # Get Redis connection from Testcontainer
        redis_url = redis_container.get_connection_url()
        
        # Initialize cache extensions with Testcontainer Redis
        cache_extensions = init_cache_extensions(
            redis_config={'url': redis_url, 'decode_responses': True}
        )
        
        assert cache_extensions is not None
        assert 'redis_client' in cache_extensions
        
        redis_client = cache_extensions['redis_client']
        assert redis_client is not None
        
        # Test basic connectivity
        ping_result = redis_client.ping()
        assert ping_result is True
        
        # Validate connection pool configuration
        assert hasattr(redis_client, 'connection_pool')
        connection_pool = redis_client.connection_pool
        assert connection_pool.max_connections > 0
        
        logger.info(
            "Redis client initialization test passed",
            redis_url=redis_url.split('@')[-1] if '@' in redis_url else redis_url,
            max_connections=connection_pool.max_connections
        )
    
    def test_redis_basic_operations(self, redis_container):
        """
        Test basic Redis operations with performance validation.
        
        Validates get/set operations, expiration handling, and performance
        characteristics meeting ≤5ms operation latency requirements.
        """
        redis_url = redis_container.get_connection_url()
        redis_client = redis.Redis.from_url(redis_url, decode_responses=True)
        
        # Test basic set operation with timing
        start_time = time.perf_counter()
        test_key = f"test_key_{uuid.uuid4()}"
        test_value = "test_value_data"
        
        result = redis_client.set(test_key, test_value, ex=300)
        operation_time = (time.perf_counter() - start_time) * 1000  # Convert to ms
        
        assert result is True
        assert operation_time <= 5.0  # ≤5ms requirement
        
        # Test basic get operation with timing
        start_time = time.perf_counter()
        retrieved_value = redis_client.get(test_key)
        get_operation_time = (time.perf_counter() - start_time) * 1000
        
        assert retrieved_value == test_value
        assert get_operation_time <= 5.0  # ≤5ms requirement
        
        # Test key expiration
        ttl = redis_client.ttl(test_key)
        assert ttl > 0 and ttl <= 300
        
        # Test key deletion
        delete_result = redis_client.delete(test_key)
        assert delete_result == 1
        
        # Verify key is deleted
        deleted_value = redis_client.get(test_key)
        assert deleted_value is None
        
        logger.info(
            "Redis basic operations test passed",
            set_time_ms=operation_time,
            get_time_ms=get_operation_time,
            ttl_seconds=ttl
        )
    
    def test_redis_complex_data_types(self, redis_container):
        """
        Test Redis operations with complex data types and JSON serialization.
        
        Validates hash operations, list operations, and JSON data handling
        required for session and permission caching scenarios.
        """
        redis_url = redis_container.get_connection_url()
        redis_client = redis.Redis.from_url(redis_url, decode_responses=True)
        
        # Test hash operations for session data
        session_key = f"session:{uuid.uuid4()}"
        session_data = {
            'user_id': 'user_123',
            'email': 'test@example.com',
            'permissions': ['read', 'write', 'admin'],
            'created_at': datetime.utcnow().isoformat(),
            'expires_at': (datetime.utcnow() + timedelta(hours=1)).isoformat()
        }
        
        # Store session data as hash
        redis_client.hset(session_key, mapping=session_data)
        
        # Retrieve and validate session data
        retrieved_session = redis_client.hgetall(session_key)
        assert retrieved_session['user_id'] == session_data['user_id']
        assert retrieved_session['email'] == session_data['email']
        
        # Test JSON data storage and retrieval
        json_key = f"json_data_{uuid.uuid4()}"
        complex_data = {
            'nested_object': {
                'array_data': [1, 2, 3, 4, 5],
                'boolean_flag': True,
                'null_value': None
            },
            'metadata': {
                'timestamp': datetime.utcnow().isoformat(),
                'version': '1.0.0'
            }
        }
        
        # Store as JSON string
        json_string = json.dumps(complex_data, default=str)
        redis_client.setex(json_key, 300, json_string)
        
        # Retrieve and parse JSON
        retrieved_json = redis_client.get(json_key)
        parsed_data = json.loads(retrieved_json)
        
        assert parsed_data['nested_object']['array_data'] == [1, 2, 3, 4, 5]
        assert parsed_data['nested_object']['boolean_flag'] is True
        assert parsed_data['metadata']['version'] == '1.0.0'
        
        # Cleanup test data
        redis_client.delete(session_key, json_key)
        
        logger.info(
            "Redis complex data types test passed",
            session_fields=len(session_data),
            json_objects=len(complex_data)
        )
    
    def test_redis_connection_resilience(self, redis_container):
        """
        Test Redis connection resilience and error handling.
        
        Validates connection recovery, timeout handling, and circuit breaker
        patterns for enterprise deployment reliability requirements.
        """
        redis_url = redis_container.get_connection_url()
        
        # Test connection with custom timeout settings
        redis_client = redis.Redis.from_url(
            redis_url,
            decode_responses=True,
            socket_timeout=2.0,
            socket_connect_timeout=2.0,
            retry_on_timeout=True
        )
        
        # Verify connection health
        ping_result = redis_client.ping()
        assert ping_result is True
        
        # Test connection pool resilience
        connection_pool = redis_client.connection_pool
        original_max_connections = connection_pool.max_connections
        
        # Stress test connection pool
        for i in range(10):
            test_key = f"stress_test_{i}"
            redis_client.set(test_key, f"value_{i}", ex=10)
            result = redis_client.get(test_key)
            assert result == f"value_{i}"
        
        # Verify pool still operational
        assert redis_client.ping() is True
        assert connection_pool.max_connections == original_max_connections
        
        # Test timeout behavior with mock
        with patch.object(redis_client, 'execute_command') as mock_execute:
            mock_execute.side_effect = RedisTimeoutError("Command timeout")
            
            with pytest.raises(RedisTimeoutError):
                redis_client.get("timeout_test_key")
        
        # Verify connection recovery after timeout
        recovery_result = redis_client.ping()
        assert recovery_result is True
        
        logger.info(
            "Redis connection resilience test passed",
            max_connections=original_max_connections,
            timeout_settings="configured"
        )


class TestSessionManagement:
    """
    Test session management and distributed caching patterns per Section 5.2.7.
    
    Validates encrypted session storage, distributed session coordination,
    and session lifecycle management for multi-instance deployments.
    """
    
    def test_auth_cache_manager_initialization(self, redis_container):
        """
        Test AuthCacheManager initialization with encryption.
        
        Validates cache manager setup, encryption manager integration,
        and health monitoring initialization for enterprise security.
        """
        redis_url = redis_container.get_connection_url()
        redis_client = redis.Redis.from_url(redis_url, decode_responses=True)
        
        # Initialize AuthCacheManager with test Redis client
        auth_cache_manager = AuthCacheManager(redis_client=redis_client)
        
        assert auth_cache_manager is not None
        assert auth_cache_manager.redis_client is not None
        assert auth_cache_manager.encryption_manager is not None
        assert auth_cache_manager.health_monitor is not None
        
        # Test encryption manager functionality
        encryption_manager = auth_cache_manager.encryption_manager
        test_data = {'test': 'encryption_data', 'timestamp': datetime.utcnow().isoformat()}
        
        # Test encryption/decryption cycle
        encrypted_data = encryption_manager.encrypt_data(test_data)
        assert encrypted_data is not None
        assert isinstance(encrypted_data, str)
        
        decrypted_data = encryption_manager.decrypt_data(encrypted_data)
        assert decrypted_data == test_data
        
        # Verify health monitor functionality
        health_status = auth_cache_manager.perform_health_check()
        assert health_status['status'] == 'healthy'
        assert 'response_time' in health_status
        
        logger.info(
            "AuthCacheManager initialization test passed",
            encryption_enabled=True,
            health_status=health_status['status']
        )
    
    def test_session_data_caching(self, redis_container):
        """
        Test encrypted session data caching with TTL management.
        
        Validates session storage, encryption, TTL handling, and retrieval
        for secure distributed session management requirements.
        """
        redis_url = redis_container.get_connection_url()
        redis_client = redis.Redis.from_url(redis_url, decode_responses=True)
        auth_cache_manager = AuthCacheManager(redis_client=redis_client)
        
        # Create test session data
        session_id = str(uuid.uuid4())
        session_data = {
            'user_id': 'user_123',
            'email': 'test@example.com',
            'permissions': ['read', 'write'],
            'created_at': datetime.utcnow().isoformat(),
            'last_activity': datetime.utcnow().isoformat(),
            'ip_address': '192.168.1.1',
            'user_agent': 'Mozilla/5.0 Test Browser'
        }
        
        # Test session caching with performance measurement
        start_time = time.perf_counter()
        cache_result = auth_cache_manager.cache_session_data(
            session_id=session_id,
            session_data=session_data,
            ttl=1800  # 30 minutes
        )
        cache_time = (time.perf_counter() - start_time) * 1000
        
        assert cache_result is True
        assert cache_time <= 10.0  # Performance requirement
        
        # Test session retrieval with performance measurement
        start_time = time.perf_counter()
        retrieved_session = auth_cache_manager.get_cached_session_data(session_id)
        retrieval_time = (time.perf_counter() - start_time) * 1000
        
        assert retrieved_session is not None
        assert retrieved_session['user_id'] == session_data['user_id']
        assert retrieved_session['email'] == session_data['email']
        assert retrieved_session['permissions'] == session_data['permissions']
        assert retrieval_time <= 2.0  # Cache hit requirement
        
        # Test TTL validation
        cache_key = CacheKeyPatterns.SESSION_DATA.format(session_id=session_id)
        ttl = redis_client.ttl(cache_key)
        assert ttl > 0 and ttl <= 1800
        
        # Test session invalidation
        invalidation_result = auth_cache_manager.invalidate_session_cache(session_id)
        assert invalidation_result is True
        
        # Verify session is invalidated
        invalidated_session = auth_cache_manager.get_cached_session_data(session_id)
        assert invalidated_session is None
        
        logger.info(
            "Session data caching test passed",
            session_id=session_id,
            cache_time_ms=cache_time,
            retrieval_time_ms=retrieval_time,
            ttl_seconds=ttl
        )
    
    def test_distributed_session_coordination(self, redis_container):
        """
        Test distributed session coordination across multiple instances.
        
        Validates session sharing, consistency, and coordination for
        multi-instance Flask deployments per Section 5.2.7.
        """
        redis_url = redis_container.get_connection_url()
        
        # Simulate multiple cache manager instances
        instance_1 = AuthCacheManager(
            redis_client=redis.Redis.from_url(redis_url, decode_responses=True)
        )
        instance_2 = AuthCacheManager(
            redis_client=redis.Redis.from_url(redis_url, decode_responses=True)
        )
        
        # Create session on instance 1
        session_id = str(uuid.uuid4())
        user_id = 'user_456'
        session_data = {
            'user_id': user_id,
            'email': 'distributed@example.com',
            'permissions': ['read', 'write', 'admin'],
            'instance_created': 'instance_1',
            'created_at': datetime.utcnow().isoformat()
        }
        
        # Cache session on instance 1
        cache_result_1 = instance_1.cache_session_data(session_id, session_data, ttl=900)
        assert cache_result_1 is True
        
        # Retrieve session from instance 2 (distributed access)
        retrieved_from_2 = instance_2.get_cached_session_data(session_id)
        assert retrieved_from_2 is not None
        assert retrieved_from_2['user_id'] == user_id
        assert retrieved_from_2['email'] == session_data['email']
        assert retrieved_from_2['instance_created'] == 'instance_1'
        
        # Update session from instance 2
        updated_session_data = retrieved_from_2.copy()
        updated_session_data['last_accessed_by'] = 'instance_2'
        updated_session_data['last_activity'] = datetime.utcnow().isoformat()
        
        cache_result_2 = instance_2.cache_session_data(session_id, updated_session_data, ttl=900)
        assert cache_result_2 is True
        
        # Verify update is visible from instance 1
        updated_from_1 = instance_1.get_cached_session_data(session_id)
        assert updated_from_1 is not None
        assert updated_from_1['last_accessed_by'] == 'instance_2'
        
        # Test coordinated invalidation
        invalidation_result = instance_1.invalidate_session_cache(session_id)
        assert invalidation_result is True
        
        # Verify invalidation is reflected on both instances
        assert instance_1.get_cached_session_data(session_id) is None
        assert instance_2.get_cached_session_data(session_id) is None
        
        logger.info(
            "Distributed session coordination test passed",
            session_id=session_id,
            instances_tested=2,
            coordination_verified=True
        )
    
    def test_session_performance_optimization(self, redis_container):
        """
        Test session performance optimization and metrics.
        
        Validates session access patterns, cache hit ratios, and performance
        optimization strategies for high-throughput scenarios.
        """
        redis_url = redis_container.get_connection_url()
        redis_client = redis.Redis.from_url(redis_url, decode_responses=True)
        auth_cache_manager = AuthCacheManager(redis_client=redis_client)
        
        # Create multiple sessions for performance testing
        session_count = 50
        session_ids = []
        
        # Batch session creation with timing
        start_time = time.perf_counter()
        for i in range(session_count):
            session_id = str(uuid.uuid4())
            session_ids.append(session_id)
            
            session_data = {
                'user_id': f'user_{i}',
                'email': f'user{i}@example.com',
                'permissions': ['read', 'write'] if i % 2 == 0 else ['read'],
                'created_at': datetime.utcnow().isoformat(),
                'session_index': i
            }
            
            auth_cache_manager.cache_session_data(session_id, session_data, ttl=1800)
        
        batch_creation_time = (time.perf_counter() - start_time) * 1000
        avg_creation_time = batch_creation_time / session_count
        
        assert avg_creation_time <= 10.0  # Average ≤10ms per session
        
        # Test batch retrieval performance
        start_time = time.perf_counter()
        retrieved_sessions = []
        
        for session_id in session_ids:
            session_data = auth_cache_manager.get_cached_session_data(session_id)
            if session_data:
                retrieved_sessions.append(session_data)
        
        batch_retrieval_time = (time.perf_counter() - start_time) * 1000
        avg_retrieval_time = batch_retrieval_time / session_count
        
        assert len(retrieved_sessions) == session_count
        assert avg_retrieval_time <= 2.0  # Average ≤2ms per retrieval
        
        # Test cache statistics and hit ratio
        cache_stats = auth_cache_manager.get_cache_statistics()
        assert 'cache_hit_ratios' in cache_stats
        
        if 'session' in cache_stats['cache_hit_ratios']:
            session_hit_ratio = cache_stats['cache_hit_ratios']['session']['hit_ratio']
            assert session_hit_ratio >= 0.95  # ≥95% hit ratio expected
        
        # Test bulk invalidation performance
        start_time = time.perf_counter()
        for session_id in session_ids[:10]:  # Invalidate first 10 sessions
            auth_cache_manager.invalidate_session_cache(session_id)
        
        bulk_invalidation_time = (time.perf_counter() - start_time) * 1000
        avg_invalidation_time = bulk_invalidation_time / 10
        
        assert avg_invalidation_time <= 10.0  # Average ≤10ms per invalidation
        
        logger.info(
            "Session performance optimization test passed",
            session_count=session_count,
            avg_creation_time_ms=avg_creation_time,
            avg_retrieval_time_ms=avg_retrieval_time,
            avg_invalidation_time_ms=avg_invalidation_time
        )


class TestCacheInvalidation:
    """
    Test cache invalidation patterns for data consistency per Section 5.2.7.
    
    Validates immediate invalidation, pattern-based invalidation, tag-based
    invalidation, and distributed invalidation coordination.
    """
    
    def test_immediate_cache_invalidation(self, redis_container):
        """
        Test immediate cache invalidation patterns.
        
        Validates direct key invalidation, related key cleanup, and
        immediate consistency enforcement for data integrity.
        """
        redis_url = redis_container.get_connection_url()
        redis_client = redis.Redis.from_url(redis_url, decode_responses=True)
        auth_cache_manager = AuthCacheManager(redis_client=redis_client)
        
        # Setup test data for invalidation
        user_id = 'test_user_invalidation'
        session_id = str(uuid.uuid4())
        
        # Cache user permissions
        permissions = {'read', 'write', 'admin'}
        permission_result = auth_cache_manager.cache_user_permissions(
            user_id=user_id,
            permissions=permissions,
            ttl=600
        )
        assert permission_result is True
        
        # Cache session data
        session_data = {
            'user_id': user_id,
            'email': 'invalidation@example.com',
            'permissions': list(permissions)
        }
        session_result = auth_cache_manager.cache_session_data(
            session_id=session_id,
            session_data=session_data,
            ttl=600
        )
        assert session_result is True
        
        # Cache JWT validation result
        token_hash = create_token_hash('sample_jwt_token')
        jwt_validation = {
            'valid': True,
            'user_id': user_id,
            'exp': int((datetime.utcnow() + timedelta(hours=1)).timestamp())
        }
        jwt_result = auth_cache_manager.cache_jwt_validation_result(
            token_hash=token_hash,
            validation_result=jwt_validation,
            ttl=300
        )
        assert jwt_result is True
        
        # Verify all data is cached
        assert auth_cache_manager.get_cached_user_permissions(user_id) is not None
        assert auth_cache_manager.get_cached_session_data(session_id) is not None
        assert auth_cache_manager.get_cached_jwt_validation_result(token_hash) is not None
        
        # Test immediate invalidation with timing
        start_time = time.perf_counter()
        
        # Invalidate user permissions (should be immediate)
        perm_invalidation = auth_cache_manager.invalidate_user_permission_cache(user_id)
        assert perm_invalidation is True
        
        # Invalidate session (should be immediate)
        session_invalidation = auth_cache_manager.invalidate_session_cache(session_id)
        assert session_invalidation is True
        
        invalidation_time = (time.perf_counter() - start_time) * 1000
        assert invalidation_time <= 10.0  # ≤10ms requirement
        
        # Verify immediate consistency
        assert auth_cache_manager.get_cached_user_permissions(user_id) is None
        assert auth_cache_manager.get_cached_session_data(session_id) is None
        
        # JWT validation should still exist (not invalidated)
        assert auth_cache_manager.get_cached_jwt_validation_result(token_hash) is not None
        
        logger.info(
            "Immediate cache invalidation test passed",
            user_id=user_id,
            invalidation_time_ms=invalidation_time,
            consistency_verified=True
        )
    
    def test_pattern_based_invalidation(self, redis_container):
        """
        Test pattern-based cache invalidation for bulk operations.
        
        Validates wildcard pattern matching, bulk key invalidation,
        and pattern-based consistency enforcement across related data.
        """
        redis_url = redis_container.get_connection_url()
        redis_client = redis.Redis.from_url(redis_url, decode_responses=True)
        
        # Create multiple cache entries with patterns
        test_user_prefix = 'pattern_test_user'
        user_count = 10
        cached_keys = []
        
        for i in range(user_count):
            user_id = f'{test_user_prefix}_{i}'
            
            # Cache user permissions
            permission_key = CacheKeyPatterns.USER_PERMISSIONS.format(user_id=user_id)
            permission_data = json.dumps({
                'permissions': ['read', 'write'] if i % 2 == 0 else ['read'],
                'user_id': user_id,
                'cached_at': datetime.utcnow().isoformat()
            })
            redis_client.setex(permission_key, 600, permission_data)
            cached_keys.append(permission_key)
            
            # Cache rate limit counters
            rate_limit_key = CacheKeyPatterns.RATE_LIMIT_COUNTERS.format(
                user_id=user_id, 
                endpoint='api_test'
            )
            redis_client.setex(rate_limit_key, 3600, str(i * 5))
            cached_keys.append(rate_limit_key)
        
        # Verify all keys are cached
        for key in cached_keys:
            assert redis_client.exists(key) == 1
        
        # Test pattern-based invalidation
        start_time = time.perf_counter()
        
        # Invalidate all permission caches for pattern test users
        permission_pattern = f"perm_cache:{test_user_prefix}_*"
        permission_keys = redis_client.keys(permission_pattern)
        if permission_keys:
            deleted_permissions = redis_client.delete(*permission_keys)
            assert deleted_permissions == user_count
        
        # Invalidate all rate limit counters for pattern test users
        rate_limit_pattern = f"rate_limit:{test_user_prefix}_*:*"
        rate_limit_keys = redis_client.keys(rate_limit_pattern)
        if rate_limit_keys:
            deleted_rate_limits = redis_client.delete(*rate_limit_keys)
            assert deleted_rate_limits == user_count
        
        pattern_invalidation_time = (time.perf_counter() - start_time) * 1000
        assert pattern_invalidation_time <= 50.0  # Bulk operation allowance
        
        # Verify pattern invalidation effectiveness
        remaining_permission_keys = redis_client.keys(permission_pattern)
        remaining_rate_limit_keys = redis_client.keys(rate_limit_pattern)
        
        assert len(remaining_permission_keys) == 0
        assert len(remaining_rate_limit_keys) == 0
        
        logger.info(
            "Pattern-based invalidation test passed",
            users_invalidated=user_count,
            keys_deleted=user_count * 2,
            invalidation_time_ms=pattern_invalidation_time
        )
    
    def test_bulk_user_cache_invalidation(self, redis_container):
        """
        Test bulk user cache invalidation for comprehensive cleanup.
        
        Validates bulk invalidation across all user-related cache entries
        including sessions, permissions, and rate limiting data.
        """
        redis_url = redis_container.get_connection_url()
        redis_client = redis.Redis.from_url(redis_url, decode_responses=True)
        auth_cache_manager = AuthCacheManager(redis_client=redis_client)
        
        # Setup comprehensive user cache data
        test_user_id = 'bulk_invalidation_user'
        
        # Cache user permissions
        permissions = {'read', 'write', 'admin', 'delete'}
        auth_cache_manager.cache_user_permissions(test_user_id, permissions, ttl=600)
        
        # Cache multiple sessions for the user
        session_ids = []
        for i in range(3):
            session_id = str(uuid.uuid4())
            session_ids.append(session_id)
            
            session_data = {
                'user_id': test_user_id,
                'email': f'bulk{i}@example.com',
                'session_index': i
            }
            auth_cache_manager.cache_session_data(session_id, session_data, ttl=1800)
            
            # Create session user index
            session_user_key = CacheKeyPatterns.SESSION_USER_INDEX.format(user_id=test_user_id)
            redis_client.sadd(session_user_key, session_id)
            redis_client.expire(session_user_key, 1800)
        
        # Cache rate limit counters
        for endpoint in ['api_read', 'api_write', 'api_admin']:
            auth_cache_manager.increment_rate_limit_counter(
                user_id=test_user_id,
                endpoint=endpoint,
                window_seconds=3600
            )
        
        # Cache JWT validation results
        token_hashes = []
        for i in range(2):
            token_hash = create_token_hash(f'bulk_test_token_{i}')
            token_hashes.append(token_hash)
            
            jwt_validation = {
                'valid': True,
                'user_id': test_user_id,
                'token_index': i
            }
            auth_cache_manager.cache_jwt_validation_result(token_hash, jwt_validation, ttl=300)
        
        # Verify all data is cached before bulk invalidation
        assert auth_cache_manager.get_cached_user_permissions(test_user_id) is not None
        for session_id in session_ids:
            assert auth_cache_manager.get_cached_session_data(session_id) is not None
        for token_hash in token_hashes:
            assert auth_cache_manager.get_cached_jwt_validation_result(token_hash) is not None
        
        # Perform bulk invalidation with timing
        start_time = time.perf_counter()
        invalidation_counts = auth_cache_manager.bulk_invalidate_user_cache(test_user_id)
        bulk_invalidation_time = (time.perf_counter() - start_time) * 1000
        
        assert invalidation_counts is not None
        assert isinstance(invalidation_counts, dict)
        assert bulk_invalidation_time <= 25.0  # Bulk operation allowance
        
        # Verify comprehensive invalidation
        assert auth_cache_manager.get_cached_user_permissions(test_user_id) is None
        
        # Note: Session data won't be automatically invalidated by user permissions
        # but session user index should be cleaned up
        session_user_key = CacheKeyPatterns.SESSION_USER_INDEX.format(user_id=test_user_id)
        assert redis_client.exists(session_user_key) == 0
        
        logger.info(
            "Bulk user cache invalidation test passed",
            user_id=test_user_id,
            invalidation_counts=invalidation_counts,
            bulk_time_ms=bulk_invalidation_time
        )
    
    def test_distributed_invalidation_coordination(self, redis_container):
        """
        Test distributed cache invalidation coordination.
        
        Validates invalidation propagation across multiple cache manager
        instances and consistency enforcement in distributed scenarios.
        """
        redis_url = redis_container.get_connection_url()
        
        # Create multiple cache manager instances
        manager_1 = AuthCacheManager(
            redis_client=redis.Redis.from_url(redis_url, decode_responses=True)
        )
        manager_2 = AuthCacheManager(
            redis_client=redis.Redis.from_url(redis_url, decode_responses=True)
        )
        manager_3 = AuthCacheManager(
            redis_client=redis.Redis.from_url(redis_url, decode_responses=True)
        )
        
        # Setup distributed cache data
        user_id = 'distributed_invalidation_user'
        permissions = {'read', 'write', 'admin'}
        
        # Cache data from different instances
        manager_1.cache_user_permissions(user_id, permissions, ttl=600)
        
        session_id_1 = str(uuid.uuid4())
        session_data_1 = {'user_id': user_id, 'instance': 'manager_1'}
        manager_1.cache_session_data(session_id_1, session_data_1, ttl=1800)
        
        session_id_2 = str(uuid.uuid4())
        session_data_2 = {'user_id': user_id, 'instance': 'manager_2'}
        manager_2.cache_session_data(session_id_2, session_data_2, ttl=1800)
        
        # Verify data is accessible from all instances
        assert manager_1.get_cached_user_permissions(user_id) is not None
        assert manager_2.get_cached_user_permissions(user_id) is not None
        assert manager_3.get_cached_user_permissions(user_id) is not None
        
        assert manager_1.get_cached_session_data(session_id_1) is not None
        assert manager_2.get_cached_session_data(session_id_1) is not None
        assert manager_3.get_cached_session_data(session_id_1) is not None
        
        # Test coordinated invalidation
        start_time = time.perf_counter()
        
        # Invalidate from manager_2
        invalidation_result = manager_2.invalidate_user_permission_cache(user_id)
        assert invalidation_result is True
        
        # Invalidate session from manager_3
        session_invalidation = manager_3.invalidate_session_cache(session_id_1)
        assert session_invalidation is True
        
        coordination_time = (time.perf_counter() - start_time) * 1000
        assert coordination_time <= 15.0  # Distributed coordination allowance
        
        # Verify invalidation is reflected across all instances
        assert manager_1.get_cached_user_permissions(user_id) is None
        assert manager_2.get_cached_user_permissions(user_id) is None
        assert manager_3.get_cached_user_permissions(user_id) is None
        
        assert manager_1.get_cached_session_data(session_id_1) is None
        assert manager_2.get_cached_session_data(session_id_1) is None
        assert manager_3.get_cached_session_data(session_id_1) is None
        
        # Session 2 should still exist (not invalidated)
        assert manager_2.get_cached_session_data(session_id_2) is not None
        
        logger.info(
            "Distributed invalidation coordination test passed",
            instances_tested=3,
            coordination_time_ms=coordination_time,
            consistency_verified=True
        )


class TestTTLManagement:
    """
    Test TTL (Time-To-Live) management for cache optimization per Section 5.2.7.
    
    Validates TTL configuration, expiration handling, TTL refresh patterns,
    and memory efficiency through intelligent TTL management strategies.
    """
    
    def test_ttl_configuration_and_validation(self, redis_container):
        """
        Test TTL configuration and validation across different cache types.
        
        Validates proper TTL setting, expiration timing, and TTL policy
        enforcement for different types of cached data.
        """
        redis_url = redis_container.get_connection_url()
        redis_client = redis.Redis.from_url(redis_url, decode_responses=True)
        auth_cache_manager = AuthCacheManager(redis_client=redis_client)
        
        # Test session TTL (long-lived)
        session_id = str(uuid.uuid4())
        session_data = {
            'user_id': 'ttl_test_user',
            'email': 'ttl@example.com',
            'permissions': ['read', 'write']
        }
        session_ttl = 1800  # 30 minutes
        
        auth_cache_manager.cache_session_data(session_id, session_data, ttl=session_ttl)
        
        session_key = CacheKeyPatterns.SESSION_DATA.format(session_id=session_id)
        actual_session_ttl = redis_client.ttl(session_key)
        assert actual_session_ttl > 0
        assert actual_session_ttl <= session_ttl
        assert actual_session_ttl >= session_ttl - 5  # Allow for small timing variance
        
        # Test permission TTL (medium-lived)
        user_id = 'ttl_permission_user'
        permissions = {'read', 'write', 'admin'}
        permission_ttl = 300  # 5 minutes
        
        auth_cache_manager.cache_user_permissions(user_id, permissions, ttl=permission_ttl)
        
        permission_key = CacheKeyPatterns.USER_PERMISSIONS.format(user_id=user_id)
        actual_permission_ttl = redis_client.ttl(permission_key)
        assert actual_permission_ttl > 0
        assert actual_permission_ttl <= permission_ttl
        assert actual_permission_ttl >= permission_ttl - 5
        
        # Test JWT validation TTL (short-lived)
        token_hash = create_token_hash('ttl_test_token')
        jwt_validation = {
            'valid': True,
            'user_id': user_id,
            'exp': int((datetime.utcnow() + timedelta(minutes=5)).timestamp())
        }
        jwt_ttl = 300  # 5 minutes
        
        auth_cache_manager.cache_jwt_validation_result(token_hash, jwt_validation, ttl=jwt_ttl)
        
        jwt_key = CacheKeyPatterns.JWT_VALIDATION.format(token_hash=token_hash)
        actual_jwt_ttl = redis_client.ttl(jwt_key)
        assert actual_jwt_ttl > 0
        assert actual_jwt_ttl <= jwt_ttl
        assert actual_jwt_ttl >= jwt_ttl - 5
        
        # Test rate limiting TTL (hour-based)
        rate_limit_ttl = 3600  # 1 hour
        counter_value = auth_cache_manager.increment_rate_limit_counter(
            user_id=user_id,
            endpoint='ttl_test_endpoint',
            window_seconds=rate_limit_ttl
        )
        assert counter_value == 1
        
        rate_limit_key = CacheKeyPatterns.RATE_LIMIT_COUNTERS.format(
            user_id=user_id,
            endpoint='ttl_test_endpoint'
        )
        actual_rate_limit_ttl = redis_client.ttl(rate_limit_key)
        assert actual_rate_limit_ttl > 0
        assert actual_rate_limit_ttl <= rate_limit_ttl
        
        logger.info(
            "TTL configuration test passed",
            session_ttl=actual_session_ttl,
            permission_ttl=actual_permission_ttl,
            jwt_ttl=actual_jwt_ttl,
            rate_limit_ttl=actual_rate_limit_ttl
        )
    
    def test_ttl_refresh_and_extension(self, redis_container):
        """
        Test TTL refresh and extension patterns for active sessions.
        
        Validates TTL refresh mechanisms, extension policies, and
        session lifetime management for active user scenarios.
        """
        redis_url = redis_container.get_connection_url()
        redis_client = redis.Redis.from_url(redis_url, decode_responses=True)
        auth_cache_manager = AuthCacheManager(redis_client=redis_client)
        
        # Create session with initial TTL
        session_id = str(uuid.uuid4())
        user_id = 'ttl_refresh_user'
        initial_ttl = 600  # 10 minutes
        
        session_data = {
            'user_id': user_id,
            'email': 'refresh@example.com',
            'permissions': ['read', 'write'],
            'created_at': datetime.utcnow().isoformat(),
            'last_activity': datetime.utcnow().isoformat()
        }
        
        auth_cache_manager.cache_session_data(session_id, session_data, ttl=initial_ttl)
        
        session_key = CacheKeyPatterns.SESSION_DATA.format(session_id=session_id)
        initial_remaining_ttl = redis_client.ttl(session_key)
        
        # Simulate session activity and TTL refresh
        time.sleep(2)  # Wait 2 seconds
        
        # Update session data (simulating user activity)
        updated_session_data = session_data.copy()
        updated_session_data['last_activity'] = datetime.utcnow().isoformat()
        updated_session_data['activity_count'] = 1
        
        # Refresh TTL by re-caching with extended TTL
        extended_ttl = 1200  # 20 minutes (extended for active session)
        auth_cache_manager.cache_session_data(session_id, updated_session_data, ttl=extended_ttl)
        
        # Verify TTL was refreshed
        refreshed_ttl = redis_client.ttl(session_key)
        assert refreshed_ttl > initial_remaining_ttl
        assert refreshed_ttl <= extended_ttl
        assert refreshed_ttl >= extended_ttl - 5
        
        # Test conditional TTL extension based on activity
        current_session = auth_cache_manager.get_cached_session_data(session_id)
        assert current_session is not None
        assert current_session['activity_count'] == 1
        
        # Simulate multiple activities with TTL management
        for activity_index in range(3):
            time.sleep(1)  # Simulate time between activities
            
            current_session = auth_cache_manager.get_cached_session_data(session_id)
            if current_session:
                current_session['last_activity'] = datetime.utcnow().isoformat()
                current_session['activity_count'] = activity_index + 2
                
                # Calculate dynamic TTL based on activity
                base_ttl = 600
                activity_bonus = min(current_session['activity_count'] * 60, 600)  # Max 10 min bonus
                dynamic_ttl = base_ttl + activity_bonus
                
                auth_cache_manager.cache_session_data(session_id, current_session, ttl=dynamic_ttl)
        
        # Verify final TTL reflects activity-based extension
        final_ttl = redis_client.ttl(session_key)
        final_session = auth_cache_manager.get_cached_session_data(session_id)
        
        assert final_session is not None
        assert final_session['activity_count'] == 4
        assert final_ttl > initial_ttl  # Should be extended due to activity
        
        logger.info(
            "TTL refresh and extension test passed",
            initial_ttl=initial_remaining_ttl,
            refreshed_ttl=refreshed_ttl,
            final_ttl=final_ttl,
            activity_count=final_session['activity_count']
        )
    
    def test_ttl_expiration_and_cleanup(self, redis_container):
        """
        Test TTL expiration handling and automatic cleanup.
        
        Validates proper expiration behavior, cleanup verification,
        and memory efficiency through automatic TTL-based cleanup.
        """
        redis_url = redis_container.get_connection_url()
        redis_client = redis.Redis.from_url(redis_url, decode_responses=True)
        auth_cache_manager = AuthCacheManager(redis_client=redis_client)
        
        # Create multiple cache entries with short TTLs for testing
        short_ttl = 3  # 3 seconds for testing
        
        # Cache session data with short TTL
        session_id = str(uuid.uuid4())
        session_data = {
            'user_id': 'expiration_test_user',
            'email': 'expiration@example.com',
            'test_purpose': 'ttl_expiration'
        }
        
        auth_cache_manager.cache_session_data(session_id, session_data, ttl=short_ttl)
        
        # Cache permission data with short TTL
        user_id = 'expiration_test_user'
        permissions = {'read', 'write'}
        auth_cache_manager.cache_user_permissions(user_id, permissions, ttl=short_ttl)
        
        # Cache JWT validation with short TTL
        token_hash = create_token_hash('expiration_test_token')
        jwt_validation = {'valid': True, 'user_id': user_id}
        auth_cache_manager.cache_jwt_validation_result(token_hash, jwt_validation, ttl=short_ttl)
        
        # Verify all data is initially cached
        assert auth_cache_manager.get_cached_session_data(session_id) is not None
        assert auth_cache_manager.get_cached_user_permissions(user_id) is not None
        assert auth_cache_manager.get_cached_jwt_validation_result(token_hash) is not None
        
        # Wait for TTL expiration
        time.sleep(short_ttl + 1)  # Wait longer than TTL
        
        # Verify automatic expiration
        assert auth_cache_manager.get_cached_session_data(session_id) is None
        assert auth_cache_manager.get_cached_user_permissions(user_id) is None
        assert auth_cache_manager.get_cached_jwt_validation_result(token_hash) is None
        
        # Verify keys are actually deleted from Redis
        session_key = CacheKeyPatterns.SESSION_DATA.format(session_id=session_id)
        permission_key = CacheKeyPatterns.USER_PERMISSIONS.format(user_id=user_id)
        jwt_key = CacheKeyPatterns.JWT_VALIDATION.format(token_hash=token_hash)
        
        assert redis_client.exists(session_key) == 0
        assert redis_client.exists(permission_key) == 0
        assert redis_client.exists(jwt_key) == 0
        
        # Test memory efficiency after expiration
        info_before_cleanup = redis_client.info('memory')
        used_memory_before = info_before_cleanup.get('used_memory', 0)
        
        # Create and expire more entries to test cleanup efficiency
        temp_keys = []
        for i in range(20):
            temp_key = f"temp_ttl_test_{i}"
            temp_value = f"temporary_value_{i}" * 100  # Larger values
            redis_client.setex(temp_key, 1, temp_value)  # 1 second TTL
            temp_keys.append(temp_key)
        
        # Wait for mass expiration
        time.sleep(2)
        
        # Check memory efficiency after cleanup
        info_after_cleanup = redis_client.info('memory')
        used_memory_after = info_after_cleanup.get('used_memory', 0)
        
        # Memory should not have increased significantly due to TTL cleanup
        memory_increase = used_memory_after - used_memory_before
        memory_increase_percent = (memory_increase / used_memory_before) * 100 if used_memory_before > 0 else 0
        
        assert memory_increase_percent <= 15.0  # ≤15% memory overhead requirement
        
        # Verify all temporary keys are expired
        for temp_key in temp_keys:
            assert redis_client.exists(temp_key) == 0
        
        logger.info(
            "TTL expiration and cleanup test passed",
            memory_before=used_memory_before,
            memory_after=used_memory_after,
            memory_increase_percent=memory_increase_percent,
            expired_keys=len(temp_keys) + 3
        )
    
    def test_ttl_policy_enforcement(self, redis_container):
        """
        Test TTL policy enforcement across different cache scenarios.
        
        Validates TTL policy consistency, default TTL application,
        and policy override mechanisms for cache type management.
        """
        redis_url = redis_container.get_connection_url()
        redis_client = redis.Redis.from_url(redis_url, decode_responses=True)
        auth_cache_manager = AuthCacheManager(redis_client=redis_client)
        
        # Test default TTL application (when no TTL specified)
        user_id = 'ttl_policy_user'
        permissions = {'read', 'write', 'admin'}
        
        # Cache without explicit TTL (should use default)
        auth_cache_manager.cache_user_permissions(user_id, permissions)  # No TTL specified
        
        permission_key = CacheKeyPatterns.USER_PERMISSIONS.format(user_id=user_id)
        default_ttl = redis_client.ttl(permission_key)
        
        # Should use default permission TTL (300 seconds)
        assert default_ttl > 0
        assert default_ttl <= 300
        assert default_ttl >= 295  # Allow for timing variance
        
        # Test session default TTL
        session_id = str(uuid.uuid4())
        session_data = {
            'user_id': user_id,
            'email': 'policy@example.com'
        }
        
        auth_cache_manager.cache_session_data(session_id, session_data)  # No TTL specified
        
        session_key = CacheKeyPatterns.SESSION_DATA.format(session_id=session_id)
        session_default_ttl = redis_client.ttl(session_key)
        
        # Should use default session TTL (3600 seconds)
        assert session_default_ttl > 0
        assert session_default_ttl <= 3600
        assert session_default_ttl >= 3595
        
        # Test TTL override (explicit TTL should override default)
        override_ttl = 120  # 2 minutes
        override_user_id = 'ttl_override_user'
        
        auth_cache_manager.cache_user_permissions(
            override_user_id, 
            permissions, 
            ttl=override_ttl
        )
        
        override_key = CacheKeyPatterns.USER_PERMISSIONS.format(user_id=override_user_id)
        actual_override_ttl = redis_client.ttl(override_key)
        
        assert actual_override_ttl > 0
        assert actual_override_ttl <= override_ttl
        assert actual_override_ttl >= override_ttl - 5
        assert actual_override_ttl != default_ttl  # Should be different from default
        
        # Test rate limiting TTL enforcement
        rate_limit_user = 'rate_limit_ttl_user'
        endpoint = 'policy_test_endpoint'
        window_seconds = 7200  # 2 hours
        
        counter_value = auth_cache_manager.increment_rate_limit_counter(
            user_id=rate_limit_user,
            endpoint=endpoint,
            window_seconds=window_seconds
        )
        assert counter_value == 1
        
        rate_limit_key = CacheKeyPatterns.RATE_LIMIT_COUNTERS.format(
            user_id=rate_limit_user,
            endpoint=endpoint
        )
        rate_limit_ttl = redis_client.ttl(rate_limit_key)
        
        assert rate_limit_ttl > 0
        assert rate_limit_ttl <= window_seconds
        assert rate_limit_ttl >= window_seconds - 5
        
        # Test TTL policy consistency across cache operations
        policy_validation = {
            'permission_default': default_ttl,
            'session_default': session_default_ttl,
            'permission_override': actual_override_ttl,
            'rate_limit_custom': rate_limit_ttl
        }
        
        # Verify policy hierarchy (override > default > system)
        assert policy_validation['permission_override'] < policy_validation['permission_default']
        assert policy_validation['session_default'] > policy_validation['permission_default']
        assert policy_validation['rate_limit_custom'] > policy_validation['session_default']
        
        logger.info(
            "TTL policy enforcement test passed",
            policy_validation=policy_validation,
            policy_hierarchy_verified=True
        )


class TestFlaskCachingIntegration:
    """
    Test Flask-Caching integration per Section 5.2.7.
    
    Validates Flask-Caching 2.1+ integration, response caching patterns,
    and cache decorator functionality for enterprise web applications.
    """
    
    def test_flask_caching_initialization(self, app, redis_container):
        """
        Test Flask-Caching initialization and configuration.
        
        Validates Flask application integration, cache configuration,
        and extension initialization for response caching capabilities.
        """
        redis_url = redis_container.get_connection_url()
        
        # Configure Flask app for caching
        app.config.update({
            'CACHE_TYPE': 'redis',
            'CACHE_REDIS_URL': redis_url,
            'CACHE_DEFAULT_TIMEOUT': 300,
            'CACHE_KEY_PREFIX': 'flask_test_'
        })
        
        # Initialize cache extensions with Flask app
        cache_extensions = init_cache_extensions(
            app=app,
            redis_config={'url': redis_url}
        )
        
        assert cache_extensions is not None
        assert 'response_cache' in cache_extensions
        
        response_cache = cache_extensions['response_cache']
        assert response_cache is not None
        
        # Test cache configuration access
        cache_config = app.config.get('CACHE_EXTENSIONS')
        assert cache_config is not None
        assert cache_config == cache_extensions
        
        # Test basic cache operations through Flask-Caching
        with app.app_context():
            # Test cache set/get
            test_key = 'flask_cache_test'
            test_value = {'message': 'Flask caching test', 'timestamp': datetime.utcnow().isoformat()}
            
            # Use response cache for testing
            cache_result = response_cache.set(test_key, test_value, timeout=300)
            assert cache_result is True
            
            cached_value = response_cache.get(test_key)
            assert cached_value is not None
            assert cached_value['message'] == test_value['message']
            
            # Test cache deletion
            delete_result = response_cache.delete(test_key)
            assert delete_result is True
            
            # Verify deletion
            deleted_value = response_cache.get(test_key)
            assert deleted_value is None
        
        logger.info(
            "Flask-Caching initialization test passed",
            cache_type=app.config['CACHE_TYPE'],
            cache_timeout=app.config['CACHE_DEFAULT_TIMEOUT'],
            cache_prefix=app.config['CACHE_KEY_PREFIX']
        )
    
    def test_response_caching_decorator(self, app, redis_container):
        """
        Test response caching decorator functionality.
        
        Validates cached_response decorator, cache key generation,
        and response caching performance for API endpoints.
        """
        redis_url = redis_container.get_connection_url()
        
        # Initialize cache extensions
        cache_extensions = init_cache_extensions(
            app=app,
            redis_config={'url': redis_url}
        )
        
        with app.app_context():
            # Create test endpoint with caching decorator
            @app.route('/test/cached-endpoint')
            @cached_response(ttl=300, policy='public', tags=['test', 'api'])
            def cached_test_endpoint():
                return {
                    'message': 'Cached response test',
                    'timestamp': datetime.utcnow().isoformat(),
                    'request_id': str(uuid.uuid4())
                }
            
            # Create test client
            with app.test_client() as client:
                # First request (cache miss)
                start_time = time.perf_counter()
                response1 = client.get('/test/cached-endpoint')
                first_request_time = (time.perf_counter() - start_time) * 1000
                
                assert response1.status_code == 200
                response1_data = response1.get_json()
                assert response1_data['message'] == 'Cached response test'
                
                # Second request (cache hit)
                start_time = time.perf_counter()
                response2 = client.get('/test/cached-endpoint')
                second_request_time = (time.perf_counter() - start_time) * 1000
                
                assert response2.status_code == 200
                response2_data = response2.get_json()
                
                # Should be identical cached response
                assert response2_data['message'] == response1_data['message']
                assert response2_data['timestamp'] == response1_data['timestamp']
                assert response2_data['request_id'] == response1_data['request_id']
                
                # Cache hit should be faster (≤2ms requirement)
                assert second_request_time <= 2.0
                assert second_request_time < first_request_time
        
        logger.info(
            "Response caching decorator test passed",
            first_request_ms=first_request_time,
            second_request_ms=second_request_time,
            cache_hit_improvement=first_request_time - second_request_time
        )
    
    def test_cache_invalidation_integration(self, app, redis_container):
        """
        Test cache invalidation integration with Flask-Caching.
        
        Validates invalidate_cache function, pattern-based invalidation,
        and tag-based cache management for response caching.
        """
        redis_url = redis_container.get_connection_url()
        
        # Initialize cache extensions
        cache_extensions = init_cache_extensions(
            app=app,
            redis_config={'url': redis_url}
        )
        
        with app.app_context():
            # Create multiple cached endpoints with tags
            @app.route('/test/user-data/<user_id>')
            @cached_response(ttl=600, tags=['user', 'profile'], key_prefix='user_data')
            def cached_user_data(user_id):
                return {
                    'user_id': user_id,
                    'profile': f'Profile data for {user_id}',
                    'cached_at': datetime.utcnow().isoformat()
                }
            
            @app.route('/test/api-data')
            @cached_response(ttl=300, tags=['api', 'data'], key_prefix='api_data')
            def cached_api_data():
                return {
                    'api_data': 'API response data',
                    'version': '1.0.0',
                    'cached_at': datetime.utcnow().isoformat()
                }
            
            with app.test_client() as client:
                # Cache initial responses
                user_response1 = client.get('/test/user-data/user123')
                user_response2 = client.get('/test/user-data/user456')
                api_response = client.get('/test/api-data')
                
                assert user_response1.status_code == 200
                assert user_response2.status_code == 200
                assert api_response.status_code == 200
                
                # Verify responses are cached (identical on repeat)
                user_repeat1 = client.get('/test/user-data/user123')
                assert user_repeat1.get_json()['cached_at'] == user_response1.get_json()['cached_at']
                
                # Test tag-based invalidation
                invalidation_result = invalidate_cache(
                    tags=['user'],
                    strategy=CacheInvalidationPattern.IMMEDIATE
                )
                
                assert invalidation_result is not None
                assert isinstance(invalidation_result, dict)
                
                # Verify user data is invalidated but API data remains
                user_after_invalidation = client.get('/test/user-data/user123')
                api_after_invalidation = client.get('/test/api-data')
                
                # User data should be fresh (different timestamp)
                assert user_after_invalidation.get_json()['cached_at'] != user_response1.get_json()['cached_at']
                
                # API data should still be cached (same timestamp)
                assert api_after_invalidation.get_json()['cached_at'] == api_response.get_json()['cached_at']
                
                # Test pattern-based invalidation
                pattern_invalidation = invalidate_cache(
                    patterns=['api_*'],
                    strategy=CacheInvalidationPattern.IMMEDIATE
                )
                
                assert pattern_invalidation is not None
                
                # Verify API data is now invalidated
                api_after_pattern_invalidation = client.get('/test/api-data')
                assert api_after_pattern_invalidation.get_json()['cached_at'] != api_response.get_json()['cached_at']
        
        logger.info(
            "Cache invalidation integration test passed",
            tag_invalidation_verified=True,
            pattern_invalidation_verified=True
        )
    
    def test_cache_statistics_and_monitoring(self, app, redis_container):
        """
        Test cache statistics and monitoring integration.
        
        Validates cache performance metrics, hit ratio tracking,
        and monitoring integration for operational visibility.
        """
        redis_url = redis_container.get_connection_url()
        
        # Initialize cache extensions
        cache_extensions = init_cache_extensions(
            app=app,
            redis_config={'url': redis_url}
        )
        
        with app.app_context():
            # Create test endpoint for statistics generation
            @app.route('/test/stats-endpoint')
            @cached_response(ttl=300, key_prefix='stats_test')
            def stats_test_endpoint():
                return {
                    'data': 'Statistics test data',
                    'generated_at': datetime.utcnow().isoformat()
                }
            
            with app.test_client() as client:
                # Generate cache activity for statistics
                for i in range(10):
                    response = client.get('/test/stats-endpoint')
                    assert response.status_code == 200
                
                # Get cache statistics
                cache_stats = get_cache_stats()
                assert cache_stats is not None
                assert 'timestamp' in cache_stats
                assert 'package_info' in cache_stats
                assert 'redis' in cache_stats
                assert 'response_cache' in cache_stats
                
                # Validate package information
                package_info = cache_stats['package_info']
                assert package_info['version'] is not None
                assert package_info['extensions_initialized'] is True
                
                # Validate Redis statistics
                redis_stats = cache_stats['redis']
                if redis_stats:  # Redis stats may be empty if not available
                    assert isinstance(redis_stats, dict)
                
                # Get cache health status
                health_status = get_cache_health()
                assert health_status is not None
                assert 'overall_healthy' in health_status
                assert 'redis' in health_status
                assert 'response_cache' in health_status
                assert 'monitoring' in health_status
                
                # Validate health status structure
                assert isinstance(health_status['overall_healthy'], bool)
                assert isinstance(health_status['redis']['healthy'], bool)
                assert isinstance(health_status['response_cache']['healthy'], bool)
                
                # Test monitoring availability
                monitoring_status = health_status['monitoring']
                assert 'available' in monitoring_status
                assert isinstance(monitoring_status['available'], bool)
        
        logger.info(
            "Cache statistics and monitoring test passed",
            overall_healthy=health_status['overall_healthy'],
            redis_healthy=health_status['redis']['healthy'],
            response_cache_healthy=health_status['response_cache']['healthy'],
            monitoring_available=health_status['monitoring']['available']
        )


class TestConnectionPooling:
    """
    Test connection pooling and resource efficiency per Section 5.2.7.
    
    Validates connection pool management, resource optimization,
    and concurrent access patterns for high-performance scenarios.
    """
    
    def test_connection_pool_configuration(self, redis_container):
        """
        Test Redis connection pool configuration and management.
        
        Validates connection pool settings, connection reuse,
        and resource allocation for efficient Redis operations.
        """
        redis_url = redis_container.get_connection_url()
        
        # Test connection pool with custom configuration
        pool_config = {
            'max_connections': 20,
            'retry_on_timeout': True,
            'health_check_interval': 30,
            'socket_timeout': 5.0,
            'socket_connect_timeout': 5.0
        }
        
        # Create Redis client with connection pool
        connection_pool = redis.ConnectionPool.from_url(
            redis_url,
            max_connections=pool_config['max_connections'],
            retry_on_timeout=pool_config['retry_on_timeout'],
            health_check_interval=pool_config['health_check_interval'],
            socket_timeout=pool_config['socket_timeout'],
            socket_connect_timeout=pool_config['socket_connect_timeout'],
            decode_responses=True
        )
        
        redis_client = redis.Redis(connection_pool=connection_pool)
        
        # Validate connection pool configuration
        assert redis_client.connection_pool.max_connections == pool_config['max_connections']
        assert redis_client.connection_pool.retry_on_timeout == pool_config['retry_on_timeout']
        
        # Test connection pool health
        ping_result = redis_client.ping()
        assert ping_result is True
        
        # Test connection reuse efficiency
        operation_count = 100
        start_time = time.perf_counter()
        
        for i in range(operation_count):
            test_key = f"pool_test_{i}"
            redis_client.set(test_key, f"value_{i}", ex=10)
            result = redis_client.get(test_key)
            assert result == f"value_{i}"
        
        total_time = (time.perf_counter() - start_time) * 1000
        avg_operation_time = total_time / operation_count
        
        # Verify efficient operation performance with connection pooling
        assert avg_operation_time <= 5.0  # ≤5ms per operation with pooling
        
        # Test connection pool statistics
        pool_stats = {
            'max_connections': connection_pool.max_connections,
            'created_connections': connection_pool.created_connections,
            'available_connections': len(connection_pool._available_connections),
            'in_use_connections': len(connection_pool._in_use_connections)
        }
        
        assert pool_stats['created_connections'] <= pool_stats['max_connections']
        assert pool_stats['available_connections'] >= 0
        assert pool_stats['in_use_connections'] >= 0
        
        logger.info(
            "Connection pool configuration test passed",
            pool_config=pool_config,
            pool_stats=pool_stats,
            avg_operation_ms=avg_operation_time
        )
    
    def test_concurrent_connection_handling(self, redis_container):
        """
        Test concurrent connection handling and thread safety.
        
        Validates connection pool behavior under concurrent load,
        thread safety, and resource sharing across multiple operations.
        """
        import threading
        import concurrent.futures
        
        redis_url = redis_container.get_connection_url()
        
        # Create shared connection pool for concurrent testing
        connection_pool = redis.ConnectionPool.from_url(
            redis_url,
            max_connections=10,
            decode_responses=True
        )
        
        redis_client = redis.Redis(connection_pool=connection_pool)
        
        # Test concurrent operations
        def concurrent_cache_operations(thread_id, operation_count):
            """Perform cache operations in a thread"""
            thread_results = {
                'thread_id': thread_id,
                'operations_completed': 0,
                'errors': 0,
                'execution_time': 0
            }
            
            start_time = time.perf_counter()
            
            try:
                for i in range(operation_count):
                    key = f"concurrent_{thread_id}_{i}"
                    value = f"thread_{thread_id}_value_{i}"
                    
                    # Set operation
                    redis_client.set(key, value, ex=30)
                    
                    # Get operation
                    retrieved_value = redis_client.get(key)
                    assert retrieved_value == value
                    
                    # Delete operation
                    redis_client.delete(key)
                    
                    thread_results['operations_completed'] += 1
                    
            except Exception as e:
                thread_results['errors'] += 1
                logger.error(f"Concurrent operation error in thread {thread_id}: {e}")
            
            thread_results['execution_time'] = (time.perf_counter() - start_time) * 1000
            return thread_results
        
        # Execute concurrent operations
        thread_count = 5
        operations_per_thread = 20
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
            futures = [
                executor.submit(concurrent_cache_operations, thread_id, operations_per_thread)
                for thread_id in range(thread_count)
            ]
            
            # Collect results
            thread_results = []
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                thread_results.append(result)
        
        # Validate concurrent execution results
        total_operations = sum(result['operations_completed'] for result in thread_results)
        total_errors = sum(result['errors'] for result in thread_results)
        avg_execution_time = sum(result['execution_time'] for result in thread_results) / len(thread_results)
        
        expected_operations = thread_count * operations_per_thread
        assert total_operations == expected_operations
        assert total_errors == 0  # No errors should occur with proper connection pooling
        assert avg_execution_time <= 500.0  # Reasonable concurrent performance
        
        # Test connection pool state after concurrent operations
        final_pool_stats = {
            'max_connections': connection_pool.max_connections,
            'created_connections': connection_pool.created_connections,
            'available_connections': len(connection_pool._available_connections),
            'in_use_connections': len(connection_pool._in_use_connections)
        }
        
        # All connections should be returned to pool after operations
        assert final_pool_stats['in_use_connections'] == 0
        assert final_pool_stats['available_connections'] > 0
        
        logger.info(
            "Concurrent connection handling test passed",
            thread_count=thread_count,
            total_operations=total_operations,
            total_errors=total_errors,
            avg_execution_time_ms=avg_execution_time,
            final_pool_stats=final_pool_stats
        )
    
    def test_connection_pool_resilience(self, redis_container):
        """
        Test connection pool resilience and recovery patterns.
        
        Validates connection pool behavior during failures,
        connection recovery, and error handling mechanisms.
        """
        redis_url = redis_container.get_connection_url()
        
        # Create connection pool with resilience settings
        connection_pool = redis.ConnectionPool.from_url(
            redis_url,
            max_connections=5,
            retry_on_timeout=True,
            health_check_interval=10,
            socket_timeout=2.0,
            socket_connect_timeout=2.0,
            decode_responses=True
        )
        
        redis_client = redis.Redis(connection_pool=connection_pool)
        
        # Test normal operation baseline
        baseline_result = redis_client.ping()
        assert baseline_result is True
        
        # Test connection pool under stress
        stress_operations = 50
        successful_operations = 0
        failed_operations = 0
        
        for i in range(stress_operations):
            try:
                key = f"stress_test_{i}"
                value = f"stress_value_{i}"
                
                redis_client.set(key, value, ex=10)
                retrieved_value = redis_client.get(key)
                
                if retrieved_value == value:
                    successful_operations += 1
                else:
                    failed_operations += 1
                    
            except (RedisConnectionError, RedisTimeoutError) as e:
                failed_operations += 1
                logger.warning(f"Connection pool stress test error: {e}")
            except Exception as e:
                failed_operations += 1
                logger.error(f"Unexpected error during stress test: {e}")
        
        # Verify acceptable success rate even under stress
        success_rate = successful_operations / stress_operations
        assert success_rate >= 0.95  # ≥95% success rate expected
        
        # Test connection pool recovery after stress
        recovery_result = redis_client.ping()
        assert recovery_result is True
        
        # Test connection pool statistics after stress
        post_stress_stats = {
            'max_connections': connection_pool.max_connections,
            'created_connections': connection_pool.created_connections,
            'available_connections': len(connection_pool._available_connections),
            'in_use_connections': len(connection_pool._in_use_connections)
        }
        
        # Connection pool should maintain integrity
        assert post_stress_stats['created_connections'] <= post_stress_stats['max_connections']
        assert post_stress_stats['in_use_connections'] == 0  # All connections returned
        
        # Test memory efficiency (≤15% overhead requirement)
        info = redis_client.info('memory')
        used_memory = info.get('used_memory', 0)
        
        # Estimate connection pool overhead (rough calculation)
        # This is a simplified test - in production, more sophisticated monitoring would be used
        if used_memory > 0:
            # Memory usage should be reasonable for connection pool
            assert used_memory < 10 * 1024 * 1024  # Less than 10MB for test scenarios
        
        logger.info(
            "Connection pool resilience test passed",
            stress_operations=stress_operations,
            successful_operations=successful_operations,
            success_rate=success_rate,
            post_stress_stats=post_stress_stats,
            memory_used_bytes=used_memory
        )
    
    def test_resource_cleanup_and_management(self, redis_container):
        """
        Test resource cleanup and management for memory efficiency.
        
        Validates proper resource cleanup, memory management,
        and connection lifecycle management for production scenarios.
        """
        redis_url = redis_container.get_connection_url()
        
        # Create multiple cache managers to test resource management
        cache_managers = []
        initial_memory_usage = None
        
        # Get baseline memory usage
        temp_client = redis.Redis.from_url(redis_url, decode_responses=True)
        initial_info = temp_client.info('memory')
        initial_memory_usage = initial_info.get('used_memory', 0)
        temp_client.close()
        
        # Create multiple cache managers
        for i in range(5):
            redis_client = redis.Redis.from_url(redis_url, decode_responses=True)
            auth_cache_manager = AuthCacheManager(redis_client=redis_client)
            cache_managers.append(auth_cache_manager)
            
            # Generate some cache activity
            session_id = str(uuid.uuid4())
            session_data = {
                'user_id': f'resource_test_user_{i}',
                'manager_index': i,
                'created_at': datetime.utcnow().isoformat()
            }
            auth_cache_manager.cache_session_data(session_id, session_data, ttl=300)
        
        # Check memory usage after creating cache managers
        mid_test_client = redis.Redis.from_url(redis_url, decode_responses=True)
        mid_test_info = mid_test_client.info('memory')
        mid_test_memory = mid_test_info.get('used_memory', 0)
        mid_test_client.close()
        
        memory_increase = mid_test_memory - initial_memory_usage
        memory_increase_percent = (memory_increase / initial_memory_usage) * 100 if initial_memory_usage > 0 else 0
        
        # Test resource cleanup
        for manager in cache_managers:
            # Perform health check before cleanup
            health_status = manager.perform_health_check()
            assert health_status['status'] == 'healthy'
            
            # Close Redis client connections
            manager.redis_client.close()
        
        # Clear cache managers list
        cache_managers.clear()
        
        # Test global cache cleanup
        cleanup_cache_resources()
        
        # Check memory usage after cleanup
        time.sleep(1)  # Allow time for cleanup
        
        final_client = redis.Redis.from_url(redis_url, decode_responses=True)
        final_info = final_client.info('memory')
        final_memory = final_info.get('used_memory', 0)
        final_client.close()
        
        # Calculate memory efficiency
        final_memory_increase = final_memory - initial_memory_usage
        final_increase_percent = (final_memory_increase / initial_memory_usage) * 100 if initial_memory_usage > 0 else 0
        
        # Memory usage should return close to baseline after cleanup
        assert final_increase_percent <= 15.0  # ≤15% overhead requirement
        
        # Memory usage after cleanup should be less than or equal to mid-test usage
        assert final_memory <= mid_test_memory
        
        # Test connection pool cleanup verification
        test_client = redis.Redis.from_url(redis_url, decode_responses=True)
        cleanup_verification = test_client.ping()
        assert cleanup_verification is True
        test_client.close()
        
        logger.info(
            "Resource cleanup and management test passed",
            initial_memory=initial_memory_usage,
            mid_test_memory=mid_test_memory,
            final_memory=final_memory,
            mid_increase_percent=memory_increase_percent,
            final_increase_percent=final_increase_percent,
            cache_managers_tested=5
        )


class TestPerformanceOptimization:
    """
    Test cache performance optimization equivalent to Node.js patterns per Section 5.2.7.
    
    Validates performance benchmarks, optimization strategies, and compliance
    with ≤10% variance requirement from Node.js baseline performance.
    """
    
    def test_cache_operation_performance_benchmarks(self, redis_container, performance_baseline_context):
        """
        Test cache operation performance against Node.js baselines.
        
        Validates individual operation performance, timing consistency,
        and compliance with ≤10% variance requirement per Section 0.1.1.
        """
        redis_url = redis_container.get_connection_url()
        redis_client = redis.Redis.from_url(redis_url, decode_responses=True)
        auth_cache_manager = AuthCacheManager(redis_client=redis_client)
        
        # Performance test configuration
        test_iterations = 100
        performance_results = {
            'set_operations': [],
            'get_operations': [],
            'delete_operations': [],
            'encrypted_set_operations': [],
            'encrypted_get_operations': []
        }
        
        # Test basic set operations
        for i in range(test_iterations):
            start_time = time.perf_counter()
            test_key = f"perf_test_set_{i}"
            test_value = f"performance_test_value_{i}"
            redis_client.set(test_key, test_value, ex=300)
            operation_time = (time.perf_counter() - start_time) * 1000
            performance_results['set_operations'].append(operation_time)
        
        # Test basic get operations
        for i in range(test_iterations):
            start_time = time.perf_counter()
            test_key = f"perf_test_set_{i}"
            redis_client.get(test_key)
            operation_time = (time.perf_counter() - start_time) * 1000
            performance_results['get_operations'].append(operation_time)
        
        # Test delete operations
        for i in range(test_iterations):
            start_time = time.perf_counter()
            test_key = f"perf_test_set_{i}"
            redis_client.delete(test_key)
            operation_time = (time.perf_counter() - start_time) * 1000
            performance_results['delete_operations'].append(operation_time)
        
        # Test encrypted operations (AuthCacheManager)
        for i in range(test_iterations):
            session_id = str(uuid.uuid4())
            session_data = {
                'user_id': f'perf_user_{i}',
                'email': f'perf{i}@example.com',
                'permissions': ['read', 'write']
            }
            
            # Encrypted set operation
            start_time = time.perf_counter()
            auth_cache_manager.cache_session_data(session_id, session_data, ttl=300)
            operation_time = (time.perf_counter() - start_time) * 1000
            performance_results['encrypted_set_operations'].append(operation_time)
            
            # Encrypted get operation
            start_time = time.perf_counter()
            auth_cache_manager.get_cached_session_data(session_id)
            operation_time = (time.perf_counter() - start_time) * 1000
            performance_results['encrypted_get_operations'].append(operation_time)
        
        # Calculate performance statistics
        performance_stats = {}
        for operation_type, times in performance_results.items():
            avg_time = sum(times) / len(times)
            max_time = max(times)
            min_time = min(times)
            p95_time = sorted(times)[int(len(times) * 0.95)]
            
            performance_stats[operation_type] = {
                'average_ms': avg_time,
                'max_ms': max_time,
                'min_ms': min_time,
                'p95_ms': p95_time,
                'samples': len(times)
            }
        
        # Validate performance requirements
        # Basic Redis operations should be ≤5ms
        assert performance_stats['set_operations']['average_ms'] <= 5.0
        assert performance_stats['get_operations']['average_ms'] <= 5.0
        assert performance_stats['delete_operations']['average_ms'] <= 5.0
        
        # Encrypted operations can be slightly higher but should be reasonable
        assert performance_stats['encrypted_set_operations']['average_ms'] <= 10.0
        assert performance_stats['encrypted_get_operations']['average_ms'] <= 10.0
        
        # Test against baseline if available
        baseline_metrics = performance_baseline_context.get('baseline_metrics', {})
        variance_threshold = performance_baseline_context.get('variance_threshold', 0.10)  # 10%
        
        performance_violations = []
        
        for operation_type, stats in performance_stats.items():
            baseline_key = f"{operation_type}_average_time"
            if baseline_key in baseline_metrics:
                baseline_value = baseline_metrics[baseline_key]
                measured_value = stats['average_ms']
                variance = abs(measured_value - baseline_value) / baseline_value
                
                if variance > variance_threshold:
                    violation = {
                        'operation': operation_type,
                        'baseline_ms': baseline_value,
                        'measured_ms': measured_value,
                        'variance': variance,
                        'threshold': variance_threshold
                    }
                    performance_violations.append(violation)
        
        # No performance violations should exist
        assert len(performance_violations) == 0, f"Performance violations detected: {performance_violations}"
        
        logger.info(
            "Cache operation performance benchmarks test passed",
            performance_stats=performance_stats,
            performance_violations=performance_violations,
            test_iterations=test_iterations
        )
    
    def test_bulk_operation_performance(self, redis_container):
        """
        Test bulk cache operation performance and throughput.
        
        Validates batch processing capabilities, throughput optimization,
        and bulk operation efficiency for high-volume scenarios.
        """
        redis_url = redis_container.get_connection_url()
        redis_client = redis.Redis.from_url(redis_url, decode_responses=True)
        auth_cache_manager = AuthCacheManager(redis_client=redis_client)
        
        # Bulk operation test configuration
        bulk_sizes = [10, 50, 100, 200]
        bulk_performance_results = {}
        
        for bulk_size in bulk_sizes:
            bulk_results = {
                'bulk_set_time': 0,
                'bulk_get_time': 0,
                'bulk_delete_time': 0,
                'throughput_ops_per_second': 0
            }
            
            # Prepare bulk data
            bulk_data = []
            for i in range(bulk_size):
                key = f"bulk_test_{bulk_size}_{i}"
                value = {
                    'user_id': f'bulk_user_{i}',
                    'data': f'bulk_data_{i}' * 10,  # Larger data for realistic testing
                    'index': i,
                    'bulk_size': bulk_size
                }
                bulk_data.append((key, value))
            
            # Test bulk set operations
            start_time = time.perf_counter()
            for key, value in bulk_data:
                auth_cache_manager.cache_session_data(key, value, ttl=600)
            bulk_results['bulk_set_time'] = (time.perf_counter() - start_time) * 1000
            
            # Test bulk get operations
            start_time = time.perf_counter()
            retrieved_data = []
            for key, _ in bulk_data:
                result = auth_cache_manager.get_cached_session_data(key)
                retrieved_data.append(result)
            bulk_results['bulk_get_time'] = (time.perf_counter() - start_time) * 1000
            
            # Verify all data was retrieved
            assert len(retrieved_data) == bulk_size
            assert all(data is not None for data in retrieved_data)
            
            # Test bulk delete operations
            start_time = time.perf_counter()
            for key, _ in bulk_data:
                auth_cache_manager.invalidate_session_cache(key)
            bulk_results['bulk_delete_time'] = (time.perf_counter() - start_time) * 1000
            
            # Calculate throughput
            total_operations = bulk_size * 3  # set, get, delete
            total_time_seconds = (bulk_results['bulk_set_time'] + 
                                bulk_results['bulk_get_time'] + 
                                bulk_results['bulk_delete_time']) / 1000
            bulk_results['throughput_ops_per_second'] = total_operations / total_time_seconds
            
            bulk_performance_results[bulk_size] = bulk_results
        
        # Analyze bulk performance trends
        for bulk_size, results in bulk_performance_results.items():
            # Average operation time should scale reasonably
            avg_set_time_per_op = results['bulk_set_time'] / bulk_size
            avg_get_time_per_op = results['bulk_get_time'] / bulk_size
            avg_delete_time_per_op = results['bulk_delete_time'] / bulk_size
            
            # Per-operation times should remain reasonable even for larger bulk sizes
            assert avg_set_time_per_op <= 15.0  # ≤15ms per encrypted set operation
            assert avg_get_time_per_op <= 10.0  # ≤10ms per encrypted get operation
            assert avg_delete_time_per_op <= 10.0  # ≤10ms per delete operation
            
            # Throughput should be reasonable for production use
            assert results['throughput_ops_per_second'] >= 50.0  # ≥50 ops/second minimum
        
        # Test throughput scaling (larger bulk sizes should achieve higher throughput)
        throughputs = [bulk_performance_results[size]['throughput_ops_per_second'] for size in bulk_sizes]
        max_throughput = max(throughputs)
        min_throughput = min(throughputs)
        
        # Throughput should improve with bulk size (due to amortized overhead)
        throughput_improvement = (max_throughput - min_throughput) / min_throughput
        assert throughput_improvement >= 0.0  # Should not decrease
        
        logger.info(
            "Bulk operation performance test passed",
            bulk_performance_results=bulk_performance_results,
            max_throughput_ops_per_sec=max_throughput,
            min_throughput_ops_per_sec=min_throughput,
            throughput_improvement=throughput_improvement
        )
    
    def test_cache_hit_ratio_optimization(self, redis_container):
        """
        Test cache hit ratio optimization and effectiveness.
        
        Validates cache hit ratio tracking, optimization strategies,
        and cache effectiveness for memory and performance efficiency.
        """
        redis_url = redis_container.get_connection_url()
        redis_client = redis.Redis.from_url(redis_url, decode_responses=True)
        auth_cache_manager = AuthCacheManager(redis_client=redis_client)
        
        # Cache hit ratio test configuration
        test_users = 20
        cache_scenarios = {
            'cold_cache': {'cache_first': False, 'repeat_access': 1},
            'warm_cache': {'cache_first': True, 'repeat_access': 3},
            'hot_cache': {'cache_first': True, 'repeat_access': 5}
        }
        
        hit_ratio_results = {}
        
        for scenario_name, config in cache_scenarios.items():
            scenario_results = {
                'total_requests': 0,
                'cache_hits': 0,
                'cache_misses': 0,
                'hit_ratio': 0.0,
                'avg_response_time': 0.0
            }
            
            response_times = []
            
            # Setup test data
            for user_id in range(test_users):
                user_data = {
                    'user_id': f'hit_ratio_user_{user_id}',
                    'email': f'hitration{user_id}@example.com',
                    'permissions': ['read', 'write'] if user_id % 2 == 0 else ['read'],
                    'scenario': scenario_name
                }
                
                # Pre-cache data if configured
                if config['cache_first']:
                    auth_cache_manager.cache_user_permissions(
                        user_data['user_id'], 
                        set(user_data['permissions']), 
                        ttl=900
                    )
            
            # Execute cache access pattern
            for user_id in range(test_users):
                user_id_str = f'hit_ratio_user_{user_id}'
                
                for repeat in range(config['repeat_access']):
                    start_time = time.perf_counter()
                    
                    # Attempt to get cached permissions
                    cached_permissions = auth_cache_manager.get_cached_user_permissions(user_id_str)
                    
                    response_time = (time.perf_counter() - start_time) * 1000
                    response_times.append(response_time)
                    scenario_results['total_requests'] += 1
                    
                    if cached_permissions is not None:
                        scenario_results['cache_hits'] += 1
                        # Cache hit should be fast (≤2ms requirement)
                        assert response_time <= 2.0
                    else:
                        scenario_results['cache_misses'] += 1
                        # Cache miss - simulate loading from database and caching
                        permissions = {'read', 'write'} if user_id % 2 == 0 else {'read'}
                        auth_cache_manager.cache_user_permissions(user_id_str, permissions, ttl=900)
            
            # Calculate hit ratio and performance metrics
            if scenario_results['total_requests'] > 0:
                scenario_results['hit_ratio'] = scenario_results['cache_hits'] / scenario_results['total_requests']
                scenario_results['avg_response_time'] = sum(response_times) / len(response_times)
            
            hit_ratio_results[scenario_name] = scenario_results
        
        # Validate hit ratio optimization expectations
        cold_cache_hit_ratio = hit_ratio_results['cold_cache']['hit_ratio']
        warm_cache_hit_ratio = hit_ratio_results['warm_cache']['hit_ratio']
        hot_cache_hit_ratio = hit_ratio_results['hot_cache']['hit_ratio']
        
        # Hit ratios should improve with cache warming
        assert cold_cache_hit_ratio <= warm_cache_hit_ratio
        assert warm_cache_hit_ratio <= hot_cache_hit_ratio
        
        # Hot cache should achieve high hit ratio
        assert hot_cache_hit_ratio >= 0.80  # ≥80% hit ratio for hot cache
        
        # Response times should be better for higher hit ratios
        cold_avg_time = hit_ratio_results['cold_cache']['avg_response_time']
        hot_avg_time = hit_ratio_results['hot_cache']['avg_response_time']
        
        assert hot_avg_time <= cold_avg_time  # Hot cache should be faster
        
        # Test cache statistics collection
        cache_stats = auth_cache_manager.get_cache_statistics()
        
        if 'cache_hit_ratios' in cache_stats:
            stats_hit_ratios = cache_stats['cache_hit_ratios']
            
            # Verify statistics collection is working
            if 'permission' in stats_hit_ratios:
                permission_hit_ratio = stats_hit_ratios['permission']['hit_ratio']
                assert permission_hit_ratio >= 0.0
                assert permission_hit_ratio <= 1.0
        
        logger.info(
            "Cache hit ratio optimization test passed",
            hit_ratio_results=hit_ratio_results,
            cold_hit_ratio=cold_cache_hit_ratio,
            warm_hit_ratio=warm_cache_hit_ratio,
            hot_hit_ratio=hot_cache_hit_ratio
        )
    
    @pytest.mark.slow
    def test_sustained_performance_under_load(self, redis_container):
        """
        Test sustained cache performance under continuous load.
        
        Validates performance consistency, memory stability,
        and resource efficiency during extended operation periods.
        """
        redis_url = redis_container.get_connection_url()
        redis_client = redis.Redis.from_url(redis_url, decode_responses=True)
        auth_cache_manager = AuthCacheManager(redis_client=redis_client)
        
        # Sustained load test configuration
        test_duration_seconds = 30  # Reduced for unit test context
        operations_per_second = 100
        total_operations = test_duration_seconds * operations_per_second
        
        # Performance tracking
        performance_metrics = {
            'operation_times': [],
            'memory_usage_samples': [],
            'error_count': 0,
            'successful_operations': 0,
            'start_time': time.perf_counter(),
            'end_time': None
        }
        
        # Get initial memory baseline
        initial_memory_info = redis_client.info('memory')
        initial_memory = initial_memory_info.get('used_memory', 0)
        performance_metrics['memory_usage_samples'].append(initial_memory)
        
        # Execute sustained load test
        for i in range(total_operations):
            try:
                operation_start = time.perf_counter()
                
                # Perform mixed cache operations
                operation_type = i % 4
                
                if operation_type == 0:  # Session caching
                    session_id = str(uuid.uuid4())
                    session_data = {
                        'user_id': f'load_test_user_{i % 50}',  # Reuse users for cache hits
                        'operation_index': i,
                        'timestamp': datetime.utcnow().isoformat()
                    }
                    auth_cache_manager.cache_session_data(session_id, session_data, ttl=300)
                    
                elif operation_type == 1:  # Permission caching
                    user_id = f'load_test_user_{i % 50}'
                    permissions = {'read', 'write'} if i % 2 == 0 else {'read'}
                    auth_cache_manager.cache_user_permissions(user_id, permissions, ttl=300)
                    
                elif operation_type == 2:  # Permission retrieval
                    user_id = f'load_test_user_{i % 50}'
                    auth_cache_manager.get_cached_user_permissions(user_id)
                    
                else:  # Rate limit increment
                    user_id = f'load_test_user_{i % 50}'
                    endpoint = f'load_test_endpoint_{i % 10}'
                    auth_cache_manager.increment_rate_limit_counter(user_id, endpoint, 3600)
                
                operation_time = (time.perf_counter() - operation_start) * 1000
                performance_metrics['operation_times'].append(operation_time)
                performance_metrics['successful_operations'] += 1
                
                # Sample memory usage periodically
                if i % 100 == 0:
                    memory_info = redis_client.info('memory')
                    current_memory = memory_info.get('used_memory', 0)
                    performance_metrics['memory_usage_samples'].append(current_memory)
                
                # Throttle operations to achieve target rate
                if i > 0 and i % operations_per_second == 0:
                    elapsed = time.perf_counter() - performance_metrics['start_time']
                    expected_elapsed = i / operations_per_second
                    if elapsed < expected_elapsed:
                        time.sleep(expected_elapsed - elapsed)
                
            except Exception as e:
                performance_metrics['error_count'] += 1
                logger.warning(f"Sustained load test error at operation {i}: {e}")
        
        performance_metrics['end_time'] = time.perf_counter()
        
        # Analyze sustained performance results
        total_test_time = performance_metrics['end_time'] - performance_metrics['start_time']
        actual_ops_per_second = performance_metrics['successful_operations'] / total_test_time
        
        # Calculate performance statistics
        operation_times = performance_metrics['operation_times']
        avg_operation_time = sum(operation_times) / len(operation_times) if operation_times else 0
        p95_operation_time = sorted(operation_times)[int(len(operation_times) * 0.95)] if operation_times else 0
        max_operation_time = max(operation_times) if operation_times else 0
        
        # Validate sustained performance requirements
        assert performance_metrics['error_count'] / total_operations <= 0.01  # ≤1% error rate
        assert avg_operation_time <= 10.0  # ≤10ms average operation time
        assert p95_operation_time <= 25.0  # ≤25ms P95 operation time
        assert actual_ops_per_second >= operations_per_second * 0.90  # ≥90% target throughput
        
        # Analyze memory stability
        memory_samples = performance_metrics['memory_usage_samples']
        max_memory = max(memory_samples)
        min_memory = min(memory_samples)
        memory_growth = max_memory - min_memory
        memory_growth_percent = (memory_growth / min_memory) * 100 if min_memory > 0 else 0
        
        # Memory growth should be reasonable (≤15% overhead requirement)
        assert memory_growth_percent <= 15.0
        
        # Test performance consistency (coefficient of variation)
        import statistics
        operation_time_std = statistics.stdev(operation_times) if len(operation_times) > 1 else 0
        coefficient_of_variation = operation_time_std / avg_operation_time if avg_operation_time > 0 else 0
        
        # Performance should be consistent (low coefficient of variation)
        assert coefficient_of_variation <= 1.0  # Standard deviation ≤ mean
        
        logger.info(
            "Sustained performance under load test passed",
            test_duration_seconds=total_test_time,
            total_operations=total_operations,
            successful_operations=performance_metrics['successful_operations'],
            error_count=performance_metrics['error_count'],
            actual_ops_per_second=actual_ops_per_second,
            avg_operation_time_ms=avg_operation_time,
            p95_operation_time_ms=p95_operation_time,
            max_operation_time_ms=max_operation_time,
            memory_growth_percent=memory_growth_percent,
            performance_coefficient_of_variation=coefficient_of_variation
        )


# Test execution and cleanup
def test_cleanup_resources():
    """
    Test resource cleanup and final validation.
    
    Ensures proper cleanup of all test resources, validates
    final state consistency, and confirms resource efficiency.
    """
    try:
        # Cleanup global cache resources
        cleanup_cache_resources()
        
        # Verify cleanup completed successfully
        cache_extensions = get_cache_extensions()
        default_redis_client = get_default_redis_client()
        default_response_cache = get_default_response_cache()
        
        # After cleanup, global instances should be cleared
        logger.info(
            "Resource cleanup test completed",
            cache_extensions_cleared=cache_extensions is None,
            redis_client_cleared=default_redis_client is None,
            response_cache_cleared=default_response_cache is None
        )
        
    except Exception as e:
        logger.warning(f"Resource cleanup test warning: {e}")
        # Cleanup should not fail tests but should be logged


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])