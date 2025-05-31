"""
Redis Cache Integration Testing with Testcontainers - Enterprise-Grade Caching Validation

This module provides comprehensive integration testing for Redis distributed caching, session 
management, cache invalidation patterns, and distributed caching scenarios using Testcontainers
for production-equivalent behavior. Tests redis-py 5.0+ client integration, connection pooling,
TTL management, and cache performance optimization across multiple Flask instances.

Key Test Coverage:
- Redis distributed caching for session and permission management per Section 6.4.1
- Cache integration testing with production-equivalent behavior per Section 6.6.1 enhanced mocking strategy
- Performance optimization testing equivalent to Node.js caching patterns per Section 5.2.7
- Distributed session management across multiple Flask instances per Section 3.4.2
- Redis-py 5.0+ integration testing with Testcontainers Redis per Section 6.6.1
- Session management and distributed caching testing per Section 5.2.7 caching layer
- Cache invalidation and TTL management integration testing per Section 5.2.7 cache invalidation
- Connection pooling and resource efficiency testing per Section 6.1.3 Redis connection pool settings
- Flask-Caching integration with response caching patterns per Section 3.4.2 caching solutions
- Cache performance monitoring integration with Prometheus metrics per Section 6.1.1 metrics collection
- Circuit breaker testing for Redis connectivity resilience per Section 6.1.3 resilience mechanisms

Technical Requirements:
- Production-equivalent Redis behavior through Testcontainers per Section 6.6.1
- Performance validation maintaining ≤10% variance from Node.js baseline per Section 0.1.1
- Enterprise-grade connection pooling and resource optimization per Section 6.1.3
- Comprehensive cache invalidation patterns and TTL management per Section 5.2.7
- Distributed session management validation across multiple Flask instances per Section 3.4.2
- Circuit breaker patterns for Redis connectivity resilience per Section 6.1.3
- Cache performance monitoring with Prometheus metrics integration per Section 6.1.1

Test Architecture:
- Testcontainers Redis integration for realistic cache behavior
- Multi-instance Flask application testing for distributed scenarios
- Performance baseline comparison with Node.js cache implementation
- Comprehensive error handling and circuit breaker validation
- Cache effectiveness and hit ratio monitoring
- Resource efficiency and connection pool optimization testing

References:
- Section 6.4.1: Redis distributed caching for session and permission management
- Section 6.6.1: Enhanced mocking strategy with production-equivalent behavior
- Section 5.2.7: Performance optimization and cache invalidation management
- Section 3.4.2: Distributed session management across multiple Flask instances
- Section 6.1.3: Redis connection pool settings and resilience mechanisms
- Section 6.1.1: Metrics collection and performance monitoring integration
"""

import asyncio
import json
import logging
import os
import random
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from unittest.mock import Mock, patch, MagicMock

import pytest
from flask import Flask, request, jsonify, session, g
from flask.testing import FlaskClient
import redis
from redis import ConnectionPool
from redis.exceptions import ConnectionError, TimeoutError, ResponseError
from testcontainers.redis import RedisContainer
import requests
import threading
from prometheus_client import REGISTRY, CollectorRegistry

# Import cache components for testing
from src.cache import (
    RedisClient, RedisConnectionManager, create_redis_client, 
    init_redis_client, get_redis_client, close_redis_client,
    FlaskResponseCache, CacheConfiguration, CachePolicy,
    CompressionType, CachedResponse, ResponseCacheMetrics,
    create_response_cache, get_response_cache, init_response_cache,
    CacheInvalidationPattern, TTLPolicy, CacheWarmingStrategy,
    CacheKeyPattern, TTLConfiguration, CacheStrategyMetrics,
    CacheInvalidationStrategy, TTLManagementStrategy, CacheKeyPatternManager,
    init_cache_extensions, get_cache_extensions, cached_response,
    invalidate_cache, get_cache_health, get_cache_stats,
    cleanup_cache_resources, MONITORING_AVAILABLE
)

# Import authentication cache components
from src.auth.cache import (
    AuthenticationCache,
    SessionManager,
    PermissionCache,
    cache_user_session,
    get_cached_permissions,
    invalidate_user_cache
)

# Import configuration and exceptions
from src.config.database import DatabaseConfig
from src.cache.exceptions import (
    CacheError, RedisConnectionError, CacheOperationTimeoutError,
    CacheInvalidationError, CircuitBreakerOpenError,
    CacheKeyError, CacheSerializationError, CachePoolExhaustedError
)

# Configure test logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TestRedisConnectionIntegration:
    """
    Test Redis connection integration with enterprise-grade connection pooling,
    circuit breaker patterns, and distributed connection management.
    """
    
    @pytest.fixture(scope="class")
    def redis_container(self):
        """
        Testcontainers Redis instance for production-equivalent behavior.
        """
        with RedisContainer("redis:7.2-alpine") as redis_container:
            # Configure Redis container for enterprise testing
            redis_container.with_env("REDIS_MAXMEMORY", "512mb")
            redis_container.with_env("REDIS_MAXMEMORY_POLICY", "allkeys-lru")
            
            # Wait for Redis to be ready
            redis_container.get_connection_url()
            
            # Validate Redis container health
            test_client = redis.Redis.from_url(redis_container.get_connection_url())
            test_client.ping()
            test_client.close()
            
            logger.info(
                "Redis container initialized successfully",
                connection_url=redis_container.get_connection_url(),
                container_id=redis_container.get_container_host_ip()
            )
            
            yield redis_container
    
    @pytest.fixture
    def redis_config(self, redis_container):
        """
        Redis configuration for testing with Testcontainers.
        """
        connection_url = redis_container.get_connection_url()
        
        return {
            'host': redis_container.get_container_host_ip(),
            'port': redis_container.get_exposed_port(6379),
            'db': 0,
            'decode_responses': True,
            'socket_timeout': 30.0,
            'socket_connect_timeout': 10.0,
            'max_connections': 50,
            'retry_on_timeout': True,
            'health_check_interval': 30,
            'connection_pool_class': ConnectionPool
        }
    
    @pytest.fixture
    def redis_client(self, redis_config):
        """
        Redis client fixture with proper cleanup.
        """
        client = create_redis_client(config=redis_config)
        yield client
        if client:
            client.close()
    
    def test_redis_connection_establishment(self, redis_client):
        """
        Test Redis connection establishment with connection pooling.
        
        Validates:
        - Successful connection to Testcontainers Redis instance
        - Connection pool initialization per Section 6.1.3
        - Health check endpoint functionality per Section 6.1.3
        """
        # Test basic connectivity
        assert redis_client.ping() is True
        
        # Validate connection pool configuration
        pool_info = redis_client.get_connection_info()
        assert pool_info['max_connections'] == 50
        assert pool_info['socket_timeout'] == 30.0
        assert pool_info['socket_connect_timeout'] == 10.0
        
        # Test health check functionality
        is_healthy, health_details = redis_client.health_check()
        assert is_healthy is True
        assert 'redis_version' in health_details
        assert 'memory_usage' in health_details
        assert 'connected_clients' in health_details
        
        logger.info(
            "Redis connection established successfully",
            health_details=health_details,
            pool_info=pool_info
        )
    
    def test_connection_pool_efficiency(self, redis_client):
        """
        Test connection pool efficiency and resource optimization.
        
        Validates:
        - Connection pool resource management per Section 6.1.3
        - Concurrent connection handling efficiency
        - Pool exhaustion protection and recovery
        """
        def perform_redis_operations(operation_id: int) -> Dict[str, Any]:
            """Perform Redis operations to test connection pool."""
            start_time = time.time()
            
            # Basic operations
            redis_client.set(f'test_key_{operation_id}', f'test_value_{operation_id}', ttl=60)
            retrieved_value = redis_client.get(f'test_key_{operation_id}')
            redis_client.delete(f'test_key_{operation_id}')
            
            end_time = time.time()
            operation_time = end_time - start_time
            
            return {
                'operation_id': operation_id,
                'operation_time': operation_time,
                'value_match': retrieved_value == f'test_value_{operation_id}',
                'success': True
            }
        
        # Test concurrent operations
        concurrent_operations = 20
        with ThreadPoolExecutor(max_workers=concurrent_operations) as executor:
            futures = [
                executor.submit(perform_redis_operations, i) 
                for i in range(concurrent_operations)
            ]
            
            results = [future.result() for future in as_completed(futures)]
        
        # Validate all operations succeeded
        assert len(results) == concurrent_operations
        successful_operations = [r for r in results if r['success'] and r['value_match']]
        assert len(successful_operations) == concurrent_operations
        
        # Validate performance metrics
        operation_times = [r['operation_time'] for r in results]
        avg_operation_time = sum(operation_times) / len(operation_times)
        max_operation_time = max(operation_times)
        
        # Performance requirements: ≤10ms average, ≤50ms max
        assert avg_operation_time <= 0.010, f"Average operation time {avg_operation_time:.3f}s exceeds 10ms"
        assert max_operation_time <= 0.050, f"Max operation time {max_operation_time:.3f}s exceeds 50ms"
        
        # Validate connection pool statistics
        pool_stats = redis_client.get_stats()
        assert pool_stats['connection_pool']['created_connections'] >= 1
        assert pool_stats['connection_pool']['available_connections'] >= 0
        
        logger.info(
            "Connection pool efficiency validated",
            concurrent_operations=concurrent_operations,
            avg_operation_time=avg_operation_time,
            max_operation_time=max_operation_time,
            pool_stats=pool_stats
        )
    
    def test_circuit_breaker_functionality(self, redis_client):
        """
        Test circuit breaker patterns for Redis connectivity resilience.
        
        Validates:
        - Circuit breaker activation on connection failures per Section 6.1.3
        - Graceful degradation during Redis unavailability
        - Circuit breaker recovery mechanisms
        """
        # Test normal operation first
        assert redis_client.set('circuit_test', 'normal_operation', ttl=60) is True
        assert redis_client.get('circuit_test') == 'normal_operation'
        
        # Simulate Redis connection failures by closing the connection
        original_ping = redis_client._client.ping
        
        def failing_ping():
            raise ConnectionError("Simulated Redis connection failure")
        
        # Test circuit breaker activation
        with patch.object(redis_client._client, 'ping', side_effect=failing_ping):
            with pytest.raises((CircuitBreakerOpenError, RedisConnectionError, CacheError)):
                # Multiple failures should trigger circuit breaker
                for _ in range(10):
                    try:
                        redis_client.set('failing_operation', 'should_fail')
                    except Exception:
                        pass
                
                # This should raise circuit breaker error
                redis_client.set('circuit_breaker_test', 'should_fail')
        
        # Restore normal operation and test recovery
        redis_client._client.ping = original_ping
        
        # Allow circuit breaker to reset (may need to wait)
        time.sleep(1)
        
        # Test recovery
        recovery_success = False
        for attempt in range(5):
            try:
                redis_client.set('recovery_test', 'recovery_successful', ttl=60)
                recovery_value = redis_client.get('recovery_test')
                if recovery_value == 'recovery_successful':
                    recovery_success = True
                    break
            except Exception as e:
                logger.info(f"Recovery attempt {attempt + 1} failed: {e}")
                time.sleep(0.5)
        
        assert recovery_success, "Circuit breaker failed to recover after connection restoration"
        
        logger.info("Circuit breaker functionality validated successfully")
    
    def test_distributed_connection_coordination(self, redis_config):
        """
        Test distributed connection coordination across multiple clients.
        
        Validates:
        - Multiple Redis client coordination per Section 3.4.2
        - Distributed cache coherence and consistency
        - Multi-instance coordination patterns
        """
        # Create multiple Redis clients to simulate distributed deployment
        clients = []
        try:
            for i in range(3):
                client = create_redis_client(config=redis_config)
                clients.append(client)
            
            # Test distributed coordination
            coordination_key = f'distributed_test_{uuid.uuid4()}'
            test_data = {'timestamp': time.time(), 'client_id': 'client_0'}
            
            # Client 0 sets data
            clients[0].set(coordination_key, json.dumps(test_data), ttl=300)
            
            # All clients should read the same data
            for i, client in enumerate(clients):
                retrieved_data = client.get(coordination_key)
                assert retrieved_data is not None
                
                parsed_data = json.loads(retrieved_data)
                assert parsed_data['timestamp'] == test_data['timestamp']
                assert parsed_data['client_id'] == test_data['client_id']
            
            # Test distributed invalidation
            invalidation_pattern = f'distributed_test_*'
            
            # Set multiple keys from different clients
            for i, client in enumerate(clients):
                client.set(f'distributed_test_client_{i}', f'data_from_client_{i}', ttl=300)
            
            # Invalidate from one client
            invalidated_keys = clients[0].delete_pattern(invalidation_pattern)
            assert invalidated_keys >= 3  # At least 3 keys should be invalidated
            
            # Verify invalidation across all clients
            for i, client in enumerate(clients):
                assert client.get(f'distributed_test_client_{i}') is None
            
            logger.info(
                "Distributed connection coordination validated",
                client_count=len(clients),
                invalidated_keys=invalidated_keys
            )
            
        finally:
            # Clean up clients
            for client in clients:
                if client:
                    client.close()


class TestSessionManagementIntegration:
    """
    Test distributed session management across multiple Flask instances
    with comprehensive session security and performance validation.
    """
    
    @pytest.fixture
    def flask_app_with_cache(self, redis_client):
        """
        Flask application with cache extensions configured.
        """
        app = Flask(__name__)
        app.config.update({
            'SECRET_KEY': 'test-secret-key-for-session-testing',
            'TESTING': True,
            'SESSION_TYPE': 'redis',
            'SESSION_PERMANENT': False,
            'SESSION_USE_SIGNER': True,
            'SESSION_KEY_PREFIX': 'test_session:',
            'SESSION_COOKIE_SECURE': False,  # For testing
            'SESSION_COOKIE_HTTPONLY': True,
            'SESSION_COOKIE_SAMESITE': 'Lax',
            'WTF_CSRF_ENABLED': False
        })
        
        # Initialize cache extensions
        cache_extensions = init_cache_extensions(
            app=app,
            redis_config=redis_client.get_connection_info(),
            monitoring_enabled=True
        )
        
        # Add test routes
        @app.route('/set_session/<key>/<value>')
        def set_session_value(key, value):
            session[key] = value
            return jsonify({'status': 'set', 'key': key, 'value': value})
        
        @app.route('/get_session/<key>')
        def get_session_value(key):
            value = session.get(key)
            return jsonify({'key': key, 'value': value})
        
        @app.route('/clear_session')
        def clear_session():
            session.clear()
            return jsonify({'status': 'cleared'})
        
        @app.route('/cached_data/<data_id>')
        @cached_response(ttl=300, policy='public', tags=['test_data'])
        def get_cached_data(data_id):
            # Simulate data processing
            return jsonify({
                'data_id': data_id,
                'timestamp': time.time(),
                'processed': True
            })
        
        yield app, cache_extensions
        
        # Cleanup
        cleanup_cache_resources()
    
    def test_session_persistence_across_requests(self, flask_app_with_cache):
        """
        Test session persistence across multiple requests.
        
        Validates:
        - Session data persistence in Redis per Section 6.4.1
        - Session security and encryption per Section 6.4.3
        - Cross-request session continuity
        """
        app, cache_extensions = flask_app_with_cache
        redis_client = cache_extensions['redis_client']
        
        with app.test_client() as client:
            # Set session data
            response = client.get('/set_session/user_id/test_user_123')
            assert response.status_code == 200
            session_data = response.get_json()
            assert session_data['status'] == 'set'
            
            # Verify session exists in Redis
            redis_keys = redis_client.scan_pattern('test_session:*')
            assert len(redis_keys) >= 1, "Session not found in Redis"
            
            # Retrieve session data in subsequent request
            response = client.get('/get_session/user_id')
            assert response.status_code == 200
            retrieved_data = response.get_json()
            assert retrieved_data['value'] == 'test_user_123'
            
            # Test session data types
            test_cases = [
                ('string_data', 'test_string'),
                ('number_data', 42),
                ('boolean_data', True),
                ('list_data', [1, 2, 3]),
                ('dict_data', {'nested': 'value'})
            ]
            
            for key, value in test_cases:
                # Set complex data
                response = client.get(f'/set_session/{key}/{json.dumps(value)}')
                assert response.status_code == 200
                
                # Retrieve and validate
                response = client.get(f'/get_session/{key}')
                assert response.status_code == 200
                retrieved = response.get_json()
                
                if isinstance(value, (dict, list)):
                    assert json.loads(retrieved['value']) == value
                else:
                    assert retrieved['value'] == str(value)
            
            logger.info("Session persistence across requests validated successfully")
    
    def test_distributed_session_management(self, flask_app_with_cache):
        """
        Test distributed session management across multiple Flask instances.
        
        Validates:
        - Session sharing across multiple Flask instances per Section 3.4.2
        - Distributed session consistency and synchronization
        - Multi-instance session coordination
        """
        app, cache_extensions = flask_app_with_cache
        
        # Simulate multiple Flask instances
        clients = []
        try:
            for i in range(3):
                client = app.test_client()
                clients.append(client)
            
            # Set session data from first client
            session_key = f'distributed_session_{uuid.uuid4()}'
            session_value = f'distributed_value_{time.time()}'
            
            response = clients[0].get(f'/set_session/{session_key}/{session_value}')
            assert response.status_code == 200
            
            # Extract session cookie for sharing across instances
            session_cookie = None
            for cookie in clients[0].cookie_jar:
                if cookie.name == 'session':
                    session_cookie = cookie
                    break
            
            assert session_cookie is not None, "Session cookie not found"
            
            # Share session cookie across all clients
            for client in clients[1:]:
                client.set_cookie('localhost', 'session', session_cookie.value)
            
            # Verify session access from all clients
            for i, client in enumerate(clients):
                response = client.get(f'/get_session/{session_key}')
                assert response.status_code == 200
                
                retrieved_data = response.get_json()
                assert retrieved_data['value'] == session_value
            
            # Test session modification from different instances
            modification_clients = random.sample(clients, 2)
            
            # Client A modifies session
            new_value = f'modified_value_{time.time()}'
            response = modification_clients[0].get(f'/set_session/modified_key/{new_value}')
            assert response.status_code == 200
            
            # Client B reads modification
            response = modification_clients[1].get('/get_session/modified_key')
            assert response.status_code == 200
            retrieved_data = response.get_json()
            assert retrieved_data['value'] == new_value
            
            logger.info(
                "Distributed session management validated",
                client_count=len(clients),
                session_key=session_key
            )
            
        finally:
            # Clear session data
            if clients:
                clients[0].get('/clear_session')
    
    def test_session_security_and_encryption(self, flask_app_with_cache):
        """
        Test session security features and encryption validation.
        
        Validates:
        - Session data encryption in Redis per Section 6.4.3
        - Session security headers and configuration
        - Session tampering protection
        """
        app, cache_extensions = flask_app_with_cache
        redis_client = cache_extensions['redis_client']
        
        with app.test_client() as client:
            # Set sensitive session data
            sensitive_data = {
                'user_id': 'user_123',
                'permissions': ['read', 'write', 'admin'],
                'auth_token': 'sensitive_auth_token_12345'
            }
            
            response = client.get(f'/set_session/sensitive_data/{json.dumps(sensitive_data)}')
            assert response.status_code == 200
            
            # Verify data is encrypted in Redis (not readable as plain text)
            redis_keys = redis_client.scan_pattern('test_session:*')
            assert len(redis_keys) >= 1
            
            for key in redis_keys:
                stored_data = redis_client._client.get(key)
                assert stored_data is not None
                
                # Ensure sensitive data is not stored as plain text
                stored_str = str(stored_data)
                assert 'user_123' not in stored_str
                assert 'sensitive_auth_token_12345' not in stored_str
                assert 'admin' not in stored_str
            
            # Verify session can be properly decrypted and retrieved
            response = client.get('/get_session/sensitive_data')
            assert response.status_code == 200
            retrieved_data = response.get_json()
            
            retrieved_sensitive = json.loads(retrieved_data['value'])
            assert retrieved_sensitive == sensitive_data
            
            logger.info("Session security and encryption validation completed")
    
    def test_session_ttl_management(self, flask_app_with_cache):
        """
        Test session TTL management and expiration policies.
        
        Validates:
        - Session TTL configuration per Section 5.2.7
        - Automatic session cleanup and expiration
        - Session renewal and extension mechanisms
        """
        app, cache_extensions = flask_app_with_cache
        redis_client = cache_extensions['redis_client']
        
        with app.test_client() as client:
            # Set session with default TTL
            response = client.get('/set_session/ttl_test/ttl_test_value')
            assert response.status_code == 200
            
            # Get session key from Redis
            redis_keys = redis_client.scan_pattern('test_session:*')
            assert len(redis_keys) >= 1
            
            session_key = redis_keys[0]
            
            # Check initial TTL
            initial_ttl = redis_client._client.ttl(session_key)
            assert initial_ttl > 0, "Session TTL not set properly"
            
            # Verify session is accessible
            response = client.get('/get_session/ttl_test')
            assert response.status_code == 200
            assert response.get_json()['value'] == 'ttl_test_value'
            
            # Check TTL after access (should be renewed)
            renewed_ttl = redis_client._client.ttl(session_key)
            assert renewed_ttl > 0
            
            # Wait for a short period and check TTL decrease
            time.sleep(2)
            decreased_ttl = redis_client._client.ttl(session_key)
            assert decreased_ttl < initial_ttl, "TTL not decreasing properly"
            
            logger.info(
                "Session TTL management validated",
                initial_ttl=initial_ttl,
                renewed_ttl=renewed_ttl,
                decreased_ttl=decreased_ttl
            )


class TestCacheInvalidationIntegration:
    """
    Test comprehensive cache invalidation patterns and TTL management
    with enterprise-grade invalidation strategies.
    """
    
    @pytest.fixture
    def cache_strategy_manager(self, redis_client):
        """
        Cache strategy manager for invalidation testing.
        """
        invalidation_strategy = CacheInvalidationStrategy(
            redis_client=redis_client,
            monitoring=None
        )
        
        ttl_strategy = TTLManagementStrategy(
            redis_client=redis_client,
            monitoring=None
        )
        
        key_pattern_manager = CacheKeyPatternManager(
            redis_client=redis_client,
            monitoring=None
        )
        
        yield {
            'invalidation': invalidation_strategy,
            'ttl': ttl_strategy,
            'key_pattern': key_pattern_manager,
            'redis_client': redis_client
        }
    
    def test_immediate_cache_invalidation(self, cache_strategy_manager):
        """
        Test immediate cache invalidation patterns.
        
        Validates:
        - Immediate invalidation for critical data per Section 5.2.7
        - Single key and pattern-based invalidation
        - Invalidation performance requirements
        """
        strategies = cache_strategy_manager
        redis_client = strategies['redis_client']
        invalidation_strategy = strategies['invalidation']
        
        # Set up test data
        test_keys = [
            'user:123:profile',
            'user:123:permissions',
            'user:123:session',
            'user:456:profile',
            'api:cache:endpoint_1',
            'api:cache:endpoint_2'
        ]
        
        test_data = {
            'timestamp': time.time(),
            'invalidation_test': True
        }
        
        # Populate cache with test data
        for key in test_keys:
            redis_client.set(key, json.dumps(test_data), ttl=3600)
        
        # Verify all keys exist
        for key in test_keys:
            assert redis_client.get(key) is not None
        
        # Test single key invalidation
        start_time = time.time()
        invalidation_strategy.invalidate_keys(['user:123:profile'])
        single_invalidation_time = time.time() - start_time
        
        assert redis_client.get('user:123:profile') is None
        assert redis_client.get('user:123:permissions') is not None  # Should still exist
        
        # Performance requirement: ≤5ms for single key invalidation
        assert single_invalidation_time <= 0.005, f"Single key invalidation took {single_invalidation_time:.3f}s"
        
        # Test pattern-based invalidation
        start_time = time.time()
        invalidated_count = invalidation_strategy.invalidate_pattern('user:123:*')
        pattern_invalidation_time = time.time() - start_time
        
        assert invalidated_count >= 2  # Should invalidate remaining user:123 keys
        assert redis_client.get('user:123:permissions') is None
        assert redis_client.get('user:123:session') is None
        assert redis_client.get('user:456:profile') is not None  # Different user, should exist
        
        # Performance requirement: ≤50ms for pattern-based invalidation
        assert pattern_invalidation_time <= 0.050, f"Pattern invalidation took {pattern_invalidation_time:.3f}s"
        
        logger.info(
            "Immediate cache invalidation validated",
            single_invalidation_time=single_invalidation_time,
            pattern_invalidation_time=pattern_invalidation_time,
            invalidated_count=invalidated_count
        )
    
    def test_tag_based_invalidation(self, cache_strategy_manager):
        """
        Test tag-based cache invalidation for complex scenarios.
        
        Validates:
        - Tag-based invalidation for related data per Section 5.2.7
        - Cross-cutting invalidation patterns
        - Tag coordination and consistency
        """
        strategies = cache_strategy_manager
        redis_client = strategies['redis_client']
        invalidation_strategy = strategies['invalidation']
        
        # Set up test data with tags
        tagged_data = [
            ('product:123:details', {'tag': 'product:123', 'data': 'product details'}),
            ('product:123:inventory', {'tag': 'product:123', 'data': 'inventory data'}),
            ('product:123:reviews', {'tag': 'product:123', 'data': 'review data'}),
            ('product:456:details', {'tag': 'product:456', 'data': 'other product'}),
            ('user:789:cart', {'tag': 'user:789', 'data': 'cart data'}),
            ('global:featured', {'tag': 'featured', 'data': 'featured products'})
        ]
        
        # Populate cache with tagged data
        for key, data in tagged_data:
            redis_client.set(key, json.dumps(data), ttl=3600)
            # Set tag mapping
            redis_client.sadd(f'cache_tag:{data["tag"]}', key)
        
        # Test tag-based invalidation
        tag_to_invalidate = 'product:123'
        start_time = time.time()
        invalidated_keys = invalidation_strategy.invalidate_by_tag(tag_to_invalidate)
        tag_invalidation_time = time.time() - start_time
        
        # Verify product:123 related data is invalidated
        assert redis_client.get('product:123:details') is None
        assert redis_client.get('product:123:inventory') is None
        assert redis_client.get('product:123:reviews') is None
        
        # Verify other data remains
        assert redis_client.get('product:456:details') is not None
        assert redis_client.get('user:789:cart') is not None
        assert redis_client.get('global:featured') is not None
        
        # Verify tag cleanup
        tag_members = redis_client.smembers(f'cache_tag:{tag_to_invalidate}')
        assert len(tag_members) == 0, "Tag mapping not cleaned up properly"
        
        assert len(invalidated_keys) == 3
        assert tag_invalidation_time <= 0.050, f"Tag invalidation took {tag_invalidation_time:.3f}s"
        
        logger.info(
            "Tag-based cache invalidation validated",
            tag=tag_to_invalidate,
            invalidated_keys=len(invalidated_keys),
            invalidation_time=tag_invalidation_time
        )
    
    def test_ttl_management_strategies(self, cache_strategy_manager):
        """
        Test intelligent TTL management strategies.
        
        Validates:
        - Adaptive TTL policies per Section 5.2.7
        - TTL calculation performance requirements
        - Dynamic TTL adjustment based on access patterns
        """
        strategies = cache_strategy_manager
        redis_client = strategies['redis_client']
        ttl_strategy = strategies['ttl']
        
        # Test different TTL policies
        ttl_test_cases = [
            {
                'key': 'static_content:logo',
                'policy': TTLPolicy.STATIC,
                'expected_ttl_range': (3600, 86400),  # 1 hour to 1 day
                'data': {'type': 'static', 'content': 'logo data'}
            },
            {
                'key': 'user:session:active',
                'policy': TTLPolicy.DYNAMIC,
                'expected_ttl_range': (300, 3600),  # 5 minutes to 1 hour
                'data': {'type': 'session', 'user_id': 'user_123'}
            },
            {
                'key': 'api:cache:frequent',
                'policy': TTLPolicy.ADAPTIVE,
                'expected_ttl_range': (60, 1800),  # 1 minute to 30 minutes
                'data': {'type': 'api_cache', 'endpoint': '/api/frequent'}
            }
        ]
        
        for test_case in ttl_test_cases:
            key = test_case['key']
            policy = test_case['policy']
            expected_range = test_case['expected_ttl_range']
            data = test_case['data']
            
            # Calculate TTL based on policy
            start_time = time.time()
            calculated_ttl = ttl_strategy.calculate_ttl(key, policy, metadata=data)
            ttl_calculation_time = time.time() - start_time
            
            # Performance requirement: ≤1ms for TTL calculation
            assert ttl_calculation_time <= 0.001, f"TTL calculation took {ttl_calculation_time:.3f}s"
            
            # Validate TTL is within expected range
            assert expected_range[0] <= calculated_ttl <= expected_range[1], \
                f"TTL {calculated_ttl} not in expected range {expected_range}"
            
            # Set data with calculated TTL
            redis_client.set(key, json.dumps(data), ttl=calculated_ttl)
            
            # Verify TTL is set correctly
            actual_ttl = redis_client._client.ttl(key)
            assert abs(actual_ttl - calculated_ttl) <= 2, "TTL not set correctly"
        
        # Test TTL adjustment based on access patterns
        frequent_access_key = 'user:profile:frequent'
        redis_client.set(frequent_access_key, json.dumps({'frequent': True}), ttl=300)
        
        # Simulate frequent access
        for _ in range(10):
            redis_client.get(frequent_access_key)
            ttl_strategy.record_access(frequent_access_key)
        
        # Adjust TTL based on access pattern
        new_ttl = ttl_strategy.adjust_ttl_by_access_pattern(frequent_access_key)
        assert new_ttl > 300, "TTL should be increased for frequently accessed data"
        
        logger.info(
            "TTL management strategies validated",
            test_cases=len(ttl_test_cases),
            adaptive_ttl=new_ttl
        )
    
    def test_distributed_invalidation_coordination(self, cache_strategy_manager):
        """
        Test distributed cache invalidation coordination across instances.
        
        Validates:
        - Multi-instance invalidation coordination per Section 3.4.2
        - Distributed invalidation consistency
        - Performance of distributed operations
        """
        strategies = cache_strategy_manager
        redis_client = strategies['redis_client']
        invalidation_strategy = strategies['invalidation']
        
        # Set up distributed test scenario
        instance_prefix = f'instance_{uuid.uuid4()}'
        distributed_keys = [
            f'{instance_prefix}:cache:user:123:profile',
            f'{instance_prefix}:cache:user:123:settings',
            f'{instance_prefix}:cache:api:endpoint:data'
        ]
        
        test_data = {
            'distributed_test': True,
            'timestamp': time.time(),
            'instance_id': instance_prefix
        }
        
        # Populate distributed cache
        for key in distributed_keys:
            redis_client.set(key, json.dumps(test_data), ttl=3600)
            # Add to distributed invalidation set
            redis_client.sadd('distributed_invalidation:user:123', key)
        
        # Test distributed invalidation
        start_time = time.time()
        distributed_keys_invalidated = invalidation_strategy.invalidate_distributed_set('user:123')
        distributed_invalidation_time = time.time() - start_time
        
        # Verify all distributed keys are invalidated
        for key in distributed_keys:
            assert redis_client.get(key) is None, f"Key {key} was not invalidated"
        
        # Verify distributed set is cleaned up
        remaining_keys = redis_client.smembers('distributed_invalidation:user:123')
        assert len(remaining_keys) == 0, "Distributed invalidation set not cleaned up"
        
        # Performance requirement: ≤10ms for distributed coordination
        assert distributed_invalidation_time <= 0.010, \
            f"Distributed invalidation took {distributed_invalidation_time:.3f}s"
        
        assert len(distributed_keys_invalidated) == len(distributed_keys)
        
        logger.info(
            "Distributed invalidation coordination validated",
            keys_invalidated=len(distributed_keys_invalidated),
            invalidation_time=distributed_invalidation_time
        )


class TestResponseCacheIntegration:
    """
    Test Flask-Caching integration with response caching patterns
    and HTTP cache optimization.
    """
    
    @pytest.fixture
    def flask_app_with_response_cache(self, redis_client):
        """
        Flask application with response caching configured.
        """
        app = Flask(__name__)
        app.config.update({
            'SECRET_KEY': 'test-secret-key-response-cache',
            'TESTING': True,
            'CACHE_TYPE': 'RedisCache',
            'CACHE_DEFAULT_TIMEOUT': 300,
            'CACHE_KEY_PREFIX': 'test_response_cache:'
        })
        
        # Initialize cache extensions with response caching
        cache_config = CacheConfiguration(
            policy=CachePolicy.DYNAMIC,
            ttl_seconds=300,
            compression=CompressionType.AUTO,
            vary_headers=['Accept', 'Accept-Encoding', 'Authorization'],
            cache_private_responses=False,
            distributed_invalidation=True
        )
        
        cache_extensions = init_cache_extensions(
            app=app,
            redis_config=redis_client.get_connection_info(),
            response_cache_config=cache_config,
            monitoring_enabled=True
        )
        
        response_cache = cache_extensions['response_cache']
        
        # Add test routes with different caching patterns
        @app.route('/api/public/data/<data_id>')
        @cached_response(ttl=600, policy='public', tags=['public_data'])
        def get_public_data(data_id):
            return jsonify({
                'data_id': data_id,
                'timestamp': time.time(),
                'type': 'public',
                'processing_time': random.uniform(0.1, 0.5)
            })
        
        @app.route('/api/private/user/<user_id>')
        @cached_response(ttl=300, policy='private', tags=['user_data'])
        def get_user_data(user_id):
            return jsonify({
                'user_id': user_id,
                'timestamp': time.time(),
                'type': 'private',
                'processing_time': random.uniform(0.1, 0.5)
            })
        
        @app.route('/api/dynamic/content')
        @cached_response(ttl=60, policy='dynamic', tags=['dynamic_content'])
        def get_dynamic_content():
            return jsonify({
                'content': f'Dynamic content {uuid.uuid4()}',
                'timestamp': time.time(),
                'processing_time': random.uniform(0.1, 0.5)
            })
        
        @app.route('/api/no-cache/sensitive')
        @cached_response(ttl=0, policy='no-cache')
        def get_sensitive_data():
            return jsonify({
                'sensitive': True,
                'timestamp': time.time(),
                'processing_time': random.uniform(0.1, 0.5)
            })
        
        @app.route('/invalidate/<tag>')
        def invalidate_by_tag(tag):
            result = invalidate_cache(tags=[tag])
            return jsonify(result)
        
        yield app, cache_extensions, response_cache
        
        # Cleanup
        cleanup_cache_resources()
    
    def test_response_cache_hit_miss_patterns(self, flask_app_with_response_cache):
        """
        Test response cache hit/miss patterns and performance optimization.
        
        Validates:
        - Cache hit/miss behavior per Section 3.4.2
        - Response cache performance requirements
        - Cache key generation and retrieval
        """
        app, cache_extensions, response_cache = flask_app_with_response_cache
        
        with app.test_client() as client:
            # Test cache miss (first request)
            start_time = time.time()
            response1 = client.get('/api/public/data/test_item_123')
            miss_time = time.time() - start_time
            
            assert response1.status_code == 200
            data1 = response1.get_json()
            
            # Test cache hit (second request)
            start_time = time.time()
            response2 = client.get('/api/public/data/test_item_123')
            hit_time = time.time() - start_time
            
            assert response2.status_code == 200
            data2 = response2.get_json()
            
            # Verify same data returned (cached)
            assert data1['data_id'] == data2['data_id']
            assert data1['timestamp'] == data2['timestamp']  # Should be cached
            
            # Performance requirements
            # Cache hit should be faster than cache miss
            assert hit_time < miss_time, "Cache hit should be faster than cache miss"
            # Cache hit latency: ≤2ms
            assert hit_time <= 0.002, f"Cache hit took {hit_time:.3f}s, exceeds 2ms requirement"
            
            # Test different data_id (should be cache miss)
            response3 = client.get('/api/public/data/test_item_456')
            assert response3.status_code == 200
            data3 = response3.get_json()
            assert data3['data_id'] == 'test_item_456'
            assert data3['timestamp'] != data1['timestamp']  # Different data
            
            logger.info(
                "Response cache hit/miss patterns validated",
                miss_time=miss_time,
                hit_time=hit_time,
                performance_improvement=miss_time / hit_time
            )
    
    def test_cache_policy_enforcement(self, flask_app_with_response_cache):
        """
        Test different cache policy enforcement and behavior.
        
        Validates:
        - Public, private, and no-cache policies per Section 3.4.2
        - Cache headers and HTTP optimization
        - Policy-specific cache behavior
        """
        app, cache_extensions, response_cache = flask_app_with_response_cache
        
        with app.test_client() as client:
            # Test public cache policy
            response = client.get('/api/public/data/public_test')
            assert response.status_code == 200
            
            # Check cache headers for public policy
            cache_control = response.headers.get('Cache-Control', '')
            assert 'public' in cache_control or 'max-age' in cache_control
            
            # Test private cache policy
            response = client.get('/api/private/user/user_123')
            assert response.status_code == 200
            
            # Test dynamic cache policy
            response1 = client.get('/api/dynamic/content')
            assert response1.status_code == 200
            data1 = response1.get_json()
            
            # Wait and test again (should use cache within TTL)
            response2 = client.get('/api/dynamic/content')
            assert response2.status_code == 200
            data2 = response2.get_json()
            
            # Should be cached (same timestamp within TTL)
            assert data1['timestamp'] == data2['timestamp']
            
            # Test no-cache policy
            response1 = client.get('/api/no-cache/sensitive')
            assert response1.status_code == 200
            data1 = response1.get_json()
            
            time.sleep(0.1)  # Small delay
            
            response2 = client.get('/api/no-cache/sensitive')
            assert response2.status_code == 200
            data2 = response2.get_json()
            
            # Should not be cached (different timestamps)
            assert data1['timestamp'] != data2['timestamp']
            
            logger.info("Cache policy enforcement validated successfully")
    
    def test_cache_invalidation_by_tags(self, flask_app_with_response_cache):
        """
        Test tag-based cache invalidation for response cache.
        
        Validates:
        - Tag-based invalidation per Section 5.2.7
        - Response cache tag coordination
        - Invalidation effectiveness and performance
        """
        app, cache_extensions, response_cache = flask_app_with_response_cache
        
        with app.test_client() as client:
            # Populate cache with tagged data
            tagged_endpoints = [
                ('/api/public/data/tagged_1', 'public_data'),
                ('/api/public/data/tagged_2', 'public_data'),
                ('/api/private/user/tagged_user_1', 'user_data'),
                ('/api/dynamic/content', 'dynamic_content')
            ]
            
            cached_responses = {}
            for endpoint, tag in tagged_endpoints:
                response = client.get(endpoint)
                assert response.status_code == 200
                cached_responses[endpoint] = response.get_json()
            
            # Verify data is cached (second requests return same data)
            for endpoint, tag in tagged_endpoints:
                response = client.get(endpoint)
                assert response.status_code == 200
                data = response.get_json()
                assert data['timestamp'] == cached_responses[endpoint]['timestamp']
            
            # Invalidate by tag
            response = client.get('/invalidate/public_data')
            assert response.status_code == 200
            invalidation_result = response.get_json()
            
            # Verify public_data tagged items are invalidated
            public_endpoints = [ep for ep, tag in tagged_endpoints if tag == 'public_data']
            for endpoint in public_endpoints:
                response = client.get(endpoint)
                assert response.status_code == 200
                data = response.get_json()
                # Should be new data (different timestamp)
                assert data['timestamp'] != cached_responses[endpoint]['timestamp']
            
            # Verify other tagged data remains cached
            other_endpoints = [ep for ep, tag in tagged_endpoints if tag != 'public_data']
            for endpoint in other_endpoints:
                response = client.get(endpoint)
                assert response.status_code == 200
                data = response.get_json()
                # Should still be cached (same timestamp)
                assert data['timestamp'] == cached_responses[endpoint]['timestamp']
            
            logger.info(
                "Cache invalidation by tags validated",
                invalidated_endpoints=len(public_endpoints),
                preserved_endpoints=len(other_endpoints)
            )
    
    def test_response_cache_compression(self, flask_app_with_response_cache):
        """
        Test response cache compression and memory optimization.
        
        Validates:
        - Response compression for memory efficiency per Section 3.4.2
        - Compression effectiveness and performance
        - Memory usage optimization
        """
        app, cache_extensions, response_cache = flask_app_with_response_cache
        redis_client = cache_extensions['redis_client']
        
        with app.test_client() as client:
            # Generate large response data for compression testing
            large_data_endpoint = '/api/public/data/large_data_test'
            
            # Mock a large response
            with patch('src.cache.response_cache.uuid.uuid4') as mock_uuid:
                mock_uuid.return_value = 'large_data_test'
                
                # Create large response data
                large_response_data = {
                    'data_id': 'large_data_test',
                    'timestamp': time.time(),
                    'large_content': 'x' * 10000,  # 10KB of data
                    'repeated_data': ['item'] * 1000
                }
                
                with patch.object(app.view_functions['get_public_data'], '__call__') as mock_view:
                    mock_view.return_value = jsonify(large_response_data)
                    
                    # Request large data
                    response = client.get(large_data_endpoint)
                    assert response.status_code == 200
                    
                    # Check if data is cached and compressed
                    cache_keys = redis_client.scan_pattern('test_response_cache:*large_data_test*')
                    assert len(cache_keys) >= 1, "Response not found in cache"
                    
                    # Get cached data size
                    cached_data = redis_client._client.get(cache_keys[0])
                    cached_size = len(cached_data) if cached_data else 0
                    
                    # Original response size
                    original_size = len(json.dumps(large_response_data))
                    
                    # Compression should reduce size
                    compression_ratio = cached_size / original_size if original_size > 0 else 1
                    
                    assert compression_ratio < 0.8, f"Compression ratio {compression_ratio:.2f} not effective"
                    
                    logger.info(
                        "Response cache compression validated",
                        original_size=original_size,
                        cached_size=cached_size,
                        compression_ratio=compression_ratio
                    )


class TestCachePerformanceMonitoring:
    """
    Test cache performance monitoring and metrics collection
    with Prometheus integration.
    """
    
    @pytest.fixture
    def monitoring_enabled_cache(self, redis_client):
        """
        Cache setup with monitoring enabled.
        """
        if not MONITORING_AVAILABLE:
            pytest.skip("Cache monitoring not available")
        
        # Create custom registry for test isolation
        test_registry = CollectorRegistry()
        
        cache_extensions = init_cache_extensions(
            redis_config=redis_client.get_connection_info(),
            monitoring_enabled=True
        )
        
        yield cache_extensions, test_registry
        
        cleanup_cache_resources()
    
    def test_cache_hit_miss_metrics(self, monitoring_enabled_cache):
        """
        Test cache hit/miss ratio monitoring and metrics collection.
        
        Validates:
        - Cache hit/miss metrics tracking per Section 6.1.1
        - Prometheus metrics collection
        - Performance monitoring accuracy
        """
        cache_extensions, test_registry = monitoring_enabled_cache
        redis_client = cache_extensions['redis_client']
        monitoring_manager = cache_extensions['monitoring_manager']
        
        if not monitoring_manager:
            pytest.skip("Monitoring manager not available")
        
        # Perform cache operations to generate metrics
        test_operations = [
            ('cache_hit_test_1', 'hit_test_value_1'),
            ('cache_hit_test_2', 'hit_test_value_2'),
            ('cache_hit_test_3', 'hit_test_value_3')
        ]
        
        # Set data (cache misses)
        for key, value in test_operations:
            redis_client.set(key, value, ttl=300)
        
        # Retrieve data (cache hits)
        for key, expected_value in test_operations:
            retrieved_value = redis_client.get(key)
            assert retrieved_value == expected_value
        
        # Generate some cache misses
        for i in range(5):
            redis_client.get(f'non_existent_key_{i}')
        
        # Get cache statistics
        cache_stats = get_cache_stats()
        assert 'redis' in cache_stats
        
        redis_stats = cache_stats['redis']
        if 'hit_rate' in redis_stats:
            hit_rate = redis_stats['hit_rate']
            assert 0.0 <= hit_rate <= 1.0, f"Invalid hit rate: {hit_rate}"
        
        # Verify monitoring data collection
        if hasattr(monitoring_manager, 'get_metrics_summary'):
            metrics_summary = monitoring_manager.get_metrics_summary()
            assert 'total_operations' in metrics_summary
            assert metrics_summary['total_operations'] > 0
        
        logger.info(
            "Cache hit/miss metrics validated",
            cache_stats=cache_stats,
            test_operations=len(test_operations)
        )
    
    def test_performance_baseline_comparison(self, monitoring_enabled_cache):
        """
        Test performance baseline comparison with Node.js cache implementation.
        
        Validates:
        - Performance variance ≤10% from Node.js baseline per Section 0.1.1
        - Latency measurement and comparison
        - Throughput validation
        """
        cache_extensions, test_registry = monitoring_enabled_cache
        redis_client = cache_extensions['redis_client']
        
        # Node.js baseline performance metrics (simulated)
        nodejs_baseline = {
            'get_latency_ms': 2.5,
            'set_latency_ms': 3.0,
            'throughput_ops_per_sec': 5000
        }
        
        # Performance test parameters
        test_iterations = 100
        performance_data = {
            'get_times': [],
            'set_times': [],
            'total_operations': 0
        }
        
        # Warm up cache
        for i in range(10):
            redis_client.set(f'warmup_{i}', f'warmup_value_{i}', ttl=300)
        
        # Performance testing
        start_total = time.time()
        
        for i in range(test_iterations):
            # Test SET performance
            start_time = time.time()
            redis_client.set(f'perf_test_{i}', f'performance_test_value_{i}', ttl=300)
            set_time = (time.time() - start_time) * 1000  # Convert to milliseconds
            performance_data['set_times'].append(set_time)
            
            # Test GET performance
            start_time = time.time()
            value = redis_client.get(f'perf_test_{i}')
            get_time = (time.time() - start_time) * 1000  # Convert to milliseconds
            performance_data['get_times'].append(get_time)
            
            assert value == f'performance_test_value_{i}'
            performance_data['total_operations'] += 2
        
        total_time = time.time() - start_total
        
        # Calculate performance metrics
        avg_get_time = sum(performance_data['get_times']) / len(performance_data['get_times'])
        avg_set_time = sum(performance_data['set_times']) / len(performance_data['set_times'])
        throughput = performance_data['total_operations'] / total_time
        
        # Performance variance validation (≤10% from baseline)
        get_variance = abs(avg_get_time - nodejs_baseline['get_latency_ms']) / nodejs_baseline['get_latency_ms']
        set_variance = abs(avg_set_time - nodejs_baseline['set_latency_ms']) / nodejs_baseline['set_latency_ms']
        throughput_variance = abs(throughput - nodejs_baseline['throughput_ops_per_sec']) / nodejs_baseline['throughput_ops_per_sec']
        
        assert get_variance <= 0.10, f"GET latency variance {get_variance:.2%} exceeds 10%"
        assert set_variance <= 0.10, f"SET latency variance {set_variance:.2%} exceeds 10%"
        assert throughput_variance <= 0.10, f"Throughput variance {throughput_variance:.2%} exceeds 10%"
        
        logger.info(
            "Performance baseline comparison validated",
            avg_get_time_ms=avg_get_time,
            avg_set_time_ms=avg_set_time,
            throughput_ops_per_sec=throughput,
            get_variance_percent=get_variance * 100,
            set_variance_percent=set_variance * 100,
            throughput_variance_percent=throughput_variance * 100
        )
    
    def test_cache_health_monitoring(self, monitoring_enabled_cache):
        """
        Test comprehensive cache health monitoring and alerting.
        
        Validates:
        - Cache health status monitoring per Section 6.1.1
        - Health check endpoint functionality
        - Monitoring integration and alerting
        """
        cache_extensions, test_registry = monitoring_enabled_cache
        
        # Test cache health status
        health_status = get_cache_health()
        
        assert 'overall_healthy' in health_status
        assert 'redis' in health_status
        assert 'response_cache' in health_status
        assert 'monitoring' in health_status
        assert 'extensions' in health_status
        
        # Validate Redis health
        redis_health = health_status['redis']
        assert 'healthy' in redis_health
        assert redis_health['healthy'] is True
        assert 'details' in redis_health
        
        redis_details = redis_health['details']
        required_health_fields = ['redis_version', 'memory_usage', 'connected_clients']
        for field in required_health_fields:
            assert field in redis_details, f"Missing health field: {field}"
        
        # Validate response cache health
        response_cache_health = health_status['response_cache']
        assert 'healthy' in response_cache_health
        
        # Validate monitoring health
        monitoring_health = health_status['monitoring']
        assert 'available' in monitoring_health
        assert monitoring_health['available'] == MONITORING_AVAILABLE
        
        # Test overall health assessment
        assert health_status['overall_healthy'] is True
        
        # Test health monitoring over time
        health_checks = []
        for i in range(5):
            health = get_cache_health()
            health_checks.append(health['overall_healthy'])
            time.sleep(0.1)
        
        # All health checks should be consistent
        assert all(health_checks), "Inconsistent health status detected"
        
        logger.info(
            "Cache health monitoring validated",
            overall_healthy=health_status['overall_healthy'],
            redis_healthy=redis_health['healthy'],
            monitoring_available=monitoring_health['available'],
            health_checks_performed=len(health_checks)
        )


class TestCircuitBreakerResilience:
    """
    Test circuit breaker patterns for Redis connectivity resilience
    with comprehensive failure scenarios and recovery testing.
    """
    
    @pytest.fixture
    def resilient_cache_client(self, redis_client):
        """
        Cache client with circuit breaker configured for testing.
        """
        # Configure circuit breaker for testing (lower thresholds)
        circuit_breaker_config = {
            'fail_max': 3,  # Lower threshold for testing
            'reset_timeout': 2,  # Shorter timeout for testing
            'expected_exception': (ConnectionError, TimeoutError, ResponseError)
        }
        
        # Apply circuit breaker configuration
        if hasattr(redis_client, 'configure_circuit_breaker'):
            redis_client.configure_circuit_breaker(**circuit_breaker_config)
        
        yield redis_client
    
    def test_circuit_breaker_activation(self, resilient_cache_client):
        """
        Test circuit breaker activation on connection failures.
        
        Validates:
        - Circuit breaker activation on Redis failures per Section 6.1.3
        - Failure threshold enforcement
        - Circuit breaker state transitions
        """
        redis_client = resilient_cache_client
        
        # Test normal operation first
        assert redis_client.set('circuit_test_normal', 'normal_value', ttl=60) is True
        assert redis_client.get('circuit_test_normal') == 'normal_value'
        
        # Simulate Redis connection failures
        original_get = redis_client._client.get
        original_set = redis_client._client.set
        
        def failing_operation(*args, **kwargs):
            raise ConnectionError("Simulated Redis connection failure")
        
        # Mock failing operations to trigger circuit breaker
        with patch.object(redis_client._client, 'get', side_effect=failing_operation):
            with patch.object(redis_client._client, 'set', side_effect=failing_operation):
                
                # Perform operations that should fail and trigger circuit breaker
                failures = 0
                for i in range(5):
                    try:
                        redis_client.set(f'failing_key_{i}', f'failing_value_{i}')
                    except (ConnectionError, CircuitBreakerOpenError, CacheError):
                        failures += 1
                
                # At least some operations should fail (triggering circuit breaker)
                assert failures >= 3, f"Expected at least 3 failures, got {failures}"
        
        # Restore normal operations
        redis_client._client.get = original_get
        redis_client._client.set = original_set
        
        # Test circuit breaker recovery
        recovery_success = False
        max_recovery_attempts = 10
        
        for attempt in range(max_recovery_attempts):
            try:
                # Wait for circuit breaker reset
                time.sleep(0.5)
                
                # Test recovery
                redis_client.set('recovery_test', 'recovery_value', ttl=60)
                recovery_value = redis_client.get('recovery_test')
                
                if recovery_value == 'recovery_value':
                    recovery_success = True
                    break
                    
            except (CircuitBreakerOpenError, CacheError):
                # Circuit breaker still open, continue waiting
                continue
        
        assert recovery_success, "Circuit breaker failed to recover after connection restoration"
        
        logger.info(
            "Circuit breaker activation and recovery validated",
            failures_detected=failures,
            recovery_attempts=attempt + 1
        )
    
    def test_graceful_degradation_patterns(self, resilient_cache_client):
        """
        Test graceful degradation during Redis unavailability.
        
        Validates:
        - Graceful degradation strategies per Section 6.1.3
        - Fallback mechanisms during service unavailability
        - Application continuity during cache failures
        """
        redis_client = resilient_cache_client
        
        # Set up test data before simulating failures
        test_data = {
            'user:123:profile': {'name': 'Test User', 'email': 'test@example.com'},
            'api:cache:endpoint': {'data': 'cached_api_response'},
            'session:abc123': {'user_id': '123', 'permissions': ['read', 'write']}
        }
        
        # Populate cache with test data
        for key, value in test_data.items():
            redis_client.set(key, json.dumps(value), ttl=300)
        
        # Verify data is accessible
        for key, expected_value in test_data.items():
            cached_value = redis_client.get(key)
            assert cached_value is not None
            assert json.loads(cached_value) == expected_value
        
        # Simulate Redis unavailability
        def unavailable_operation(*args, **kwargs):
            raise ConnectionError("Redis service unavailable")
        
        with patch.object(redis_client._client, 'get', side_effect=unavailable_operation):
            with patch.object(redis_client._client, 'set', side_effect=unavailable_operation):
                
                # Test graceful degradation - operations should handle failures gracefully
                degraded_results = {}
                
                for key in test_data.keys():
                    try:
                        # This should fail gracefully without crashing
                        value = redis_client.get(key)
                        degraded_results[key] = value
                    except (ConnectionError, CircuitBreakerOpenError, CacheError) as e:
                        # Expected behavior - record the graceful failure
                        degraded_results[key] = None
                        logger.info(f"Graceful degradation for key {key}: {type(e).__name__}")
                
                # Verify graceful handling (no unhandled exceptions)
                assert len(degraded_results) == len(test_data)
                
                # All values should be None or handled gracefully
                for key, value in degraded_results.items():
                    assert value is None or isinstance(value, str)
        
        # Test service recovery
        recovery_data = {}
        for key, expected_value in test_data.items():
            try:
                # Some data might still be available after recovery
                cached_value = redis_client.get(key)
                if cached_value:
                    recovery_data[key] = json.loads(cached_value)
            except Exception as e:
                logger.info(f"Recovery attempt for {key} failed: {e}")
        
        logger.info(
            "Graceful degradation patterns validated",
            test_keys=len(test_data),
            degraded_results=len(degraded_results),
            recovered_keys=len(recovery_data)
        )
    
    def test_multi_instance_resilience(self, redis_config):
        """
        Test resilience patterns across multiple cache instances.
        
        Validates:
        - Multi-instance resilience coordination per Section 3.4.2
        - Distributed failure handling
        - Instance isolation and recovery
        """
        # Create multiple cache instances
        cache_instances = []
        try:
            for i in range(3):
                instance = create_redis_client(config=redis_config)
                cache_instances.append(instance)
            
            # Test normal multi-instance coordination
            coordination_key = f'multi_instance_test_{uuid.uuid4()}'
            test_value = {'instance_test': True, 'timestamp': time.time()}
            
            # Instance 0 sets data
            cache_instances[0].set(coordination_key, json.dumps(test_value), ttl=300)
            
            # All instances should read the same data
            for i, instance in enumerate(cache_instances):
                retrieved_value = instance.get(coordination_key)
                assert retrieved_value is not None
                parsed_value = json.loads(retrieved_value)
                assert parsed_value == test_value
            
            # Simulate failure in one instance
            failing_instance = cache_instances[1]
            
            def failing_operation(*args, **kwargs):
                raise ConnectionError("Instance connection failure")
            
            with patch.object(failing_instance._client, 'get', side_effect=failing_operation):
                with patch.object(failing_instance._client, 'set', side_effect=failing_operation):
                    
                    # Test that other instances continue working
                    working_instances = [cache_instances[0], cache_instances[2]]
                    
                    for instance in working_instances:
                        # Should still work on non-failing instances
                        value = instance.get(coordination_key)
                        assert value is not None
                        
                        # Set new data
                        new_key = f'resilience_test_{uuid.uuid4()}'
                        instance.set(new_key, 'resilience_value', ttl=300)
                        retrieved = instance.get(new_key)
                        assert retrieved == 'resilience_value'
                    
                    # Failing instance should handle gracefully
                    try:
                        failing_instance.get(coordination_key)
                        assert False, "Expected failure on failing instance"
                    except (ConnectionError, CircuitBreakerOpenError, CacheError):
                        # Expected graceful failure
                        pass
            
            # Test recovery coordination
            time.sleep(1)  # Allow for recovery
            
            # All instances should recover
            recovery_key = f'recovery_coordination_{uuid.uuid4()}'
            recovery_value = 'all_instances_recovered'
            
            # Set from recovered instance
            cache_instances[1].set(recovery_key, recovery_value, ttl=300)
            
            # Verify all instances can access
            for i, instance in enumerate(cache_instances):
                retrieved = instance.get(recovery_key)
                assert retrieved == recovery_value
            
            logger.info(
                "Multi-instance resilience validated",
                instance_count=len(cache_instances),
                coordination_successful=True
            )
            
        finally:
            # Clean up instances
            for instance in cache_instances:
                if instance:
                    instance.close()


# Integration test configuration and markers
pytestmark = [
    pytest.mark.integration,
    pytest.mark.redis,
    pytest.mark.cache,
    pytest.mark.testcontainers
]

# Test execution configuration
def pytest_configure(config):
    """Configure pytest for cache integration testing."""
    config.addinivalue_line(
        "markers", "integration: mark test as integration test requiring external services"
    )
    config.addinivalue_line(
        "markers", "redis: mark test as requiring Redis functionality"
    )
    config.addinivalue_line(
        "markers", "cache: mark test as cache-specific functionality"
    )
    config.addinivalue_line(
        "markers", "testcontainers: mark test as using Testcontainers for service integration"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection to ensure proper ordering and dependencies."""
    # Ensure connection tests run first
    connection_tests = [item for item in items if 'connection' in item.name.lower()]
    other_tests = [item for item in items if 'connection' not in item.name.lower()]
    
    # Reorder items to run connection tests first
    items[:] = connection_tests + other_tests


if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__, "-v", "--tb=short"])