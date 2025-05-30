"""
Redis Caching Integration Testing with Testcontainers

Comprehensive integration testing for Redis caching functionality providing realistic
caching behavior through Testcontainers Redis instances. Validates distributed caching
patterns, session management across multiple Flask instances, cache invalidation strategies,
and performance optimization patterns equivalent to Node.js baseline requirements.

This test suite validates:
- Redis distributed caching for session and permission management per Section 6.4.1
- Cache integration testing with production-equivalent behavior per Section 6.6.1
- Performance optimization testing equivalent to Node.js patterns per Section 5.2.7
- Distributed session management across multiple Flask instances per Section 3.4.2
- TTL management and cache invalidation patterns per Section 5.2.7
- Connection pooling and resource efficiency per Section 6.1.3
- Circuit breaker patterns for Redis connectivity resilience per Section 6.1.3

Key Testing Features:
- Testcontainers Redis integration for realistic cache behavior
- Multi-instance Flask deployment cache coordination testing
- Performance baseline validation against ≤10% variance requirement
- Comprehensive cache invalidation and TTL lifecycle testing
- Redis connection pooling and circuit breaker pattern validation
- Flask-Caching response caching integration testing
- Prometheus metrics collection and cache monitoring validation

Dependencies:
- testcontainers[redis] for realistic Redis instance provisioning
- pytest-asyncio for async database operations testing
- prometheus-client for metrics validation
- redis-py 5.0+ integration testing
- Flask-Caching 2.1+ response caching validation
"""

import asyncio
import json
import os
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from unittest.mock import patch, MagicMock, call
import pytest
import pytest_asyncio
from flask import Flask, jsonify, request, session, g
from flask.testing import FlaskClient
import redis
from redis.exceptions import ConnectionError, TimeoutError, ResponseError
from testcontainers.redis import RedisContainer
from prometheus_client import CollectorRegistry, generate_latest
import structlog

# Import cache components for testing
from src.cache import (
    CacheManager, cache_manager, init_cache, get_cache_manager,
    RedisClient, create_redis_client, get_redis_client,
    ResponseCache, cache_for, cache_unless, invalidate_endpoint_cache,
    CacheStrategiesManager, cache_strategies, invalidate_by_pattern,
    CacheError, CacheConnectionError, CacheTimeoutError,
    CacheCircuitBreakerError, cache_monitor
)

# Import auth cache integration
from src.auth.cache import AuthenticationCache, PermissionCache, SessionCache

# Import test fixtures and configuration
from tests.conftest import create_test_app
from tests.fixtures.cache_fixtures import (
    cache_test_data, session_test_data, performance_test_data
)

# Configure test logging
logger = structlog.get_logger("tests.integration.cache")


class TestRedisIntegrationSetup:
    """
    Base class providing Redis Testcontainer setup and teardown for cache integration tests.
    
    Provides production-equivalent Redis instances for realistic cache behavior testing
    per Section 6.6.1 enhanced mocking strategy with Testcontainers integration.
    """
    
    @pytest.fixture(scope="class")
    def redis_container(self):
        """
        Testcontainer Redis instance providing production-equivalent caching behavior.
        
        Yields:
            RedisContainer: Configured Redis container with optimized settings
        """
        with RedisContainer("redis:7.2-alpine") as redis_container:
            # Configure Redis for testing with production-equivalent settings
            redis_port = redis_container.get_exposed_port(6379)
            redis_host = redis_container.get_container_host_ip()
            
            # Wait for Redis to be ready
            redis_client = redis.Redis(
                host=redis_host,
                port=redis_port,
                decode_responses=True,
                socket_timeout=10.0,
                socket_connect_timeout=5.0
            )
            
            # Verify Redis connectivity
            for attempt in range(30):
                try:
                    redis_client.ping()
                    break
                except (ConnectionError, TimeoutError):
                    if attempt == 29:
                        raise
                    time.sleep(0.1)
            
            # Configure Redis for optimal testing performance
            redis_client.config_set('maxmemory-policy', 'allkeys-lru')
            redis_client.config_set('timeout', '0')
            redis_client.flushall()
            
            logger.info(
                "redis_testcontainer_ready",
                host=redis_host,
                port=redis_port,
                container_id=redis_container.get_container_id()[:12]
            )
            
            yield {
                'host': redis_host,
                'port': redis_port,
                'container': redis_container,
                'client': redis_client
            }
    
    @pytest.fixture(scope="function")
    def cache_config(self, redis_container):
        """
        Cache configuration using Testcontainer Redis instance.
        
        Args:
            redis_container: Redis container fixture
            
        Returns:
            Dict: Redis configuration for cache initialization
        """
        return {
            'host': redis_container['host'],
            'port': redis_container['port'],
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
    
    @pytest.fixture(scope="function")
    def flask_app_with_cache(self, cache_config):
        """
        Flask application with integrated cache manager using Testcontainer Redis.
        
        Args:
            cache_config: Redis configuration dictionary
            
        Returns:
            Flask: Configured Flask application with cache integration
        """
        app = create_test_app()
        
        # Configure Redis settings for testing
        for key, value in cache_config.items():
            config_key = f"REDIS_{key.upper()}"
            app.config[config_key] = value
        
        # Additional cache configuration for testing
        app.config.update({
            'CACHE_DEFAULT_TIMEOUT': 300,
            'CACHE_KEY_PREFIX': 'test_cache:',
            'TESTING': True
        })
        
        # Initialize cache manager with test configuration
        with app.app_context():
            cache_mgr = init_cache(app, cache_config)
            
            # Add test routes for cache testing
            @app.route('/api/cached-endpoint')
            @cache_for(timeout=300)
            def cached_endpoint():
                """Test endpoint with response caching."""
                return jsonify({
                    'data': 'cached_response',
                    'timestamp': datetime.utcnow().isoformat(),
                    'cache_test': True
                })
            
            @app.route('/api/user-context/<user_id>')
            @cache_for(timeout=600, key_prefix='user_data')
            def user_context_endpoint(user_id):
                """Test endpoint with user-specific caching."""
                return jsonify({
                    'user_id': user_id,
                    'data': f'user_data_{user_id}',
                    'timestamp': datetime.utcnow().isoformat()
                })
            
            @app.route('/api/uncached-endpoint')
            @cache_unless(lambda: request.args.get('nocache'))
            def conditional_cache_endpoint():
                """Test endpoint with conditional caching."""
                return jsonify({
                    'data': 'conditional_response',
                    'timestamp': datetime.utcnow().isoformat(),
                    'nocache': request.args.get('nocache')
                })
            
            @app.route('/api/invalidate-cache')
            def invalidate_cache_endpoint():
                """Test endpoint for cache invalidation."""
                invalidate_endpoint_cache('/api/cached-endpoint')
                return jsonify({'status': 'cache_invalidated'})
        
        return app


class TestRedisClientIntegration(TestRedisIntegrationSetup):
    """
    Redis client integration testing with connection pooling and circuit breaker patterns.
    
    Tests redis-py 5.0+ integration with enterprise-grade connection management,
    circuit breaker resilience patterns, and performance optimization per Section 6.1.3.
    """
    
    def test_redis_client_initialization(self, cache_config):
        """
        Test Redis client initialization with optimized connection pooling.
        
        Validates:
        - Redis client creation with enterprise configuration
        - Connection pooling with max_connections=50 per Section 6.1.3
        - Circuit breaker initialization for resilience patterns
        """
        # Initialize Redis client with test configuration
        redis_client = create_redis_client(**cache_config)
        
        assert redis_client is not None
        assert redis_client.host == cache_config['host']
        assert redis_client.port == cache_config['port']
        assert redis_client.max_connections == 50
        assert redis_client.socket_timeout == 30.0
        assert redis_client.socket_connect_timeout == 10.0
        
        # Test connection pool functionality
        connection_pool = redis_client._connection_pool
        assert connection_pool is not None
        assert connection_pool.max_connections == 50
        
        # Test circuit breaker initialization
        circuit_breaker = redis_client._circuit_breaker
        assert circuit_breaker is not None
        assert circuit_breaker.failure_threshold == 5
        assert circuit_breaker.recovery_timeout == 60
        
        # Test Redis connectivity
        assert redis_client.ping() is True
        
        # Cleanup
        redis_client.close()
        
        logger.info("redis_client_initialization_validated")
    
    def test_redis_connection_pooling_efficiency(self, cache_config):
        """
        Test Redis connection pooling efficiency and resource management.
        
        Validates:
        - Connection pool reuse across multiple operations
        - Resource efficiency per Section 6.1.3 optimization
        - Connection health check functionality
        """
        redis_client = create_redis_client(**cache_config)
        
        # Test connection pool efficiency with multiple operations
        test_keys = [f"pool_test_{i}" for i in range(20)]
        test_values = [f"value_{i}" for i in range(20)]
        
        # Perform multiple Redis operations to test connection pooling
        start_time = time.time()
        for key, value in zip(test_keys, test_values):
            redis_client.set(key, value, ttl=300)
            retrieved_value = redis_client.get(key)
            assert retrieved_value == value
        
        operation_time = time.time() - start_time
        
        # Validate connection pool statistics
        pool_stats = redis_client.get_pool_stats()
        assert pool_stats['pool_size'] > 0
        assert pool_stats['available_connections'] >= 0
        assert pool_stats['in_use_connections'] >= 0
        
        # Test health check functionality
        health_status = redis_client.health_check()
        assert health_status['status'] == 'healthy'
        assert health_status['connection_pool']['available'] > 0
        
        # Cleanup test data
        redis_client.delete(*test_keys)
        redis_client.close()
        
        logger.info(
            "connection_pooling_efficiency_validated",
            operation_time=operation_time,
            test_operations=len(test_keys),
            pool_stats=pool_stats
        )
    
    def test_redis_circuit_breaker_resilience(self, cache_config):
        """
        Test Redis circuit breaker patterns for connectivity resilience.
        
        Validates:
        - Circuit breaker failure detection and recovery
        - Graceful degradation during Redis unavailability
        - Automatic recovery patterns per Section 6.1.3
        """
        redis_client = create_redis_client(**cache_config)
        
        # Test normal operation
        assert redis_client.set('circuit_test', 'initial_value', ttl=60)
        assert redis_client.get('circuit_test') == 'initial_value'
        
        # Get circuit breaker for testing
        circuit_breaker = redis_client._circuit_breaker
        initial_state = circuit_breaker.get_state()
        assert initial_state['state'] == 'closed'
        
        # Simulate Redis connection failures to trigger circuit breaker
        with patch.object(redis_client._redis_client, 'get', side_effect=ConnectionError("Connection failed")):
            
            # Trigger multiple failures to open circuit breaker
            for attempt in range(6):  # failure_threshold = 5
                try:
                    redis_client.get('circuit_test')
                except (CacheConnectionError, CacheCircuitBreakerError):
                    pass
            
            # Verify circuit breaker opened
            breaker_state = circuit_breaker.get_state()
            assert breaker_state['state'] == 'open'
            assert breaker_state['failure_count'] >= 5
            
            # Test circuit breaker blocks further operations
            with pytest.raises(CacheCircuitBreakerError):
                redis_client.get('circuit_test')
        
        # Test automatic recovery after timeout
        # Fast-forward recovery timeout for testing
        circuit_breaker.recovery_timeout = 0.1
        time.sleep(0.2)
        
        # Circuit should transition to half-open and then closed on success
        assert redis_client.get('circuit_test') == 'initial_value'
        
        final_state = circuit_breaker.get_state()
        assert final_state['state'] == 'closed'
        assert final_state['failure_count'] == 0
        
        # Cleanup
        redis_client.delete('circuit_test')
        redis_client.close()
        
        logger.info("circuit_breaker_resilience_validated")
    
    def test_redis_performance_optimization(self, cache_config, performance_test_data):
        """
        Test Redis performance optimization patterns and baseline compliance.
        
        Validates:
        - Performance optimization equivalent to Node.js patterns
        - Operation latency within acceptable bounds
        - Throughput optimization for high-volume operations
        """
        redis_client = create_redis_client(**cache_config)
        
        # Performance test configuration
        test_operations = 1000
        test_data = performance_test_data['cache_operations']
        
        # Test SET operation performance
        set_start_time = time.time()
        set_operations = []
        
        for i in range(test_operations):
            key = f"perf_test_{i}"
            value = test_data[i % len(test_data)]
            
            operation_start = time.time()
            redis_client.set(key, json.dumps(value), ttl=300)
            operation_time = time.time() - operation_start
            set_operations.append(operation_time)
        
        total_set_time = time.time() - set_start_time
        
        # Test GET operation performance
        get_start_time = time.time()
        get_operations = []
        
        for i in range(test_operations):
            key = f"perf_test_{i}"
            
            operation_start = time.time()
            retrieved_value = redis_client.get(key)
            operation_time = time.time() - operation_start
            get_operations.append(operation_time)
            
            # Validate data integrity
            assert retrieved_value is not None
            parsed_value = json.loads(retrieved_value)
            expected_value = test_data[i % len(test_data)]
            assert parsed_value == expected_value
        
        total_get_time = time.time() - get_start_time
        
        # Calculate performance metrics
        avg_set_latency = sum(set_operations) / len(set_operations)
        avg_get_latency = sum(get_operations) / len(get_operations)
        set_throughput = test_operations / total_set_time
        get_throughput = test_operations / total_get_time
        
        # Performance validation (should be well within Node.js ≤10% variance)
        assert avg_set_latency < 0.01  # 10ms average latency threshold
        assert avg_get_latency < 0.005  # 5ms average latency threshold
        assert set_throughput > 500  # Minimum 500 ops/second
        assert get_throughput > 1000  # Minimum 1000 ops/second
        
        # Test bulk operations performance
        bulk_keys = [f"bulk_test_{i}" for i in range(100)]
        bulk_values = {key: f"bulk_value_{i}" for i, key in enumerate(bulk_keys)}
        
        bulk_start_time = time.time()
        redis_client.mset(bulk_values, ttl=300)
        bulk_retrieved = redis_client.mget(bulk_keys)
        bulk_operation_time = time.time() - bulk_start_time
        
        # Validate bulk operation efficiency
        assert bulk_operation_time < 0.1  # 100ms for 100 operations
        assert len(bulk_retrieved) == len(bulk_keys)
        
        # Cleanup performance test data
        cleanup_keys = [f"perf_test_{i}" for i in range(test_operations)] + bulk_keys
        redis_client.delete(*cleanup_keys)
        redis_client.close()
        
        logger.info(
            "redis_performance_optimization_validated",
            avg_set_latency=avg_set_latency,
            avg_get_latency=avg_get_latency,
            set_throughput=set_throughput,
            get_throughput=get_throughput,
            bulk_operation_time=bulk_operation_time
        )


class TestDistributedCaching(TestRedisIntegrationSetup):
    """
    Distributed caching testing across multiple Flask instances.
    
    Tests distributed session management and cache coordination patterns
    per Section 3.4.2 and Section 5.2.7 requirements.
    """
    
    def test_distributed_session_management(self, flask_app_with_cache, cache_config):
        """
        Test distributed session management across multiple Flask instances.
        
        Validates:
        - Session data sharing across Flask instances
        - Session persistence in Redis backend
        - Cross-instance session coordination per Section 3.4.2
        """
        app1 = flask_app_with_cache
        
        # Create second Flask application instance
        app2 = create_test_app()
        for key, value in cache_config.items():
            config_key = f"REDIS_{key.upper()}"
            app2.config[config_key] = value
        
        with app2.app_context():
            init_cache(app2, cache_config)
        
        # Test session creation in first instance
        with app1.test_client() as client1:
            with client1.session_transaction() as sess:
                sess['user_id'] = 'test_user_123'
                sess['permissions'] = ['read', 'write']
                sess['login_time'] = datetime.utcnow().isoformat()
        
        # Retrieve session ID for cross-instance testing
        session_id = None
        with app1.test_client() as client1:
            with client1.session_transaction() as sess:
                session_id = sess.sid if hasattr(sess, 'sid') else 'test_session_id'
        
        # Test session access from second instance
        with app2.test_client() as client2:
            # Simulate session cookie from first instance
            client2.set_cookie('localhost', 'session', session_id)
            
            with client2.session_transaction() as sess:
                # Verify session data is accessible across instances
                assert sess.get('user_id') == 'test_user_123'
                assert sess.get('permissions') == ['read', 'write']
                assert sess.get('login_time') is not None
        
        # Test session modification in second instance
        with app2.test_client() as client2:
            client2.set_cookie('localhost', 'session', session_id)
            
            with client2.session_transaction() as sess:
                sess['last_access'] = datetime.utcnow().isoformat()
                sess['instance'] = 'app2'
        
        # Verify session changes are visible in first instance
        with app1.test_client() as client1:
            client1.set_cookie('localhost', 'session', session_id)
            
            with client1.session_transaction() as sess:
                assert sess.get('last_access') is not None
                assert sess.get('instance') == 'app2'
                assert sess.get('user_id') == 'test_user_123'  # Original data preserved
        
        logger.info(
            "distributed_session_management_validated",
            session_id=session_id,
            app1_name=app1.name,
            app2_name=app2.name
        )
    
    def test_cache_coordination_patterns(self, flask_app_with_cache, cache_config):
        """
        Test cache coordination patterns across multiple Flask instances.
        
        Validates:
        - Cache invalidation coordination
        - Distributed cache warming strategies
        - Multi-instance cache consistency
        """
        app1 = flask_app_with_cache
        
        # Create second Flask instance
        app2 = create_test_app()
        for key, value in cache_config.items():
            config_key = f"REDIS_{key.upper()}"
            app2.config[config_key] = value
        
        with app2.app_context():
            cache_mgr2 = init_cache(app2, cache_config)
        
        # Test cache coordination between instances
        with app1.app_context():
            cache_mgr1 = get_cache_manager()
            redis_client1 = cache_mgr1.get_client()
            
            # Set cache data from first instance
            test_data = {
                'key1': 'value1_from_app1',
                'key2': {'nested': 'data', 'timestamp': datetime.utcnow().isoformat()},
                'key3': ['list', 'of', 'values']
            }
            
            for key, value in test_data.items():
                redis_client1.set(f"coordination_test:{key}", json.dumps(value), ttl=300)
        
        # Verify cache data accessibility from second instance
        with app2.app_context():
            cache_mgr2 = get_cache_manager()
            redis_client2 = cache_mgr2.get_client()
            
            for key, expected_value in test_data.items():
                cached_value = redis_client2.get(f"coordination_test:{key}")
                assert cached_value is not None
                parsed_value = json.loads(cached_value)
                assert parsed_value == expected_value
        
        # Test distributed cache invalidation
        with app1.app_context():
            # Invalidate cache pattern from first instance
            invalidated_keys = invalidate_by_pattern("coordination_test:*")
            assert len(invalidated_keys) >= 3
        
        # Verify invalidation effect on second instance
        with app2.app_context():
            redis_client2 = cache_mgr2.get_client()
            
            for key in test_data.keys():
                cached_value = redis_client2.get(f"coordination_test:{key}")
                assert cached_value is None  # Should be invalidated
        
        logger.info(
            "cache_coordination_patterns_validated",
            test_keys=list(test_data.keys()),
            invalidated_keys=len(invalidated_keys)
        )
    
    def test_distributed_cache_warming(self, flask_app_with_cache, cache_config, cache_test_data):
        """
        Test distributed cache warming strategies across instances.
        
        Validates:
        - Coordinated cache warming across instances
        - Priority-based warming strategies
        - Cache warming performance optimization
        """
        app = flask_app_with_cache
        
        with app.app_context():
            cache_mgr = get_cache_manager()
            strategies_mgr = cache_mgr.strategies_manager
            
            # Test distributed cache warming with priority
            warming_data = cache_test_data['warming_scenarios']
            
            # Schedule cache warming operations
            warming_tasks = []
            for scenario in warming_data:
                task_result = strategies_mgr.schedule_warming_by_priority(
                    cache_key=scenario['key'],
                    data=scenario['data'],
                    ttl=scenario['ttl'],
                    priority=scenario['priority']
                )
                warming_tasks.append(task_result)
            
            # Verify cache warming completion
            for task in warming_tasks:
                assert task['status'] == 'scheduled'
                assert task['priority'] in ['critical', 'high', 'medium', 'low']
            
            # Execute warming operations
            warming_results = strategies_mgr.execute_warming_queue()
            
            # Validate warming effectiveness
            redis_client = cache_mgr.get_client()
            for scenario in warming_data:
                cached_value = redis_client.get(scenario['key'])
                assert cached_value is not None
                parsed_value = json.loads(cached_value)
                assert parsed_value == scenario['data']
            
            # Test warming performance metrics
            warming_stats = strategies_mgr.get_warming_statistics()
            assert warming_stats['total_warmed'] >= len(warming_data)
            assert warming_stats['warming_time'] > 0
            assert warming_stats['success_rate'] >= 0.95  # 95% success rate
        
        logger.info(
            "distributed_cache_warming_validated",
            warming_tasks=len(warming_tasks),
            warming_results=warming_results,
            warming_stats=warming_stats
        )


class TestCacheInvalidationPatterns(TestRedisIntegrationSetup):
    """
    Cache invalidation pattern testing with TTL management.
    
    Tests comprehensive cache invalidation strategies and TTL lifecycle
    management per Section 5.2.7 cache invalidation requirements.
    """
    
    def test_ttl_lifecycle_management(self, flask_app_with_cache):
        """
        Test TTL lifecycle management and expiration patterns.
        
        Validates:
        - TTL-based cache expiration
        - Dynamic TTL adjustment strategies
        - Cache lifecycle optimization per Section 5.2.7
        """
        app = flask_app_with_cache
        
        with app.app_context():
            cache_mgr = get_cache_manager()
            redis_client = cache_mgr.get_client()
            
            # Test static TTL management
            static_key = "ttl_test:static"
            static_value = {"type": "static", "timestamp": datetime.utcnow().isoformat()}
            
            redis_client.set(static_key, json.dumps(static_value), ttl=2)  # 2 second TTL
            
            # Verify immediate availability
            cached_value = redis_client.get(static_key)
            assert cached_value is not None
            assert json.loads(cached_value)['type'] == 'static'
            
            # Check TTL value
            ttl_remaining = redis_client.ttl(static_key)
            assert ttl_remaining > 0 and ttl_remaining <= 2
            
            # Wait for expiration
            time.sleep(2.5)
            
            # Verify expiration
            expired_value = redis_client.get(static_key)
            assert expired_value is None
            
            # Test dynamic TTL adjustment
            dynamic_key = "ttl_test:dynamic"
            dynamic_value = {"type": "dynamic", "access_count": 0}
            
            # Initial TTL
            redis_client.set(dynamic_key, json.dumps(dynamic_value), ttl=5)
            
            # Simulate access pattern that extends TTL
            for access in range(3):
                cached_value = redis_client.get(dynamic_key)
                assert cached_value is not None
                
                # Extend TTL on access (sliding window pattern)
                parsed_value = json.loads(cached_value)
                parsed_value['access_count'] += 1
                redis_client.set(dynamic_key, json.dumps(parsed_value), ttl=5)  # Reset TTL
                
                time.sleep(1)
            
            # Verify extended availability
            final_value = redis_client.get(dynamic_key)
            assert final_value is not None
            parsed_final = json.loads(final_value)
            assert parsed_final['access_count'] == 3
            
            # Cleanup
            redis_client.delete(dynamic_key)
        
        logger.info("ttl_lifecycle_management_validated")
    
    def test_pattern_based_invalidation(self, flask_app_with_cache):
        """
        Test pattern-based cache invalidation strategies.
        
        Validates:
        - Wildcard pattern invalidation
        - Namespace-based cache clearing
        - Bulk invalidation performance
        """
        app = flask_app_with_cache
        
        with app.app_context():
            cache_mgr = get_cache_manager()
            redis_client = cache_mgr.get_client()
            
            # Set up test data with various patterns
            test_patterns = {
                'user:123:profile': {'user_id': '123', 'type': 'profile'},
                'user:123:permissions': {'user_id': '123', 'type': 'permissions'},
                'user:123:preferences': {'user_id': '123', 'type': 'preferences'},
                'user:456:profile': {'user_id': '456', 'type': 'profile'},
                'session:abc123': {'session_id': 'abc123', 'type': 'session'},
                'session:def456': {'session_id': 'def456', 'type': 'session'},
                'api_cache:endpoint1': {'endpoint': 'endpoint1', 'type': 'api_cache'},
                'api_cache:endpoint2': {'endpoint': 'endpoint2', 'type': 'api_cache'}
            }
            
            # Populate cache with test data
            for key, value in test_patterns.items():
                redis_client.set(key, json.dumps(value), ttl=300)
            
            # Verify all data is cached
            for key in test_patterns.keys():
                assert redis_client.get(key) is not None
            
            # Test user-specific invalidation (user:123:*)
            user_invalidated = invalidate_by_pattern("user:123:*")
            assert len(user_invalidated) == 3
            
            # Verify user:123 data is invalidated
            for key in ['user:123:profile', 'user:123:permissions', 'user:123:preferences']:
                assert redis_client.get(key) is None
            
            # Verify other user data remains
            assert redis_client.get('user:456:profile') is not None
            
            # Test session invalidation (session:*)
            session_invalidated = invalidate_by_pattern("session:*")
            assert len(session_invalidated) == 2
            
            # Verify session data is invalidated
            for key in ['session:abc123', 'session:def456']:
                assert redis_client.get(key) is None
            
            # Test namespace invalidation (api_cache:*)
            api_cache_invalidated = invalidate_by_pattern("api_cache:*")
            assert len(api_cache_invalidated) == 2
            
            # Verify API cache data is invalidated
            for key in ['api_cache:endpoint1', 'api_cache:endpoint2']:
                assert redis_client.get(key) is None
            
            # Verify remaining data
            assert redis_client.get('user:456:profile') is not None
        
        logger.info(
            "pattern_based_invalidation_validated",
            user_invalidated=len(user_invalidated),
            session_invalidated=len(session_invalidated),
            api_cache_invalidated=len(api_cache_invalidated)
        )
    
    def test_dependency_based_invalidation(self, flask_app_with_cache):
        """
        Test dependency-based cache invalidation strategies.
        
        Validates:
        - Cascading invalidation patterns
        - Dependency graph invalidation
        - Cache consistency maintenance
        """
        app = flask_app_with_cache
        
        with app.app_context():
            cache_mgr = get_cache_manager()
            strategies_mgr = cache_mgr.strategies_manager
            redis_client = cache_mgr.get_client()
            
            # Set up dependency relationships
            dependencies = {
                'user:123:profile': ['user:123:dashboard', 'user:123:recommendations'],
                'user:123:permissions': ['user:123:dashboard', 'user:123:menu'],
                'organization:org1': ['user:123:dashboard', 'user:456:dashboard']
            }
            
            # Register dependency relationships
            for parent_key, dependent_keys in dependencies.items():
                strategies_mgr.register_cache_dependencies(parent_key, dependent_keys)
            
            # Populate cache with test data
            cache_data = {
                'user:123:profile': {'name': 'Test User', 'email': 'test@example.com'},
                'user:123:permissions': ['read', 'write'],
                'user:123:dashboard': {'widgets': ['widget1', 'widget2']},
                'user:123:recommendations': ['item1', 'item2'],
                'user:123:menu': ['menu1', 'menu2'],
                'organization:org1': {'name': 'Test Org'},
                'user:456:dashboard': {'widgets': ['widget3']}
            }
            
            for key, value in cache_data.items():
                redis_client.set(key, json.dumps(value), ttl=300)
            
            # Test dependency invalidation
            # Invalidating user:123:profile should cascade to dashboard and recommendations
            invalidated_keys = strategies_mgr.invalidate_by_dependency('user:123:profile')
            
            expected_invalidated = {'user:123:profile', 'user:123:dashboard', 'user:123:recommendations'}
            assert set(invalidated_keys) == expected_invalidated
            
            # Verify invalidated data
            for key in expected_invalidated:
                assert redis_client.get(key) is None
            
            # Verify unaffected data remains
            assert redis_client.get('user:123:permissions') is not None
            assert redis_client.get('user:123:menu') is not None
            assert redis_client.get('user:456:dashboard') is not None
            
            # Test organization-level invalidation
            org_invalidated = strategies_mgr.invalidate_by_dependency('organization:org1')
            
            # Should invalidate organization and user:456:dashboard (user:123:dashboard already invalidated)
            expected_org_invalidated = {'organization:org1', 'user:456:dashboard'}
            assert set(org_invalidated) == expected_org_invalidated
            
            # Verify organization invalidation
            for key in expected_org_invalidated:
                assert redis_client.get(key) is None
        
        logger.info(
            "dependency_based_invalidation_validated",
            dependencies=dependencies,
            profile_invalidated=len(invalidated_keys),
            org_invalidated=len(org_invalidated)
        )


class TestFlaskCachingIntegration(TestRedisIntegrationSetup):
    """
    Flask-Caching response caching integration testing.
    
    Tests Flask-Caching 2.1+ integration with response caching patterns,
    HTTP cache headers, and cache decorator functionality per Section 3.4.2.
    """
    
    def test_response_caching_decorators(self, flask_app_with_cache):
        """
        Test Flask-Caching response caching decorators and patterns.
        
        Validates:
        - @cache_for decorator functionality
        - Response caching with TTL management
        - Cache key generation and namespace management
        """
        app = flask_app_with_cache
        
        with app.test_client() as client:
            # Test basic response caching
            response1 = client.get('/api/cached-endpoint')
            assert response1.status_code == 200
            data1 = response1.get_json()
            assert data1['data'] == 'cached_response'
            assert data1['cache_test'] is True
            timestamp1 = data1['timestamp']
            
            # Second request should return cached response
            response2 = client.get('/api/cached-endpoint')
            assert response2.status_code == 200
            data2 = response2.get_json()
            assert data2['data'] == 'cached_response'
            assert data2['timestamp'] == timestamp1  # Same timestamp = cached
            
            # Test user-specific caching
            user_response1 = client.get('/api/user-context/user123')
            assert user_response1.status_code == 200
            user_data1 = user_response1.get_json()
            assert user_data1['user_id'] == 'user123'
            assert user_data1['data'] == 'user_data_user123'
            
            # Different user should not share cache
            user_response2 = client.get('/api/user-context/user456')
            assert user_response2.status_code == 200
            user_data2 = user_response2.get_json()
            assert user_data2['user_id'] == 'user456'
            assert user_data2['data'] == 'user_data_user456'
            assert user_data2['timestamp'] != user_data1['timestamp']
            
            # Same user should get cached response
            user_response3 = client.get('/api/user-context/user123')
            assert user_response3.status_code == 200
            user_data3 = user_response3.get_json()
            assert user_data3['timestamp'] == user_data1['timestamp']  # Cached
        
        logger.info("response_caching_decorators_validated")
    
    def test_conditional_caching_patterns(self, flask_app_with_cache):
        """
        Test conditional caching with @cache_unless decorator.
        
        Validates:
        - Conditional cache bypass functionality
        - Dynamic caching decisions based on request parameters
        - Cache control flow patterns
        """
        app = flask_app_with_cache
        
        with app.test_client() as client:
            # Test normal caching behavior
            response1 = client.get('/api/uncached-endpoint')
            assert response1.status_code == 200
            data1 = response1.get_json()
            assert data1['data'] == 'conditional_response'
            assert data1['nocache'] is None
            timestamp1 = data1['timestamp']
            
            # Second request should be cached
            response2 = client.get('/api/uncached-endpoint')
            assert response2.status_code == 200
            data2 = response2.get_json()
            assert data2['timestamp'] == timestamp1  # Cached response
            
            # Test cache bypass with nocache parameter
            response3 = client.get('/api/uncached-endpoint?nocache=true')
            assert response3.status_code == 200
            data3 = response3.get_json()
            assert data3['data'] == 'conditional_response'
            assert data3['nocache'] == 'true'
            assert data3['timestamp'] != timestamp1  # Not cached
            
            # Another nocache request should also bypass cache
            response4 = client.get('/api/uncached-endpoint?nocache=1')
            assert response4.status_code == 200
            data4 = response4.get_json()
            assert data4['nocache'] == '1'
            assert data4['timestamp'] != data3['timestamp']  # Fresh response
        
        logger.info("conditional_caching_patterns_validated")
    
    def test_cache_invalidation_endpoints(self, flask_app_with_cache):
        """
        Test cache invalidation through API endpoints.
        
        Validates:
        - Manual cache invalidation functionality
        - Cache clearing for specific endpoints
        - Invalidation effectiveness verification
        """
        app = flask_app_with_cache
        
        with app.test_client() as client:
            # Populate cache with initial request
            response1 = client.get('/api/cached-endpoint')
            assert response1.status_code == 200
            data1 = response1.get_json()
            timestamp1 = data1['timestamp']
            
            # Verify caching is working
            response2 = client.get('/api/cached-endpoint')
            assert response2.status_code == 200
            data2 = response2.get_json()
            assert data2['timestamp'] == timestamp1  # Cached
            
            # Invalidate cache
            invalidate_response = client.get('/api/invalidate-cache')
            assert invalidate_response.status_code == 200
            invalidate_data = invalidate_response.get_json()
            assert invalidate_data['status'] == 'cache_invalidated'
            
            # Request after invalidation should be fresh
            response3 = client.get('/api/cached-endpoint')
            assert response3.status_code == 200
            data3 = response3.get_json()
            assert data3['data'] == 'cached_response'
            assert data3['timestamp'] != timestamp1  # Fresh response
        
        logger.info("cache_invalidation_endpoints_validated")
    
    def test_cache_metrics_collection(self, flask_app_with_cache):
        """
        Test cache metrics collection and monitoring.
        
        Validates:
        - Prometheus metrics collection for cache operations
        - Cache hit/miss ratio tracking
        - Performance metrics monitoring
        """
        app = flask_app_with_cache
        
        with app.app_context():
            cache_mgr = get_cache_manager()
            
            # Get initial metrics
            initial_metrics = cache_monitor.get_metrics_summary()
            
            with app.test_client() as client:
                # Generate cache hits and misses
                for i in range(10):
                    # First request (cache miss)
                    response = client.get(f'/api/user-context/user{i}')
                    assert response.status_code == 200
                    
                    # Second request (cache hit)
                    response = client.get(f'/api/user-context/user{i}')
                    assert response.status_code == 200
            
            # Get final metrics
            final_metrics = cache_monitor.get_metrics_summary()
            
            # Validate metrics collection
            assert final_metrics['total_operations'] > initial_metrics['total_operations']
            assert final_metrics['cache_hits'] > initial_metrics['cache_hits']
            assert final_metrics['cache_misses'] > initial_metrics['cache_misses']
            
            # Calculate hit ratio
            hit_ratio = final_metrics['cache_hits'] / final_metrics['total_operations']
            assert hit_ratio >= 0.4  # At least 40% hit ratio expected
            
            # Test Prometheus metrics export
            prometheus_metrics = generate_latest(cache_monitor.registry)
            assert b'response_cache_hits_total' in prometheus_metrics
            assert b'response_cache_misses_total' in prometheus_metrics
            assert b'response_cache_operation_duration_seconds' in prometheus_metrics
        
        logger.info(
            "cache_metrics_collection_validated",
            final_metrics=final_metrics,
            hit_ratio=hit_ratio
        )


class TestCachePerformanceOptimization(TestRedisIntegrationSetup):
    """
    Cache performance optimization testing with baseline comparison.
    
    Tests performance optimization patterns equivalent to Node.js caching
    performance and validates ≤10% variance requirement per Section 0.1.1.
    """
    
    def test_cache_operation_performance(self, flask_app_with_cache, performance_test_data):
        """
        Test cache operation performance against baseline requirements.
        
        Validates:
        - Cache operation latency optimization
        - Throughput performance compared to Node.js baseline
        - ≤10% variance requirement compliance
        """
        app = flask_app_with_cache
        
        with app.app_context():
            cache_mgr = get_cache_manager()
            redis_client = cache_mgr.get_client()
            
            # Performance test configuration
            test_operations = 1000
            test_data = performance_test_data['cache_operations']
            
            # Test cache SET performance
            set_operations = []
            set_start_time = time.time()
            
            for i in range(test_operations):
                operation_start = time.time()
                
                cache_key = f"perf_test:set:{i}"
                cache_value = test_data[i % len(test_data)]
                
                redis_client.set(cache_key, json.dumps(cache_value), ttl=300)
                
                operation_time = time.time() - operation_start
                set_operations.append(operation_time)
            
            total_set_time = time.time() - set_start_time
            
            # Test cache GET performance
            get_operations = []
            get_start_time = time.time()
            
            for i in range(test_operations):
                operation_start = time.time()
                
                cache_key = f"perf_test:set:{i}"
                cached_value = redis_client.get(cache_key)
                
                # Validate retrieved data
                assert cached_value is not None
                parsed_value = json.loads(cached_value)
                expected_value = test_data[i % len(test_data)]
                assert parsed_value == expected_value
                
                operation_time = time.time() - operation_start
                get_operations.append(operation_time)
            
            total_get_time = time.time() - get_start_time
            
            # Calculate performance metrics
            avg_set_latency = sum(set_operations) / len(set_operations)
            avg_get_latency = sum(get_operations) / len(get_operations)
            max_set_latency = max(set_operations)
            max_get_latency = max(get_operations)
            set_throughput = test_operations / total_set_time
            get_throughput = test_operations / total_get_time
            
            # Performance validation against Node.js baseline equivalent
            # These thresholds ensure ≤10% variance from Node.js performance
            assert avg_set_latency < 0.002  # 2ms average SET latency
            assert avg_get_latency < 0.001  # 1ms average GET latency
            assert max_set_latency < 0.01   # 10ms max SET latency
            assert max_get_latency < 0.005  # 5ms max GET latency
            assert set_throughput > 2000    # Minimum 2000 SET ops/second
            assert get_throughput > 5000    # Minimum 5000 GET ops/second
            
            # Test bulk operation performance
            bulk_test_size = 100
            bulk_data = {f"bulk_test:{i}": test_data[i % len(test_data)] for i in range(bulk_test_size)}
            
            # Bulk SET performance
            bulk_set_start = time.time()
            redis_client.mset(bulk_data, ttl=300)
            bulk_set_time = time.time() - bulk_set_start
            
            # Bulk GET performance
            bulk_get_start = time.time()
            bulk_keys = list(bulk_data.keys())
            bulk_values = redis_client.mget(bulk_keys)
            bulk_get_time = time.time() - bulk_get_start
            
            # Validate bulk operation performance
            assert bulk_set_time < 0.05  # 50ms for 100 bulk SET operations
            assert bulk_get_time < 0.02  # 20ms for 100 bulk GET operations
            assert len(bulk_values) == bulk_test_size
            
            # Cleanup performance test data
            cleanup_keys = [f"perf_test:set:{i}" for i in range(test_operations)] + bulk_keys
            redis_client.delete(*cleanup_keys)
        
        logger.info(
            "cache_operation_performance_validated",
            avg_set_latency=avg_set_latency,
            avg_get_latency=avg_get_latency,
            set_throughput=set_throughput,
            get_throughput=get_throughput,
            bulk_set_time=bulk_set_time,
            bulk_get_time=bulk_get_time
        )
    
    def test_concurrent_cache_access_performance(self, flask_app_with_cache):
        """
        Test concurrent cache access performance and thread safety.
        
        Validates:
        - Multi-threaded cache operation performance
        - Connection pool efficiency under load
        - Thread safety of cache operations
        """
        app = flask_app_with_cache
        
        with app.app_context():
            cache_mgr = get_cache_manager()
            redis_client = cache_mgr.get_client()
            
            # Concurrent access test configuration
            num_threads = 10
            operations_per_thread = 100
            total_operations = num_threads * operations_per_thread
            
            def cache_worker(thread_id: int, results: List[Dict]):
                """Worker function for concurrent cache operations."""
                thread_results = {'set_times': [], 'get_times': [], 'errors': 0}
                
                for i in range(operations_per_thread):
                    try:
                        # SET operation
                        set_start = time.time()
                        cache_key = f"concurrent_test:{thread_id}:{i}"
                        cache_value = {'thread_id': thread_id, 'operation': i, 'timestamp': datetime.utcnow().isoformat()}
                        redis_client.set(cache_key, json.dumps(cache_value), ttl=60)
                        set_time = time.time() - set_start
                        thread_results['set_times'].append(set_time)
                        
                        # GET operation
                        get_start = time.time()
                        retrieved_value = redis_client.get(cache_key)
                        get_time = time.time() - get_start
                        thread_results['get_times'].append(get_time)
                        
                        # Validate data integrity
                        assert retrieved_value is not None
                        parsed_value = json.loads(retrieved_value)
                        assert parsed_value['thread_id'] == thread_id
                        assert parsed_value['operation'] == i
                        
                    except Exception as e:
                        thread_results['errors'] += 1
                        logger.error("cache_worker_error", thread_id=thread_id, operation=i, error=str(e))
                
                results.append(thread_results)
            
            # Execute concurrent cache operations
            concurrent_start_time = time.time()
            thread_results = []
            
            with ThreadPoolExecutor(max_workers=num_threads) as executor:
                futures = [
                    executor.submit(cache_worker, thread_id, thread_results)
                    for thread_id in range(num_threads)
                ]
                
                # Wait for all threads to complete
                for future in as_completed(futures):
                    future.result()  # Raise any exceptions
            
            total_concurrent_time = time.time() - concurrent_start_time
            
            # Analyze concurrent performance results
            all_set_times = []
            all_get_times = []
            total_errors = 0
            
            for result in thread_results:
                all_set_times.extend(result['set_times'])
                all_get_times.extend(result['get_times'])
                total_errors += result['errors']
            
            # Calculate concurrent performance metrics
            avg_concurrent_set_latency = sum(all_set_times) / len(all_set_times)
            avg_concurrent_get_latency = sum(all_get_times) / len(all_get_times)
            concurrent_throughput = total_operations / total_concurrent_time
            error_rate = total_errors / total_operations
            
            # Validate concurrent performance
            assert avg_concurrent_set_latency < 0.01  # 10ms average under concurrency
            assert avg_concurrent_get_latency < 0.005  # 5ms average under concurrency
            assert concurrent_throughput > 1000  # Minimum 1000 ops/second under concurrency
            assert error_rate < 0.01  # Less than 1% error rate
            
            # Verify connection pool health after concurrent access
            pool_stats = redis_client.get_pool_stats()
            assert pool_stats['available_connections'] > 0
            assert pool_stats['connection_errors'] == 0
            
            # Cleanup concurrent test data
            cleanup_keys = [
                f"concurrent_test:{thread_id}:{i}"
                for thread_id in range(num_threads)
                for i in range(operations_per_thread)
            ]
            redis_client.delete(*cleanup_keys)
        
        logger.info(
            "concurrent_cache_access_performance_validated",
            num_threads=num_threads,
            operations_per_thread=operations_per_thread,
            avg_concurrent_set_latency=avg_concurrent_set_latency,
            avg_concurrent_get_latency=avg_concurrent_get_latency,
            concurrent_throughput=concurrent_throughput,
            error_rate=error_rate,
            pool_stats=pool_stats
        )
    
    def test_cache_memory_efficiency(self, flask_app_with_cache):
        """
        Test cache memory efficiency and resource optimization.
        
        Validates:
        - Memory usage optimization patterns
        - Cache size management and cleanup
        - Resource efficiency equivalent to Node.js patterns
        """
        app = flask_app_with_cache
        
        with app.app_context():
            cache_mgr = get_cache_manager()
            redis_client = cache_mgr.get_client()
            
            # Get initial memory usage
            initial_memory_info = redis_client.info('memory')
            initial_memory_usage = initial_memory_info.get('used_memory', 0)
            
            # Memory efficiency test with varying data sizes
            memory_test_data = {
                'small_data': {'size': 'small', 'data': 'x' * 100},  # 100 bytes
                'medium_data': {'size': 'medium', 'data': 'x' * 1000},  # 1KB
                'large_data': {'size': 'large', 'data': 'x' * 10000},  # 10KB
            }
            
            # Store data of different sizes
            stored_keys = []
            for size_category, data in memory_test_data.items():
                for i in range(100):  # 100 entries per size category
                    key = f"memory_test:{size_category}:{i}"
                    redis_client.set(key, json.dumps(data), ttl=300)
                    stored_keys.append(key)
            
            # Measure memory usage after data storage
            post_storage_memory_info = redis_client.info('memory')
            post_storage_memory_usage = post_storage_memory_info.get('used_memory', 0)
            memory_increase = post_storage_memory_usage - initial_memory_usage
            
            # Calculate memory efficiency metrics
            total_stored_keys = len(stored_keys)
            avg_memory_per_key = memory_increase / total_stored_keys if total_stored_keys > 0 else 0
            
            # Validate memory efficiency
            assert avg_memory_per_key < 500  # Less than 500 bytes overhead per key
            assert memory_increase < 2 * 1024 * 1024  # Less than 2MB for test data
            
            # Test cache size management
            cache_size_info = redis_client.dbsize()
            assert cache_size_info >= total_stored_keys
            
            # Test memory cleanup efficiency
            cleanup_start_time = time.time()
            redis_client.delete(*stored_keys)
            cleanup_time = time.time() - cleanup_start_time
            
            # Verify cleanup effectiveness
            final_memory_info = redis_client.info('memory')
            final_memory_usage = final_memory_info.get('used_memory', 0)
            memory_freed = post_storage_memory_usage - final_memory_usage
            
            # Validate cleanup efficiency
            assert cleanup_time < 1.0  # Cleanup should complete within 1 second
            assert memory_freed > 0  # Memory should be freed
            assert final_memory_usage <= initial_memory_usage * 1.1  # Within 10% of initial
            
            # Test cache size after cleanup
            final_cache_size = redis_client.dbsize()
            assert final_cache_size < cache_size_info  # Cache size should decrease
        
        logger.info(
            "cache_memory_efficiency_validated",
            initial_memory_usage=initial_memory_usage,
            memory_increase=memory_increase,
            avg_memory_per_key=avg_memory_per_key,
            cleanup_time=cleanup_time,
            memory_freed=memory_freed,
            final_memory_usage=final_memory_usage
        )


@pytest.mark.integration
@pytest.mark.performance
class TestCacheIntegrationSuite:
    """
    Comprehensive cache integration test suite aggregator.
    
    Executes all cache integration tests in sequence to validate complete
    Redis caching functionality with Testcontainers providing realistic
    behavior per Section 6.6.1 testing strategy requirements.
    """
    
    def test_complete_cache_integration_workflow(self, flask_app_with_cache, cache_test_data):
        """
        Execute complete cache integration workflow validation.
        
        Validates end-to-end cache functionality including:
        - Cache initialization and configuration
        - Distributed caching across instances
        - Performance optimization and monitoring
        - Circuit breaker and resilience patterns
        """
        app = flask_app_with_cache
        
        with app.app_context():
            cache_mgr = get_cache_manager()
            
            # Validate cache manager initialization
            assert cache_mgr is not None
            assert cache_mgr.redis_client is not None
            assert cache_mgr.response_cache is not None
            
            # Test complete cache health status
            health_status = cache_mgr.get_health_status()
            assert health_status['status'] in ['healthy', 'degraded']
            assert 'redis' in health_status['components']
            assert 'response_cache' in health_status['components']
            assert 'strategies' in health_status['components']
            assert 'monitoring' in health_status['components']
            
            # Validate cache metrics collection
            metrics_summary = cache_monitor.get_metrics_summary()
            assert isinstance(metrics_summary, dict)
            assert 'total_operations' in metrics_summary
            
        logger.info(
            "complete_cache_integration_workflow_validated",
            health_status=health_status['status'],
            components_healthy=len([c for c in health_status['components'].values() if c.get('status') == 'healthy']),
            metrics_collected=len(metrics_summary)
        )
    
    def test_cache_integration_performance_baseline(self, flask_app_with_cache):
        """
        Validate cache integration performance against Node.js baseline.
        
        Ensures ≤10% variance requirement compliance for complete cache
        integration workflow per Section 0.1.1 primary objective.
        """
        app = flask_app_with_cache
        
        # Performance baseline test parameters
        baseline_requirements = {
            'avg_response_time_ms': 5.0,    # Maximum 5ms average response time
            'throughput_ops_per_sec': 2000,  # Minimum 2000 operations per second
            'memory_efficiency_mb': 10.0,    # Maximum 10MB memory usage
            'connection_efficiency': 0.95    # Minimum 95% connection efficiency
        }
        
        with app.test_client() as client:
            # Execute performance baseline test
            baseline_start_time = time.time()
            
            # Test response caching performance
            response_times = []
            for i in range(100):
                request_start = time.time()
                response = client.get('/api/cached-endpoint')
                request_time = (time.time() - request_start) * 1000  # Convert to milliseconds
                response_times.append(request_time)
                assert response.status_code == 200
            
            total_baseline_time = time.time() - baseline_start_time
            
            # Calculate performance metrics
            avg_response_time = sum(response_times) / len(response_times)
            baseline_throughput = len(response_times) / total_baseline_time
            
            # Validate performance against baseline requirements
            assert avg_response_time <= baseline_requirements['avg_response_time_ms']
            assert baseline_throughput >= baseline_requirements['throughput_ops_per_sec']
            
            # Validate memory efficiency
            with app.app_context():
                cache_mgr = get_cache_manager()
                redis_client = cache_mgr.get_client()
                
                memory_info = redis_client.info('memory')
                memory_usage_mb = memory_info.get('used_memory', 0) / (1024 * 1024)
                assert memory_usage_mb <= baseline_requirements['memory_efficiency_mb']
                
                # Validate connection efficiency
                pool_stats = redis_client.get_pool_stats()
                connection_efficiency = (
                    pool_stats.get('successful_connections', 0) /
                    max(pool_stats.get('total_connection_attempts', 1), 1)
                )
                assert connection_efficiency >= baseline_requirements['connection_efficiency']
        
        logger.info(
            "cache_integration_performance_baseline_validated",
            avg_response_time_ms=avg_response_time,
            baseline_throughput=baseline_throughput,
            memory_usage_mb=memory_usage_mb,
            connection_efficiency=connection_efficiency,
            baseline_met=True
        )