"""
Performance Testing Fixtures

Comprehensive performance testing fixtures providing baseline data generation, load testing utilities,
performance monitoring setup, and benchmark comparison tools for validating ≤10% variance requirement
from Node.js implementation per Section 0.1.1 primary objective.

This module serves as the central performance validation infrastructure ensuring compliance with
the critical ≤10% performance variance requirement through comprehensive baseline comparison,
load testing integration, and continuous performance monitoring.

Key Features:
- Node.js baseline data generation and comparison testing per Section 0.1.1
- Load testing data generation for locust integration per Section 6.6.1
- Performance monitoring fixtures with Prometheus metrics per Section 6.6.1
- Concurrent request testing fixtures per Section 6.6.3
- Database performance fixtures with PyMongo and Motor timing per Section 6.2.4
- Cache performance fixtures for Redis hit/miss ratio testing per Section 3.4.5
- Response time variance validation fixtures per Section 6.6.3

Dependencies:
- locust (≥2.x) for performance validation per Section 6.6.1
- apache-bench for HTTP server performance measurement per Section 6.6.1
- prometheus-client for metrics collection per Section 6.2.4
- pytest performance testing framework integration per Section 6.6.1

Compliance:
- Section 0.1.1: Performance optimization to ensure ≤10% variance from Node.js baseline
- Section 6.6.1: Load testing framework locust (≥2.x) for performance validation
- Section 6.6.3: Response Time Variance: ≤10% from Node.js baseline (project-critical requirement)
- Section 6.2.4: Database performance metrics instrumentation and monitoring
"""

import os
import time
import asyncio
import statistics
import json
from typing import Dict, List, Optional, Any, Callable, Tuple, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import pytest
from unittest.mock import Mock, patch
import logging

# Performance testing imports
import psutil
from locust import HttpUser, task, between
from locust.env import Environment
from locust.stats import stats_printer
from locust.runners import LocalRunner

# Prometheus metrics collection
from prometheus_client import Counter, Histogram, Gauge, Summary, CollectorRegistry
from prometheus_client.exposition import generate_latest

# HTTP client for performance testing
import requests
import httpx

# Database performance testing
import pymongo
import motor.motor_asyncio
import redis
from bson import ObjectId

# Flask application testing
from flask import Flask
from flask.testing import FlaskClient

# Structured logging
import structlog

# Configuration for performance testing
logger = structlog.get_logger(__name__)

# Performance testing constants
DEFAULT_PERFORMANCE_VARIANCE_THRESHOLD = 0.10  # 10% variance threshold
DEFAULT_LOAD_TEST_DURATION = 60  # seconds
DEFAULT_CONCURRENT_USERS = 50
DEFAULT_SPAWN_RATE = 5  # users per second
DEFAULT_DATABASE_OPERATION_TIMEOUT = 30.0  # seconds
DEFAULT_CACHE_OPERATION_TIMEOUT = 5.0  # seconds

# Node.js baseline performance data (milliseconds)
NODEJS_BASELINE_METRICS = {
    'api_endpoints': {
        'GET /health': 25.0,
        'GET /health/ready': 45.0,
        'GET /health/live': 15.0,
        'POST /api/auth/login': 180.0,
        'POST /api/auth/logout': 95.0,
        'GET /api/users': 125.0,
        'POST /api/users': 210.0,
        'GET /api/users/{id}': 85.0,
        'PUT /api/users/{id}': 165.0,
        'DELETE /api/users/{id}': 115.0,
        'GET /api/data/query': 320.0,
        'POST /api/data/create': 285.0,
    },
    'database_operations': {
        'user_find_one': 35.0,
        'user_find_many': 85.0,
        'user_insert_one': 65.0,
        'user_update_one': 55.0,
        'user_delete_one': 40.0,
        'data_aggregate': 145.0,
        'transaction_commit': 95.0,
        'connection_acquire': 15.0,
    },
    'cache_operations': {
        'redis_get_hit': 3.5,
        'redis_get_miss': 8.0,
        'redis_set': 6.5,
        'redis_delete': 4.0,
        'redis_exists': 2.5,
        'session_create': 12.0,
        'session_retrieve': 8.5,
        'session_update': 10.0,
    },
    'system_metrics': {
        'memory_usage_mb': 256.0,
        'cpu_usage_percent': 25.0,
        'concurrent_connections': 100,
        'throughput_rps': 250.0,
    }
}


@dataclass
class PerformanceBaseline:
    """
    Performance baseline data structure for Node.js comparison testing.
    
    Stores baseline metrics from Node.js implementation for comprehensive
    performance validation ensuring ≤10% variance compliance.
    """
    endpoint: str
    baseline_ms: float
    variance_threshold: float = DEFAULT_PERFORMANCE_VARIANCE_THRESHOLD
    method: str = 'GET'
    payload: Optional[Dict[str, Any]] = None
    headers: Optional[Dict[str, str]] = None
    
    def validate_performance(self, actual_ms: float) -> Dict[str, Any]:
        """
        Validate actual performance against baseline with variance calculation.
        
        Args:
            actual_ms: Actual response time in milliseconds
            
        Returns:
            Dict containing validation results and variance analysis
        """
        variance = abs(actual_ms - self.baseline_ms) / self.baseline_ms
        variance_percent = variance * 100
        is_within_threshold = variance <= self.variance_threshold
        
        return {
            'endpoint': self.endpoint,
            'method': self.method,
            'baseline_ms': self.baseline_ms,
            'actual_ms': actual_ms,
            'variance_percent': round(variance_percent, 2),
            'variance_threshold_percent': round(self.variance_threshold * 100, 2),
            'is_within_threshold': is_within_threshold,
            'performance_status': 'PASS' if is_within_threshold else 'FAIL',
            'timestamp': datetime.utcnow().isoformat()
        }


@dataclass
class LoadTestConfiguration:
    """
    Load testing configuration for locust integration.
    
    Comprehensive configuration for load testing scenarios ensuring
    realistic performance validation under concurrent load conditions.
    """
    users: int = DEFAULT_CONCURRENT_USERS
    spawn_rate: float = DEFAULT_SPAWN_RATE
    duration: int = DEFAULT_LOAD_TEST_DURATION
    host: str = 'http://localhost:5000'
    test_data: Optional[Dict[str, Any]] = None
    headers: Optional[Dict[str, str]] = None
    stop_on_failure: bool = False
    catch_exceptions: bool = True
    
    def to_locust_env(self) -> Dict[str, Any]:
        """Convert configuration to locust environment parameters."""
        return {
            'host': self.host,
            'stop_timeout': 30,
            'catch_exceptions': self.catch_exceptions,
        }


@dataclass
class DatabasePerformanceMetrics:
    """
    Database performance metrics for PyMongo and Motor operations.
    
    Comprehensive database performance tracking ensuring ≤10% variance
    from Node.js baseline database operation performance.
    """
    operation_type: str
    collection_name: str
    duration_ms: float
    success: bool
    error_message: Optional[str] = None
    document_count: int = 0
    query_filter: Optional[Dict[str, Any]] = None
    connection_pool_size: int = 0
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_prometheus_labels(self) -> Dict[str, str]:
        """Convert metrics to Prometheus label format."""
        return {
            'operation': self.operation_type,
            'collection': self.collection_name,
            'status': 'success' if self.success else 'error'
        }


@dataclass
class CachePerformanceMetrics:
    """
    Cache performance metrics for Redis operations.
    
    Redis cache performance tracking with hit/miss ratio analysis
    and operation timing for performance baseline compliance.
    """
    operation_type: str
    cache_key: str
    duration_ms: float
    hit: bool
    success: bool
    error_message: Optional[str] = None
    value_size_bytes: int = 0
    ttl_seconds: Optional[int] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_prometheus_labels(self) -> Dict[str, str]:
        """Convert cache metrics to Prometheus label format."""
        return {
            'operation': self.operation_type,
            'hit_status': 'hit' if self.hit else 'miss',
            'status': 'success' if self.success else 'error'
        }


class PerformanceMetricsCollector:
    """
    Comprehensive performance metrics collector with Prometheus integration.
    
    Centralized metrics collection for all performance testing scenarios
    with real-time Prometheus metrics exposition and baseline comparison.
    """
    
    def __init__(self, registry: Optional[CollectorRegistry] = None):
        """
        Initialize performance metrics collector with Prometheus registry.
        
        Args:
            registry: Optional Prometheus registry (creates new if not provided)
        """
        self.registry = registry or CollectorRegistry()
        
        # HTTP request performance metrics
        self.http_request_duration = Histogram(
            'http_request_duration_seconds',
            'HTTP request duration in seconds',
            ['method', 'endpoint', 'status'],
            registry=self.registry
        )
        
        self.http_request_count = Counter(
            'http_requests_total',
            'Total HTTP requests',
            ['method', 'endpoint', 'status'],
            registry=self.registry
        )
        
        # Database performance metrics
        self.database_operation_duration = Histogram(
            'database_operation_duration_seconds',
            'Database operation duration in seconds',
            ['operation', 'collection', 'status'],
            registry=self.registry
        )
        
        self.database_operation_count = Counter(
            'database_operations_total',
            'Total database operations',
            ['operation', 'collection', 'status'],
            registry=self.registry
        )
        
        self.database_connection_pool_size = Gauge(
            'database_connection_pool_size',
            'Database connection pool size',
            ['pool_type'],
            registry=self.registry
        )
        
        # Cache performance metrics
        self.cache_operation_duration = Histogram(
            'cache_operation_duration_seconds',
            'Cache operation duration in seconds',
            ['operation', 'hit_status', 'status'],
            registry=self.registry
        )
        
        self.cache_operation_count = Counter(
            'cache_operations_total',
            'Total cache operations',
            ['operation', 'hit_status', 'status'],
            registry=self.registry
        )
        
        self.cache_hit_ratio = Gauge(
            'cache_hit_ratio',
            'Cache hit ratio',
            ['operation'],
            registry=self.registry
        )
        
        # Performance variance metrics
        self.performance_variance = Gauge(
            'performance_variance_percent',
            'Performance variance from Node.js baseline',
            ['endpoint', 'method'],
            registry=self.registry
        )
        
        self.baseline_compliance = Gauge(
            'baseline_compliance_status',
            'Baseline compliance status (1=pass, 0=fail)',
            ['endpoint', 'method'],
            registry=self.registry
        )
        
        # System resource metrics
        self.memory_usage = Gauge(
            'memory_usage_bytes',
            'Memory usage in bytes',
            registry=self.registry
        )
        
        self.cpu_usage = Gauge(
            'cpu_usage_percent',
            'CPU usage percentage',
            registry=self.registry
        )
        
        logger.info("Performance metrics collector initialized with Prometheus registry")
    
    def record_http_request(self, method: str, endpoint: str, duration_seconds: float, 
                           status_code: int) -> None:
        """Record HTTP request performance metrics."""
        status = str(status_code)
        
        self.http_request_duration.labels(
            method=method,
            endpoint=endpoint,
            status=status
        ).observe(duration_seconds)
        
        self.http_request_count.labels(
            method=method,
            endpoint=endpoint,
            status=status
        ).inc()
    
    def record_database_operation(self, metrics: DatabasePerformanceMetrics) -> None:
        """Record database operation performance metrics."""
        labels = metrics.to_prometheus_labels()
        duration_seconds = metrics.duration_ms / 1000.0
        
        self.database_operation_duration.labels(**labels).observe(duration_seconds)
        self.database_operation_count.labels(**labels).inc()
        
        if metrics.connection_pool_size > 0:
            self.database_connection_pool_size.labels(pool_type='pymongo').set(
                metrics.connection_pool_size
            )
    
    def record_cache_operation(self, metrics: CachePerformanceMetrics) -> None:
        """Record cache operation performance metrics."""
        labels = metrics.to_prometheus_labels()
        duration_seconds = metrics.duration_ms / 1000.0
        
        self.cache_operation_duration.labels(**labels).observe(duration_seconds)
        self.cache_operation_count.labels(**labels).inc()
    
    def record_performance_variance(self, endpoint: str, method: str, 
                                  variance_percent: float, is_compliant: bool) -> None:
        """Record performance variance from Node.js baseline."""
        self.performance_variance.labels(
            endpoint=endpoint,
            method=method
        ).set(variance_percent)
        
        self.baseline_compliance.labels(
            endpoint=endpoint,
            method=method
        ).set(1.0 if is_compliant else 0.0)
    
    def update_system_metrics(self) -> None:
        """Update system resource metrics."""
        process = psutil.Process()
        
        # Memory usage
        memory_info = process.memory_info()
        self.memory_usage.set(memory_info.rss)
        
        # CPU usage
        cpu_percent = process.cpu_percent()
        self.cpu_usage.set(cpu_percent)
    
    def get_metrics_exposition(self) -> str:
        """Get Prometheus metrics in exposition format."""
        return generate_latest(self.registry).decode('utf-8')


class FlaskPerformanceTestUser(HttpUser):
    """
    Locust user class for Flask application performance testing.
    
    Comprehensive load testing user simulation with realistic request
    patterns and performance baseline validation integration.
    """
    
    wait_time = between(1, 3)  # Realistic user behavior simulation
    
    def __init__(self, environment):
        """Initialize performance test user with metrics collection."""
        super().__init__(environment)
        self.metrics_collector = PerformanceMetricsCollector()
        self.baselines = self._load_performance_baselines()
        
        logger.info("Flask performance test user initialized")
    
    def _load_performance_baselines(self) -> Dict[str, PerformanceBaseline]:
        """Load Node.js performance baselines for comparison."""
        baselines = {}
        
        for endpoint, baseline_ms in NODEJS_BASELINE_METRICS['api_endpoints'].items():
            method, path = endpoint.split(' ', 1)
            baselines[endpoint] = PerformanceBaseline(
                endpoint=path,
                baseline_ms=baseline_ms,
                method=method
            )
        
        return baselines
    
    @task(3)
    def test_health_endpoint(self):
        """Load test health check endpoint with baseline validation."""
        self._perform_request_with_validation('GET', '/health')
    
    @task(2)
    def test_readiness_endpoint(self):
        """Load test readiness check endpoint with baseline validation."""
        self._perform_request_with_validation('GET', '/health/ready')
    
    @task(1)
    def test_liveness_endpoint(self):
        """Load test liveness check endpoint with baseline validation."""
        self._perform_request_with_validation('GET', '/health/live')
    
    @task(5)
    def test_user_list_endpoint(self):
        """Load test user list endpoint with baseline validation."""
        self._perform_request_with_validation('GET', '/api/users')
    
    @task(2)
    def test_user_create_endpoint(self):
        """Load test user creation endpoint with baseline validation."""
        payload = {
            'email': f'test_{int(time.time())}@example.com',
            'name': 'Load Test User',
            'password': 'test_password_123'
        }
        self._perform_request_with_validation(
            'POST', '/api/users', json=payload
        )
    
    def _perform_request_with_validation(self, method: str, endpoint: str, 
                                       **kwargs) -> None:
        """
        Perform HTTP request with performance baseline validation.
        
        Args:
            method: HTTP method
            endpoint: API endpoint
            **kwargs: Additional request parameters
        """
        start_time = time.time()
        
        try:
            # Execute HTTP request
            if method == 'GET':
                response = self.client.get(endpoint, **kwargs)
            elif method == 'POST':
                response = self.client.post(endpoint, **kwargs)
            elif method == 'PUT':
                response = self.client.put(endpoint, **kwargs)
            elif method == 'DELETE':
                response = self.client.delete(endpoint, **kwargs)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            duration_seconds = time.time() - start_time
            duration_ms = duration_seconds * 1000
            
            # Record metrics
            self.metrics_collector.record_http_request(
                method, endpoint, duration_seconds, response.status_code
            )
            
            # Validate against baseline
            baseline_key = f"{method} {endpoint}"
            if baseline_key in self.baselines:
                baseline = self.baselines[baseline_key]
                validation_result = baseline.validate_performance(duration_ms)
                
                self.metrics_collector.record_performance_variance(
                    endpoint, method,
                    validation_result['variance_percent'],
                    validation_result['is_within_threshold']
                )
                
                # Log performance validation results
                if not validation_result['is_within_threshold']:
                    logger.warning(
                        "Performance baseline exceeded",
                        endpoint=endpoint,
                        method=method,
                        baseline_ms=validation_result['baseline_ms'],
                        actual_ms=validation_result['actual_ms'],
                        variance_percent=validation_result['variance_percent']
                    )
            
        except Exception as e:
            duration_seconds = time.time() - start_time
            self.metrics_collector.record_http_request(
                method, endpoint, duration_seconds, 500
            )
            logger.error(f"Load test request failed: {e}")
            raise


class DatabasePerformanceTester:
    """
    Database performance testing utilities for PyMongo and Motor operations.
    
    Comprehensive database performance validation ensuring ≤10% variance
    from Node.js baseline with PyMongo sync and Motor async operations.
    """
    
    def __init__(self, mongodb_uri: str, database_name: str = 'test_performance'):
        """
        Initialize database performance tester.
        
        Args:
            mongodb_uri: MongoDB connection URI
            database_name: Test database name
        """
        self.mongodb_uri = mongodb_uri
        self.database_name = database_name
        self.sync_client = None
        self.async_client = None
        self.metrics_collector = PerformanceMetricsCollector()
        self.baselines = NODEJS_BASELINE_METRICS['database_operations']
        
        logger.info(
            "Database performance tester initialized",
            mongodb_uri=mongodb_uri.split('@')[-1] if '@' in mongodb_uri else mongodb_uri,
            database_name=database_name
        )
    
    def setup_sync_client(self) -> pymongo.MongoClient:
        """Setup PyMongo synchronous client for performance testing."""
        if not self.sync_client:
            self.sync_client = pymongo.MongoClient(
                self.mongodb_uri,
                maxPoolSize=50,
                serverSelectionTimeoutMS=10000,
                connectTimeoutMS=10000,
                socketTimeoutMS=60000
            )
        return self.sync_client
    
    async def setup_async_client(self) -> motor.motor_asyncio.AsyncIOMotorClient:
        """Setup Motor async client for performance testing."""
        if not self.async_client:
            self.async_client = motor.motor_asyncio.AsyncIOMotorClient(
                self.mongodb_uri,
                maxPoolSize=100,
                serverSelectionTimeoutMS=10000,
                connectTimeoutMS=10000,
                socketTimeoutMS=60000
            )
        return self.async_client
    
    def test_sync_operations(self, collection_name: str = 'test_users',
                           operation_count: int = 100) -> List[DatabasePerformanceMetrics]:
        """
        Test PyMongo synchronous operations with performance measurement.
        
        Args:
            collection_name: MongoDB collection name
            operation_count: Number of operations to perform
            
        Returns:
            List of database performance metrics
        """
        client = self.setup_sync_client()
        db = client[self.database_name]
        collection = db[collection_name]
        
        metrics = []
        
        # Test insert operations
        for i in range(operation_count):
            start_time = time.time()
            try:
                document = {
                    '_id': ObjectId(),
                    'name': f'Test User {i}',
                    'email': f'user{i}@test.com',
                    'created_at': datetime.utcnow(),
                    'test_data': {'index': i, 'batch': 'performance_test'}
                }
                
                result = collection.insert_one(document)
                duration_ms = (time.time() - start_time) * 1000
                
                metric = DatabasePerformanceMetrics(
                    operation_type='insert_one',
                    collection_name=collection_name,
                    duration_ms=duration_ms,
                    success=True,
                    document_count=1,
                    connection_pool_size=client.options.pool_options.max_pool_size
                )
                
                metrics.append(metric)
                self.metrics_collector.record_database_operation(metric)
                
                # Validate against baseline
                if duration_ms > self.baselines.get('user_insert_one', 0) * 1.1:
                    logger.warning(
                        "Database insert operation exceeded baseline",
                        operation='insert_one',
                        duration_ms=duration_ms,
                        baseline_ms=self.baselines.get('user_insert_one')
                    )
                
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                metric = DatabasePerformanceMetrics(
                    operation_type='insert_one',
                    collection_name=collection_name,
                    duration_ms=duration_ms,
                    success=False,
                    error_message=str(e)
                )
                metrics.append(metric)
                self.metrics_collector.record_database_operation(metric)
        
        # Test find operations
        start_time = time.time()
        try:
            cursor = collection.find({'test_data.batch': 'performance_test'})
            documents = list(cursor)
            duration_ms = (time.time() - start_time) * 1000
            
            metric = DatabasePerformanceMetrics(
                operation_type='find_many',
                collection_name=collection_name,
                duration_ms=duration_ms,
                success=True,
                document_count=len(documents),
                connection_pool_size=client.options.pool_options.max_pool_size
            )
            
            metrics.append(metric)
            self.metrics_collector.record_database_operation(metric)
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            metric = DatabasePerformanceMetrics(
                operation_type='find_many',
                collection_name=collection_name,
                duration_ms=duration_ms,
                success=False,
                error_message=str(e)
            )
            metrics.append(metric)
            self.metrics_collector.record_database_operation(metric)
        
        return metrics
    
    async def test_async_operations(self, collection_name: str = 'test_users_async',
                                  operation_count: int = 100) -> List[DatabasePerformanceMetrics]:
        """
        Test Motor async operations with performance measurement.
        
        Args:
            collection_name: MongoDB collection name
            operation_count: Number of operations to perform
            
        Returns:
            List of database performance metrics
        """
        client = await self.setup_async_client()
        db = client[self.database_name]
        collection = db[collection_name]
        
        metrics = []
        
        # Test async insert operations
        for i in range(operation_count):
            start_time = time.time()
            try:
                document = {
                    '_id': ObjectId(),
                    'name': f'Test Async User {i}',
                    'email': f'async_user{i}@test.com',
                    'created_at': datetime.utcnow(),
                    'test_data': {'index': i, 'batch': 'async_performance_test'}
                }
                
                result = await collection.insert_one(document)
                duration_ms = (time.time() - start_time) * 1000
                
                metric = DatabasePerformanceMetrics(
                    operation_type='async_insert_one',
                    collection_name=collection_name,
                    duration_ms=duration_ms,
                    success=True,
                    document_count=1
                )
                
                metrics.append(metric)
                self.metrics_collector.record_database_operation(metric)
                
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                metric = DatabasePerformanceMetrics(
                    operation_type='async_insert_one',
                    collection_name=collection_name,
                    duration_ms=duration_ms,
                    success=False,
                    error_message=str(e)
                )
                metrics.append(metric)
                self.metrics_collector.record_database_operation(metric)
        
        # Test async find operations
        start_time = time.time()
        try:
            cursor = collection.find({'test_data.batch': 'async_performance_test'})
            documents = await cursor.to_list(length=None)
            duration_ms = (time.time() - start_time) * 1000
            
            metric = DatabasePerformanceMetrics(
                operation_type='async_find_many',
                collection_name=collection_name,
                duration_ms=duration_ms,
                success=True,
                document_count=len(documents)
            )
            
            metrics.append(metric)
            self.metrics_collector.record_database_operation(metric)
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            metric = DatabasePerformanceMetrics(
                operation_type='async_find_many',
                collection_name=collection_name,
                duration_ms=duration_ms,
                success=False,
                error_message=str(e)
            )
            metrics.append(metric)
            self.metrics_collector.record_database_operation(metric)
        
        return metrics
    
    def cleanup_test_data(self, collection_name: str = None) -> None:
        """Clean up test data after performance testing."""
        if self.sync_client:
            db = self.sync_client[self.database_name]
            if collection_name:
                db[collection_name].delete_many({'test_data.batch': {'$regex': 'performance_test'}})
            else:
                # Clean up all test collections
                for coll_name in db.list_collection_names():
                    if 'test_' in coll_name:
                        db[coll_name].delete_many({'test_data.batch': {'$regex': 'performance_test'}})
    
    def close_connections(self) -> None:
        """Close database connections."""
        if self.sync_client:
            self.sync_client.close()
        if self.async_client:
            self.async_client.close()


class CachePerformanceTester:
    """
    Cache performance testing utilities for Redis operations.
    
    Comprehensive Redis cache performance validation with hit/miss ratio
    analysis and operation timing for baseline compliance testing.
    """
    
    def __init__(self, redis_uri: str = 'redis://localhost:6379/0'):
        """
        Initialize cache performance tester.
        
        Args:
            redis_uri: Redis connection URI
        """
        self.redis_uri = redis_uri
        self.redis_client = None
        self.metrics_collector = PerformanceMetricsCollector()
        self.baselines = NODEJS_BASELINE_METRICS['cache_operations']
        self.hit_count = 0
        self.miss_count = 0
        
        logger.info("Cache performance tester initialized", redis_uri=redis_uri)
    
    def setup_redis_client(self) -> redis.Redis:
        """Setup Redis client for performance testing."""
        if not self.redis_client:
            self.redis_client = redis.from_url(
                self.redis_uri,
                decode_responses=True,
                socket_timeout=DEFAULT_CACHE_OPERATION_TIMEOUT,
                socket_connect_timeout=10.0,
                health_check_interval=30
            )
        return self.redis_client
    
    def test_cache_operations(self, operation_count: int = 1000) -> List[CachePerformanceMetrics]:
        """
        Test Redis cache operations with performance measurement.
        
        Args:
            operation_count: Number of cache operations to perform
            
        Returns:
            List of cache performance metrics
        """
        client = self.setup_redis_client()
        metrics = []
        
        # Pre-populate cache with some data for hit testing
        for i in range(operation_count // 2):
            key = f'perf_test_key_{i}'
            value = f'test_value_{i}_' + 'x' * 100  # 100+ character value
            client.set(key, value, ex=3600)
        
        # Test cache GET operations (mix of hits and misses)
        for i in range(operation_count):
            # 70% hits, 30% misses for realistic testing
            if i % 10 < 7 and i < operation_count // 2:
                key = f'perf_test_key_{i}'  # Hit
            else:
                key = f'perf_test_miss_key_{i}'  # Miss
            
            start_time = time.time()
            try:
                value = client.get(key)
                duration_ms = (time.time() - start_time) * 1000
                hit = value is not None
                
                if hit:
                    self.hit_count += 1
                else:
                    self.miss_count += 1
                
                metric = CachePerformanceMetrics(
                    operation_type='get',
                    cache_key=key,
                    duration_ms=duration_ms,
                    hit=hit,
                    success=True,
                    value_size_bytes=len(value.encode('utf-8')) if value else 0
                )
                
                metrics.append(metric)
                self.metrics_collector.record_cache_operation(metric)
                
                # Validate against baseline
                baseline_key = 'redis_get_hit' if hit else 'redis_get_miss'
                if duration_ms > self.baselines.get(baseline_key, 0) * 1.1:
                    logger.warning(
                        "Cache operation exceeded baseline",
                        operation='get',
                        hit_status='hit' if hit else 'miss',
                        duration_ms=duration_ms,
                        baseline_ms=self.baselines.get(baseline_key)
                    )
                
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                metric = CachePerformanceMetrics(
                    operation_type='get',
                    cache_key=key,
                    duration_ms=duration_ms,
                    hit=False,
                    success=False,
                    error_message=str(e)
                )
                metrics.append(metric)
                self.metrics_collector.record_cache_operation(metric)
        
        # Test cache SET operations
        for i in range(operation_count // 4):
            key = f'perf_test_set_key_{i}'
            value = f'set_test_value_{i}_' + 'y' * 200
            
            start_time = time.time()
            try:
                client.set(key, value, ex=1800)  # 30 minute TTL
                duration_ms = (time.time() - start_time) * 1000
                
                metric = CachePerformanceMetrics(
                    operation_type='set',
                    cache_key=key,
                    duration_ms=duration_ms,
                    hit=False,  # Not applicable for SET
                    success=True,
                    value_size_bytes=len(value.encode('utf-8')),
                    ttl_seconds=1800
                )
                
                metrics.append(metric)
                self.metrics_collector.record_cache_operation(metric)
                
                # Validate against baseline
                if duration_ms > self.baselines.get('redis_set', 0) * 1.1:
                    logger.warning(
                        "Cache SET operation exceeded baseline",
                        duration_ms=duration_ms,
                        baseline_ms=self.baselines.get('redis_set')
                    )
                
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                metric = CachePerformanceMetrics(
                    operation_type='set',
                    cache_key=key,
                    duration_ms=duration_ms,
                    hit=False,
                    success=False,
                    error_message=str(e)
                )
                metrics.append(metric)
                self.metrics_collector.record_cache_operation(metric)
        
        # Update hit ratio metrics
        total_gets = self.hit_count + self.miss_count
        if total_gets > 0:
            hit_ratio = self.hit_count / total_gets
            self.metrics_collector.cache_hit_ratio.labels(operation='get').set(hit_ratio)
            
            logger.info(
                "Cache performance test completed",
                total_operations=len(metrics),
                hit_count=self.hit_count,
                miss_count=self.miss_count,
                hit_ratio=round(hit_ratio, 3)
            )
        
        return metrics
    
    def cleanup_test_data(self) -> None:
        """Clean up test cache data."""
        if self.redis_client:
            # Delete test keys
            pattern_keys = [
                'perf_test_key_*',
                'perf_test_miss_key_*',
                'perf_test_set_key_*'
            ]
            
            for pattern in pattern_keys:
                keys = self.redis_client.keys(pattern)
                if keys:
                    self.redis_client.delete(*keys)
    
    def close_connection(self) -> None:
        """Close Redis connection."""
        if self.redis_client:
            self.redis_client.close()


class ResponseTimeValidator:
    """
    Response time variance validation for ≤10% compliance testing.
    
    Comprehensive response time analysis and variance calculation ensuring
    compliance with project-critical ≤10% variance requirement.
    """
    
    def __init__(self, variance_threshold: float = DEFAULT_PERFORMANCE_VARIANCE_THRESHOLD):
        """
        Initialize response time validator.
        
        Args:
            variance_threshold: Maximum allowed variance (default 10%)
        """
        self.variance_threshold = variance_threshold
        self.measurements = []
        self.baseline_violations = []
        
        logger.info(
            "Response time validator initialized",
            variance_threshold_percent=variance_threshold * 100
        )
    
    def validate_response_time(self, endpoint: str, method: str, 
                             actual_ms: float, baseline_ms: float) -> Dict[str, Any]:
        """
        Validate response time against baseline with comprehensive analysis.
        
        Args:
            endpoint: API endpoint
            method: HTTP method
            actual_ms: Actual response time in milliseconds
            baseline_ms: Baseline response time in milliseconds
            
        Returns:
            Dictionary containing validation results
        """
        variance = abs(actual_ms - baseline_ms) / baseline_ms
        variance_percent = variance * 100
        is_compliant = variance <= self.variance_threshold
        
        measurement = {
            'endpoint': endpoint,
            'method': method,
            'actual_ms': actual_ms,
            'baseline_ms': baseline_ms,
            'variance': variance,
            'variance_percent': variance_percent,
            'is_compliant': is_compliant,
            'timestamp': datetime.utcnow().isoformat(),
            'performance_impact': self._calculate_performance_impact(variance)
        }
        
        self.measurements.append(measurement)
        
        if not is_compliant:
            self.baseline_violations.append(measurement)
            logger.warning(
                "Performance baseline violation detected",
                endpoint=endpoint,
                method=method,
                actual_ms=actual_ms,
                baseline_ms=baseline_ms,
                variance_percent=round(variance_percent, 2),
                threshold_percent=round(self.variance_threshold * 100, 2)
            )
        
        return measurement
    
    def _calculate_performance_impact(self, variance: float) -> str:
        """Calculate performance impact category based on variance."""
        if variance <= 0.05:  # ≤5%
            return 'MINIMAL'
        elif variance <= 0.10:  # ≤10%
            return 'ACCEPTABLE'
        elif variance <= 0.20:  # ≤20%
            return 'MODERATE'
        else:  # >20%
            return 'SIGNIFICANT'
    
    def get_compliance_summary(self) -> Dict[str, Any]:
        """
        Get comprehensive compliance summary and statistics.
        
        Returns:
            Dictionary containing compliance analysis results
        """
        if not self.measurements:
            return {
                'total_measurements': 0,
                'compliance_rate': 0.0,
                'overall_status': 'NO_DATA'
            }
        
        total_measurements = len(self.measurements)
        compliant_measurements = len([m for m in self.measurements if m['is_compliant']])
        compliance_rate = compliant_measurements / total_measurements
        
        variances = [m['variance_percent'] for m in self.measurements]
        
        summary = {
            'total_measurements': total_measurements,
            'compliant_measurements': compliant_measurements,
            'violation_count': len(self.baseline_violations),
            'compliance_rate': round(compliance_rate, 3),
            'overall_status': 'PASS' if compliance_rate >= 0.95 else 'FAIL',
            'variance_statistics': {
                'mean_variance_percent': round(statistics.mean(variances), 2),
                'median_variance_percent': round(statistics.median(variances), 2),
                'max_variance_percent': round(max(variances), 2),
                'min_variance_percent': round(min(variances), 2),
                'std_deviation': round(statistics.stdev(variances) if len(variances) > 1 else 0, 2)
            },
            'threshold_analysis': {
                'variance_threshold_percent': round(self.variance_threshold * 100, 2),
                'measurements_within_5_percent': len([v for v in variances if v <= 5.0]),
                'measurements_within_10_percent': len([v for v in variances if v <= 10.0]),
                'measurements_above_threshold': len(self.baseline_violations)
            },
            'worst_violations': sorted(
                self.baseline_violations,
                key=lambda x: x['variance_percent'],
                reverse=True
            )[:5]  # Top 5 worst violations
        }
        
        return summary


# Pytest fixtures for performance testing
@pytest.fixture(scope="session")
def performance_metrics_collector():
    """
    Performance metrics collector fixture for Prometheus integration.
    
    Provides centralized metrics collection across all performance tests
    with Prometheus exposition for external monitoring integration.
    """
    collector = PerformanceMetricsCollector()
    yield collector
    
    # Export final metrics for analysis
    logger.info("Final performance metrics collected", 
                metrics_exposition=collector.get_metrics_exposition())


@pytest.fixture(scope="function")
def nodejs_baselines():
    """
    Node.js baseline performance data fixture.
    
    Provides comprehensive baseline metrics for performance comparison
    ensuring ≤10% variance validation across all test scenarios.
    """
    baselines = {}
    
    # Convert baseline data to PerformanceBaseline objects
    for endpoint_key, baseline_ms in NODEJS_BASELINE_METRICS['api_endpoints'].items():
        method, path = endpoint_key.split(' ', 1)
        baselines[endpoint_key] = PerformanceBaseline(
            endpoint=path,
            baseline_ms=baseline_ms,
            method=method,
            variance_threshold=DEFAULT_PERFORMANCE_VARIANCE_THRESHOLD
        )
    
    return baselines


@pytest.fixture(scope="function")
def load_test_config():
    """
    Load testing configuration fixture for locust integration.
    
    Provides configurable load testing parameters for comprehensive
    performance validation under realistic traffic conditions.
    """
    config = LoadTestConfiguration(
        users=int(os.getenv('LOAD_TEST_USERS', DEFAULT_CONCURRENT_USERS)),
        spawn_rate=float(os.getenv('LOAD_TEST_SPAWN_RATE', DEFAULT_SPAWN_RATE)),
        duration=int(os.getenv('LOAD_TEST_DURATION', DEFAULT_LOAD_TEST_DURATION)),
        host=os.getenv('LOAD_TEST_HOST', 'http://localhost:5000')
    )
    
    return config


@pytest.fixture(scope="function")
def database_performance_tester(mongodb_uri):
    """
    Database performance tester fixture for PyMongo and Motor operations.
    
    Provides comprehensive database performance testing utilities with
    baseline validation and Prometheus metrics integration.
    """
    tester = DatabasePerformanceTester(mongodb_uri, 'test_performance_db')
    yield tester
    
    # Cleanup after test
    tester.cleanup_test_data()
    tester.close_connections()


@pytest.fixture(scope="function")
def cache_performance_tester(redis_uri):
    """
    Cache performance tester fixture for Redis operations.
    
    Provides comprehensive Redis cache performance testing with hit/miss
    ratio analysis and operation timing baseline validation.
    """
    tester = CachePerformanceTester(redis_uri)
    yield tester
    
    # Cleanup after test
    tester.cleanup_test_data()
    tester.close_connection()


@pytest.fixture(scope="function")
def response_time_validator():
    """
    Response time variance validator fixture.
    
    Provides comprehensive response time analysis and variance calculation
    for ≤10% compliance validation across all performance tests.
    """
    validator = ResponseTimeValidator(DEFAULT_PERFORMANCE_VARIANCE_THRESHOLD)
    yield validator
    
    # Log final compliance summary
    summary = validator.get_compliance_summary()
    logger.info("Performance validation summary", **summary)


@pytest.fixture(scope="function")
async def concurrent_request_tester(app):
    """
    Concurrent request testing fixture for load simulation.
    
    Provides utilities for testing concurrent request handling capacity
    and performance under realistic multi-user scenarios.
    """
    async def execute_concurrent_requests(endpoints: List[Tuple[str, str]], 
                                        concurrent_users: int = 10,
                                        requests_per_user: int = 5) -> List[Dict[str, Any]]:
        """
        Execute concurrent requests to test application performance.
        
        Args:
            endpoints: List of (method, endpoint) tuples
            concurrent_users: Number of concurrent users
            requests_per_user: Requests per user
            
        Returns:
            List of response timing results
        """
        results = []
        
        async def user_session(user_id: int):
            """Simulate a single user session with multiple requests."""
            async with httpx.AsyncClient(base_url='http://localhost:5000') as client:
                for request_id in range(requests_per_user):
                    for method, endpoint in endpoints:
                        start_time = time.time()
                        try:
                            if method.upper() == 'GET':
                                response = await client.get(endpoint)
                            elif method.upper() == 'POST':
                                response = await client.post(endpoint, json={})
                            else:
                                continue
                            
                            duration_ms = (time.time() - start_time) * 1000
                            
                            results.append({
                                'user_id': user_id,
                                'request_id': request_id,
                                'method': method,
                                'endpoint': endpoint,
                                'status_code': response.status_code,
                                'duration_ms': duration_ms,
                                'timestamp': datetime.utcnow().isoformat()
                            })
                            
                        except Exception as e:
                            duration_ms = (time.time() - start_time) * 1000
                            results.append({
                                'user_id': user_id,
                                'request_id': request_id,
                                'method': method,
                                'endpoint': endpoint,
                                'status_code': 500,
                                'duration_ms': duration_ms,
                                'error': str(e),
                                'timestamp': datetime.utcnow().isoformat()
                            })
        
        # Execute concurrent user sessions
        tasks = [user_session(user_id) for user_id in range(concurrent_users)]
        await asyncio.gather(*tasks)
        
        return results
    
    return execute_concurrent_requests


def run_locust_load_test(host: str = 'http://localhost:5000',
                        users: int = DEFAULT_CONCURRENT_USERS,
                        spawn_rate: float = DEFAULT_SPAWN_RATE,
                        duration: int = DEFAULT_LOAD_TEST_DURATION) -> Dict[str, Any]:
    """
    Execute locust load test with comprehensive performance analysis.
    
    Args:
        host: Target host URL
        users: Number of concurrent users
        spawn_rate: User spawn rate per second
        duration: Test duration in seconds
        
    Returns:
        Dictionary containing load test results and performance analysis
    """
    # Setup locust environment
    env = Environment(user_classes=[FlaskPerformanceTestUser])
    env.create_local_runner()
    
    # Configure test parameters
    env.host = host
    
    logger.info(
        "Starting locust load test",
        host=host,
        users=users,
        spawn_rate=spawn_rate,
        duration=duration
    )
    
    try:
        # Start load test
        env.runner.start(user_count=users, spawn_rate=spawn_rate)
        
        # Run for specified duration
        start_time = time.time()
        while time.time() - start_time < duration:
            time.sleep(1)
        
        # Stop load test
        env.runner.stop()
        
        # Collect results
        stats = env.runner.stats
        results = {
            'test_duration': duration,
            'total_requests': stats.total.num_requests,
            'total_failures': stats.total.num_failures,
            'average_response_time': stats.total.avg_response_time,
            'median_response_time': stats.total.median_response_time,
            'min_response_time': stats.total.min_response_time,
            'max_response_time': stats.total.max_response_time,
            'requests_per_second': stats.total.total_rps,
            'failure_rate': stats.total.fail_ratio,
            'endpoint_stats': {}
        }
        
        # Collect per-endpoint statistics
        for name, endpoint_stats in stats.entries.items():
            if name != 'Aggregated':
                results['endpoint_stats'][name] = {
                    'request_count': endpoint_stats.num_requests,
                    'failure_count': endpoint_stats.num_failures,
                    'average_response_time': endpoint_stats.avg_response_time,
                    'median_response_time': endpoint_stats.median_response_time,
                    'requests_per_second': endpoint_stats.total_rps
                }
        
        logger.info("Locust load test completed", **results)
        return results
        
    except Exception as e:
        logger.error(f"Locust load test failed: {e}")
        return {'error': str(e)}
    
    finally:
        env.runner.quit()


# Utility functions for performance analysis
def calculate_performance_variance(actual_ms: float, baseline_ms: float) -> Dict[str, float]:
    """
    Calculate performance variance with comprehensive analysis.
    
    Args:
        actual_ms: Actual response time in milliseconds
        baseline_ms: Baseline response time in milliseconds
        
    Returns:
        Dictionary containing variance analysis
    """
    if baseline_ms == 0:
        return {'variance': 0.0, 'variance_percent': 0.0, 'performance_ratio': 1.0}
    
    variance = abs(actual_ms - baseline_ms) / baseline_ms
    variance_percent = variance * 100
    performance_ratio = actual_ms / baseline_ms
    
    return {
        'variance': round(variance, 4),
        'variance_percent': round(variance_percent, 2),
        'performance_ratio': round(performance_ratio, 3),
        'improvement': actual_ms < baseline_ms,
        'degradation': actual_ms > baseline_ms * (1 + DEFAULT_PERFORMANCE_VARIANCE_THRESHOLD)
    }


def generate_performance_report(metrics_collector: PerformanceMetricsCollector,
                              response_validator: ResponseTimeValidator) -> Dict[str, Any]:
    """
    Generate comprehensive performance test report.
    
    Args:
        metrics_collector: Performance metrics collector instance
        response_validator: Response time validator instance
        
    Returns:
        Dictionary containing comprehensive performance analysis
    """
    compliance_summary = response_validator.get_compliance_summary()
    metrics_exposition = metrics_collector.get_metrics_exposition()
    
    report = {
        'report_timestamp': datetime.utcnow().isoformat(),
        'performance_compliance': compliance_summary,
        'prometheus_metrics': metrics_exposition,
        'baseline_comparison': {
            'nodejs_baselines_loaded': len(NODEJS_BASELINE_METRICS['api_endpoints']),
            'variance_threshold_percent': DEFAULT_PERFORMANCE_VARIANCE_THRESHOLD * 100,
            'critical_requirement': '≤10% variance from Node.js baseline'
        },
        'test_environment': {
            'python_version': os.sys.version,
            'platform': os.name,
            'test_timestamp': datetime.utcnow().isoformat()
        }
    }
    
    logger.info("Performance test report generated", report_summary=report['performance_compliance'])
    return report


# Export all fixtures and utilities for pytest integration
__all__ = [
    # Core data structures
    'PerformanceBaseline',
    'LoadTestConfiguration', 
    'DatabasePerformanceMetrics',
    'CachePerformanceMetrics',
    
    # Testing classes
    'PerformanceMetricsCollector',
    'FlaskPerformanceTestUser',
    'DatabasePerformanceTester',
    'CachePerformanceTester',
    'ResponseTimeValidator',
    
    # Pytest fixtures
    'performance_metrics_collector',
    'nodejs_baselines',
    'load_test_config',
    'database_performance_tester',
    'cache_performance_tester',
    'response_time_validator',
    'concurrent_request_tester',
    
    # Utility functions
    'run_locust_load_test',
    'calculate_performance_variance',
    'generate_performance_report',
    
    # Constants
    'NODEJS_BASELINE_METRICS',
    'DEFAULT_PERFORMANCE_VARIANCE_THRESHOLD',
    'DEFAULT_LOAD_TEST_DURATION',
    'DEFAULT_CONCURRENT_USERS'
]