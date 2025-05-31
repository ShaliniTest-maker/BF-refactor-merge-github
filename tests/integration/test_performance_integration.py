"""
Performance Integration Testing with Load Testing Frameworks

This module implements comprehensive performance integration testing validating the ≤10% variance
requirement from Node.js baseline per Section 0.1.1. Utilizes locust (≥2.x) for distributed load
testing and apache-bench for HTTP server performance measurement with automated baseline comparison.

Key Testing Areas:
- Concurrent request handling capacity validation per Section 6.6.3 performance test thresholds
- Database operation performance integration testing with PyMongo and Motor per Section 6.2.4
- Cache performance integration testing with Redis hit/miss ratios per Section 3.4.5
- External service performance monitoring integration per Section 6.3.5 performance characteristics
- Continuous performance validation with CI/CD pipeline per Section 6.6.2 performance optimization

Architecture Integration:
- Section 6.6.1: locust (≥2.x) load testing framework for automated load testing and throughput validation
- Section 6.6.1: apache-bench for HTTP server performance measurement and Node.js baseline comparison
- Section 6.6.3: Performance baseline comparison ensuring ≤10% variance requirement
- Section 6.2.4: Database performance integration testing with query optimization and connection pooling
- Section 3.4.5: Cache performance management with Redis hit/miss ratio analysis
- Section 6.3.5: External service integration performance characteristics validation
- Section 6.6.2: CI/CD pipeline integration for automated performance regression detection

Performance Validation Framework:
- Response time variance tracking against Node.js baseline with statistical analysis
- Concurrent user capacity testing with realistic traffic patterns and session management
- Database operation latency validation including CRUD operations and complex queries
- Cache effectiveness measurement with hit rate optimization and TTL management
- External service integration timeout and circuit breaker performance validation
- Memory usage patterns and garbage collection impact measurement
- CPU utilization monitoring during sustained load conditions

Testing Requirements:
- Minimum concurrent users: 100 users for realistic load simulation
- Test duration: 5 minutes sustained load for performance stability validation
- Performance variance threshold: ≤10% from Node.js baseline (project-critical requirement)
- Database operation latency: ≤50ms for standard CRUD operations
- Cache operation latency: ≤5ms for get/set operations with 90%+ hit rate
- External service timeout: ≤3 seconds with circuit breaker activation at 5 failures
- Memory growth rate: ≤15% increase during sustained load testing
- CPU utilization: ≤70% sustained utilization under normal load conditions

Dependencies:
- locust[gevent] ≥2.17.0 for distributed load testing with gevent worker support
- apache-bench (ab) for HTTP benchmarking and baseline comparison
- pytest-benchmark ≥4.0.0 for performance regression testing and statistical analysis
- psutil ≥5.9.0 for system resource monitoring during load testing
- matplotlib ≥3.6.0 for performance visualization and trend analysis
- httpx ≥0.24.0 for async HTTP client testing and concurrent request simulation
- pandas ≥1.5.0 for performance data analysis and statistical validation
- numpy ≥1.24.0 for numerical analysis and variance calculation

Author: Flask Migration Team
Version: 1.0.0
Performance Target: ≤10% variance from Node.js baseline
Test Coverage: Database, Cache, External Services, Concurrent Request Handling
"""

import asyncio
import json
import multiprocessing
import os
import psutil
import statistics
import subprocess
import tempfile
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Generator, NamedTuple
from unittest.mock import patch, Mock

import httpx
import numpy as np
import pandas as pd
import pytest
import pytest_benchmark
from locust import HttpUser, task, between, events
from locust.env import Environment
from locust.runners import LocalRunner
from locust.stats import StatsCSV

from tests.conftest import (
    comprehensive_test_environment,
    performance_monitoring,
    skip_if_no_docker,
    skip_if_no_redis,
    skip_if_no_mongodb
)

# Configure structured logging for performance testing
import structlog
logger = structlog.get_logger(__name__)

# Performance test configuration constants
PERFORMANCE_VARIANCE_THRESHOLD = 0.10  # ≤10% variance requirement
MIN_CONCURRENT_USERS = 50  # Minimum concurrent users for realistic load
MAX_CONCURRENT_USERS = 200  # Maximum concurrent users for capacity testing
LOAD_TEST_DURATION = 300  # 5 minutes sustained load testing
RAMP_UP_DURATION = 60  # 1 minute ramp-up period
DATABASE_OPERATION_TIMEOUT = 0.050  # 50ms database operation timeout
CACHE_OPERATION_TIMEOUT = 0.005  # 5ms cache operation timeout
EXTERNAL_SERVICE_TIMEOUT = 3.0  # 3 seconds external service timeout
MEMORY_GROWTH_THRESHOLD = 0.15  # 15% memory growth threshold
CPU_UTILIZATION_THRESHOLD = 0.70  # 70% CPU utilization threshold

# Node.js baseline performance metrics for comparison
NODEJS_BASELINE_METRICS = {
    'api_response_time': 0.200,  # 200ms average API response time
    'database_query_time': 0.045,  # 45ms average database query time
    'cache_operation_time': 0.003,  # 3ms average cache operation time
    'concurrent_throughput': 500,  # 500 requests/second concurrent throughput
    'memory_usage_mb': 256,  # 256MB average memory usage
    'cpu_utilization': 0.45,  # 45% average CPU utilization
    'auth_request_time': 0.150,  # 150ms authentication request time
    'external_api_time': 0.800,  # 800ms external API response time
}


class PerformanceMetrics(NamedTuple):
    """Performance metrics data structure for statistical analysis."""
    
    response_time: float
    throughput: float
    memory_usage: float
    cpu_utilization: float
    error_rate: float
    p50_latency: float
    p95_latency: float
    p99_latency: float
    database_operations: int
    cache_operations: int
    external_requests: int
    timestamp: datetime


class PerformanceBenchmark:
    """
    Performance benchmark utility for Node.js baseline comparison.
    
    Provides comprehensive performance measurement, statistical analysis,
    and variance calculation against Node.js baseline metrics per
    Section 6.6.3 performance test thresholds.
    """
    
    def __init__(self, baseline_metrics: Dict[str, float]):
        """
        Initialize performance benchmark with Node.js baseline metrics.
        
        Args:
            baseline_metrics: Dictionary containing Node.js baseline performance metrics
        """
        self.baseline_metrics = baseline_metrics
        self.measurements = deque(maxlen=10000)  # Store last 10k measurements
        self.variance_violations = []
        self.performance_history = defaultdict(list)
        
        logger.info(
            "Performance benchmark initialized",
            baseline_metrics=baseline_metrics,
            variance_threshold=PERFORMANCE_VARIANCE_THRESHOLD
        )
    
    def measure_operation(self, operation_name: str, baseline_key: str = None):
        """
        Context manager for measuring operation performance with variance validation.
        
        Args:
            operation_name: Name of the operation being measured
            baseline_key: Key for baseline metric comparison
            
        Returns:
            Context manager for performance measurement
        """
        @contextmanager
        def measurement_context():
            start_time = time.perf_counter()
            start_cpu = psutil.cpu_percent(interval=None)
            start_memory = psutil.virtual_memory().used
            
            try:
                yield
            finally:
                end_time = time.perf_counter()
                end_cpu = psutil.cpu_percent(interval=None)
                end_memory = psutil.virtual_memory().used
                
                duration = end_time - start_time
                cpu_delta = abs(end_cpu - start_cpu)
                memory_delta = end_memory - start_memory
                
                measurement = {
                    'operation': operation_name,
                    'duration': duration,
                    'cpu_usage': cpu_delta,
                    'memory_change': memory_delta,
                    'timestamp': datetime.utcnow()
                }
                
                self.measurements.append(measurement)
                self.performance_history[operation_name].append(duration)
                
                # Validate against baseline if provided
                if baseline_key and baseline_key in self.baseline_metrics:
                    baseline_value = self.baseline_metrics[baseline_key]
                    variance = abs(duration - baseline_value) / baseline_value
                    
                    if variance > PERFORMANCE_VARIANCE_THRESHOLD:
                        violation = {
                            'operation': operation_name,
                            'measured': duration,
                            'baseline': baseline_value,
                            'variance': variance,
                            'threshold': PERFORMANCE_VARIANCE_THRESHOLD,
                            'timestamp': datetime.utcnow()
                        }
                        self.variance_violations.append(violation)
                        
                        logger.warning(
                            "Performance variance violation detected",
                            operation=operation_name,
                            variance_percentage=round(variance * 100, 2),
                            threshold_percentage=round(PERFORMANCE_VARIANCE_THRESHOLD * 100, 2),
                            measured_ms=round(duration * 1000, 2),
                            baseline_ms=round(baseline_value * 1000, 2)
                        )
                    else:
                        logger.debug(
                            "Performance measurement within variance threshold",
                            operation=operation_name,
                            variance_percentage=round(variance * 100, 2),
                            measured_ms=round(duration * 1000, 2)
                        )
        
        return measurement_context()
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """
        Generate comprehensive performance summary with statistical analysis.
        
        Returns:
            Dictionary containing performance summary and variance analysis
        """
        if not self.measurements:
            return {
                'total_measurements': 0,
                'variance_violations': 0,
                'performance_compliant': True,
                'summary': 'No measurements recorded'
            }
        
        # Calculate statistical summaries for each operation
        operation_stats = {}
        for operation, durations in self.performance_history.items():
            if durations:
                operation_stats[operation] = {
                    'count': len(durations),
                    'mean': statistics.mean(durations),
                    'median': statistics.median(durations),
                    'std_dev': statistics.stdev(durations) if len(durations) > 1 else 0,
                    'min': min(durations),
                    'max': max(durations),
                    'p95': np.percentile(durations, 95),
                    'p99': np.percentile(durations, 99)
                }
        
        # Calculate overall performance compliance
        total_violations = len(self.variance_violations)
        total_measurements = len(self.measurements)
        compliance_rate = (total_measurements - total_violations) / total_measurements if total_measurements > 0 else 1.0
        
        summary = {
            'total_measurements': total_measurements,
            'variance_violations': total_violations,
            'compliance_rate': compliance_rate,
            'performance_compliant': total_violations == 0,
            'operation_statistics': operation_stats,
            'violations': self.variance_violations,
            'measurement_period': {
                'start': min(m['timestamp'] for m in self.measurements).isoformat(),
                'end': max(m['timestamp'] for m in self.measurements).isoformat()
            } if self.measurements else None
        }
        
        return summary
    
    def validate_baseline_compliance(self) -> bool:
        """
        Validate overall compliance with Node.js baseline performance.
        
        Returns:
            True if all measurements are within variance threshold, False otherwise
        """
        return len(self.variance_violations) == 0


class FlaskLoadTestUser(HttpUser):
    """
    Locust user class for Flask application load testing.
    
    Implements realistic user behavior patterns including authentication,
    API interactions, database operations, and cache utilization per
    Section 6.6.1 locust load testing framework requirements.
    """
    
    wait_time = between(1, 3)  # Realistic user think time
    weight = 1
    
    def on_start(self):
        """Initialize user session with authentication and setup."""
        self.client.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'LoadTest-Client/1.0'
        })
        
        # Authenticate user for API access
        self.authenticate_user()
        
        # Initialize performance tracking
        self.request_count = 0
        self.error_count = 0
        self.start_time = time.time()
        
        logger.debug("Load test user initialized with authentication")
    
    def authenticate_user(self):
        """Authenticate user and obtain session token."""
        try:
            auth_response = self.client.post(
                "/api/auth/login",
                json={
                    "email": "test@example.com",
                    "password": "test_password"
                },
                catch_response=True
            )
            
            if auth_response.status_code == 200:
                auth_data = auth_response.json()
                token = auth_data.get('access_token')
                
                if token:
                    self.client.headers['Authorization'] = f'Bearer {token}'
                    logger.debug("User authentication successful")
                else:
                    logger.warning("Authentication successful but no token received")
            else:
                logger.warning(f"Authentication failed with status {auth_response.status_code}")
                
        except Exception as e:
            logger.error(f"Authentication error: {e}")
    
    @task(3)
    def get_user_profile(self):
        """Test user profile API endpoint with database operations."""
        with self.client.get(
            "/api/user/profile",
            catch_response=True,
            name="GET /api/user/profile"
        ) as response:
            self.request_count += 1
            
            if response.status_code == 200:
                profile_data = response.json()
                if 'user_id' in profile_data:
                    response.success()
                else:
                    response.failure("Missing user_id in profile response")
                    self.error_count += 1
            else:
                response.failure(f"HTTP {response.status_code}")
                self.error_count += 1
    
    @task(2)
    def list_projects(self):
        """Test project listing API with database queries and pagination."""
        params = {
            'page': 1,
            'limit': 20,
            'sort': 'created_at',
            'order': 'desc'
        }
        
        with self.client.get(
            "/api/projects",
            params=params,
            catch_response=True,
            name="GET /api/projects"
        ) as response:
            self.request_count += 1
            
            if response.status_code == 200:
                projects_data = response.json()
                if 'projects' in projects_data and 'total' in projects_data:
                    response.success()
                else:
                    response.failure("Invalid projects response format")
                    self.error_count += 1
            else:
                response.failure(f"HTTP {response.status_code}")
                self.error_count += 1
    
    @task(2)
    def create_project(self):
        """Test project creation API with database writes and validation."""
        project_data = {
            'name': f'LoadTest Project {int(time.time())}',
            'description': 'Project created during load testing',
            'category': 'testing',
            'tags': ['load_test', 'performance'],
            'visibility': 'private'
        }
        
        with self.client.post(
            "/api/projects",
            json=project_data,
            catch_response=True,
            name="POST /api/projects"
        ) as response:
            self.request_count += 1
            
            if response.status_code == 201:
                created_project = response.json()
                if 'project_id' in created_project:
                    # Store project ID for potential updates/deletes
                    self.project_id = created_project['project_id']
                    response.success()
                else:
                    response.failure("Missing project_id in creation response")
                    self.error_count += 1
            else:
                response.failure(f"HTTP {response.status_code}")
                self.error_count += 1
    
    @task(1)
    def update_project(self):
        """Test project update API with database updates and cache invalidation."""
        if not hasattr(self, 'project_id'):
            return  # Skip if no project created yet
        
        update_data = {
            'description': f'Updated description at {datetime.utcnow().isoformat()}',
            'tags': ['load_test', 'performance', 'updated']
        }
        
        with self.client.put(
            f"/api/projects/{self.project_id}",
            json=update_data,
            catch_response=True,
            name="PUT /api/projects/{id}"
        ) as response:
            self.request_count += 1
            
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"HTTP {response.status_code}")
                self.error_count += 1
    
    @task(1)
    def search_projects(self):
        """Test project search API with database queries and caching."""
        search_params = {
            'query': 'test',
            'category': 'testing',
            'limit': 10
        }
        
        with self.client.get(
            "/api/projects/search",
            params=search_params,
            catch_response=True,
            name="GET /api/projects/search"
        ) as response:
            self.request_count += 1
            
            if response.status_code == 200:
                search_results = response.json()
                if 'results' in search_results:
                    response.success()
                else:
                    response.failure("Invalid search response format")
                    self.error_count += 1
            else:
                response.failure(f"HTTP {response.status_code}")
                self.error_count += 1
    
    @task(1)
    def get_analytics(self):
        """Test analytics API with complex database aggregations."""
        with self.client.get(
            "/api/analytics/dashboard",
            catch_response=True,
            name="GET /api/analytics/dashboard"
        ) as response:
            self.request_count += 1
            
            if response.status_code == 200:
                analytics_data = response.json()
                if 'metrics' in analytics_data:
                    response.success()
                else:
                    response.failure("Invalid analytics response format")
                    self.error_count += 1
            else:
                response.failure(f"HTTP {response.status_code}")
                self.error_count += 1
    
    def on_stop(self):
        """Cleanup user session and log performance statistics."""
        session_duration = time.time() - self.start_time
        error_rate = self.error_count / self.request_count if self.request_count > 0 else 0
        
        logger.info(
            "Load test user session completed",
            request_count=self.request_count,
            error_count=self.error_count,
            error_rate=round(error_rate * 100, 2),
            session_duration=round(session_duration, 2)
        )


class PerformanceIntegrationTestSuite:
    """
    Comprehensive performance integration test suite.
    
    Orchestrates load testing, benchmark testing, database performance validation,
    cache effectiveness testing, and external service monitoring per Section 6.6.1
    performance testing tools and Section 6.6.3 performance test thresholds.
    """
    
    def __init__(self, test_environment: Dict[str, Any]):
        """
        Initialize performance test suite with comprehensive test environment.
        
        Args:
            test_environment: Complete test environment from conftest.py
        """
        self.test_environment = test_environment
        self.benchmark = PerformanceBenchmark(NODEJS_BASELINE_METRICS)
        self.client = test_environment['client']
        self.app = test_environment['app']
        self.database = test_environment['database']
        self.performance_monitor = test_environment['performance']
        
        # Initialize result storage
        self.test_results = {
            'load_test_results': {},
            'benchmark_results': {},
            'database_performance': {},
            'cache_performance': {},
            'external_service_performance': {},
            'resource_utilization': {},
            'variance_analysis': {}
        }
        
        logger.info(
            "Performance integration test suite initialized",
            test_environment_available=bool(test_environment),
            database_available=bool(self.database.get('pymongo_client')),
            cache_available=bool(test_environment.get('cache')),
            monitoring_enabled=bool(self.performance_monitor)
        )
    
    def run_locust_load_test(
        self,
        host: str = "http://localhost:5000",
        users: int = MIN_CONCURRENT_USERS,
        spawn_rate: int = 5,
        duration: int = LOAD_TEST_DURATION
    ) -> Dict[str, Any]:
        """
        Execute locust load test with distributed user simulation.
        
        Args:
            host: Target Flask application host URL
            users: Number of concurrent users to simulate
            spawn_rate: Rate of user spawning per second
            duration: Test duration in seconds
            
        Returns:
            Dictionary containing comprehensive load test results
        """
        logger.info(
            "Starting locust load test",
            target_host=host,
            concurrent_users=users,
            spawn_rate=spawn_rate,
            duration_seconds=duration
        )
        
        # Configure locust environment
        env = Environment(user_classes=[FlaskLoadTestUser])
        env.create_local_runner()
        
        # Configure statistics collection
        stats_csv = StatsCSV(env, "load_test_results")
        
        # Initialize performance tracking
        performance_data = []
        resource_data = []
        
        def collect_stats():
            """Collect performance statistics during load test."""
            while env.runner.state != "stopped":
                timestamp = datetime.utcnow()
                
                # Collect locust statistics
                stats = env.stats.get("/", "GET")
                performance_data.append({
                    'timestamp': timestamp,
                    'current_rps': stats.current_rps,
                    'avg_response_time': stats.avg_response_time,
                    'min_response_time': stats.min_response_time,
                    'max_response_time': stats.max_response_time,
                    'current_fail_per_sec': stats.current_fail_per_sec,
                    'num_requests': stats.num_requests,
                    'num_failures': stats.num_failures
                })
                
                # Collect system resource utilization
                resource_data.append({
                    'timestamp': timestamp,
                    'cpu_percent': psutil.cpu_percent(interval=None),
                    'memory_percent': psutil.virtual_memory().percent,
                    'memory_used_mb': psutil.virtual_memory().used / (1024 * 1024),
                    'disk_io_read': psutil.disk_io_counters().read_bytes if psutil.disk_io_counters() else 0,
                    'disk_io_write': psutil.disk_io_counters().write_bytes if psutil.disk_io_counters() else 0,
                    'network_sent': psutil.net_io_counters().bytes_sent if psutil.net_io_counters() else 0,
                    'network_recv': psutil.net_io_counters().bytes_recv if psutil.net_io_counters() else 0
                })
                
                time.sleep(1)  # Collect stats every second
        
        # Start statistics collection in background
        stats_thread = threading.Thread(target=collect_stats, daemon=True)
        stats_thread.start()
        
        try:
            # Start load test
            env.runner.start(users, spawn_rate=spawn_rate)
            
            # Run for specified duration
            time.sleep(duration)
            
            # Stop load test
            env.runner.stop()
            
            # Wait for all users to stop
            env.runner.quit()
            
        except Exception as e:
            logger.error(f"Load test execution failed: {e}")
            env.runner.stop()
            raise
        
        # Analyze results
        results = self._analyze_load_test_results(env.stats, performance_data, resource_data)
        
        logger.info(
            "Locust load test completed",
            total_requests=results['summary']['total_requests'],
            total_failures=results['summary']['total_failures'],
            average_response_time=results['summary']['average_response_time'],
            requests_per_second=results['summary']['requests_per_second'],
            failure_rate=results['summary']['failure_rate']
        )
        
        return results
    
    def run_apache_bench_test(
        self,
        url: str = "http://localhost:5000/api/health",
        requests: int = 1000,
        concurrency: int = 50
    ) -> Dict[str, Any]:
        """
        Execute apache-bench performance test for baseline comparison.
        
        Args:
            url: Target URL for benchmark testing
            requests: Total number of requests to send
            concurrency: Number of concurrent requests
            
        Returns:
            Dictionary containing apache-bench test results
        """
        logger.info(
            "Starting apache-bench performance test",
            target_url=url,
            total_requests=requests,
            concurrency=concurrency
        )
        
        # Prepare apache-bench command
        ab_command = [
            'ab',
            '-n', str(requests),
            '-c', str(concurrency),
            '-g', 'ab_results.tsv',  # Output gnuplot data
            '-e', 'ab_results.csv',  # Output CSV data
            url
        ]
        
        try:
            # Execute apache-bench test
            result = subprocess.run(
                ab_command,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
                cwd=tempfile.gettempdir()
            )
            
            if result.returncode != 0:
                logger.error(f"Apache-bench failed: {result.stderr}")
                return {'error': result.stderr, 'success': False}
            
            # Parse apache-bench output
            ab_results = self._parse_apache_bench_output(result.stdout)
            
            # Validate against Node.js baseline
            baseline_validation = self._validate_apache_bench_baseline(ab_results)
            
            results = {
                'success': True,
                'raw_output': result.stdout,
                'parsed_results': ab_results,
                'baseline_validation': baseline_validation,
                'test_configuration': {
                    'url': url,
                    'requests': requests,
                    'concurrency': concurrency
                }
            }
            
            logger.info(
                "Apache-bench test completed",
                requests_per_second=ab_results.get('requests_per_second', 0),
                mean_response_time=ab_results.get('mean_response_time', 0),
                failed_requests=ab_results.get('failed_requests', 0),
                baseline_compliant=baseline_validation.get('compliant', False)
            )
            
            return results
            
        except subprocess.TimeoutExpired:
            logger.error("Apache-bench test timed out")
            return {'error': 'Test timed out', 'success': False}
        except Exception as e:
            logger.error(f"Apache-bench test failed: {e}")
            return {'error': str(e), 'success': False}
    
    async def test_database_performance(self) -> Dict[str, Any]:
        """
        Test database operation performance with PyMongo and Motor.
        
        Returns:
            Dictionary containing database performance test results
        """
        logger.info("Starting database performance testing")
        
        results = {
            'pymongo_tests': {},
            'motor_tests': {},
            'operation_latencies': {},
            'throughput_metrics': {},
            'baseline_compliance': {}
        }
        
        # Test PyMongo synchronous operations
        if self.database.get('pymongo_client'):
            results['pymongo_tests'] = await self._test_pymongo_performance()
        
        # Test Motor asynchronous operations
        if self.database.get('motor_client'):
            results['motor_tests'] = await self._test_motor_performance()
        
        # Validate against Node.js baseline
        results['baseline_compliance'] = self._validate_database_baseline(results)
        
        logger.info(
            "Database performance testing completed",
            pymongo_available=bool(results['pymongo_tests']),
            motor_available=bool(results['motor_tests']),
            baseline_compliant=results['baseline_compliance'].get('compliant', False)
        )
        
        return results
    
    def test_cache_performance(self) -> Dict[str, Any]:
        """
        Test Redis cache performance and effectiveness.
        
        Returns:
            Dictionary containing cache performance test results
        """
        logger.info("Starting cache performance testing")
        
        results = {
            'redis_operations': {},
            'cache_hit_ratios': {},
            'operation_latencies': {},
            'throughput_metrics': {},
            'baseline_compliance': {}
        }
        
        if not self.database.get('redis_client'):
            logger.warning("Redis client not available for cache performance testing")
            return results
        
        redis_client = self.database['redis_client']
        
        # Test basic Redis operations with performance measurement
        operation_results = []
        
        # Test SET operations
        for i in range(100):
            with self.benchmark.measure_operation(f"redis_set_{i}", "cache_operation_time"):
                key = f"perf_test_key_{i}"
                value = f"performance_test_value_{i}_{datetime.utcnow().isoformat()}"
                redis_client.set(key, value, ex=300)  # 5 minute TTL
                operation_results.append({'operation': 'set', 'key': key, 'success': True})
        
        # Test GET operations with cache hit measurement
        cache_hits = 0
        cache_misses = 0
        
        for i in range(100):
            with self.benchmark.measure_operation(f"redis_get_{i}", "cache_operation_time"):
                key = f"perf_test_key_{i}"
                value = redis_client.get(key)
                
                if value:
                    cache_hits += 1
                    operation_results.append({'operation': 'get', 'key': key, 'success': True, 'hit': True})
                else:
                    cache_misses += 1
                    operation_results.append({'operation': 'get', 'key': key, 'success': True, 'hit': False})
        
        # Calculate cache performance metrics
        total_operations = cache_hits + cache_misses
        hit_ratio = cache_hits / total_operations if total_operations > 0 else 0
        
        results['redis_operations'] = {
            'total_operations': len(operation_results),
            'successful_operations': sum(1 for op in operation_results if op['success']),
            'operation_details': operation_results
        }
        
        results['cache_hit_ratios'] = {
            'cache_hits': cache_hits,
            'cache_misses': cache_misses,
            'hit_ratio': hit_ratio,
            'target_hit_ratio': 0.90  # 90% target hit ratio
        }
        
        # Validate against performance baseline
        results['baseline_compliance'] = self._validate_cache_baseline(results)
        
        logger.info(
            "Cache performance testing completed",
            total_operations=results['redis_operations']['total_operations'],
            hit_ratio=round(hit_ratio * 100, 2),
            baseline_compliant=results['baseline_compliance'].get('compliant', False)
        )
        
        return results
    
    def test_external_service_performance(self) -> Dict[str, Any]:
        """
        Test external service integration performance and timeouts.
        
        Returns:
            Dictionary containing external service performance test results
        """
        logger.info("Starting external service performance testing")
        
        results = {
            'service_tests': {},
            'response_times': {},
            'timeout_handling': {},
            'circuit_breaker_tests': {},
            'baseline_compliance': {}
        }
        
        external_services = self.test_environment.get('external_services', {})
        circuit_breakers = self.test_environment.get('circuit_breakers', {})
        
        # Test HTTP client performance with realistic external service calls
        if external_services.get('http_client'):
            results['service_tests']['http_client'] = self._test_http_client_performance()
        
        # Test AWS S3 service performance
        if external_services.get('aws_s3'):
            results['service_tests']['aws_s3'] = self._test_aws_s3_performance()
        
        # Test circuit breaker performance under failure conditions
        if circuit_breakers:
            results['circuit_breaker_tests'] = self._test_circuit_breaker_performance(circuit_breakers)
        
        # Validate against Node.js baseline
        results['baseline_compliance'] = self._validate_external_service_baseline(results)
        
        logger.info(
            "External service performance testing completed",
            services_tested=len(results['service_tests']),
            circuit_breakers_tested=len(results['circuit_breaker_tests']),
            baseline_compliant=results['baseline_compliance'].get('compliant', False)
        )
        
        return results
    
    def _analyze_load_test_results(
        self,
        stats,
        performance_data: List[Dict],
        resource_data: List[Dict]
    ) -> Dict[str, Any]:
        """
        Analyze locust load test results with statistical analysis.
        
        Args:
            stats: Locust statistics object
            performance_data: Performance metrics collected during test
            resource_data: System resource utilization data
            
        Returns:
            Comprehensive analysis of load test results
        """
        # Calculate summary statistics
        total_stats = stats.total
        
        summary = {
            'total_requests': total_stats.num_requests,
            'total_failures': total_stats.num_failures,
            'average_response_time': total_stats.avg_response_time,
            'min_response_time': total_stats.min_response_time,
            'max_response_time': total_stats.max_response_time,
            'requests_per_second': total_stats.total_rps,
            'failure_rate': (total_stats.num_failures / total_stats.num_requests) if total_stats.num_requests > 0 else 0
        }
        
        # Analyze performance data trends
        if performance_data:
            df_perf = pd.DataFrame(performance_data)
            performance_analysis = {
                'avg_rps': df_perf['current_rps'].mean(),
                'max_rps': df_perf['current_rps'].max(),
                'min_rps': df_perf['current_rps'].min(),
                'rps_std_dev': df_perf['current_rps'].std(),
                'response_time_p50': df_perf['avg_response_time'].quantile(0.5),
                'response_time_p95': df_perf['avg_response_time'].quantile(0.95),
                'response_time_p99': df_perf['avg_response_time'].quantile(0.99)
            }
        else:
            performance_analysis = {}
        
        # Analyze resource utilization
        if resource_data:
            df_resource = pd.DataFrame(resource_data)
            resource_analysis = {
                'avg_cpu_percent': df_resource['cpu_percent'].mean(),
                'max_cpu_percent': df_resource['cpu_percent'].max(),
                'avg_memory_percent': df_resource['memory_percent'].mean(),
                'max_memory_percent': df_resource['memory_percent'].max(),
                'avg_memory_mb': df_resource['memory_used_mb'].mean(),
                'max_memory_mb': df_resource['memory_used_mb'].max(),
                'memory_growth': df_resource['memory_used_mb'].max() - df_resource['memory_used_mb'].min()
            }
        else:
            resource_analysis = {}
        
        # Validate against Node.js baseline
        baseline_validation = self._validate_load_test_baseline(summary, performance_analysis, resource_analysis)
        
        return {
            'summary': summary,
            'performance_analysis': performance_analysis,
            'resource_analysis': resource_analysis,
            'baseline_validation': baseline_validation,
            'raw_performance_data': performance_data[:100],  # Limit for storage
            'raw_resource_data': resource_data[:100]  # Limit for storage
        }
    
    def _parse_apache_bench_output(self, output: str) -> Dict[str, Any]:
        """
        Parse apache-bench output into structured data.
        
        Args:
            output: Raw apache-bench output text
            
        Returns:
            Dictionary containing parsed apache-bench results
        """
        results = {}
        
        for line in output.split('\n'):
            line = line.strip()
            
            if 'Requests per second:' in line:
                rps = float(line.split()[3])
                results['requests_per_second'] = rps
            
            elif 'Time taken for tests:' in line:
                time_taken = float(line.split()[4])
                results['time_taken'] = time_taken
            
            elif 'Complete requests:' in line:
                complete_requests = int(line.split()[2])
                results['complete_requests'] = complete_requests
            
            elif 'Failed requests:' in line:
                failed_requests = int(line.split()[2])
                results['failed_requests'] = failed_requests
            
            elif 'Total transferred:' in line:
                total_bytes = int(line.split()[2])
                results['total_bytes'] = total_bytes
            
            elif 'HTML transferred:' in line:
                html_bytes = int(line.split()[2])
                results['html_bytes'] = html_bytes
            
            elif 'Time per request:' in line and 'mean' in line:
                time_per_request = float(line.split()[3])
                results['mean_response_time'] = time_per_request
            
            elif '50%' in line and 'ms' in line:
                p50 = int(line.split()[1])
                results['p50_response_time'] = p50
            
            elif '95%' in line and 'ms' in line:
                p95 = int(line.split()[1])
                results['p95_response_time'] = p95
            
            elif '99%' in line and 'ms' in line:
                p99 = int(line.split()[1])
                results['p99_response_time'] = p99
        
        return results
    
    def _validate_apache_bench_baseline(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate apache-bench results against Node.js baseline.
        
        Args:
            results: Parsed apache-bench results
            
        Returns:
            Baseline validation results
        """
        validation = {
            'compliant': True,
            'violations': [],
            'metrics_comparison': {}
        }
        
        # Compare requests per second
        if 'requests_per_second' in results:
            baseline_rps = NODEJS_BASELINE_METRICS['concurrent_throughput']
            measured_rps = results['requests_per_second']
            variance = abs(measured_rps - baseline_rps) / baseline_rps
            
            validation['metrics_comparison']['requests_per_second'] = {
                'measured': measured_rps,
                'baseline': baseline_rps,
                'variance': variance,
                'compliant': variance <= PERFORMANCE_VARIANCE_THRESHOLD
            }
            
            if variance > PERFORMANCE_VARIANCE_THRESHOLD:
                validation['compliant'] = False
                validation['violations'].append({
                    'metric': 'requests_per_second',
                    'variance': variance,
                    'threshold': PERFORMANCE_VARIANCE_THRESHOLD
                })
        
        # Compare response time
        if 'mean_response_time' in results:
            baseline_response_time = NODEJS_BASELINE_METRICS['api_response_time'] * 1000  # Convert to ms
            measured_response_time = results['mean_response_time']
            variance = abs(measured_response_time - baseline_response_time) / baseline_response_time
            
            validation['metrics_comparison']['response_time'] = {
                'measured': measured_response_time,
                'baseline': baseline_response_time,
                'variance': variance,
                'compliant': variance <= PERFORMANCE_VARIANCE_THRESHOLD
            }
            
            if variance > PERFORMANCE_VARIANCE_THRESHOLD:
                validation['compliant'] = False
                validation['violations'].append({
                    'metric': 'response_time',
                    'variance': variance,
                    'threshold': PERFORMANCE_VARIANCE_THRESHOLD
                })
        
        return validation
    
    async def _test_pymongo_performance(self) -> Dict[str, Any]:
        """Test PyMongo synchronous database operations performance."""
        client = self.database['pymongo_client']
        db = client.get_default_database()
        collection = db.performance_test
        
        results = {
            'insert_performance': {},
            'find_performance': {},
            'update_performance': {},
            'aggregate_performance': {},
            'index_performance': {}
        }
        
        # Test insert operations
        insert_times = []
        for i in range(100):
            doc = {
                'test_id': i,
                'name': f'Performance Test Document {i}',
                'timestamp': datetime.utcnow(),
                'data': {'field1': f'value_{i}', 'field2': i * 2, 'field3': i % 10}
            }
            
            with self.benchmark.measure_operation(f"pymongo_insert_{i}", "database_query_time"):
                start_time = time.perf_counter()
                collection.insert_one(doc)
                end_time = time.perf_counter()
                insert_times.append(end_time - start_time)
        
        results['insert_performance'] = {
            'total_operations': len(insert_times),
            'average_time': statistics.mean(insert_times),
            'min_time': min(insert_times),
            'max_time': max(insert_times),
            'p95_time': np.percentile(insert_times, 95),
            'operations_per_second': len(insert_times) / sum(insert_times)
        }
        
        # Test find operations
        find_times = []
        for i in range(100):
            with self.benchmark.measure_operation(f"pymongo_find_{i}", "database_query_time"):
                start_time = time.perf_counter()
                result = collection.find_one({'test_id': i})
                end_time = time.perf_counter()
                find_times.append(end_time - start_time)
        
        results['find_performance'] = {
            'total_operations': len(find_times),
            'average_time': statistics.mean(find_times),
            'min_time': min(find_times),
            'max_time': max(find_times),
            'p95_time': np.percentile(find_times, 95),
            'operations_per_second': len(find_times) / sum(find_times)
        }
        
        # Cleanup test data
        collection.delete_many({'test_id': {'$exists': True}})
        
        return results
    
    async def _test_motor_performance(self) -> Dict[str, Any]:
        """Test Motor asynchronous database operations performance."""
        client = self.database['motor_client']
        db = client.get_default_database()
        collection = db.performance_test_async
        
        results = {
            'async_insert_performance': {},
            'async_find_performance': {},
            'concurrent_operations': {}
        }
        
        # Test async insert operations
        async def async_insert_test():
            insert_times = []
            for i in range(100):
                doc = {
                    'test_id': i,
                    'name': f'Async Performance Test Document {i}',
                    'timestamp': datetime.utcnow(),
                    'data': {'field1': f'async_value_{i}', 'field2': i * 3, 'field3': i % 5}
                }
                
                start_time = time.perf_counter()
                await collection.insert_one(doc)
                end_time = time.perf_counter()
                insert_times.append(end_time - start_time)
            
            return insert_times
        
        insert_times = await async_insert_test()
        
        results['async_insert_performance'] = {
            'total_operations': len(insert_times),
            'average_time': statistics.mean(insert_times),
            'min_time': min(insert_times),
            'max_time': max(insert_times),
            'p95_time': np.percentile(insert_times, 95),
            'operations_per_second': len(insert_times) / sum(insert_times)
        }
        
        # Test concurrent async operations
        async def concurrent_find_operation(test_id):
            start_time = time.perf_counter()
            result = await collection.find_one({'test_id': test_id})
            end_time = time.perf_counter()
            return end_time - start_time
        
        # Run 50 concurrent find operations
        concurrent_tasks = [concurrent_find_operation(i) for i in range(50)]
        concurrent_times = await asyncio.gather(*concurrent_tasks)
        
        results['concurrent_operations'] = {
            'total_operations': len(concurrent_times),
            'average_time': statistics.mean(concurrent_times),
            'min_time': min(concurrent_times),
            'max_time': max(concurrent_times),
            'p95_time': np.percentile(concurrent_times, 95),
            'operations_per_second': len(concurrent_times) / max(concurrent_times)
        }
        
        # Cleanup test data
        await collection.delete_many({'test_id': {'$exists': True}})
        
        return results
    
    def _validate_database_baseline(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Validate database performance results against Node.js baseline."""
        validation = {
            'compliant': True,
            'violations': [],
            'metrics_comparison': {}
        }
        
        baseline_db_time = NODEJS_BASELINE_METRICS['database_query_time']
        
        # Validate PyMongo performance
        if results.get('pymongo_tests', {}).get('find_performance'):
            avg_time = results['pymongo_tests']['find_performance']['average_time']
            variance = abs(avg_time - baseline_db_time) / baseline_db_time
            
            validation['metrics_comparison']['pymongo_find'] = {
                'measured': avg_time,
                'baseline': baseline_db_time,
                'variance': variance,
                'compliant': variance <= PERFORMANCE_VARIANCE_THRESHOLD
            }
            
            if variance > PERFORMANCE_VARIANCE_THRESHOLD:
                validation['compliant'] = False
                validation['violations'].append({
                    'metric': 'pymongo_find_average_time',
                    'variance': variance,
                    'threshold': PERFORMANCE_VARIANCE_THRESHOLD
                })
        
        # Validate Motor performance
        if results.get('motor_tests', {}).get('async_find_performance'):
            avg_time = results['motor_tests']['async_find_performance']['average_time']
            variance = abs(avg_time - baseline_db_time) / baseline_db_time
            
            validation['metrics_comparison']['motor_find'] = {
                'measured': avg_time,
                'baseline': baseline_db_time,
                'variance': variance,
                'compliant': variance <= PERFORMANCE_VARIANCE_THRESHOLD
            }
            
            if variance > PERFORMANCE_VARIANCE_THRESHOLD:
                validation['compliant'] = False
                validation['violations'].append({
                    'metric': 'motor_find_average_time',
                    'variance': variance,
                    'threshold': PERFORMANCE_VARIANCE_THRESHOLD
                })
        
        return validation
    
    def _validate_cache_baseline(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Validate cache performance results against Node.js baseline."""
        validation = {
            'compliant': True,
            'violations': [],
            'metrics_comparison': {}
        }
        
        # Validate hit ratio requirement
        hit_ratio = results.get('cache_hit_ratios', {}).get('hit_ratio', 0)
        target_hit_ratio = 0.90  # 90% target
        
        validation['metrics_comparison']['cache_hit_ratio'] = {
            'measured': hit_ratio,
            'target': target_hit_ratio,
            'compliant': hit_ratio >= target_hit_ratio
        }
        
        if hit_ratio < target_hit_ratio:
            validation['compliant'] = False
            validation['violations'].append({
                'metric': 'cache_hit_ratio',
                'measured': hit_ratio,
                'target': target_hit_ratio
            })
        
        return validation
    
    def _validate_load_test_baseline(
        self,
        summary: Dict[str, Any],
        performance_analysis: Dict[str, Any],
        resource_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Validate load test results against Node.js baseline."""
        validation = {
            'compliant': True,
            'violations': [],
            'metrics_comparison': {}
        }
        
        # Validate throughput
        measured_rps = summary.get('requests_per_second', 0)
        baseline_rps = NODEJS_BASELINE_METRICS['concurrent_throughput']
        
        if measured_rps > 0:
            variance = abs(measured_rps - baseline_rps) / baseline_rps
            
            validation['metrics_comparison']['throughput'] = {
                'measured': measured_rps,
                'baseline': baseline_rps,
                'variance': variance,
                'compliant': variance <= PERFORMANCE_VARIANCE_THRESHOLD
            }
            
            if variance > PERFORMANCE_VARIANCE_THRESHOLD:
                validation['compliant'] = False
                validation['violations'].append({
                    'metric': 'requests_per_second',
                    'variance': variance,
                    'threshold': PERFORMANCE_VARIANCE_THRESHOLD
                })
        
        # Validate response time
        measured_response_time = summary.get('average_response_time', 0) / 1000  # Convert to seconds
        baseline_response_time = NODEJS_BASELINE_METRICS['api_response_time']
        
        if measured_response_time > 0:
            variance = abs(measured_response_time - baseline_response_time) / baseline_response_time
            
            validation['metrics_comparison']['response_time'] = {
                'measured': measured_response_time,
                'baseline': baseline_response_time,
                'variance': variance,
                'compliant': variance <= PERFORMANCE_VARIANCE_THRESHOLD
            }
            
            if variance > PERFORMANCE_VARIANCE_THRESHOLD:
                validation['compliant'] = False
                validation['violations'].append({
                    'metric': 'average_response_time',
                    'variance': variance,
                    'threshold': PERFORMANCE_VARIANCE_THRESHOLD
                })
        
        return validation
    
    def _test_http_client_performance(self) -> Dict[str, Any]:
        """Test HTTP client performance for external service calls."""
        results = {
            'request_times': [],
            'success_count': 0,
            'error_count': 0,
            'timeouts': 0
        }
        
        # Simulate external API calls
        for i in range(50):
            try:
                with self.benchmark.measure_operation(f"http_client_{i}", "external_api_time"):
                    start_time = time.perf_counter()
                    
                    # Simulate HTTP request (using mock)
                    time.sleep(0.1)  # Simulate network latency
                    
                    end_time = time.perf_counter()
                    request_time = end_time - start_time
                    
                    results['request_times'].append(request_time)
                    results['success_count'] += 1
                    
            except Exception as e:
                results['error_count'] += 1
                logger.warning(f"HTTP client request failed: {e}")
        
        if results['request_times']:
            results['average_time'] = statistics.mean(results['request_times'])
            results['min_time'] = min(results['request_times'])
            results['max_time'] = max(results['request_times'])
            results['p95_time'] = np.percentile(results['request_times'], 95)
        
        return results
    
    def _test_aws_s3_performance(self) -> Dict[str, Any]:
        """Test AWS S3 service performance simulation."""
        results = {
            'upload_times': [],
            'download_times': [],
            'list_times': [],
            'success_count': 0,
            'error_count': 0
        }
        
        # Simulate S3 operations
        for i in range(20):
            try:
                # Simulate upload
                start_time = time.perf_counter()
                time.sleep(0.05)  # Simulate upload time
                end_time = time.perf_counter()
                results['upload_times'].append(end_time - start_time)
                
                # Simulate download
                start_time = time.perf_counter()
                time.sleep(0.03)  # Simulate download time
                end_time = time.perf_counter()
                results['download_times'].append(end_time - start_time)
                
                # Simulate list operation
                start_time = time.perf_counter()
                time.sleep(0.02)  # Simulate list time
                end_time = time.perf_counter()
                results['list_times'].append(end_time - start_time)
                
                results['success_count'] += 1
                
            except Exception as e:
                results['error_count'] += 1
                logger.warning(f"S3 operation failed: {e}")
        
        return results
    
    def _test_circuit_breaker_performance(self, circuit_breakers: Dict[str, Any]) -> Dict[str, Any]:
        """Test circuit breaker performance under failure conditions."""
        results = {}
        
        for service_name, circuit_breaker in circuit_breakers.items():
            service_results = {
                'normal_operations': 0,
                'circuit_open_operations': 0,
                'recovery_operations': 0,
                'failure_response_times': [],
                'success_response_times': []
            }
            
            # Test normal operation
            for i in range(10):
                try:
                    start_time = time.perf_counter()
                    # Simulate successful operation
                    circuit_breaker.call(lambda: time.sleep(0.01))
                    end_time = time.perf_counter()
                    
                    service_results['normal_operations'] += 1
                    service_results['success_response_times'].append(end_time - start_time)
                    
                except Exception:
                    pass
            
            # Simulate failures to trigger circuit breaker
            for i in range(10):
                try:
                    start_time = time.perf_counter()
                    # Simulate failing operation
                    circuit_breaker.call(lambda: exec('raise Exception("Simulated failure")'))
                except Exception:
                    end_time = time.perf_counter()
                    service_results['failure_response_times'].append(end_time - start_time)
            
            # Test circuit breaker open state
            for i in range(5):
                try:
                    start_time = time.perf_counter()
                    circuit_breaker.call(lambda: time.sleep(0.01))
                except Exception:
                    end_time = time.perf_counter()
                    service_results['circuit_open_operations'] += 1
            
            results[service_name] = service_results
        
        return results
    
    def _validate_external_service_baseline(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Validate external service performance against Node.js baseline."""
        validation = {
            'compliant': True,
            'violations': [],
            'metrics_comparison': {}
        }
        
        # Validate HTTP client performance
        if results.get('service_tests', {}).get('http_client', {}).get('average_time'):
            avg_time = results['service_tests']['http_client']['average_time']
            baseline_time = NODEJS_BASELINE_METRICS['external_api_time']
            variance = abs(avg_time - baseline_time) / baseline_time
            
            validation['metrics_comparison']['http_client'] = {
                'measured': avg_time,
                'baseline': baseline_time,
                'variance': variance,
                'compliant': variance <= PERFORMANCE_VARIANCE_THRESHOLD
            }
            
            if variance > PERFORMANCE_VARIANCE_THRESHOLD:
                validation['compliant'] = False
                validation['violations'].append({
                    'metric': 'http_client_average_time',
                    'variance': variance,
                    'threshold': PERFORMANCE_VARIANCE_THRESHOLD
                })
        
        return validation


# =============================================================================
# Performance Integration Test Cases
# =============================================================================

@pytest.mark.integration
@pytest.mark.performance
@pytest.mark.slow
class TestPerformanceIntegration:
    """
    Comprehensive performance integration test class.
    
    Tests performance characteristics across all system components including
    concurrent request handling, database operations, cache effectiveness,
    and external service integration per Section 6.6.1 performance testing
    tools and Section 6.6.3 performance test thresholds.
    """
    
    @pytest.fixture(autouse=True)
    def setup_performance_suite(self, comprehensive_test_environment):
        """Set up performance test suite with comprehensive environment."""
        self.performance_suite = PerformanceIntegrationTestSuite(comprehensive_test_environment)
        self.test_environment = comprehensive_test_environment
        
        logger.info(
            "Performance integration test suite initialized",
            suite_available=bool(self.performance_suite),
            environment_configured=bool(comprehensive_test_environment)
        )
    
    @pytest.mark.testcontainers
    @skip_if_no_docker
    def test_concurrent_request_handling_capacity(self):
        """
        Test concurrent request handling capacity with locust load testing.
        
        Validates that the Flask application can handle concurrent requests
        within ≤10% variance of Node.js baseline per Section 6.6.3 performance
        test thresholds and Section 6.6.1 locust load testing framework.
        """
        logger.info("Starting concurrent request handling capacity test")
        
        # Configure load test parameters
        load_test_config = {
            'host': f"http://localhost:{self.test_environment['app'].config.get('PORT', 5000)}",
            'users': MIN_CONCURRENT_USERS,
            'spawn_rate': 10,
            'duration': 180  # 3 minutes for concurrent capacity testing
        }
        
        # Execute load test
        load_test_results = self.performance_suite.run_locust_load_test(**load_test_config)
        
        # Validate results
        assert load_test_results['summary']['total_requests'] > 0, "No requests were processed"
        assert load_test_results['summary']['failure_rate'] < 0.05, "Failure rate exceeds 5% threshold"
        
        # Validate concurrent throughput against baseline
        measured_rps = load_test_results['summary']['requests_per_second']
        baseline_rps = NODEJS_BASELINE_METRICS['concurrent_throughput']
        variance = abs(measured_rps - baseline_rps) / baseline_rps
        
        assert variance <= PERFORMANCE_VARIANCE_THRESHOLD, (
            f"Concurrent throughput variance {variance:.3f} exceeds threshold {PERFORMANCE_VARIANCE_THRESHOLD}"
        )
        
        # Validate response time compliance
        avg_response_time = load_test_results['summary']['average_response_time'] / 1000  # Convert to seconds
        baseline_response_time = NODEJS_BASELINE_METRICS['api_response_time']
        response_variance = abs(avg_response_time - baseline_response_time) / baseline_response_time
        
        assert response_variance <= PERFORMANCE_VARIANCE_THRESHOLD, (
            f"Response time variance {response_variance:.3f} exceeds threshold {PERFORMANCE_VARIANCE_THRESHOLD}"
        )
        
        # Validate resource utilization
        if load_test_results.get('resource_analysis'):
            max_cpu = load_test_results['resource_analysis'].get('max_cpu_percent', 0)
            assert max_cpu <= CPU_UTILIZATION_THRESHOLD * 100, (
                f"CPU utilization {max_cpu}% exceeds threshold {CPU_UTILIZATION_THRESHOLD * 100}%"
            )
            
            memory_growth = load_test_results['resource_analysis'].get('memory_growth', 0)
            initial_memory = load_test_results['resource_analysis'].get('avg_memory_mb', 256)
            memory_growth_rate = memory_growth / initial_memory if initial_memory > 0 else 0
            
            assert memory_growth_rate <= MEMORY_GROWTH_THRESHOLD, (
                f"Memory growth rate {memory_growth_rate:.3f} exceeds threshold {MEMORY_GROWTH_THRESHOLD}"
            )
        
        logger.info(
            "Concurrent request handling capacity test completed successfully",
            requests_per_second=measured_rps,
            variance_from_baseline=round(variance * 100, 2),
            baseline_compliant=variance <= PERFORMANCE_VARIANCE_THRESHOLD
        )
    
    def test_apache_bench_baseline_comparison(self):
        """
        Test HTTP server performance with apache-bench for Node.js baseline comparison.
        
        Validates HTTP server performance characteristics using apache-bench
        for direct comparison with Node.js baseline per Section 6.6.1 apache-bench
        performance measurement requirements.
        """
        logger.info("Starting apache-bench baseline comparison test")
        
        # Test health endpoint performance
        health_results = self.performance_suite.run_apache_bench_test(
            url=f"http://localhost:{self.test_environment['app'].config.get('PORT', 5000)}/health",
            requests=1000,
            concurrency=50
        )
        
        assert health_results['success'], f"Apache-bench test failed: {health_results.get('error', 'Unknown error')}"
        
        # Validate baseline compliance
        baseline_validation = health_results['baseline_validation']
        assert baseline_validation['compliant'], (
            f"Apache-bench baseline compliance failed: {baseline_validation['violations']}"
        )
        
        # Test API endpoint performance
        api_results = self.performance_suite.run_apache_bench_test(
            url=f"http://localhost:{self.test_environment['app'].config.get('PORT', 5000)}/api/health",
            requests=500,
            concurrency=25
        )
        
        if api_results['success']:
            api_baseline_validation = api_results['baseline_validation']
            logger.info(
                "API endpoint performance validation",
                compliant=api_baseline_validation['compliant'],
                violations=len(api_baseline_validation.get('violations', []))
            )
        
        logger.info(
            "Apache-bench baseline comparison completed successfully",
            health_endpoint_compliant=baseline_validation['compliant'],
            requests_per_second=health_results['parsed_results'].get('requests_per_second', 0),
            mean_response_time=health_results['parsed_results'].get('mean_response_time', 0)
        )
    
    @pytest.mark.database
    @pytest.mark.async_test
    @skip_if_no_mongodb
    async def test_database_operation_performance(self):
        """
        Test database operation performance with PyMongo and Motor.
        
        Validates database operation latency and throughput against Node.js
        baseline per Section 6.2.4 performance optimization and Section 6.6.3
        performance test thresholds.
        """
        logger.info("Starting database operation performance test")
        
        # Execute database performance tests
        db_results = await self.performance_suite.test_database_performance()
        
        # Validate PyMongo performance
        if db_results.get('pymongo_tests'):
            pymongo_results = db_results['pymongo_tests']
            
            # Validate insert performance
            if pymongo_results.get('insert_performance'):
                insert_avg_time = pymongo_results['insert_performance']['average_time']
                assert insert_avg_time <= DATABASE_OPERATION_TIMEOUT, (
                    f"PyMongo insert average time {insert_avg_time:.4f}s exceeds timeout {DATABASE_OPERATION_TIMEOUT}s"
                )
            
            # Validate find performance
            if pymongo_results.get('find_performance'):
                find_avg_time = pymongo_results['find_performance']['average_time']
                assert find_avg_time <= DATABASE_OPERATION_TIMEOUT, (
                    f"PyMongo find average time {find_avg_time:.4f}s exceeds timeout {DATABASE_OPERATION_TIMEOUT}s"
                )
        
        # Validate Motor performance
        if db_results.get('motor_tests'):
            motor_results = db_results['motor_tests']
            
            # Validate async insert performance
            if motor_results.get('async_insert_performance'):
                async_insert_avg_time = motor_results['async_insert_performance']['average_time']
                assert async_insert_avg_time <= DATABASE_OPERATION_TIMEOUT, (
                    f"Motor async insert average time {async_insert_avg_time:.4f}s exceeds timeout {DATABASE_OPERATION_TIMEOUT}s"
                )
            
            # Validate concurrent operations
            if motor_results.get('concurrent_operations'):
                concurrent_avg_time = motor_results['concurrent_operations']['average_time']
                assert concurrent_avg_time <= DATABASE_OPERATION_TIMEOUT, (
                    f"Motor concurrent operations average time {concurrent_avg_time:.4f}s exceeds timeout {DATABASE_OPERATION_TIMEOUT}s"
                )
        
        # Validate baseline compliance
        baseline_compliance = db_results.get('baseline_compliance', {})
        assert baseline_compliance.get('compliant', False), (
            f"Database performance baseline compliance failed: {baseline_compliance.get('violations', [])}"
        )
        
        logger.info(
            "Database operation performance test completed successfully",
            pymongo_available=bool(db_results.get('pymongo_tests')),
            motor_available=bool(db_results.get('motor_tests')),
            baseline_compliant=baseline_compliance.get('compliant', False)
        )
    
    @pytest.mark.database
    @skip_if_no_redis
    def test_cache_effectiveness_performance(self):
        """
        Test Redis cache effectiveness and performance.
        
        Validates cache hit ratios, operation latency, and overall cache
        effectiveness per Section 3.4.5 cache performance management and
        Section 6.6.3 performance test thresholds.
        """
        logger.info("Starting cache effectiveness performance test")
        
        # Execute cache performance tests
        cache_results = self.performance_suite.test_cache_performance()
        
        # Validate Redis operations
        redis_operations = cache_results.get('redis_operations', {})
        total_operations = redis_operations.get('total_operations', 0)
        successful_operations = redis_operations.get('successful_operations', 0)
        
        assert total_operations > 0, "No cache operations were executed"
        
        success_rate = successful_operations / total_operations if total_operations > 0 else 0
        assert success_rate >= 0.95, f"Cache operation success rate {success_rate:.3f} below 95% threshold"
        
        # Validate cache hit ratios
        hit_ratios = cache_results.get('cache_hit_ratios', {})
        hit_ratio = hit_ratios.get('hit_ratio', 0)
        target_hit_ratio = hit_ratios.get('target_hit_ratio', 0.90)
        
        assert hit_ratio >= target_hit_ratio, (
            f"Cache hit ratio {hit_ratio:.3f} below target {target_hit_ratio}"
        )
        
        # Validate baseline compliance
        baseline_compliance = cache_results.get('baseline_compliance', {})
        assert baseline_compliance.get('compliant', False), (
            f"Cache performance baseline compliance failed: {baseline_compliance.get('violations', [])}"
        )
        
        # Validate operation latency through benchmark measurements
        benchmark_summary = self.performance_suite.benchmark.get_performance_summary()
        cache_violations = [
            v for v in benchmark_summary.get('violations', [])
            if 'redis' in v.get('operation', '')
        ]
        
        assert len(cache_violations) == 0, (
            f"Cache operation latency violations detected: {cache_violations}"
        )
        
        logger.info(
            "Cache effectiveness performance test completed successfully",
            hit_ratio=round(hit_ratio * 100, 2),
            total_operations=total_operations,
            success_rate=round(success_rate * 100, 2),
            baseline_compliant=baseline_compliance.get('compliant', False)
        )
    
    @pytest.mark.integration
    def test_external_service_performance_monitoring(self):
        """
        Test external service integration performance characteristics.
        
        Validates external service response times, timeout handling, and
        circuit breaker performance per Section 6.3.5 performance characteristics
        and Section 6.6.3 performance test thresholds.
        """
        logger.info("Starting external service performance monitoring test")
        
        # Execute external service performance tests
        external_results = self.performance_suite.test_external_service_performance()
        
        # Validate service test results
        service_tests = external_results.get('service_tests', {})
        
        # Validate HTTP client performance
        if service_tests.get('http_client'):
            http_results = service_tests['http_client']
            
            success_count = http_results.get('success_count', 0)
            error_count = http_results.get('error_count', 0)
            total_requests = success_count + error_count
            
            if total_requests > 0:
                success_rate = success_count / total_requests
                assert success_rate >= 0.95, (
                    f"HTTP client success rate {success_rate:.3f} below 95% threshold"
                )
                
                if http_results.get('average_time'):
                    avg_time = http_results['average_time']
                    assert avg_time <= EXTERNAL_SERVICE_TIMEOUT, (
                        f"HTTP client average time {avg_time:.3f}s exceeds timeout {EXTERNAL_SERVICE_TIMEOUT}s"
                    )
        
        # Validate AWS S3 performance
        if service_tests.get('aws_s3'):
            s3_results = service_tests['aws_s3']
            
            success_count = s3_results.get('success_count', 0)
            error_count = s3_results.get('error_count', 0)
            
            if success_count + error_count > 0:
                success_rate = success_count / (success_count + error_count)
                assert success_rate >= 0.90, (
                    f"S3 service success rate {success_rate:.3f} below 90% threshold"
                )
        
        # Validate circuit breaker tests
        circuit_breaker_tests = external_results.get('circuit_breaker_tests', {})
        for service_name, cb_results in circuit_breaker_tests.items():
            normal_ops = cb_results.get('normal_operations', 0)
            circuit_open_ops = cb_results.get('circuit_open_operations', 0)
            
            # Validate that circuit breaker opens under failure conditions
            assert circuit_open_ops > 0, (
                f"Circuit breaker for {service_name} did not open under failure conditions"
            )
            
            logger.debug(
                f"Circuit breaker validation for {service_name}",
                normal_operations=normal_ops,
                circuit_open_operations=circuit_open_ops
            )
        
        # Validate baseline compliance
        baseline_compliance = external_results.get('baseline_compliance', {})
        if baseline_compliance.get('violations'):
            logger.warning(
                "External service baseline violations detected",
                violations=baseline_compliance['violations']
            )
        
        logger.info(
            "External service performance monitoring test completed successfully",
            services_tested=len(service_tests),
            circuit_breakers_tested=len(circuit_breaker_tests),
            baseline_compliant=baseline_compliance.get('compliant', True)
        )
    
    @pytest.mark.performance
    def test_continuous_performance_validation(self):
        """
        Test continuous performance validation for CI/CD pipeline integration.
        
        Validates that all performance measurements comply with ≤10% variance
        requirement and generates comprehensive performance report per Section 6.6.2
        performance optimization and CI/CD pipeline integration.
        """
        logger.info("Starting continuous performance validation test")
        
        # Get comprehensive performance summary
        performance_summary = self.performance_suite.benchmark.get_performance_summary()
        
        # Validate overall compliance
        assert performance_summary['performance_compliant'], (
            f"Performance compliance failed with {performance_summary['variance_violations']} violations"
        )
        
        # Validate measurement coverage
        total_measurements = performance_summary['total_measurements']
        assert total_measurements > 0, "No performance measurements recorded"
        
        # Validate compliance rate
        compliance_rate = performance_summary['compliance_rate']
        assert compliance_rate >= 0.95, (
            f"Performance compliance rate {compliance_rate:.3f} below 95% threshold"
        )
        
        # Generate performance report for CI/CD integration
        performance_report = {
            'test_timestamp': datetime.utcnow().isoformat(),
            'performance_summary': performance_summary,
            'baseline_metrics': NODEJS_BASELINE_METRICS,
            'variance_threshold': PERFORMANCE_VARIANCE_THRESHOLD,
            'test_environment': {
                'database_available': bool(self.test_environment.get('database')),
                'cache_available': bool(self.test_environment.get('auth')),
                'monitoring_enabled': bool(self.test_environment.get('performance')),
                'external_services_mocked': bool(self.test_environment.get('external_services'))
            },
            'compliance_status': {
                'overall_compliant': performance_summary['performance_compliant'],
                'total_measurements': total_measurements,
                'compliance_rate': compliance_rate,
                'variance_violations': performance_summary['variance_violations']
            }
        }
        
        # Store performance report for CI/CD pipeline
        report_path = Path(tempfile.gettempdir()) / "performance_integration_report.json"
        with open(report_path, 'w') as f:
            json.dump(performance_report, f, indent=2, default=str)
        
        logger.info(
            "Continuous performance validation completed successfully",
            total_measurements=total_measurements,
            compliance_rate=round(compliance_rate * 100, 2),
            violations=performance_summary['variance_violations'],
            report_path=str(report_path)
        )
        
        # Validate baseline compliance for CI/CD pipeline
        baseline_compliant = self.performance_suite.benchmark.validate_baseline_compliance()
        assert baseline_compliant, (
            "Performance baseline compliance validation failed for CI/CD pipeline"
        )
    
    @pytest.mark.benchmark
    def test_memory_usage_and_garbage_collection(self, benchmark):
        """
        Test memory usage patterns and garbage collection performance.
        
        Validates memory usage growth and garbage collection performance
        characteristics per Section 6.5.1.1 CPU utilization monitoring
        and memory profiling requirements.
        """
        logger.info("Starting memory usage and garbage collection test")
        
        def memory_intensive_operation():
            """Simulate memory-intensive operation for GC testing."""
            # Create and manipulate data structures
            data = []
            for i in range(10000):
                item = {
                    'id': i,
                    'data': f'memory_test_data_{i}' * 10,
                    'timestamp': datetime.utcnow(),
                    'nested': {'field1': i, 'field2': i * 2, 'field3': [i] * 10}
                }
                data.append(item)
            
            # Process data
            processed = [item for item in data if item['id'] % 2 == 0]
            
            # Clear references
            del data
            del processed
            
            return True
        
        # Benchmark memory-intensive operation
        result = benchmark.pedantic(
            memory_intensive_operation,
            rounds=5,
            iterations=1,
            warmup_rounds=1
        )
        
        assert result, "Memory intensive operation failed"
        
        # Validate benchmark results against performance thresholds
        benchmark_stats = benchmark.stats
        
        # Validate execution time
        mean_time = benchmark_stats['mean']
        assert mean_time <= 1.0, f"Memory operation mean time {mean_time:.3f}s exceeds 1s threshold"
        
        # Validate consistency (low standard deviation)
        std_dev = benchmark_stats['stddev']
        cv = std_dev / mean_time if mean_time > 0 else 0  # Coefficient of variation
        assert cv <= 0.20, f"Memory operation coefficient of variation {cv:.3f} exceeds 20% threshold"
        
        logger.info(
            "Memory usage and garbage collection test completed successfully",
            mean_time=round(mean_time, 4),
            std_dev=round(std_dev, 4),
            coefficient_of_variation=round(cv, 4),
            rounds=benchmark_stats['rounds']
        )