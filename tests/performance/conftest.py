"""
Performance Testing-Specific pytest Configuration Module

This module extends the global pytest configuration with specialized fixtures for performance testing,
load testing, baseline comparison, and performance monitoring. Implements comprehensive support for
≤10% variance requirement compliance, Locust load testing integration, Apache Bench performance
measurement, and Testcontainers-based performance test environments.

Key Features per Technical Specification:
- Locust (≥2.x) integration for load testing per Section 6.6.1
- Apache Bench integration for HTTP performance measurement per Section 6.6.1
- Performance monitoring fixture configuration per Section 3.6.2
- Baseline comparison data loading per Section 0.3.2
- Testcontainers performance testing environment per Section 6.6.1
- Performance test data isolation and cleanup per Section 6.6.1

Performance Requirements Compliance:
- ≤10% variance threshold enforcement per Section 0.1.1
- Response time ≤500ms (95th percentile) per Section 4.6.3
- 100-500 requests/second throughput validation per Section 4.6.3
- Progressive load scaling (10-1000 concurrent users) per Section 4.6.3
- 30-minute sustained load testing capability per Section 4.6.3

Dependencies:
- pytest ≥7.4+ with performance testing extensions
- locust ≥2.x for distributed load testing capabilities
- apache-bench for HTTP server performance measurement
- testcontainers ≥4.10.0 for dynamic service provisioning
- prometheus-client ≥0.17+ for metrics collection
- structlog ≥23.1+ for performance logging

Author: Flask Migration Team
Version: 1.0.0
"""

import asyncio
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
import traceback
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Generator, Callable, Tuple, Union
from unittest.mock import patch, Mock, MagicMock
import logging

import pytest
from flask import Flask
from flask.testing import FlaskClient

# Performance testing framework imports
try:
    import locust
    from locust import HttpUser, task, between, events
    from locust.env import Environment
    from locust.stats import stats_printer, stats_history
    from locust.runners import LocalRunner
    LOCUST_AVAILABLE = True
except ImportError:
    LOCUST_AVAILABLE = False

# Metrics and monitoring imports
try:
    import structlog
    from prometheus_client import CollectorRegistry, Counter, Histogram, Gauge, generate_latest
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

# Container and infrastructure imports
try:
    from testcontainers.mongodb import MongoDbContainer
    from testcontainers.redis import RedisContainer
    from testcontainers.compose import DockerCompose
    TESTCONTAINERS_AVAILABLE = True
except ImportError:
    TESTCONTAINERS_AVAILABLE = False

# Import performance testing configuration and baseline data
from tests.performance.performance_config import (
    BasePerformanceConfig,
    PerformanceConfigFactory,
    LoadTestConfiguration,
    BaselineMetrics,
    PerformanceThreshold,
    PerformanceTestType,
    LoadTestPhase,
    create_performance_config,
    get_performance_baseline_comparison
)

from tests.performance.baseline_data import (
    BaselineDataManager,
    ResponseTimeBaseline,
    ResourceUtilizationBaseline,
    ThroughputBaseline,
    get_default_baseline_data,
    validate_flask_performance_against_baseline,
    PERFORMANCE_VARIANCE_THRESHOLD
)

# Import global fixtures from main conftest.py
from tests.conftest import *

# Configure performance-specific logging
logger = structlog.get_logger(__name__)

# Performance test constants per Section 4.6.3
PERFORMANCE_TEST_TIMEOUT = 3600  # 60-minute maximum test duration
LOAD_TEST_RAMP_UP_TIME = 300     # 5-minute ramp-up time
LOAD_TEST_STEADY_STATE = 1200    # 20-minute steady state
BASELINE_VARIANCE_LIMIT = 10.0   # ≤10% variance requirement per Section 0.1.1
MIN_SAMPLE_SIZE = 100            # Minimum sample size for statistical validity
APACHE_BENCH_CONCURRENCY = 50    # Default Apache Bench concurrency level
LOCUST_SPAWN_RATE = 2.0          # Users spawned per second


class PerformanceTestError(Exception):
    """Custom exception for performance testing failures."""
    pass


class BaselineComparisonError(Exception):
    """Custom exception for baseline comparison failures."""
    pass


@pytest.fixture(scope="session")
def performance_config() -> BasePerformanceConfig:
    """
    Performance configuration fixture providing environment-specific settings.
    
    Detects testing environment and provides appropriate performance configuration
    with variance thresholds, load testing parameters, and baseline comparison settings.
    
    Returns:
        BasePerformanceConfig: Environment-specific performance configuration
    """
    config = create_performance_config()
    logger.info(
        "Performance configuration loaded",
        environment=config.get_environment_name(),
        variance_threshold=config.PERFORMANCE_VARIANCE_THRESHOLD,
        load_test_users=f"{config.LOAD_TEST_MIN_USERS}-{config.LOAD_TEST_MAX_USERS}"
    )
    return config


@pytest.fixture(scope="session")
def baseline_data_manager() -> BaselineDataManager:
    """
    Baseline data manager fixture providing Node.js performance baselines.
    
    Provides comprehensive Node.js baseline performance metrics for variance
    calculation and regression detection during Flask migration validation.
    
    Returns:
        BaselineDataManager: Manager with Node.js baseline performance data
    """
    manager = get_default_baseline_data()
    summary = manager.generate_baseline_summary()
    
    logger.info(
        "Baseline data manager initialized",
        total_baselines=summary["baseline_data_summary"]["total_response_time_baselines"],
        data_period=summary["baseline_data_summary"]["data_collection_period"]
    )
    
    return manager


@pytest.fixture(scope="session")
def load_test_config(performance_config: BasePerformanceConfig) -> LoadTestConfiguration:
    """
    Load testing configuration fixture for progressive scaling tests.
    
    Provides load testing parameters including user progression, request rates,
    and test duration settings based on Section 4.6.3 specifications.
    
    Args:
        performance_config: Performance configuration instance
        
    Returns:
        LoadTestConfiguration: Load testing parameter configuration
    """
    config = performance_config.get_load_test_config()
    
    logger.info(
        "Load test configuration prepared",
        min_users=config.min_users,
        max_users=config.max_users,
        test_duration=config.test_duration,
        target_rps=config.target_request_rate
    )
    
    return config


@pytest.fixture(scope="function")
def performance_metrics_registry() -> CollectorRegistry:
    """
    Prometheus metrics registry fixture for performance data collection.
    
    Creates isolated metrics registry for each performance test to ensure
    clean metric collection without interference between test runs.
    
    Returns:
        CollectorRegistry: Isolated Prometheus metrics registry
    """
    if not PROMETHEUS_AVAILABLE:
        pytest.skip("Prometheus client not available for metrics collection")
    
    registry = CollectorRegistry()
    
    # Create performance-specific metrics
    response_time_histogram = Histogram(
        'response_time_seconds',
        'Response time distribution',
        buckets=[0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
        registry=registry
    )
    
    request_counter = Counter(
        'requests_total',
        'Total request count',
        ['method', 'endpoint', 'status'],
        registry=registry
    )
    
    concurrent_users_gauge = Gauge(
        'concurrent_users',
        'Current concurrent user count',
        registry=registry
    )
    
    error_rate_gauge = Gauge(
        'error_rate_percent',
        'Current error rate percentage',
        registry=registry
    )
    
    logger.info("Performance metrics registry initialized")
    
    return registry


@pytest.fixture(scope="function")
def locust_environment(app: Flask, performance_config: BasePerformanceConfig) -> Generator[Environment, None, None]:
    """
    Locust testing environment fixture for load testing execution.
    
    Creates configured Locust environment with Flask application integration,
    custom user behaviors, and performance monitoring capabilities per Section 6.6.1.
    
    Args:
        app: Flask application instance
        performance_config: Performance configuration
        
    Yields:
        Environment: Configured Locust testing environment
    """
    if not LOCUST_AVAILABLE:
        pytest.skip("Locust not available for load testing")
    
    # Create Locust user class for Flask application testing
    class FlaskPerformanceUser(HttpUser):
        """Locust user class for Flask application performance testing."""
        
        wait_time = between(1, 3)  # Realistic user think time
        
        def on_start(self):
            """User initialization - called when user starts testing."""
            self.client.verify = False  # Disable SSL verification for testing
            
        @task(60)  # 60% of requests
        def test_api_get_operations(self):
            """Test API GET operations with realistic patterns."""
            endpoints = [
                "/api/v1/users",
                "/api/v1/data/reports",
                "/health",
            ]
            
            for endpoint in endpoints:
                with self.client.get(endpoint, catch_response=True) as response:
                    if response.status_code == 200:
                        response.success()
                    else:
                        response.failure(f"Unexpected status code: {response.status_code}")
        
        @task(25)  # 25% of requests
        def test_api_post_operations(self):
            """Test API POST operations with realistic payloads."""
            with self.client.post(
                "/api/v1/users",
                json={"name": "Test User", "email": "test@example.com"},
                catch_response=True
            ) as response:
                if response.status_code in [200, 201]:
                    response.success()
                else:
                    response.failure(f"Unexpected status code: {response.status_code}")
        
        @task(10)  # 10% of requests
        def test_authentication_flow(self):
            """Test authentication endpoints."""
            with self.client.post(
                "/api/v1/auth/login",
                json={"email": "test@example.com", "password": "testpass"},
                catch_response=True
            ) as response:
                if response.status_code in [200, 401]:  # Both valid for testing
                    response.success()
                else:
                    response.failure(f"Unexpected status code: {response.status_code}")
        
        @task(5)  # 5% of requests
        def test_file_operations(self):
            """Test file upload operations."""
            files = {"file": ("test.txt", "test content", "text/plain")}
            with self.client.post(
                "/api/v1/files/upload",
                files=files,
                catch_response=True
            ) as response:
                if response.status_code in [200, 201, 400]:  # Allow validation errors
                    response.success()
                else:
                    response.failure(f"Unexpected status code: {response.status_code}")
    
    # Create Locust environment
    env = Environment(
        user_classes=[FlaskPerformanceUser],
        events=events
    )
    
    # Configure Locust with Flask test client
    with app.test_client() as client:
        # Patch the Locust client to use Flask test client
        original_client = FlaskPerformanceUser.client
        FlaskPerformanceUser.client = client
        
        try:
            logger.info("Locust environment created for Flask application testing")
            yield env
        finally:
            # Restore original client
            FlaskPerformanceUser.client = original_client


@pytest.fixture(scope="function")
def apache_bench_runner(app: Flask) -> Callable:
    """
    Apache Bench runner fixture for HTTP performance measurement.
    
    Provides Apache Bench integration for individual endpoint performance
    testing and baseline comparison per Section 6.6.1 requirements.
    
    Args:
        app: Flask application instance
        
    Returns:
        Callable: Apache Bench execution function
    """
    
    def run_apache_bench(
        url: str,
        requests: int = 1000,
        concurrency: int = APACHE_BENCH_CONCURRENCY,
        timeout: int = 30
    ) -> Dict[str, Any]:
        """
        Execute Apache Bench performance test against Flask application.
        
        Args:
            url: Target URL for performance testing
            requests: Total number of requests to perform
            concurrency: Number of concurrent requests
            timeout: Request timeout in seconds
            
        Returns:
            Dictionary containing Apache Bench performance results
            
        Raises:
            PerformanceTestError: If Apache Bench execution fails
        """
        # Check if Apache Bench is available
        try:
            subprocess.run(["ab", "-V"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("Apache Bench (ab) not available for performance testing")
        
        # Prepare Apache Bench command
        with app.test_client() as client:
            # Start Flask test server for Apache Bench testing
            from threading import Thread
            import socket
            
            # Find available port
            sock = socket.socket()
            sock.bind(('', 0))
            port = sock.getsockname()[1]
            sock.close()
            
            # Start test server
            server_thread = Thread(
                target=lambda: app.run(host='127.0.0.1', port=port, debug=False),
                daemon=True
            )
            server_thread.start()
            
            # Wait for server to start
            time.sleep(2)
            
            # Build full URL
            test_url = f"http://127.0.0.1:{port}{url}"
            
            # Execute Apache Bench command
            cmd = [
                "ab",
                "-n", str(requests),
                "-c", str(concurrency),
                "-s", str(timeout),
                "-g", "-",  # Generate gnuplot data
                test_url
            ]
            
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=PERFORMANCE_TEST_TIMEOUT
                )
                
                if result.returncode != 0:
                    raise PerformanceTestError(
                        f"Apache Bench failed: {result.stderr}"
                    )
                
                # Parse Apache Bench output
                output = result.stdout
                parsed_results = _parse_apache_bench_output(output)
                
                logger.info(
                    "Apache Bench test completed",
                    url=url,
                    requests=requests,
                    concurrency=concurrency,
                    response_time_mean=parsed_results.get("response_time_mean", 0),
                    requests_per_second=parsed_results.get("requests_per_second", 0)
                )
                
                return parsed_results
                
            except subprocess.TimeoutExpired:
                raise PerformanceTestError(
                    f"Apache Bench test timed out after {PERFORMANCE_TEST_TIMEOUT} seconds"
                )
            except Exception as e:
                raise PerformanceTestError(f"Apache Bench execution error: {str(e)}")
    
    return run_apache_bench


def _parse_apache_bench_output(output: str) -> Dict[str, Any]:
    """
    Parse Apache Bench output to extract performance metrics.
    
    Args:
        output: Raw Apache Bench stdout output
        
    Returns:
        Dictionary containing parsed performance metrics
    """
    results = {}
    
    try:
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            if "Requests per second:" in line:
                # Extract requests per second
                parts = line.split()
                results["requests_per_second"] = float(parts[3])
                
            elif "Time per request:" in line and "mean" in line:
                # Extract mean response time
                parts = line.split()
                results["response_time_mean"] = float(parts[3])
                
            elif "Time per request:" in line and "across all concurrent requests" in line:
                # Extract mean across concurrent requests
                parts = line.split()
                results["response_time_concurrent"] = float(parts[3])
                
            elif "Transfer rate:" in line:
                # Extract transfer rate
                parts = line.split()
                results["transfer_rate_kbps"] = float(parts[2])
                
            elif "Total:" in line and "Connect:" not in line:
                # Extract timing breakdown
                parts = line.split()
                if len(parts) >= 6:
                    results["connection_time"] = float(parts[1])
                    results["processing_time"] = float(parts[2])
                    results["waiting_time"] = float(parts[3])
                    results["total_time"] = float(parts[4])
                    
            elif "Percentage of the requests served within" in line:
                # Start of percentile data
                results["percentiles"] = {}
                
            elif "%" in line and "ms" in line:
                # Parse percentile data
                parts = line.strip().split()
                if len(parts) >= 2:
                    try:
                        percentile = int(parts[0].replace('%', ''))
                        time_ms = float(parts[1])
                        if "percentiles" not in results:
                            results["percentiles"] = {}
                        results["percentiles"][percentile] = time_ms
                    except (ValueError, IndexError):
                        continue
                        
            elif "Complete requests:" in line:
                parts = line.split()
                results["total_requests"] = int(parts[2])
                
            elif "Failed requests:" in line:
                parts = line.split()
                results["failed_requests"] = int(parts[2])
                
    except Exception as e:
        logger.warning("Error parsing Apache Bench output", error=str(e))
    
    return results


@pytest.fixture(scope="function") 
def performance_monitoring_setup(
    performance_metrics_registry: CollectorRegistry,
    baseline_data_manager: BaselineDataManager
) -> Dict[str, Any]:
    """
    Performance monitoring fixture providing comprehensive metrics collection.
    
    Sets up performance monitoring infrastructure including metrics collection,
    baseline comparison, and variance calculation per Section 3.6.2 requirements.
    
    Args:
        performance_metrics_registry: Prometheus metrics registry
        baseline_data_manager: Baseline data manager for comparison
        
    Returns:
        Dictionary containing monitoring setup and utilities
    """
    monitoring_setup = {
        "metrics_registry": performance_metrics_registry,
        "baseline_manager": baseline_data_manager,
        "start_time": time.time(),
        "collected_metrics": {},
        "performance_violations": [],
        "monitoring_active": True
    }
    
    def collect_response_time_metric(endpoint: str, method: str, response_time_ms: float):
        """Collect response time metric for specific endpoint."""
        key = f"{method.upper()} {endpoint}"
        if "response_times" not in monitoring_setup["collected_metrics"]:
            monitoring_setup["collected_metrics"]["response_times"] = {}
        
        if key not in monitoring_setup["collected_metrics"]["response_times"]:
            monitoring_setup["collected_metrics"]["response_times"][key] = []
        
        monitoring_setup["collected_metrics"]["response_times"][key].append(response_time_ms)
        
        # Check against baseline if available
        baseline = baseline_data_manager.get_response_time_baseline(endpoint, method)
        if baseline:
            variance = baseline_data_manager.calculate_variance_percentage(
                baseline.mean_response_time_ms, response_time_ms
            )
            
            if abs(variance) > BASELINE_VARIANCE_LIMIT:
                violation = {
                    "type": "response_time_variance",
                    "endpoint": endpoint,
                    "method": method,
                    "baseline_ms": baseline.mean_response_time_ms,
                    "current_ms": response_time_ms,
                    "variance_percent": variance,
                    "timestamp": datetime.now(timezone.utc)
                }
                monitoring_setup["performance_violations"].append(violation)
                
                logger.warning(
                    "Performance variance violation detected",
                    **violation
                )
    
    def collect_throughput_metric(requests_per_second: float):
        """Collect throughput metric."""
        if "throughput_samples" not in monitoring_setup["collected_metrics"]:
            monitoring_setup["collected_metrics"]["throughput_samples"] = []
        
        monitoring_setup["collected_metrics"]["throughput_samples"].append(requests_per_second)
        
        # Check against baseline
        peak_throughput = baseline_data_manager.get_peak_throughput_baseline()
        if peak_throughput:
            variance = baseline_data_manager.calculate_variance_percentage(
                peak_throughput.requests_per_second, requests_per_second
            )
            
            if abs(variance) > BASELINE_VARIANCE_LIMIT:
                violation = {
                    "type": "throughput_variance",
                    "baseline_rps": peak_throughput.requests_per_second,
                    "current_rps": requests_per_second,
                    "variance_percent": variance,
                    "timestamp": datetime.now(timezone.utc)
                }
                monitoring_setup["performance_violations"].append(violation)
    
    def collect_resource_metric(cpu_percent: float, memory_mb: float):
        """Collect resource utilization metrics."""
        if "resource_samples" not in monitoring_setup["collected_metrics"]:
            monitoring_setup["collected_metrics"]["resource_samples"] = []
        
        resource_sample = {
            "cpu_percent": cpu_percent,
            "memory_mb": memory_mb,
            "timestamp": datetime.now(timezone.utc)
        }
        monitoring_setup["collected_metrics"]["resource_samples"].append(resource_sample)
        
        # Check against baseline
        avg_resources = baseline_data_manager.get_average_resource_utilization()
        if avg_resources:
            cpu_variance = baseline_data_manager.calculate_variance_percentage(
                avg_resources.cpu_utilization_percent, cpu_percent
            )
            memory_variance = baseline_data_manager.calculate_variance_percentage(
                avg_resources.memory_usage_mb, memory_mb
            )
            
            # Use 15% threshold for memory as specified
            memory_threshold = 15.0
            
            if abs(cpu_variance) > BASELINE_VARIANCE_LIMIT:
                violation = {
                    "type": "cpu_variance",
                    "baseline_percent": avg_resources.cpu_utilization_percent,
                    "current_percent": cpu_percent,
                    "variance_percent": cpu_variance,
                    "timestamp": datetime.now(timezone.utc)
                }
                monitoring_setup["performance_violations"].append(violation)
            
            if abs(memory_variance) > memory_threshold:
                violation = {
                    "type": "memory_variance",
                    "baseline_mb": avg_resources.memory_usage_mb,
                    "current_mb": memory_mb,
                    "variance_percent": memory_variance,
                    "timestamp": datetime.now(timezone.utc)
                }
                monitoring_setup["performance_violations"].append(violation)
    
    def generate_performance_report() -> Dict[str, Any]:
        """Generate comprehensive performance test report."""
        test_duration = time.time() - monitoring_setup["start_time"]
        metrics = monitoring_setup["collected_metrics"]
        
        report = {
            "test_execution_summary": {
                "test_duration_seconds": test_duration,
                "monitoring_start_time": monitoring_setup["start_time"],
                "total_violations": len(monitoring_setup["performance_violations"]),
                "monitoring_status": "active" if monitoring_setup["monitoring_active"] else "completed"
            },
            "performance_metrics": {},
            "baseline_comparison": {},
            "violations": monitoring_setup["performance_violations"],
            "compliance_status": {
                "within_variance_threshold": len(monitoring_setup["performance_violations"]) == 0,
                "performance_gates_passed": True,  # To be determined
                "recommendation": "Performance validation successful" if len(monitoring_setup["performance_violations"]) == 0 else "Performance issues detected"
            }
        }
        
        # Analyze response time metrics
        if "response_times" in metrics:
            response_time_analysis = {}
            for endpoint, times in metrics["response_times"].items():
                if times:
                    response_time_analysis[endpoint] = {
                        "sample_count": len(times),
                        "mean_ms": statistics.mean(times),
                        "median_ms": statistics.median(times),
                        "min_ms": min(times),
                        "max_ms": max(times),
                        "p95_ms": statistics.quantiles(times, n=20)[18] if len(times) >= 20 else max(times),
                        "std_dev_ms": statistics.stdev(times) if len(times) > 1 else 0
                    }
            report["performance_metrics"]["response_times"] = response_time_analysis
        
        # Analyze throughput metrics
        if "throughput_samples" in metrics and metrics["throughput_samples"]:
            throughput_samples = metrics["throughput_samples"]
            report["performance_metrics"]["throughput"] = {
                "sample_count": len(throughput_samples),
                "mean_rps": statistics.mean(throughput_samples),
                "median_rps": statistics.median(throughput_samples),
                "min_rps": min(throughput_samples),
                "max_rps": max(throughput_samples),
                "std_dev_rps": statistics.stdev(throughput_samples) if len(throughput_samples) > 1 else 0
            }
        
        # Analyze resource utilization
        if "resource_samples" in metrics and metrics["resource_samples"]:
            resource_samples = metrics["resource_samples"]
            cpu_samples = [sample["cpu_percent"] for sample in resource_samples]
            memory_samples = [sample["memory_mb"] for sample in resource_samples]
            
            report["performance_metrics"]["resource_utilization"] = {
                "sample_count": len(resource_samples),
                "cpu_stats": {
                    "mean_percent": statistics.mean(cpu_samples),
                    "max_percent": max(cpu_samples),
                    "std_dev": statistics.stdev(cpu_samples) if len(cpu_samples) > 1 else 0
                },
                "memory_stats": {
                    "mean_mb": statistics.mean(memory_samples),
                    "max_mb": max(memory_samples),
                    "std_dev": statistics.stdev(memory_samples) if len(memory_samples) > 1 else 0
                }
            }
        
        return report
    
    # Add utility functions to monitoring setup
    monitoring_setup.update({
        "collect_response_time": collect_response_time_metric,
        "collect_throughput": collect_throughput_metric,
        "collect_resource_metrics": collect_resource_metric,
        "generate_report": generate_performance_report
    })
    
    logger.info("Performance monitoring setup initialized")
    
    return monitoring_setup


@pytest.fixture(scope="function")
def performance_test_environment(
    app: Flask,
    performance_config: BasePerformanceConfig,
    mongodb_container: MongoDbContainer,
    redis_container: RedisContainer
) -> Generator[Dict[str, Any], None, None]:
    """
    Comprehensive performance test environment with Testcontainers integration.
    
    Creates production-equivalent testing environment using Testcontainers for
    MongoDB and Redis services, providing realistic performance validation
    per Section 6.6.1 container integration requirements.
    
    Args:
        app: Flask application instance
        performance_config: Performance configuration
        mongodb_container: Testcontainers MongoDB instance
        redis_container: Testcontainers Redis instance
        
    Yields:
        Dictionary containing performance test environment setup
    """
    if not TESTCONTAINERS_AVAILABLE:
        pytest.skip("Testcontainers not available for performance environment")
    
    # Configure application for performance testing
    app.config.update({
        'TESTING': True,
        'PERFORMANCE_TESTING_MODE': True,
        'MONGODB_URI': mongodb_container.get_connection_url(),
        'REDIS_URL': redis_container.get_connection_url(),
        'DEBUG': False,  # Disable debug mode for realistic performance
        'SQLALCHEMY_ECHO': False,  # Disable SQL logging for performance
    })
    
    environment_setup = {
        "app": app,
        "mongodb_uri": mongodb_container.get_connection_url(),
        "redis_uri": redis_container.get_connection_url(),
        "performance_config": performance_config,
        "test_data_isolation": True,
        "environment_ready": True,
        "cleanup_required": True
    }
    
    # Verify container health
    try:
        # Test MongoDB connection
        import pymongo
        mongo_client = pymongo.MongoClient(environment_setup["mongodb_uri"])
        mongo_client.admin.command('ismaster')
        mongo_client.close()
        
        # Test Redis connection
        import redis
        redis_client = redis.from_url(environment_setup["redis_uri"])
        redis_client.ping()
        redis_client.close()
        
        logger.info(
            "Performance test environment verified",
            mongodb_uri=environment_setup["mongodb_uri"],
            redis_uri=environment_setup["redis_uri"]
        )
        
    except Exception as e:
        pytest.fail(f"Performance test environment setup failed: {str(e)}")
    
    try:
        yield environment_setup
    finally:
        # Cleanup test environment
        if environment_setup["cleanup_required"]:
            _cleanup_performance_test_environment(environment_setup)


def _cleanup_performance_test_environment(environment_setup: Dict[str, Any]) -> None:
    """
    Clean up performance test environment and data.
    
    Args:
        environment_setup: Performance test environment configuration
    """
    try:
        # Clean MongoDB test data
        if "mongodb_uri" in environment_setup:
            import pymongo
            client = pymongo.MongoClient(environment_setup["mongodb_uri"])
            
            # Drop test databases
            for db_name in client.list_database_names():
                if db_name.startswith('test_') or db_name.startswith('perf_'):
                    client.drop_database(db_name)
            
            client.close()
        
        # Clean Redis test data
        if "redis_uri" in environment_setup:
            import redis
            client = redis.from_url(environment_setup["redis_uri"])
            client.flushall()
            client.close()
        
        logger.info("Performance test environment cleanup completed")
        
    except Exception as e:
        logger.warning("Performance test environment cleanup error", error=str(e))


@pytest.fixture(scope="function")
def baseline_comparison_validator(
    baseline_data_manager: BaselineDataManager,
    performance_config: BasePerformanceConfig
) -> Callable:
    """
    Baseline comparison validator fixture for variance analysis.
    
    Provides automated baseline comparison functionality ensuring ≤10% variance
    requirement compliance per Section 0.3.2 performance monitoring requirements.
    
    Args:
        baseline_data_manager: Baseline data manager instance
        performance_config: Performance configuration
        
    Returns:
        Callable: Baseline comparison validation function
    """
    
    def validate_performance_metrics(
        current_metrics: Dict[str, float],
        endpoint: Optional[str] = None,
        method: Optional[str] = None,
        test_type: str = "general"
    ) -> Dict[str, Any]:
        """
        Validate current performance metrics against Node.js baselines.
        
        Args:
            current_metrics: Dictionary of current performance metrics
            endpoint: Optional specific endpoint for targeted comparison
            method: Optional HTTP method for targeted comparison
            test_type: Type of performance test being validated
            
        Returns:
            Dictionary containing validation results and compliance status
            
        Raises:
            BaselineComparisonError: If critical variance threshold exceeded
        """
        try:
            # Perform comprehensive baseline comparison
            validation_results = validate_flask_performance_against_baseline(
                current_metrics, endpoint, method
            )
            
            # Enhanced validation with performance config thresholds
            config_thresholds = performance_config.get_performance_thresholds()
            
            # Additional threshold validation
            for metric_name, current_value in current_metrics.items():
                if metric_name in config_thresholds:
                    threshold = config_thresholds[metric_name]
                    
                    if not threshold.is_within_threshold(current_value):
                        violation = {
                            "metric": metric_name,
                            "current_value": current_value,
                            "baseline_value": threshold.baseline_value,
                            "variance_percent": threshold.calculate_variance(current_value),
                            "threshold_status": threshold.get_threshold_status(current_value),
                            "test_type": test_type
                        }
                        
                        validation_results["critical_issues"].append(
                            f"❌ {metric_name}: {violation['variance_percent']:.2f}% variance exceeds threshold"
                        )
                        validation_results["overall_compliance"] = False
            
            # Log validation results
            if validation_results["overall_compliance"]:
                logger.info(
                    "Baseline comparison validation passed",
                    test_type=test_type,
                    endpoint=endpoint,
                    method=method,
                    variance_analysis=validation_results["variance_analysis"]
                )
            else:
                logger.error(
                    "Baseline comparison validation failed",
                    test_type=test_type,
                    critical_issues=validation_results["critical_issues"],
                    variance_analysis=validation_results["variance_analysis"]
                )
                
                # Raise exception for critical failures
                if validation_results["critical_issues"]:
                    raise BaselineComparisonError(
                        f"Critical performance variance detected: {validation_results['critical_issues']}"
                    )
            
            return validation_results
            
        except Exception as e:
            logger.error("Baseline comparison validation error", error=str(e))
            raise BaselineComparisonError(f"Baseline validation failed: {str(e)}")
    
    def compare_response_times(
        endpoint: str,
        method: str,
        response_times_ms: List[float]
    ) -> Dict[str, Any]:
        """
        Compare response times against baseline for specific endpoint.
        
        Args:
            endpoint: API endpoint path
            method: HTTP method
            response_times_ms: List of response times in milliseconds
            
        Returns:
            Dictionary containing response time comparison results
        """
        if not response_times_ms:
            raise BaselineComparisonError("No response time data provided for comparison")
        
        baseline = baseline_data_manager.get_response_time_baseline(endpoint, method)
        if not baseline:
            logger.warning(
                "No baseline found for endpoint",
                endpoint=endpoint,
                method=method
            )
            return {"baseline_available": False, "comparison_results": None}
        
        # Calculate current metrics
        current_metrics = {
            "mean_ms": statistics.mean(response_times_ms),
            "median_ms": statistics.median(response_times_ms),
            "p95_ms": statistics.quantiles(response_times_ms, n=20)[18] if len(response_times_ms) >= 20 else max(response_times_ms),
            "min_ms": min(response_times_ms),
            "max_ms": max(response_times_ms),
            "sample_count": len(response_times_ms)
        }
        
        # Compare against baseline
        comparison_results = {
            "baseline_available": True,
            "endpoint": endpoint,
            "method": method,
            "current_metrics": current_metrics,
            "baseline_metrics": {
                "mean_ms": baseline.mean_response_time_ms,
                "median_ms": baseline.median_response_time_ms,
                "p95_ms": baseline.p95_response_time_ms,
                "sample_count": baseline.sample_count
            },
            "variance_analysis": {},
            "compliance_status": True
        }
        
        # Calculate variances
        for metric in ["mean_ms", "median_ms", "p95_ms"]:
            baseline_value = getattr(baseline, metric.replace("_ms", "_response_time_ms"))
            current_value = current_metrics[metric]
            
            variance = baseline_data_manager.calculate_variance_percentage(
                baseline_value, current_value
            )
            
            is_compliant = abs(variance) <= BASELINE_VARIANCE_LIMIT
            
            comparison_results["variance_analysis"][metric] = {
                "baseline_value": baseline_value,
                "current_value": current_value,
                "variance_percent": variance,
                "compliant": is_compliant,
                "status": "✅ PASS" if is_compliant else "❌ FAIL"
            }
            
            if not is_compliant:
                comparison_results["compliance_status"] = False
        
        return comparison_results
    
    return {
        "validate_metrics": validate_performance_metrics,
        "compare_response_times": compare_response_times,
        "baseline_manager": baseline_data_manager
    }


@pytest.fixture(scope="function")
def performance_test_data_manager() -> Generator[Dict[str, Any], None, None]:
    """
    Performance test data isolation and management fixture.
    
    Provides test data generation, isolation, and cleanup capabilities for
    performance tests ensuring clean test environments per Section 6.6.1
    test data management requirements.
    
    Yields:
        Dictionary containing test data management utilities
    """
    test_data = {
        "generated_data": {},
        "isolation_enabled": True,
        "cleanup_callbacks": [],
        "data_sets": {}
    }
    
    def generate_test_users(count: int = 100) -> List[Dict[str, Any]]:
        """Generate test user data for performance testing."""
        users = []
        for i in range(count):
            user = {
                "id": f"perf_user_{i:04d}",
                "name": f"Performance Test User {i}",
                "email": f"perftest_{i:04d}@example.com",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "is_active": True,
                "test_data": True
            }
            users.append(user)
        
        test_data["data_sets"]["users"] = users
        return users
    
    def generate_test_reports(count: int = 50) -> List[Dict[str, Any]]:
        """Generate test report data for performance testing."""
        reports = []
        for i in range(count):
            report = {
                "id": f"perf_report_{i:04d}",
                "title": f"Performance Test Report {i}",
                "content": f"This is test report content for performance testing iteration {i}",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "status": "published",
                "test_data": True
            }
            reports.append(report)
        
        test_data["data_sets"]["reports"] = reports
        return reports
    
    def register_cleanup_callback(callback: Callable) -> None:
        """Register cleanup callback for test data."""
        test_data["cleanup_callbacks"].append(callback)
    
    def cleanup_test_data() -> None:
        """Execute all cleanup callbacks."""
        for callback in test_data["cleanup_callbacks"]:
            try:
                callback()
            except Exception as e:
                logger.warning("Test data cleanup callback error", error=str(e))
        
        test_data["cleanup_callbacks"].clear()
        test_data["data_sets"].clear()
        logger.info("Performance test data cleanup completed")
    
    # Add utilities to test data manager
    test_data.update({
        "generate_users": generate_test_users,
        "generate_reports": generate_test_reports,
        "register_cleanup": register_cleanup_callback,
        "cleanup": cleanup_test_data
    })
    
    try:
        yield test_data
    finally:
        # Automatic cleanup
        cleanup_test_data()


# Performance test helper functions

def measure_response_time(func: Callable) -> Tuple[Any, float]:
    """
    Measure response time of a function call.
    
    Args:
        func: Function to measure
        
    Returns:
        Tuple of (function_result, response_time_ms)
    """
    start_time = time.time()
    result = func()
    end_time = time.time()
    response_time_ms = (end_time - start_time) * 1000
    return result, response_time_ms


@contextmanager
def performance_timer(description: str = "Operation"):
    """
    Context manager for timing performance operations.
    
    Args:
        description: Description of the operation being timed
        
    Yields:
        Dictionary containing timing information
    """
    timer_info = {"description": description, "start_time": time.time()}
    
    try:
        yield timer_info
    finally:
        timer_info["end_time"] = time.time()
        timer_info["duration_ms"] = (timer_info["end_time"] - timer_info["start_time"]) * 1000
        
        logger.info(
            f"Performance timer: {description}",
            duration_ms=timer_info["duration_ms"]
        )


def validate_response_time_threshold(
    response_time_ms: float,
    threshold_ms: float = 500.0,
    endpoint: str = "unknown"
) -> bool:
    """
    Validate response time against threshold per Section 4.6.3.
    
    Args:
        response_time_ms: Measured response time in milliseconds
        threshold_ms: Threshold in milliseconds (default 500ms per Section 4.6.3)
        endpoint: Endpoint being tested
        
    Returns:
        True if within threshold, False otherwise
    """
    is_within_threshold = response_time_ms <= threshold_ms
    
    if not is_within_threshold:
        logger.warning(
            "Response time threshold exceeded",
            endpoint=endpoint,
            response_time_ms=response_time_ms,
            threshold_ms=threshold_ms,
            variance_ms=response_time_ms - threshold_ms
        )
    
    return is_within_threshold


def validate_throughput_threshold(
    requests_per_second: float,
    min_threshold: float = 100.0,
    endpoint: str = "unknown"
) -> bool:
    """
    Validate throughput against minimum threshold per Section 4.6.3.
    
    Args:
        requests_per_second: Measured throughput in requests per second
        min_threshold: Minimum threshold (default 100 RPS per Section 4.6.3)
        endpoint: Endpoint being tested
        
    Returns:
        True if meets threshold, False otherwise
    """
    meets_threshold = requests_per_second >= min_threshold
    
    if not meets_threshold:
        logger.warning(
            "Throughput threshold not met",
            endpoint=endpoint,
            requests_per_second=requests_per_second,
            min_threshold=min_threshold,
            deficit_rps=min_threshold - requests_per_second
        )
    
    return meets_threshold


# Performance test markers
pytestmark = [
    pytest.mark.performance,
    pytest.mark.timeout(PERFORMANCE_TEST_TIMEOUT),
    pytest.mark.filterwarnings("ignore::DeprecationWarning")
]


# Performance-specific pytest configuration
def pytest_configure(config):
    """Performance-specific pytest configuration."""
    # Add performance test markers
    config.addinivalue_line(
        "markers", "performance: mark test as performance test"
    )
    config.addinivalue_line(
        "markers", "load_test: mark test as load testing"
    )
    config.addinivalue_line(
        "markers", "baseline_comparison: mark test as baseline comparison"
    )
    config.addinivalue_line(
        "markers", "apache_bench: mark test as Apache Bench performance test"
    )
    config.addinivalue_line(
        "markers", "locust_test: mark test as Locust load test"
    )
    
    # Set performance test environment variables
    os.environ['PERFORMANCE_TESTING'] = 'true'
    os.environ['PERFORMANCE_VARIANCE_THRESHOLD'] = str(BASELINE_VARIANCE_LIMIT)
    
    logger.info("Performance testing configuration initialized")


def pytest_collection_modifyitems(config, items):
    """Modify performance test collection."""
    for item in items:
        # Add timeout to all performance tests
        if "performance" in item.nodeid:
            item.add_marker(pytest.mark.timeout(PERFORMANCE_TEST_TIMEOUT))
        
        # Add specific markers based on test name
        if "load_test" in item.name:
            item.add_marker(pytest.mark.load_test)
        
        if "baseline" in item.name:
            item.add_marker(pytest.mark.baseline_comparison)
        
        if "apache_bench" in item.name:
            item.add_marker(pytest.mark.apache_bench)
        
        if "locust" in item.name:
            item.add_marker(pytest.mark.locust_test)


def pytest_runtest_setup(item):
    """Performance test setup hook."""
    if item.get_closest_marker("performance"):
        # Skip if required dependencies not available
        if item.get_closest_marker("locust_test") and not LOCUST_AVAILABLE:
            pytest.skip("Locust not available for load testing")
        
        if item.get_closest_marker("apache_bench"):
            try:
                subprocess.run(["ab", "-V"], capture_output=True, check=True)
            except (subprocess.CalledProcessError, FileNotFoundError):
                pytest.skip("Apache Bench not available for performance testing")


def pytest_runtest_teardown(item):
    """Performance test teardown hook."""
    if item.get_closest_marker("performance"):
        # Log performance test completion
        logger.info(
            "Performance test completed",
            test_name=item.name,
            test_path=item.nodeid
        )


# Export performance testing fixtures and utilities
__all__ = [
    'performance_config',
    'baseline_data_manager',
    'load_test_config',
    'performance_metrics_registry',
    'locust_environment',
    'apache_bench_runner',
    'performance_monitoring_setup',
    'performance_test_environment',
    'baseline_comparison_validator',
    'performance_test_data_manager',
    'measure_response_time',
    'performance_timer',
    'validate_response_time_threshold',
    'validate_throughput_threshold',
    'PerformanceTestError',
    'BaselineComparisonError'
]