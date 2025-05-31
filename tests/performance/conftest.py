"""
Performance Testing-Specific pytest Fixtures

This module provides comprehensive performance testing-specific pytest fixtures for the Flask migration project,
extending global test fixtures with performance testing capabilities including Locust client configuration,
Apache Bench integration, baseline metrics loading, and performance monitoring setup.

Key Features:
- Locust (≥2.x) integration for load testing per Section 6.6.1 locust framework integration
- Apache Bench integration for HTTP performance measurement per Section 6.6.1 apache-bench performance measurement
- Performance monitoring fixture configuration per Section 3.6.2 metrics collection
- Baseline comparison data loading from Node.js reference data per Section 0.3.2
- Testcontainers performance testing environment per Section 6.6.1 container integration
- Performance test data isolation and cleanup per Section 6.6.1 test data management

Architecture Integration:
- Section 6.6.1: Performance testing tools including locust (≥2.x) for load testing and apache-bench for HTTP performance
- Section 3.6.2: Performance monitoring with prometheus-client 0.17+ and Flask-Metrics integration
- Section 0.3.2: Continuous performance monitoring with baseline comparison ensuring ≤10% variance requirement
- Section 6.6.1: Testcontainers integration for production-equivalent performance testing environments
- Section 6.6.1: Performance test data management with isolation and automated cleanup

Performance Requirements:
- ≤10% variance from Node.js baseline per Section 0.1.1 performance optimization requirement
- 95th percentile response time ≤500ms per Section 4.6.3 performance thresholds
- Minimum 100 requests/second sustained throughput per Section 4.6.3
- CPU ≤70%, Memory ≤80% during peak load per Section 4.6.3

Dependencies:
- locust ≥2.x for distributed load testing framework
- apache-bench for HTTP performance measurement and benchmarking
- prometheus-client ≥0.17+ for metrics collection and monitoring
- testcontainers[mongodb,redis] ≥4.10.0 for performance testing environments
- psutil ≥5.9+ for system resource monitoring
- requests ≥2.31+ for HTTP client testing

Author: Flask Migration Team
Version: 1.0.0
Coverage Target: 95% per Section 6.6.3 quality metrics
"""

import asyncio
import concurrent.futures
import json
import logging
import os
import psutil
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import warnings
from contextlib import contextmanager, asynccontextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple, Union, Callable, NamedTuple
from unittest.mock import Mock, patch, MagicMock
from urllib.parse import urlparse, urljoin

import pytest
import pytest_asyncio
from flask import Flask
from flask.testing import FlaskClient

# Performance testing framework imports
try:
    import locust
    from locust import HttpUser, task, between, LoadTestShape
    from locust.env import Environment
    from locust.stats import stats_printer, stats_history
    from locust.log import setup_logging
    from locust.runners import LocalRunner, MasterRunner, WorkerRunner
    from locust.web import WebUI
    LOCUST_AVAILABLE = True
except ImportError as e:
    LOCUST_AVAILABLE = False
    warnings.warn(f"Locust not available - load testing disabled: {e}")

# Prometheus metrics integration
try:
    from prometheus_client import CollectorRegistry, Counter, Histogram, Gauge, push_to_gateway
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    warnings.warn("Prometheus client not available - metrics collection disabled")

# HTTP client libraries for performance testing
try:
    import requests
    import httpx
    HTTP_CLIENTS_AVAILABLE = True
except ImportError:
    HTTP_CLIENTS_AVAILABLE = False
    warnings.warn("HTTP clients not available - some performance tests may fail")

# System monitoring
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    warnings.warn("psutil not available - system monitoring disabled")

# Import global test fixtures
from tests.conftest import (
    comprehensive_test_environment,
    performance_monitoring,
    test_metrics_collector,
    flask_app,
    client,
    test_database_environment,
    auth_test_environment
)

# Import performance-specific modules
from tests.performance.performance_config import (
    PerformanceTestConfig,
    PerformanceConfigFactory,
    LoadTestScenario,
    LoadTestConfiguration,
    NodeJSBaselineMetrics,
    PerformanceMetricType,
    create_performance_config,
    get_load_test_config,
    validate_performance_results
)

from tests.performance.baseline_data import (
    BaselineDataManager,
    NodeJSPerformanceBaseline,
    BaselineDataSource,
    BaselineMetricCategory,
    BaselineValidationStatus,
    get_baseline_manager,
    get_nodejs_baseline,
    compare_with_baseline,
    validate_baseline_data,
    create_performance_thresholds
)

# Configure structured logging for performance testing
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# =============================================================================
# Performance Test Configuration and Environment Setup
# =============================================================================

@pytest.fixture(scope="session")
def performance_test_config():
    """
    Session-scoped fixture providing performance test configuration.
    
    Creates comprehensive performance testing configuration with load test parameters,
    baseline thresholds, monitoring settings, and CI/CD integration per Section 6.6.1
    performance testing tools requirements.
    
    Returns:
        PerformanceTestConfig instance with environment-specific settings
    """
    environment = os.getenv('FLASK_ENV', 'testing')
    config = create_performance_config(environment)
    
    logger.info(
        "Performance test configuration initialized",
        environment=environment,
        variance_threshold=config.PERFORMANCE_VARIANCE_THRESHOLD,
        locust_enabled=LOCUST_AVAILABLE,
        prometheus_enabled=PROMETHEUS_AVAILABLE
    )
    
    return config


@pytest.fixture(scope="session")
def nodejs_baseline_data():
    """
    Session-scoped fixture providing Node.js baseline performance data.
    
    Loads comprehensive Node.js baseline metrics for variance calculation and
    performance comparison per Section 0.3.2 baseline comparison requirements.
    
    Returns:
        NodeJSPerformanceBaseline instance with production metrics
    """
    baseline_manager = get_baseline_manager()
    baseline_data = baseline_manager.get_default_baseline()
    
    # Validate baseline data integrity
    if not baseline_data.verify_data_integrity():
        logger.warning("Baseline data integrity verification failed - using fallback data")
        baseline_data = get_nodejs_baseline()
    
    # Check for stale data
    if baseline_data.is_stale(max_age_days=30):
        logger.warning(
            "Baseline data is stale",
            age_days=(datetime.now(timezone.utc) - baseline_data.collection_timestamp).days
        )
    
    logger.info(
        "Node.js baseline data loaded",
        baseline_name=baseline_data.baseline_name,
        baseline_version=baseline_data.baseline_version,
        nodejs_version=baseline_data.nodejs_version,
        api_response_p95=baseline_data.api_response_time_p95,
        throughput_sustained=baseline_data.requests_per_second_sustained
    )
    
    return baseline_data


@pytest.fixture(scope="session")
def performance_thresholds(nodejs_baseline_data, performance_test_config):
    """
    Session-scoped fixture providing performance threshold configurations.
    
    Creates PerformanceThreshold instances from baseline data for automated
    validation and compliance checking per Section 6.6.1 performance validation.
    
    Args:
        nodejs_baseline_data: Node.js baseline performance metrics
        performance_test_config: Performance test configuration
        
    Returns:
        Dictionary of PerformanceThreshold instances by metric name
    """
    variance_threshold = performance_test_config.PERFORMANCE_VARIANCE_THRESHOLD / 100.0
    thresholds = create_performance_thresholds(
        baseline_name=nodejs_baseline_data.baseline_name,
        variance_threshold=variance_threshold
    )
    
    logger.info(
        "Performance thresholds configured",
        threshold_count=len(thresholds),
        variance_threshold_percent=performance_test_config.PERFORMANCE_VARIANCE_THRESHOLD,
        metrics=list(thresholds.keys())
    )
    
    return thresholds


# =============================================================================
# Locust Load Testing Integration per Section 6.6.1
# =============================================================================

class PerformanceTestUser(HttpUser):
    """
    Locust user class for performance testing with realistic request patterns.
    
    Implements comprehensive load testing scenarios with endpoint weight distribution,
    authentication simulation, and performance metric collection per Section 6.6.1
    locust framework integration requirements.
    """
    
    wait_time = between(1, 3)  # Realistic user think time
    
    def __init__(self, environment):
        super().__init__(environment)
        self.auth_token = None
        self.user_id = None
        self.session_id = str(uuid.uuid4())
    
    def on_start(self):
        """Initialize user session with authentication."""
        self.authenticate_user()
        logger.debug(f"Performance test user started: {self.session_id}")
    
    def on_stop(self):
        """Clean up user session."""
        if self.auth_token:
            self.logout_user()
        logger.debug(f"Performance test user stopped: {self.session_id}")
    
    def authenticate_user(self):
        """Simulate user authentication with realistic credentials."""
        auth_data = {
            "email": f"perf_user_{self.session_id}@example.com",
            "password": "performance_test_password"
        }
        
        with self.client.post(
            "/api/auth/login",
            json=auth_data,
            catch_response=True,
            name="auth_login"
        ) as response:
            if response.status_code == 200:
                try:
                    auth_response = response.json()
                    self.auth_token = auth_response.get("access_token")
                    self.user_id = auth_response.get("user_id")
                    
                    # Set authorization header for subsequent requests
                    self.client.headers.update({
                        "Authorization": f"Bearer {self.auth_token}"
                    })
                    
                    response.success()
                except (ValueError, KeyError) as e:
                    response.failure(f"Authentication response parsing failed: {e}")
            else:
                response.failure(f"Authentication failed with status {response.status_code}")
    
    def logout_user(self):
        """Simulate user logout to clean up session."""
        if self.auth_token:
            with self.client.post(
                "/api/auth/logout",
                headers={"Authorization": f"Bearer {self.auth_token}"},
                catch_response=True,
                name="auth_logout"
            ) as response:
                if response.status_code in [200, 204]:
                    response.success()
                    self.auth_token = None
                    self.user_id = None
                else:
                    response.failure(f"Logout failed with status {response.status_code}")
    
    @task(30)  # 30% of requests
    def get_users_list(self):
        """Load test GET /api/users endpoint with pagination."""
        params = {
            "page": 1,
            "limit": 20,
            "sort": "created_at",
            "order": "desc"
        }
        
        with self.client.get(
            "/api/users",
            params=params,
            catch_response=True,
            name="api_get_users"
        ) as response:
            if response.status_code == 200:
                try:
                    users_data = response.json()
                    if "users" in users_data and "total" in users_data:
                        response.success()
                    else:
                        response.failure("Invalid users list response format")
                except ValueError:
                    response.failure("Users list response is not valid JSON")
            else:
                response.failure(f"Get users failed with status {response.status_code}")
    
    @task(20)  # 20% of requests
    def get_user_profile(self):
        """Load test GET /api/users/{id} endpoint with user profiles."""
        if self.user_id:
            user_id = self.user_id
        else:
            # Use a test user ID if authentication failed
            user_id = "test_user_123"
        
        with self.client.get(
            f"/api/users/{user_id}",
            catch_response=True,
            name="api_get_user_profile"
        ) as response:
            if response.status_code == 200:
                try:
                    user_data = response.json()
                    if "id" in user_data and "email" in user_data:
                        response.success()
                    else:
                        response.failure("Invalid user profile response format")
                except ValueError:
                    response.failure("User profile response is not valid JSON")
            elif response.status_code == 404:
                response.failure("User not found")
            else:
                response.failure(f"Get user profile failed with status {response.status_code}")
    
    @task(15)  # 15% of requests
    def create_user(self):
        """Load test POST /api/users endpoint with user creation."""
        user_data = {
            "email": f"perf_new_user_{uuid.uuid4()}@example.com",
            "first_name": "Performance",
            "last_name": "Test",
            "password": "secure_test_password_123",
            "role": "user"
        }
        
        with self.client.post(
            "/api/users",
            json=user_data,
            catch_response=True,
            name="api_create_user"
        ) as response:
            if response.status_code == 201:
                try:
                    created_user = response.json()
                    if "id" in created_user and "email" in created_user:
                        response.success()
                    else:
                        response.failure("Invalid user creation response format")
                except ValueError:
                    response.failure("User creation response is not valid JSON")
            elif response.status_code == 400:
                response.failure("User creation failed - validation error")
            elif response.status_code == 409:
                response.failure("User creation failed - user already exists")
            else:
                response.failure(f"Create user failed with status {response.status_code}")
    
    @task(10)  # 10% of requests
    def update_user_profile(self):
        """Load test PUT /api/users/{id} endpoint with profile updates."""
        if not self.user_id:
            # Skip if no authenticated user
            return
        
        update_data = {
            "first_name": f"Updated_{int(time.time())}",
            "last_name": f"User_{self.session_id[:8]}",
            "profile_updated_at": datetime.now(timezone.utc).isoformat()
        }
        
        with self.client.put(
            f"/api/users/{self.user_id}",
            json=update_data,
            catch_response=True,
            name="api_update_user"
        ) as response:
            if response.status_code == 200:
                try:
                    updated_user = response.json()
                    if "id" in updated_user and "updated_at" in updated_user:
                        response.success()
                    else:
                        response.failure("Invalid user update response format")
                except ValueError:
                    response.failure("User update response is not valid JSON")
            elif response.status_code == 404:
                response.failure("User update failed - user not found")
            elif response.status_code == 403:
                response.failure("User update failed - insufficient permissions")
            else:
                response.failure(f"Update user failed with status {response.status_code}")
    
    @task(10)  # 10% of requests
    def health_check(self):
        """Load test GET /health endpoint for system health monitoring."""
        with self.client.get(
            "/health",
            catch_response=True,
            name="health_check"
        ) as response:
            if response.status_code == 200:
                try:
                    health_data = response.json()
                    if "status" in health_data:
                        if health_data["status"] == "healthy":
                            response.success()
                        else:
                            response.failure(f"Health check reports unhealthy status: {health_data['status']}")
                    else:
                        response.failure("Invalid health check response format")
                except ValueError:
                    response.failure("Health check response is not valid JSON")
            else:
                response.failure(f"Health check failed with status {response.status_code}")
    
    @task(5)  # 5% of requests
    def token_refresh(self):
        """Load test POST /api/auth/refresh endpoint for token management."""
        if not self.auth_token:
            return
        
        with self.client.post(
            "/api/auth/refresh",
            headers={"Authorization": f"Bearer {self.auth_token}"},
            catch_response=True,
            name="auth_refresh_token"
        ) as response:
            if response.status_code == 200:
                try:
                    refresh_response = response.json()
                    if "access_token" in refresh_response:
                        # Update token for continued testing
                        self.auth_token = refresh_response["access_token"]
                        self.client.headers.update({
                            "Authorization": f"Bearer {self.auth_token}"
                        })
                        response.success()
                    else:
                        response.failure("Invalid token refresh response format")
                except ValueError:
                    response.failure("Token refresh response is not valid JSON")
            elif response.status_code == 401:
                response.failure("Token refresh failed - token expired")
            else:
                response.failure(f"Token refresh failed with status {response.status_code}")
    
    @task(10)  # 10% of requests
    def search_users(self):
        """Load test GET /api/users/search endpoint with search queries."""
        search_params = {
            "q": "test",
            "filter": "active",
            "page": 1,
            "limit": 10
        }
        
        with self.client.get(
            "/api/users/search",
            params=search_params,
            catch_response=True,
            name="api_search_users"
        ) as response:
            if response.status_code == 200:
                try:
                    search_results = response.json()
                    if "results" in search_results and "total" in search_results:
                        response.success()
                    else:
                        response.failure("Invalid search results response format")
                except ValueError:
                    response.failure("Search results response is not valid JSON")
            else:
                response.failure(f"User search failed with status {response.status_code}")


class PerformanceLoadTestShape(LoadTestShape):
    """
    Custom load test shape for realistic traffic patterns.
    
    Implements progressive load scaling with ramp-up, steady state, and peak load
    phases per Section 6.6.1 load testing specifications.
    """
    
    def __init__(self, config: LoadTestConfiguration):
        super().__init__()
        self.config = config
        self.stages = self._calculate_load_stages()
    
    def _calculate_load_stages(self) -> List[Tuple[int, int, int]]:
        """Calculate load test stages with progressive scaling."""
        stages = []
        
        # Ramp-up stage
        ramp_users = self.config.users // 4
        stages.append((self.config.ramp_up_time, ramp_users, self.config.spawn_rate / 2))
        
        # Progressive increase to target load
        mid_point_time = self.config.ramp_up_time + (self.config.steady_state_time // 3)
        mid_point_users = self.config.users // 2
        stages.append((mid_point_time, mid_point_users, self.config.spawn_rate))
        
        # Target load steady state
        steady_start_time = self.config.ramp_up_time + (self.config.steady_state_time // 2)
        stages.append((steady_start_time, self.config.users, self.config.spawn_rate))
        
        # Peak load phase
        peak_time = steady_start_time + (self.config.steady_state_time // 2)
        peak_users = int(self.config.users * 1.2)  # 20% above target
        stages.append((peak_time, peak_users, self.config.spawn_rate * 1.5))
        
        # Ramp-down
        total_time = self.config.duration
        stages.append((total_time, 0, self.config.spawn_rate * 2))
        
        return stages
    
    def tick(self):
        """Calculate current load requirements based on elapsed time."""
        run_time = self.get_run_time()
        
        if run_time > self.config.duration:
            return None
        
        # Find current stage
        for stage_time, users, spawn_rate in self.stages:
            if run_time <= stage_time:
                return (users, spawn_rate)
        
        # Default to final stage
        return (0, self.config.spawn_rate)


@pytest.fixture(scope="function")
def locust_environment(performance_test_config, flask_app):
    """
    Function-scoped fixture providing Locust testing environment.
    
    Creates configured Locust environment for load testing with performance
    monitoring integration per Section 6.6.1 locust framework integration.
    
    Args:
        performance_test_config: Performance test configuration
        flask_app: Flask application instance
        
    Returns:
        Configured Locust Environment instance
        
    Raises:
        pytest.skip: If Locust is not available
    """
    if not LOCUST_AVAILABLE:
        pytest.skip("Locust not available for load testing")
    
    # Configure Locust environment
    env = Environment(
        user_classes=[PerformanceTestUser],
        host=performance_test_config.PERFORMANCE_TEST_HOST
    )
    
    # Set up Locust logging
    setup_logging("INFO")
    
    # Configure performance monitoring integration
    if hasattr(env, 'events'):
        # Add custom event handlers for performance monitoring
        @env.events.request_success.add_listener
        def on_request_success(request_type, name, response_time, response_length, **kwargs):
            logger.debug(
                "Locust request successful",
                request_type=request_type,
                name=name,
                response_time=response_time,
                response_length=response_length
            )
        
        @env.events.request_failure.add_listener
        def on_request_failure(request_type, name, response_time, response_length, exception, **kwargs):
            logger.warning(
                "Locust request failed",
                request_type=request_type,
                name=name,
                response_time=response_time,
                exception=str(exception)
            )
    
    logger.info(
        "Locust environment configured",
        host=env.host,
        user_classes=[cls.__name__ for cls in env.user_classes]
    )
    
    yield env
    
    # Cleanup
    if hasattr(env, 'runner') and env.runner:
        env.runner.quit()
    
    logger.info("Locust environment cleaned up")


@pytest.fixture(scope="function")
def locust_client(locust_environment, performance_test_config):
    """
    Function-scoped fixture providing Locust test client.
    
    Creates Locust client for automated load testing execution with scenario
    configuration per Section 6.6.1 load testing framework requirements.
    
    Args:
        locust_environment: Configured Locust environment
        performance_test_config: Performance test configuration
        
    Returns:
        Configured Locust client utilities
    """
    if not LOCUST_AVAILABLE:
        pytest.skip("Locust not available for load testing")
    
    # Create local runner for testing
    runner = LocalRunner(locust_environment, PerformanceTestUser)
    
    client_utilities = {
        'environment': locust_environment,
        'runner': runner,
        'start_load_test': lambda config: _start_locust_load_test(runner, config),
        'stop_load_test': lambda: _stop_locust_load_test(runner),
        'get_statistics': lambda: _get_locust_statistics(runner),
        'wait_for_completion': lambda timeout=300: _wait_for_locust_completion(runner, timeout)
    }
    
    logger.info("Locust client configured with local runner")
    
    yield client_utilities
    
    # Cleanup
    try:
        if runner.state != "stopped":
            runner.stop()
        runner.quit()
    except Exception as e:
        logger.warning(f"Locust client cleanup warning: {e}")
    
    logger.info("Locust client cleaned up")


def _start_locust_load_test(runner, config: LoadTestConfiguration):
    """Start Locust load test with specified configuration."""
    try:
        # Configure load test shape if available
        if hasattr(runner.environment, 'shape_class'):
            runner.environment.shape_class = PerformanceLoadTestShape(config)
        
        # Start the load test
        runner.start(config.users, config.spawn_rate)
        
        logger.info(
            "Locust load test started",
            users=config.users,
            spawn_rate=config.spawn_rate,
            duration=config.duration
        )
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to start Locust load test: {e}")
        return False


def _stop_locust_load_test(runner):
    """Stop Locust load test and collect final statistics."""
    try:
        runner.stop()
        logger.info("Locust load test stopped")
        return True
    except Exception as e:
        logger.error(f"Failed to stop Locust load test: {e}")
        return False


def _get_locust_statistics(runner) -> Dict[str, Any]:
    """Get comprehensive Locust test statistics."""
    try:
        stats = runner.stats
        
        # Aggregate request statistics
        request_stats = {}
        for name, entry in stats.entries.items():
            request_stats[name] = {
                'method': entry.method,
                'name': entry.name,
                'num_requests': entry.num_requests,
                'num_failures': entry.num_failures,
                'avg_response_time': entry.avg_response_time,
                'min_response_time': entry.min_response_time,
                'max_response_time': entry.max_response_time,
                'median_response_time': entry.median_response_time,
                'avg_content_length': entry.avg_content_length,
                'requests_per_sec': entry.current_rps,
                'failures_per_sec': entry.current_fail_per_sec
            }
        
        # Calculate percentile response times
        total_stats = stats.total
        percentiles = {}
        if hasattr(total_stats, 'get_response_time_percentile'):
            percentiles = {
                'p50': total_stats.get_response_time_percentile(0.5),
                'p75': total_stats.get_response_time_percentile(0.75),
                'p90': total_stats.get_response_time_percentile(0.9),
                'p95': total_stats.get_response_time_percentile(0.95),
                'p99': total_stats.get_response_time_percentile(0.99)
            }
        
        return {
            'request_stats': request_stats,
            'total_requests': total_stats.num_requests,
            'total_failures': total_stats.num_failures,
            'failure_rate': total_stats.num_failures / max(total_stats.num_requests, 1),
            'avg_response_time': total_stats.avg_response_time,
            'requests_per_second': total_stats.current_rps,
            'percentiles': percentiles,
            'user_count': runner.user_count,
            'state': runner.state,
            'test_duration': time.time() - runner.start_time if runner.start_time else 0
        }
        
    except Exception as e:
        logger.error(f"Failed to get Locust statistics: {e}")
        return {}


def _wait_for_locust_completion(runner, timeout: int = 300) -> bool:
    """Wait for Locust load test completion or timeout."""
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        if runner.state in ["stopped", "stopping"]:
            return True
        
        time.sleep(1)
    
    logger.warning(f"Locust load test timeout after {timeout} seconds")
    return False


# =============================================================================
# Apache Bench Integration per Section 6.6.1
# =============================================================================

@pytest.fixture(scope="function")
def apache_bench_client():
    """
    Function-scoped fixture providing Apache Bench integration.
    
    Creates Apache Bench client for HTTP performance measurement and benchmarking
    per Section 6.6.1 apache-bench performance measurement requirements.
    
    Returns:
        Apache Bench client utilities with measurement capabilities
        
    Raises:
        pytest.skip: If Apache Bench is not available
    """
    # Check if Apache Bench (ab) is available
    ab_path = shutil.which('ab')
    if not ab_path:
        pytest.skip("Apache Bench (ab) not available for HTTP performance measurement")
    
    client_utilities = {
        'ab_path': ab_path,
        'run_benchmark': _run_apache_bench_test,
        'parse_results': _parse_apache_bench_results,
        'compare_with_baseline': _compare_ab_with_baseline,
        'generate_report': _generate_ab_report
    }
    
    logger.info("Apache Bench client configured", ab_path=ab_path)
    
    yield client_utilities
    
    logger.info("Apache Bench client cleaned up")


def _run_apache_bench_test(
    url: str,
    requests: int = 1000,
    concurrency: int = 10,
    timeout: int = 30,
    post_data: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    output_file: Optional[str] = None
) -> Dict[str, Any]:
    """
    Run Apache Bench performance test with specified parameters.
    
    Args:
        url: Target URL for testing
        requests: Total number of requests to perform
        concurrency: Number of concurrent requests
        timeout: Timeout in seconds for each request
        post_data: Optional POST data for testing
        headers: Optional HTTP headers
        output_file: Optional output file for results
        
    Returns:
        Dictionary containing Apache Bench test results
    """
    ab_path = shutil.which('ab')
    if not ab_path:
        raise RuntimeError("Apache Bench not available")
    
    # Build Apache Bench command
    cmd = [
        ab_path,
        '-n', str(requests),
        '-c', str(concurrency),
        '-s', str(timeout),
        '-r',  # Don't exit on socket receive errors
        '-k',  # Enable keep-alive
        '-g', '/dev/null'  # Suppress gnuplot output
    ]
    
    # Add headers if provided
    if headers:
        for key, value in headers.items():
            cmd.extend(['-H', f'{key}: {value}'])
    
    # Add POST data if provided
    if post_data:
        cmd.extend(['-p', '-'])  # Read POST data from stdin
        cmd.extend(['-T', 'application/json'])
    
    # Add output file if specified
    if output_file:
        cmd.extend(['-e', output_file])
    
    # Add target URL
    cmd.append(url)
    
    try:
        logger.info(
            "Starting Apache Bench test",
            url=url,
            requests=requests,
            concurrency=concurrency,
            timeout=timeout
        )
        
        start_time = time.time()
        
        # Execute Apache Bench
        if post_data:
            result = subprocess.run(
                cmd,
                input=post_data.encode('utf-8'),
                capture_output=True,
                text=True,
                timeout=timeout + 60  # Add buffer to command timeout
            )
        else:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 60
            )
        
        execution_time = time.time() - start_time
        
        if result.returncode != 0:
            logger.error(
                "Apache Bench test failed",
                returncode=result.returncode,
                stderr=result.stderr
            )
            return {
                'success': False,
                'error': result.stderr,
                'returncode': result.returncode
            }
        
        # Parse Apache Bench output
        parsed_results = _parse_apache_bench_results(result.stdout)
        parsed_results.update({
            'success': True,
            'execution_time': execution_time,
            'command': ' '.join(cmd[:-1]) + ' [URL]',  # Hide URL for logging
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
        logger.info(
            "Apache Bench test completed",
            requests_completed=parsed_results.get('requests_completed', 0),
            requests_per_second=parsed_results.get('requests_per_second', 0),
            time_per_request=parsed_results.get('time_per_request_mean', 0)
        )
        
        return parsed_results
        
    except subprocess.TimeoutExpired:
        logger.error("Apache Bench test timeout", timeout=timeout + 60)
        return {
            'success': False,
            'error': 'Test execution timeout',
            'timeout': timeout + 60
        }
    
    except Exception as e:
        logger.error(f"Apache Bench test execution failed: {e}")
        return {
            'success': False,
            'error': str(e)
        }


def _parse_apache_bench_results(output: str) -> Dict[str, Any]:
    """
    Parse Apache Bench output to extract performance metrics.
    
    Args:
        output: Raw Apache Bench output text
        
    Returns:
        Dictionary containing parsed performance metrics
    """
    results = {}
    
    try:
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Complete requests
            if 'Complete requests:' in line:
                results['requests_completed'] = int(line.split(':')[1].strip())
            
            # Failed requests
            elif 'Failed requests:' in line:
                results['requests_failed'] = int(line.split(':')[1].strip())
            
            # Requests per second
            elif 'Requests per second:' in line:
                rps_value = line.split(':')[1].strip().split()[0]
                results['requests_per_second'] = float(rps_value)
            
            # Time per request (mean)
            elif 'Time per request:' in line and 'mean' in line:
                time_value = line.split(':')[1].strip().split()[0]
                results['time_per_request_mean'] = float(time_value)
            
            # Time per request (across all concurrent requests)
            elif 'Time per request:' in line and 'across all' in line:
                time_value = line.split(':')[1].strip().split()[0]
                results['time_per_request_concurrent'] = float(time_value)
            
            # Transfer rate
            elif 'Transfer rate:' in line:
                rate_value = line.split(':')[1].strip().split()[0]
                results['transfer_rate_kbps'] = float(rate_value)
            
            # Connection Times
            elif 'min  mean[+/-sd] median   max' in line:
                # Parse connection time statistics
                connect_line = None
                processing_line = None
                waiting_line = None
                total_line = None
                
                for i, next_line in enumerate(lines[lines.index(line)+1:], 1):
                    if 'Connect:' in next_line:
                        connect_line = next_line
                    elif 'Processing:' in next_line:
                        processing_line = next_line
                    elif 'Waiting:' in next_line:
                        waiting_line = next_line
                    elif 'Total:' in next_line:
                        total_line = next_line
                        break
                
                # Parse timing statistics
                if connect_line:
                    connect_stats = _parse_timing_line(connect_line)
                    results['connect_times'] = connect_stats
                
                if processing_line:
                    processing_stats = _parse_timing_line(processing_line)
                    results['processing_times'] = processing_stats
                
                if waiting_line:
                    waiting_stats = _parse_timing_line(waiting_line)
                    results['waiting_times'] = waiting_stats
                
                if total_line:
                    total_stats = _parse_timing_line(total_line)
                    results['total_times'] = total_stats
            
            # Percentage of requests served within a certain time
            elif '50%' in line:
                # Parse percentile response times
                percentiles = {}
                current_idx = lines.index(line)
                
                for i in range(current_idx, min(current_idx + 10, len(lines))):
                    perc_line = lines[i].strip()
                    if '%' in perc_line and 'ms' in perc_line:
                        parts = perc_line.split()
                        if len(parts) >= 2:
                            percentile = parts[0].replace('%', '')
                            time_ms = parts[1].replace('ms', '')
                            try:
                                percentiles[f'p{percentile}'] = float(time_ms)
                            except ValueError:
                                continue
                
                results['percentiles'] = percentiles
        
        # Calculate derived metrics
        if 'requests_completed' in results and 'requests_failed' in results:
            total_attempts = results['requests_completed'] + results['requests_failed']
            if total_attempts > 0:
                results['success_rate'] = results['requests_completed'] / total_attempts
                results['failure_rate'] = results['requests_failed'] / total_attempts
        
        # Add response time percentiles to main results
        if 'percentiles' in results:
            for percentile, value in results['percentiles'].items():
                results[f'response_time_{percentile}'] = value
        
        logger.debug("Apache Bench results parsed successfully", metrics_count=len(results))
        
    except Exception as e:
        logger.error(f"Failed to parse Apache Bench results: {e}")
        results['parse_error'] = str(e)
    
    return results


def _parse_timing_line(line: str) -> Dict[str, float]:
    """Parse Apache Bench timing statistics line."""
    try:
        # Expected format: "Connect:        0    1   0.5      1       5"
        parts = line.split()
        if len(parts) >= 6:
            return {
                'min': float(parts[1]),
                'mean': float(parts[2]),
                'std_dev': float(parts[3]),
                'median': float(parts[4]),
                'max': float(parts[5])
            }
    except (ValueError, IndexError):
        pass
    
    return {}


def _compare_ab_with_baseline(
    ab_results: Dict[str, Any],
    baseline_data: NodeJSPerformanceBaseline,
    variance_threshold: float = 0.10
) -> Dict[str, Any]:
    """
    Compare Apache Bench results with Node.js baseline metrics.
    
    Args:
        ab_results: Apache Bench test results
        baseline_data: Node.js baseline performance data
        variance_threshold: Acceptable variance threshold
        
    Returns:
        Comparison results with variance analysis
    """
    comparison_results = {
        'baseline_comparison': {},
        'variance_analysis': {},
        'compliance_status': {},
        'summary': {
            'overall_compliant': True,
            'variance_threshold': variance_threshold * 100,
            'comparison_timestamp': datetime.now(timezone.utc).isoformat()
        }
    }
    
    # Map Apache Bench metrics to baseline metrics
    metric_mappings = {
        'time_per_request_mean': ('api_response_time_mean', 'ms'),
        'requests_per_second': ('requests_per_second_sustained', 'req/s'),
        'failure_rate': ('error_rate_overall', '%'),
        'response_time_p95': ('api_response_time_p95', 'ms'),
        'response_time_p99': ('api_response_time_p99', 'ms')
    }
    
    for ab_metric, (baseline_attr, unit) in metric_mappings.items():
        if ab_metric in ab_results and hasattr(baseline_data, baseline_attr):
            current_value = ab_results[ab_metric]
            baseline_value = getattr(baseline_data, baseline_attr)
            
            # Calculate variance percentage
            if baseline_value > 0:
                variance = ((current_value - baseline_value) / baseline_value) * 100
            else:
                variance = 0.0
            
            # Determine compliance
            is_compliant = abs(variance) <= (variance_threshold * 100)
            if not is_compliant:
                comparison_results['summary']['overall_compliant'] = False
            
            comparison_results['baseline_comparison'][ab_metric] = {
                'current_value': current_value,
                'baseline_value': baseline_value,
                'unit': unit,
                'variance_percent': variance,
                'is_compliant': is_compliant,
                'status': 'PASS' if is_compliant else 'FAIL'
            }
    
    # Calculate overall variance statistics
    variances = [comp['variance_percent'] for comp in comparison_results['baseline_comparison'].values()]
    if variances:
        comparison_results['variance_analysis'] = {
            'mean_variance': sum(variances) / len(variances),
            'max_variance': max(variances, key=abs),
            'compliant_metrics': sum(1 for comp in comparison_results['baseline_comparison'].values() if comp['is_compliant']),
            'total_metrics': len(variances),
            'compliance_percentage': (sum(1 for comp in comparison_results['baseline_comparison'].values() if comp['is_compliant']) / len(variances)) * 100
        }
    
    return comparison_results


def _generate_ab_report(
    ab_results: Dict[str, Any],
    comparison_results: Optional[Dict[str, Any]] = None,
    output_file: Optional[str] = None
) -> str:
    """
    Generate comprehensive Apache Bench performance report.
    
    Args:
        ab_results: Apache Bench test results
        comparison_results: Optional baseline comparison results
        output_file: Optional output file path
        
    Returns:
        Formatted performance report as string
    """
    report_lines = []
    
    # Report header
    report_lines.append("=" * 80)
    report_lines.append("APACHE BENCH PERFORMANCE TEST REPORT")
    report_lines.append("=" * 80)
    report_lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    report_lines.append("")
    
    # Test configuration
    if ab_results.get('success'):
        report_lines.append("TEST CONFIGURATION:")
        report_lines.append(f"  Command: {ab_results.get('command', 'N/A')}")
        report_lines.append(f"  Execution Time: {ab_results.get('execution_time', 0):.2f} seconds")
        report_lines.append("")
    
    # Performance metrics
    report_lines.append("PERFORMANCE METRICS:")
    report_lines.append(f"  Requests Completed: {ab_results.get('requests_completed', 0)}")
    report_lines.append(f"  Requests Failed: {ab_results.get('requests_failed', 0)}")
    report_lines.append(f"  Success Rate: {ab_results.get('success_rate', 0):.1%}")
    report_lines.append(f"  Requests per Second: {ab_results.get('requests_per_second', 0):.2f}")
    report_lines.append(f"  Time per Request (mean): {ab_results.get('time_per_request_mean', 0):.2f} ms")
    report_lines.append(f"  Transfer Rate: {ab_results.get('transfer_rate_kbps', 0):.2f} KB/s")
    report_lines.append("")
    
    # Response time percentiles
    if 'percentiles' in ab_results:
        report_lines.append("RESPONSE TIME PERCENTILES:")
        for percentile, value in sorted(ab_results['percentiles'].items()):
            report_lines.append(f"  {percentile.upper()}: {value:.2f} ms")
        report_lines.append("")
    
    # Connection timing statistics
    timing_sections = ['connect_times', 'processing_times', 'waiting_times', 'total_times']
    for section in timing_sections:
        if section in ab_results:
            section_name = section.replace('_', ' ').title()
            report_lines.append(f"{section_name.upper()}:")
            times = ab_results[section]
            report_lines.append(f"  Min: {times.get('min', 0):.2f} ms")
            report_lines.append(f"  Mean: {times.get('mean', 0):.2f} ms")
            report_lines.append(f"  Std Dev: {times.get('std_dev', 0):.2f} ms")
            report_lines.append(f"  Median: {times.get('median', 0):.2f} ms")
            report_lines.append(f"  Max: {times.get('max', 0):.2f} ms")
            report_lines.append("")
    
    # Baseline comparison if available
    if comparison_results:
        report_lines.append("BASELINE COMPARISON:")
        report_lines.append(f"  Overall Compliant: {comparison_results['summary']['overall_compliant']}")
        report_lines.append(f"  Variance Threshold: ±{comparison_results['summary']['variance_threshold']:.1f}%")
        
        if 'variance_analysis' in comparison_results:
            va = comparison_results['variance_analysis']
            report_lines.append(f"  Compliance Rate: {va.get('compliance_percentage', 0):.1f}%")
            report_lines.append(f"  Mean Variance: {va.get('mean_variance', 0):.1f}%")
            report_lines.append(f"  Max Variance: {va.get('max_variance', 0):.1f}%")
        
        report_lines.append("")
        report_lines.append("METRIC COMPARISONS:")
        
        for metric, comp in comparison_results['baseline_comparison'].items():
            status_indicator = "✓" if comp['is_compliant'] else "✗"
            report_lines.append(f"  {status_indicator} {metric}:")
            report_lines.append(f"    Current: {comp['current_value']:.2f} {comp['unit']}")
            report_lines.append(f"    Baseline: {comp['baseline_value']:.2f} {comp['unit']}")
            report_lines.append(f"    Variance: {comp['variance_percent']:+.1f}%")
            report_lines.append(f"    Status: {comp['status']}")
            report_lines.append("")
    
    # Report footer
    report_lines.append("=" * 80)
    report_lines.append("END OF REPORT")
    report_lines.append("=" * 80)
    
    report_content = '\n'.join(report_lines)
    
    # Save to file if specified
    if output_file:
        try:
            with open(output_file, 'w') as f:
                f.write(report_content)
            logger.info(f"Apache Bench report saved to {output_file}")
        except Exception as e:
            logger.error(f"Failed to save Apache Bench report: {e}")
    
    return report_content


# =============================================================================
# Performance Monitoring Fixtures per Section 3.6.2
# =============================================================================

@pytest.fixture(scope="function")
def performance_metrics_collector(performance_test_config):
    """
    Function-scoped fixture providing performance metrics collection.
    
    Creates comprehensive performance metrics collection system with Prometheus
    integration per Section 3.6.2 metrics collection requirements.
    
    Args:
        performance_test_config: Performance test configuration
        
    Returns:
        Performance metrics collector with monitoring capabilities
    """
    collector_config = {
        'prometheus_enabled': PROMETHEUS_AVAILABLE,
        'collection_interval': 15,  # seconds
        'retention_period': 3600,  # 1 hour
        'metrics_buffer_size': 1000,
        'real_time_monitoring': True
    }
    
    # Initialize Prometheus registry if available
    if PROMETHEUS_AVAILABLE:
        registry = CollectorRegistry()
        
        # Performance metrics
        response_time_histogram = Histogram(
            'http_request_duration_seconds',
            'HTTP request response time',
            ['method', 'endpoint', 'status'],
            registry=registry
        )
        
        request_counter = Counter(
            'http_requests_total',
            'Total HTTP requests',
            ['method', 'endpoint', 'status'],
            registry=registry
        )
        
        throughput_gauge = Gauge(
            'http_requests_per_second',
            'HTTP requests per second',
            registry=registry
        )
        
        error_rate_gauge = Gauge(
            'http_error_rate',
            'HTTP error rate percentage',
            registry=registry
        )
        
        # System resource metrics
        cpu_usage_gauge = Gauge(
            'system_cpu_usage_percent',
            'System CPU usage percentage',
            registry=registry
        )
        
        memory_usage_gauge = Gauge(
            'system_memory_usage_percent',
            'System memory usage percentage',
            registry=registry
        )
        
        collector_config['prometheus_registry'] = registry
        collector_config['prometheus_metrics'] = {
            'response_time_histogram': response_time_histogram,
            'request_counter': request_counter,
            'throughput_gauge': throughput_gauge,
            'error_rate_gauge': error_rate_gauge,
            'cpu_usage_gauge': cpu_usage_gauge,
            'memory_usage_gauge': memory_usage_gauge
        }
    
    # Metrics storage
    metrics_data = {
        'request_metrics': [],
        'system_metrics': [],
        'performance_summaries': [],
        'collection_start_time': time.time(),
        'last_collection_time': time.time()
    }
    
    # System monitoring thread
    monitoring_active = threading.Event()
    monitoring_active.set()
    
    def system_monitoring_worker():
        """Background worker for system metrics collection."""
        while monitoring_active.is_set():
            try:
                if PSUTIL_AVAILABLE:
                    # Collect system metrics
                    cpu_percent = psutil.cpu_percent(interval=1)
                    memory = psutil.virtual_memory()
                    
                    system_metric = {
                        'timestamp': time.time(),
                        'cpu_usage_percent': cpu_percent,
                        'memory_usage_percent': memory.percent,
                        'memory_available_mb': memory.available / (1024 * 1024),
                        'memory_total_mb': memory.total / (1024 * 1024)
                    }
                    
                    # Store in buffer
                    metrics_data['system_metrics'].append(system_metric)
                    
                    # Update Prometheus metrics
                    if PROMETHEUS_AVAILABLE and 'prometheus_metrics' in collector_config:
                        prom_metrics = collector_config['prometheus_metrics']
                        prom_metrics['cpu_usage_gauge'].set(cpu_percent)
                        prom_metrics['memory_usage_gauge'].set(memory.percent)
                    
                    # Cleanup old metrics
                    cutoff_time = time.time() - collector_config['retention_period']
                    metrics_data['system_metrics'] = [
                        m for m in metrics_data['system_metrics']
                        if m['timestamp'] > cutoff_time
                    ]
                
                time.sleep(collector_config['collection_interval'])
                
            except Exception as e:
                logger.warning(f"System monitoring error: {e}")
                time.sleep(collector_config['collection_interval'])
    
    # Start system monitoring thread
    monitoring_thread = threading.Thread(target=system_monitoring_worker, daemon=True)
    monitoring_thread.start()
    
    def record_request_metric(
        method: str,
        endpoint: str,
        status_code: int,
        response_time: float,
        content_length: int = 0
    ):
        """Record HTTP request performance metric."""
        request_metric = {
            'timestamp': time.time(),
            'method': method,
            'endpoint': endpoint,
            'status_code': status_code,
            'response_time': response_time,
            'content_length': content_length,
            'is_error': status_code >= 400
        }
        
        # Store in buffer
        metrics_data['request_metrics'].append(request_metric)
        
        # Update Prometheus metrics
        if PROMETHEUS_AVAILABLE and 'prometheus_metrics' in collector_config:
            prom_metrics = collector_config['prometheus_metrics']
            prom_metrics['response_time_histogram'].labels(
                method=method,
                endpoint=endpoint,
                status=str(status_code)
            ).observe(response_time)
            
            prom_metrics['request_counter'].labels(
                method=method,
                endpoint=endpoint,
                status=str(status_code)
            ).inc()
        
        # Cleanup old metrics
        cutoff_time = time.time() - collector_config['retention_period']
        metrics_data['request_metrics'] = [
            m for m in metrics_data['request_metrics']
            if m['timestamp'] > cutoff_time
        ]
    
    def get_performance_summary(time_window: int = 300) -> Dict[str, Any]:
        """Get performance summary for specified time window."""
        current_time = time.time()
        cutoff_time = current_time - time_window
        
        # Filter recent request metrics
        recent_requests = [
            m for m in metrics_data['request_metrics']
            if m['timestamp'] > cutoff_time
        ]
        
        if not recent_requests:
            return {
                'time_window_seconds': time_window,
                'request_count': 0,
                'summary_timestamp': current_time
            }
        
        # Calculate request statistics
        response_times = [m['response_time'] for m in recent_requests]
        error_requests = [m for m in recent_requests if m['is_error']]
        
        request_count = len(recent_requests)
        error_count = len(error_requests)
        
        summary = {
            'time_window_seconds': time_window,
            'request_count': request_count,
            'error_count': error_count,
            'error_rate': error_count / request_count if request_count > 0 else 0,
            'requests_per_second': request_count / time_window,
            'response_time_stats': {
                'mean': sum(response_times) / len(response_times),
                'min': min(response_times),
                'max': max(response_times),
                'p50': _calculate_percentile(response_times, 0.5),
                'p95': _calculate_percentile(response_times, 0.95),
                'p99': _calculate_percentile(response_times, 0.99)
            },
            'summary_timestamp': current_time
        }
        
        # Add system metrics if available
        recent_system_metrics = [
            m for m in metrics_data['system_metrics']
            if m['timestamp'] > cutoff_time
        ]
        
        if recent_system_metrics:
            cpu_values = [m['cpu_usage_percent'] for m in recent_system_metrics]
            memory_values = [m['memory_usage_percent'] for m in recent_system_metrics]
            
            summary['system_stats'] = {
                'cpu_usage_mean': sum(cpu_values) / len(cpu_values),
                'cpu_usage_max': max(cpu_values),
                'memory_usage_mean': sum(memory_values) / len(memory_values),
                'memory_usage_max': max(memory_values)
            }
        
        # Update Prometheus summary metrics
        if PROMETHEUS_AVAILABLE and 'prometheus_metrics' in collector_config:
            prom_metrics = collector_config['prometheus_metrics']
            prom_metrics['throughput_gauge'].set(summary['requests_per_second'])
            prom_metrics['error_rate_gauge'].set(summary['error_rate'] * 100)
        
        return summary
    
    def export_metrics_to_prometheus_gateway(gateway_url: str, job_name: str = 'performance_tests'):
        """Export collected metrics to Prometheus pushgateway."""
        if not PROMETHEUS_AVAILABLE or 'prometheus_registry' not in collector_config:
            logger.warning("Prometheus not available for metrics export")
            return False
        
        try:
            push_to_gateway(
                gateway_url,
                job=job_name,
                registry=collector_config['prometheus_registry']
            )
            logger.info(f"Metrics exported to Prometheus gateway: {gateway_url}")
            return True
        except Exception as e:
            logger.error(f"Failed to export metrics to Prometheus: {e}")
            return False
    
    def cleanup_metrics_collector():
        """Clean up metrics collector resources."""
        monitoring_active.clear()
        
        if monitoring_thread.is_alive():
            monitoring_thread.join(timeout=5)
        
        logger.info("Performance metrics collector cleaned up")
    
    # Collector utilities
    collector_utilities = {
        'config': collector_config,
        'metrics_data': metrics_data,
        'record_request': record_request_metric,
        'get_summary': get_performance_summary,
        'export_to_prometheus': export_metrics_to_prometheus_gateway,
        'cleanup': cleanup_metrics_collector
    }
    
    logger.info(
        "Performance metrics collector initialized",
        prometheus_enabled=collector_config['prometheus_enabled'],
        collection_interval=collector_config['collection_interval'],
        system_monitoring_enabled=PSUTIL_AVAILABLE
    )
    
    yield collector_utilities
    
    # Cleanup
    cleanup_metrics_collector()


def _calculate_percentile(values: List[float], percentile: float) -> float:
    """Calculate percentile value from list of numbers."""
    if not values:
        return 0.0
    
    sorted_values = sorted(values)
    index = int(percentile * (len(sorted_values) - 1))
    return sorted_values[index]


# =============================================================================
# Baseline Data Loading and Comparison per Section 0.3.2
# =============================================================================

@pytest.fixture(scope="function")
def baseline_comparison_engine(nodejs_baseline_data, performance_thresholds, performance_test_config):
    """
    Function-scoped fixture providing baseline comparison capabilities.
    
    Creates comprehensive baseline comparison engine for performance variance
    calculation and compliance validation per Section 0.3.2 baseline comparison
    requirements.
    
    Args:
        nodejs_baseline_data: Node.js baseline performance metrics
        performance_thresholds: Performance threshold configurations
        performance_test_config: Performance test configuration
        
    Returns:
        Baseline comparison utilities with variance analysis
    """
    comparison_config = {
        'variance_threshold': performance_test_config.PERFORMANCE_VARIANCE_THRESHOLD / 100.0,
        'statistical_significance': 0.95,
        'sample_size_minimum': 100,
        'outlier_detection_enabled': True,
        'trend_analysis_enabled': True
    }
    
    comparison_results_cache = {}
    comparison_history = []
    
    def compare_with_nodejs_baseline(
        current_metrics: Dict[str, float],
        comparison_name: str = "performance_test"
    ) -> Dict[str, Any]:
        """
        Compare current metrics with Node.js baseline values.
        
        Args:
            current_metrics: Dictionary of current performance metrics
            comparison_name: Name identifier for this comparison
            
        Returns:
            Comprehensive comparison results with variance analysis
        """
        comparison_timestamp = datetime.now(timezone.utc)
        
        # Use baseline data manager for comparison
        comparison_results = compare_with_baseline(
            current_metrics,
            baseline_name=nodejs_baseline_data.baseline_name,
            variance_threshold=comparison_config['variance_threshold']
        )
        
        # Enhance results with additional analysis
        enhanced_results = {
            'comparison_name': comparison_name,
            'comparison_timestamp': comparison_timestamp.isoformat(),
            'baseline_metadata': {
                'baseline_name': nodejs_baseline_data.baseline_name,
                'baseline_version': nodejs_baseline_data.baseline_version,
                'nodejs_version': nodejs_baseline_data.nodejs_version,
                'collection_timestamp': nodejs_baseline_data.collection_timestamp.isoformat()
            },
            'configuration': comparison_config,
            'results': comparison_results
        }
        
        # Calculate compliance scoring
        valid_comparisons = [
            comp for comp in comparison_results['comparison_results'].values()
            if comp.get('within_threshold') is not None
        ]
        
        if valid_comparisons:
            compliant_count = sum(1 for comp in valid_comparisons if comp['within_threshold'])
            enhanced_results['compliance_score'] = {
                'total_metrics': len(valid_comparisons),
                'compliant_metrics': compliant_count,
                'compliance_percentage': (compliant_count / len(valid_comparisons)) * 100,
                'overall_compliant': compliant_count == len(valid_comparisons)
            }
        
        # Identify performance regressions and improvements
        regressions = []
        improvements = []
        
        for metric, comp in comparison_results['comparison_results'].items():
            if comp.get('variance_percentage') is not None:
                variance = comp['variance_percentage']
                if variance > (comparison_config['variance_threshold'] * 100):
                    regressions.append({
                        'metric': metric,
                        'variance': variance,
                        'current_value': comp['current_value'],
                        'baseline_value': comp['baseline_value']
                    })
                elif variance < -(comparison_config['variance_threshold'] * 50):  # Significant improvement
                    improvements.append({
                        'metric': metric,
                        'variance': variance,
                        'current_value': comp['current_value'],
                        'baseline_value': comp['baseline_value']
                    })
        
        enhanced_results['performance_analysis'] = {
            'regressions': regressions,
            'improvements': improvements,
            'regression_count': len(regressions),
            'improvement_count': len(improvements)
        }
        
        # Cache results
        comparison_results_cache[comparison_name] = enhanced_results
        comparison_history.append({
            'name': comparison_name,
            'timestamp': comparison_timestamp,
            'compliance_percentage': enhanced_results.get('compliance_score', {}).get('compliance_percentage', 0),
            'regression_count': len(regressions)
        })
        
        logger.info(
            "Baseline comparison completed",
            comparison_name=comparison_name,
            compliance_percentage=enhanced_results.get('compliance_score', {}).get('compliance_percentage', 0),
            regression_count=len(regressions),
            improvement_count=len(improvements)
        )
        
        return enhanced_results
    
    def validate_performance_compliance(
        test_results: Dict[str, float],
        test_name: str = "performance_validation"
    ) -> Dict[str, Any]:
        """
        Validate performance test results for compliance with requirements.
        
        Args:
            test_results: Performance test results to validate
            test_name: Name identifier for this validation
            
        Returns:
            Validation results with pass/fail status and recommendations
        """
        validation_results = validate_performance_results(
            test_results,
            environment=os.getenv('FLASK_ENV', 'testing')
        )
        
        # Enhance with baseline comparison
        baseline_comparison = compare_with_nodejs_baseline(test_results, f"{test_name}_validation")
        
        enhanced_validation = {
            'test_name': test_name,
            'validation_timestamp': datetime.now(timezone.utc).isoformat(),
            'performance_validation': validation_results,
            'baseline_comparison': baseline_comparison,
            'overall_status': 'PASS',
            'recommendations': []
        }
        
        # Determine overall status
        if (validation_results.get('overall_status') == 'FAIL' or
            not baseline_comparison.get('compliance_score', {}).get('overall_compliant', False)):
            enhanced_validation['overall_status'] = 'FAIL'
        
        # Generate recommendations
        if enhanced_validation['overall_status'] == 'FAIL':
            enhanced_validation['recommendations'].extend([
                "Performance optimization required to meet baseline requirements",
                "Review failing metrics and implement performance improvements"
            ])
            
            # Specific recommendations for regressions
            regressions = baseline_comparison.get('performance_analysis', {}).get('regressions', [])
            for regression in regressions:
                enhanced_validation['recommendations'].append(
                    f"Address performance regression in {regression['metric']}: "
                    f"{regression['variance']:+.1f}% variance from baseline"
                )
        else:
            enhanced_validation['recommendations'].append(
                "All performance requirements met successfully"
            )
        
        return enhanced_validation
    
    def get_comparison_history(limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent comparison history for trend analysis."""
        return comparison_history[-limit:] if comparison_history else []
    
    def get_cached_comparison(comparison_name: str) -> Optional[Dict[str, Any]]:
        """Get cached comparison results by name."""
        return comparison_results_cache.get(comparison_name)
    
    def generate_performance_report(
        test_results: Dict[str, Any],
        output_file: Optional[str] = None
    ) -> str:
        """Generate comprehensive performance analysis report."""
        report_lines = []
        
        # Report header
        report_lines.append("=" * 80)
        report_lines.append("PERFORMANCE BASELINE COMPARISON REPORT")
        report_lines.append("=" * 80)
        report_lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
        report_lines.append(f"Baseline: {nodejs_baseline_data.baseline_name} v{nodejs_baseline_data.baseline_version}")
        report_lines.append(f"Node.js Version: {nodejs_baseline_data.nodejs_version}")
        report_lines.append("")
        
        # Configuration summary
        report_lines.append("COMPARISON CONFIGURATION:")
        report_lines.append(f"  Variance Threshold: ±{comparison_config['variance_threshold']*100:.1f}%")
        report_lines.append(f"  Statistical Significance: {comparison_config['statistical_significance']*100:.0f}%")
        report_lines.append(f"  Minimum Sample Size: {comparison_config['sample_size_minimum']}")
        report_lines.append("")
        
        # Test results summary
        if 'validation_results' in test_results:
            validation = test_results['validation_results']
            report_lines.append("VALIDATION SUMMARY:")
            report_lines.append(f"  Overall Status: {validation.get('overall_status', 'UNKNOWN')}")
            
            if 'compliance_score' in validation:
                score = validation['compliance_score']
                report_lines.append(f"  Compliance Rate: {score.get('compliance_percentage', 0):.1f}%")
                report_lines.append(f"  Compliant Metrics: {score.get('compliant_metrics', 0)}/{score.get('total_metrics', 0)}")
            
            report_lines.append("")
        
        # Baseline comparison details
        if 'baseline_comparison' in test_results:
            comparison = test_results['baseline_comparison']
            
            if 'performance_analysis' in comparison:
                analysis = comparison['performance_analysis']
                report_lines.append("PERFORMANCE ANALYSIS:")
                report_lines.append(f"  Regressions: {analysis.get('regression_count', 0)}")
                report_lines.append(f"  Improvements: {analysis.get('improvement_count', 0)}")
                report_lines.append("")
                
                # List regressions
                if analysis.get('regressions'):
                    report_lines.append("PERFORMANCE REGRESSIONS:")
                    for reg in analysis['regressions']:
                        report_lines.append(f"  ✗ {reg['metric']}:")
                        report_lines.append(f"    Current: {reg['current_value']:.2f}")
                        report_lines.append(f"    Baseline: {reg['baseline_value']:.2f}")
                        report_lines.append(f"    Variance: {reg['variance']:+.1f}%")
                        report_lines.append("")
                
                # List improvements
                if analysis.get('improvements'):
                    report_lines.append("PERFORMANCE IMPROVEMENTS:")
                    for imp in analysis['improvements']:
                        report_lines.append(f"  ✓ {imp['metric']}:")
                        report_lines.append(f"    Current: {imp['current_value']:.2f}")
                        report_lines.append(f"    Baseline: {imp['baseline_value']:.2f}")
                        report_lines.append(f"    Variance: {imp['variance']:+.1f}%")
                        report_lines.append("")
        
        # Recommendations
        if 'recommendations' in test_results and test_results['recommendations']:
            report_lines.append("RECOMMENDATIONS:")
            for rec in test_results['recommendations']:
                report_lines.append(f"  • {rec}")
            report_lines.append("")
        
        # Report footer
        report_lines.append("=" * 80)
        report_lines.append("END OF REPORT")
        report_lines.append("=" * 80)
        
        report_content = '\n'.join(report_lines)
        
        # Save to file if specified
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write(report_content)
                logger.info(f"Performance report saved to {output_file}")
            except Exception as e:
                logger.error(f"Failed to save performance report: {e}")
        
        return report_content
    
    comparison_utilities = {
        'config': comparison_config,
        'baseline_data': nodejs_baseline_data,
        'thresholds': performance_thresholds,
        'compare_with_baseline': compare_with_nodejs_baseline,
        'validate_compliance': validate_performance_compliance,
        'get_comparison_history': get_comparison_history,
        'get_cached_comparison': get_cached_comparison,
        'generate_report': generate_performance_report
    }
    
    logger.info(
        "Baseline comparison engine initialized",
        baseline_name=nodejs_baseline_data.baseline_name,
        variance_threshold=comparison_config['variance_threshold'] * 100,
        threshold_count=len(performance_thresholds)
    )
    
    yield comparison_utilities
    
    logger.info(
        "Baseline comparison engine completed",
        total_comparisons=len(comparison_history),
        cached_results=len(comparison_results_cache)
    )


# =============================================================================
# Testcontainers Performance Testing Environment per Section 6.6.1
# =============================================================================

@pytest.fixture(scope="function")
def performance_testcontainers_environment(comprehensive_test_environment):
    """
    Function-scoped fixture providing Testcontainers performance testing environment.
    
    Creates production-equivalent containerized testing environment using Testcontainers
    for realistic performance validation per Section 6.6.1 container integration.
    
    Args:
        comprehensive_test_environment: Base testing environment
        
    Returns:
        Enhanced testing environment with performance-optimized Testcontainers
    """
    performance_env = comprehensive_test_environment.copy()
    
    # Check if Testcontainers is available through the existing environment
    testcontainers_available = (
        performance_env.get('database', {}).get('pymongo_client') is not None and
        performance_env.get('database', {}).get('redis_client') is not None
    )
    
    if not testcontainers_available:
        logger.warning("Testcontainers not available - using mock services for performance testing")
        pytest.skip("Testcontainers not available for performance testing environment")
    
    # Performance-specific container configuration
    performance_config = {
        'container_startup_timeout': 120,  # 2 minutes for performance containers
        'container_memory_limit': '1g',
        'container_cpu_limit': 2.0,
        'performance_optimized': True,
        'monitoring_enabled': True,
        'resource_tracking': True
    }
    
    # Container resource monitoring
    container_metrics = {
        'mongodb_metrics': {
            'startup_time': 0.0,
            'connection_time': 0.0,
            'query_performance': [],
            'memory_usage': [],
            'cpu_usage': []
        },
        'redis_metrics': {
            'startup_time': 0.0,
            'connection_time': 0.0,
            'operation_performance': [],
            'memory_usage': [],
            'cpu_usage': []
        },
        'flask_app_metrics': {
            'startup_time': 0.0,
            'response_times': [],
            'memory_usage': [],
            'cpu_usage': []
        }
    }
    
    def measure_container_performance(container_name: str, operation: str, duration: float):
        """Record container performance metrics."""
        if container_name in container_metrics:
            metric_entry = {
                'timestamp': time.time(),
                'operation': operation,
                'duration': duration
            }
            
            if operation.endswith('_time'):
                container_metrics[container_name][operation] = duration
            else:
                container_metrics[container_name].setdefault('operations', []).append(metric_entry)
    
    def get_container_performance_summary() -> Dict[str, Any]:
        """Get comprehensive container performance summary."""
        summary = {
            'collection_timestamp': time.time(),
            'containers': {}
        }
        
        for container_name, metrics in container_metrics.items():
            container_summary = {
                'startup_time': metrics.get('startup_time', 0.0),
                'connection_time': metrics.get('connection_time', 0.0),
                'total_operations': len(metrics.get('operations', [])),
                'average_operation_time': 0.0
            }
            
            operations = metrics.get('operations', [])
            if operations:
                container_summary['average_operation_time'] = sum(
                    op['duration'] for op in operations
                ) / len(operations)
                
                container_summary['operation_stats'] = {
                    'min': min(op['duration'] for op in operations),
                    'max': max(op['duration'] for op in operations),
                    'count': len(operations)
                }
            
            summary['containers'][container_name] = container_summary
        
        return summary
    
    def validate_container_performance() -> Dict[str, Any]:
        """Validate container performance against requirements."""
        summary = get_container_performance_summary()
        validation_results = {
            'overall_status': 'PASS',
            'container_validations': {},
            'performance_issues': []
        }
        
        # Performance thresholds for containers
        thresholds = {
            'mongodb_startup_time': 30.0,  # seconds
            'redis_startup_time': 10.0,    # seconds
            'flask_startup_time': 15.0,    # seconds
            'database_connection_time': 5.0,  # seconds
            'cache_connection_time': 2.0      # seconds
        }
        
        for container_name, container_summary in summary['containers'].items():
            container_validation = {
                'status': 'PASS',
                'issues': []
            }
            
            # Check startup time
            startup_threshold_key = f"{container_name.replace('_metrics', '')}_startup_time"
            if startup_threshold_key in thresholds:
                startup_time = container_summary['startup_time']
                threshold = thresholds[startup_threshold_key]
                
                if startup_time > threshold:
                    issue = f"Startup time ({startup_time:.1f}s) exceeds threshold ({threshold:.1f}s)"
                    container_validation['issues'].append(issue)
                    validation_results['performance_issues'].append(f"{container_name}: {issue}")
                    container_validation['status'] = 'FAIL'
            
            # Check connection time
            connection_time = container_summary['connection_time']
            connection_threshold = thresholds.get('database_connection_time', 5.0)
            if 'redis' in container_name:
                connection_threshold = thresholds.get('cache_connection_time', 2.0)
            
            if connection_time > connection_threshold:
                issue = f"Connection time ({connection_time:.1f}s) exceeds threshold ({connection_threshold:.1f}s)"
                container_validation['issues'].append(issue)
                validation_results['performance_issues'].append(f"{container_name}: {issue}")
                container_validation['status'] = 'FAIL'
            
            validation_results['container_validations'][container_name] = container_validation
            
            if container_validation['status'] == 'FAIL':
                validation_results['overall_status'] = 'FAIL'
        
        return validation_results
    
    def cleanup_performance_containers():
        """Clean up performance testing containers."""
        try:
            # Containers will be cleaned up by the comprehensive_test_environment fixture
            logger.info("Performance containers cleanup initiated")
        except Exception as e:
            logger.warning(f"Performance containers cleanup warning: {e}")
    
    # Enhanced performance environment
    performance_env.update({
        'performance_config': performance_config,
        'container_metrics': container_metrics,
        'measure_container_performance': measure_container_performance,
        'get_container_summary': get_container_performance_summary,
        'validate_container_performance': validate_container_performance,
        'cleanup_containers': cleanup_performance_containers
    })
    
    logger.info(
        "Performance Testcontainers environment initialized",
        mongodb_available=bool(performance_env.get('database', {}).get('pymongo_client')),
        redis_available=bool(performance_env.get('database', {}).get('redis_client')),
        performance_optimized=performance_config['performance_optimized']
    )
    
    yield performance_env
    
    # Performance validation and cleanup
    try:
        final_summary = get_container_performance_summary()
        validation_results = validate_container_performance()
        
        logger.info(
            "Performance Testcontainers environment completed",
            container_count=len(final_summary['containers']),
            performance_validation_status=validation_results['overall_status'],
            performance_issues_count=len(validation_results['performance_issues'])
        )
        
        if validation_results['performance_issues']:
            logger.warning(
                "Container performance issues detected",
                issues=validation_results['performance_issues']
            )
    
    except Exception as e:
        logger.error(f"Performance environment cleanup error: {e}")
    
    cleanup_performance_containers()


# =============================================================================
# Performance Test Data Management per Section 6.6.1
# =============================================================================

@pytest.fixture(scope="function")
def performance_test_data_manager(performance_testcontainers_environment):
    """
    Function-scoped fixture providing performance test data management.
    
    Creates comprehensive test data management system with isolation, cleanup,
    and performance optimization per Section 6.6.1 test data management.
    
    Args:
        performance_testcontainers_environment: Performance testing environment
        
    Returns:
        Test data management utilities with performance optimization
    """
    test_session_id = str(uuid.uuid4())
    data_manager_config = {
        'session_id': test_session_id,
        'isolation_enabled': True,
        'cleanup_enabled': True,
        'performance_optimized': True,
        'data_volume_target': 10000,  # Records for performance testing
        'concurrent_load_factor': 1.5,
        'cache_prewarming_enabled': True,
        'database_indexing_optimized': True
    }
    
    # Test data storage
    test_data_registry = {
        'users': [],
        'projects': [],
        'sessions': [],
        'files': [],
        'audit_logs': [],
        'performance_metrics': [],
        'generated_at': time.time(),
        'data_size_mb': 0.0
    }
    
    # Data generation utilities
    def generate_performance_test_users(count: int = 1000) -> List[Dict[str, Any]]:
        """Generate realistic user data for performance testing."""
        users = []
        
        for i in range(count):
            user = {
                'id': str(uuid.uuid4()),
                'email': f'perf_user_{i}_{test_session_id[:8]}@example.com',
                'first_name': f'PerfUser{i}',
                'last_name': f'Test{i}',
                'role': 'user' if i % 10 != 0 else 'admin',
                'created_at': datetime.now(timezone.utc) - timedelta(days=i % 365),
                'updated_at': datetime.now(timezone.utc) - timedelta(hours=i % 24),
                'last_login': datetime.now(timezone.utc) - timedelta(minutes=i % 1440),
                'status': 'active' if i % 20 != 0 else 'inactive',
                'profile': {
                    'preferences': {
                        'theme': 'light' if i % 3 == 0 else 'dark',
                        'language': 'en' if i % 5 != 0 else 'es',
                        'notifications': i % 7 != 0
                    },
                    'metadata': {
                        'signup_source': 'web' if i % 3 == 0 else 'mobile',
                        'performance_test_data': True,
                        'session_id': test_session_id
                    }
                }
            }
            users.append(user)
        
        test_data_registry['users'].extend(users)
        logger.info(f"Generated {count} performance test users")
        return users
    
    def generate_performance_test_projects(count: int = 500, users: List[Dict] = None) -> List[Dict[str, Any]]:
        """Generate realistic project data for performance testing."""
        if not users:
            users = test_data_registry['users']
        
        if not users:
            raise ValueError("No users available for project generation")
        
        projects = []
        
        for i in range(count):
            owner = users[i % len(users)]
            project = {
                'id': str(uuid.uuid4()),
                'name': f'Performance Test Project {i}',
                'description': f'Generated project for performance testing - Session {test_session_id[:8]}',
                'owner_id': owner['id'],
                'status': 'active' if i % 15 != 0 else 'archived',
                'created_at': datetime.now(timezone.utc) - timedelta(days=i % 180),
                'updated_at': datetime.now(timezone.utc) - timedelta(hours=i % 48),
                'settings': {
                    'visibility': 'private' if i % 3 == 0 else 'public',
                    'collaboration_enabled': i % 5 != 0,
                    'notifications_enabled': i % 7 != 0
                },
                'metrics': {
                    'file_count': i % 100,
                    'total_size_mb': (i % 50) * 10.5,
                    'last_activity': datetime.now(timezone.utc) - timedelta(minutes=i % 720)
                },
                'performance_test_data': True,
                'session_id': test_session_id
            }
            projects.append(project)
        
        test_data_registry['projects'].extend(projects)
        logger.info(f"Generated {count} performance test projects")
        return projects
    
    def generate_performance_test_sessions(count: int = 2000) -> List[Dict[str, Any]]:
        """Generate realistic session data for cache performance testing."""
        sessions = []
        users = test_data_registry['users']
        
        if not users:
            raise ValueError("No users available for session generation")
        
        for i in range(count):
            user = users[i % len(users)]
            session = {
                'session_id': str(uuid.uuid4()),
                'user_id': user['id'],
                'created_at': datetime.now(timezone.utc) - timedelta(minutes=i % 10080),  # Last week
                'expires_at': datetime.now(timezone.utc) + timedelta(hours=24),
                'last_activity': datetime.now(timezone.utc) - timedelta(minutes=i % 120),
                'ip_address': f'192.168.{(i % 254) + 1}.{(i % 254) + 1}',
                'user_agent': 'Performance Test Agent 1.0',
                'data': {
                    'preferences': user.get('profile', {}).get('preferences', {}),
                    'csrf_token': str(uuid.uuid4()),
                    'performance_test_session': True,
                    'session_id': test_session_id
                }
            }
            sessions.append(session)
        
        test_data_registry['sessions'].extend(sessions)
        logger.info(f"Generated {count} performance test sessions")
        return sessions
    
    def load_test_data_to_database() -> Dict[str, Any]:
        """Load generated test data to database for performance testing."""
        database_env = performance_testcontainers_environment.get('database', {})
        pymongo_client = database_env.get('pymongo_client')
        
        if not pymongo_client:
            logger.warning("MongoDB client not available - skipping database loading")
            return {'status': 'skipped', 'reason': 'MongoDB not available'}
        
        start_time = time.time()
        load_results = {
            'status': 'success',
            'collections_loaded': {},
            'total_records': 0,
            'load_duration': 0.0,
            'performance_metrics': {}
        }
        
        try:
            database = pymongo_client.get_default_database()
            
            # Load users collection
            if test_data_registry['users']:
                users_collection = database.users
                users_collection.delete_many({'performance_test_data': True, 'session_id': test_session_id})
                
                insert_start = time.time()
                result = users_collection.insert_many(test_data_registry['users'])
                insert_duration = time.time() - insert_start
                
                load_results['collections_loaded']['users'] = {
                    'count': len(result.inserted_ids),
                    'duration': insert_duration,
                    'rate': len(result.inserted_ids) / insert_duration if insert_duration > 0 else 0
                }
                load_results['total_records'] += len(result.inserted_ids)
            
            # Load projects collection
            if test_data_registry['projects']:
                projects_collection = database.projects
                projects_collection.delete_many({'performance_test_data': True, 'session_id': test_session_id})
                
                insert_start = time.time()
                result = projects_collection.insert_many(test_data_registry['projects'])
                insert_duration = time.time() - insert_start
                
                load_results['collections_loaded']['projects'] = {
                    'count': len(result.inserted_ids),
                    'duration': insert_duration,
                    'rate': len(result.inserted_ids) / insert_duration if insert_duration > 0 else 0
                }
                load_results['total_records'] += len(result.inserted_ids)
            
            # Create performance-optimized indexes
            if data_manager_config['database_indexing_optimized']:
                _create_performance_indexes(database)
            
            load_results['load_duration'] = time.time() - start_time
            
            logger.info(
                "Test data loaded to database",
                total_records=load_results['total_records'],
                load_duration=load_results['load_duration'],
                collections=list(load_results['collections_loaded'].keys())
            )
        
        except Exception as e:
            logger.error(f"Failed to load test data to database: {e}")
            load_results['status'] = 'error'
            load_results['error'] = str(e)
        
        return load_results
    
    def load_test_data_to_cache() -> Dict[str, Any]:
        """Load test session data to Redis cache for performance testing."""
        database_env = performance_testcontainers_environment.get('database', {})
        redis_client = database_env.get('redis_client')
        
        if not redis_client:
            logger.warning("Redis client not available - skipping cache loading")
            return {'status': 'skipped', 'reason': 'Redis not available'}
        
        start_time = time.time()
        load_results = {
            'status': 'success',
            'cache_operations': {},
            'total_keys': 0,
            'load_duration': 0.0
        }
        
        try:
            # Clear existing test data
            pattern = f"perf_test:{test_session_id}:*"
            existing_keys = redis_client.keys(pattern)
            if existing_keys:
                redis_client.delete(*existing_keys)
            
            # Load session data
            if test_data_registry['sessions']:
                session_ops = 0
                for session in test_data_registry['sessions']:
                    key = f"perf_test:{test_session_id}:session:{session['session_id']}"
                    value = json.dumps(session, default=str)
                    
                    redis_client.set(key, value, ex=86400)  # 24 hour expiry
                    session_ops += 1
                
                load_results['cache_operations']['sessions'] = session_ops
                load_results['total_keys'] += session_ops
            
            # Load user cache data
            if test_data_registry['users']:
                user_cache_ops = 0
                for user in test_data_registry['users'][:1000]:  # Cache first 1000 users
                    key = f"perf_test:{test_session_id}:user:{user['id']}"
                    cache_data = {
                        'id': user['id'],
                        'email': user['email'],
                        'role': user['role'],
                        'profile': user.get('profile', {})
                    }
                    value = json.dumps(cache_data, default=str)
                    
                    redis_client.set(key, value, ex=3600)  # 1 hour expiry
                    user_cache_ops += 1
                
                load_results['cache_operations']['user_cache'] = user_cache_ops
                load_results['total_keys'] += user_cache_ops
            
            load_results['load_duration'] = time.time() - start_time
            
            logger.info(
                "Test data loaded to cache",
                total_keys=load_results['total_keys'],
                load_duration=load_results['load_duration']
            )
        
        except Exception as e:
            logger.error(f"Failed to load test data to cache: {e}")
            load_results['status'] = 'error'
            load_results['error'] = str(e)
        
        return load_results
    
    def cleanup_test_data() -> Dict[str, Any]:
        """Clean up all generated test data from database and cache."""
        cleanup_results = {
            'status': 'success',
            'database_cleanup': {},
            'cache_cleanup': {},
            'cleanup_duration': 0.0
        }
        
        start_time = time.time()
        
        try:
            # Database cleanup
            database_env = performance_testcontainers_environment.get('database', {})
            pymongo_client = database_env.get('pymongo_client')
            
            if pymongo_client:
                database = pymongo_client.get_default_database()
                
                # Clean users collection
                users_result = database.users.delete_many({
                    'performance_test_data': True,
                    'session_id': test_session_id
                })
                cleanup_results['database_cleanup']['users_deleted'] = users_result.deleted_count
                
                # Clean projects collection
                projects_result = database.projects.delete_many({
                    'performance_test_data': True,
                    'session_id': test_session_id
                })
                cleanup_results['database_cleanup']['projects_deleted'] = projects_result.deleted_count
            
            # Cache cleanup
            redis_client = database_env.get('redis_client')
            
            if redis_client:
                pattern = f"perf_test:{test_session_id}:*"
                keys = redis_client.keys(pattern)
                if keys:
                    deleted_count = redis_client.delete(*keys)
                    cleanup_results['cache_cleanup']['keys_deleted'] = deleted_count
                else:
                    cleanup_results['cache_cleanup']['keys_deleted'] = 0
            
            cleanup_results['cleanup_duration'] = time.time() - start_time
            
            logger.info(
                "Performance test data cleanup completed",
                session_id=test_session_id,
                database_records_deleted=sum(cleanup_results['database_cleanup'].values()),
                cache_keys_deleted=cleanup_results['cache_cleanup'].get('keys_deleted', 0),
                cleanup_duration=cleanup_results['cleanup_duration']
            )
        
        except Exception as e:
            logger.error(f"Test data cleanup failed: {e}")
            cleanup_results['status'] = 'error'
            cleanup_results['error'] = str(e)
        
        return cleanup_results
    
    def get_data_statistics() -> Dict[str, Any]:
        """Get comprehensive test data statistics."""
        # Calculate data size
        data_size_bytes = 0
        for data_type, data_list in test_data_registry.items():
            if isinstance(data_list, list):
                data_size_bytes += len(json.dumps(data_list, default=str).encode('utf-8'))
        
        data_size_mb = data_size_bytes / (1024 * 1024)
        test_data_registry['data_size_mb'] = data_size_mb
        
        statistics = {
            'session_id': test_session_id,
            'generation_timestamp': test_data_registry['generated_at'],
            'data_types': {
                'users': len(test_data_registry['users']),
                'projects': len(test_data_registry['projects']),
                'sessions': len(test_data_registry['sessions']),
                'files': len(test_data_registry['files']),
                'audit_logs': len(test_data_registry['audit_logs'])
            },
            'total_records': sum(
                len(data_list) for data_list in test_data_registry.values()
                if isinstance(data_list, list)
            ),
            'data_size_mb': data_size_mb,
            'performance_optimized': data_manager_config['performance_optimized'],
            'isolation_enabled': data_manager_config['isolation_enabled']
        }
        
        return statistics
    
    # Data manager utilities
    data_manager_utilities = {
        'config': data_manager_config,
        'registry': test_data_registry,
        'generate_users': generate_performance_test_users,
        'generate_projects': generate_performance_test_projects,
        'generate_sessions': generate_performance_test_sessions,
        'load_to_database': load_test_data_to_database,
        'load_to_cache': load_test_data_to_cache,
        'cleanup_data': cleanup_test_data,
        'get_statistics': get_data_statistics
    }
    
    logger.info(
        "Performance test data manager initialized",
        session_id=test_session_id,
        isolation_enabled=data_manager_config['isolation_enabled'],
        performance_optimized=data_manager_config['performance_optimized']
    )
    
    yield data_manager_utilities
    
    # Automatic cleanup
    try:
        if data_manager_config['cleanup_enabled']:
            cleanup_results = cleanup_test_data()
            
            logger.info(
                "Performance test data manager cleanup completed",
                session_id=test_session_id,
                cleanup_status=cleanup_results['status']
            )
    except Exception as e:
        logger.error(f"Performance test data manager cleanup error: {e}")


def _create_performance_indexes(database):
    """Create performance-optimized database indexes for testing."""
    try:
        # Users collection indexes
        users_collection = database.users
        users_collection.create_index([('email', 1)], unique=True, background=True)
        users_collection.create_index([('status', 1)], background=True)
        users_collection.create_index([('role', 1)], background=True)
        users_collection.create_index([('created_at', -1)], background=True)
        users_collection.create_index([('last_login', -1)], background=True)
        
        # Projects collection indexes
        projects_collection = database.projects
        projects_collection.create_index([('owner_id', 1)], background=True)
        projects_collection.create_index([('status', 1)], background=True)
        projects_collection.create_index([('created_at', -1)], background=True)
        projects_collection.create_index([('updated_at', -1)], background=True)
        projects_collection.create_index([('settings.visibility', 1)], background=True)
        
        # Compound indexes for common queries
        users_collection.create_index([('status', 1), ('role', 1)], background=True)
        projects_collection.create_index([('owner_id', 1), ('status', 1)], background=True)
        
        logger.info("Performance indexes created successfully")
        
    except Exception as e:
        logger.warning(f"Failed to create performance indexes: {e}")


# =============================================================================
# Comprehensive Performance Testing Fixture Integration
# =============================================================================

@pytest.fixture(scope="function")
def comprehensive_performance_environment(
    performance_test_config,
    nodejs_baseline_data,
    performance_thresholds,
    locust_client,
    apache_bench_client,
    performance_metrics_collector,
    baseline_comparison_engine,
    performance_testcontainers_environment,
    performance_test_data_manager
):
    """
    Function-scoped fixture providing comprehensive performance testing environment.
    
    Integrates all performance testing components for complete load testing, baseline
    comparison, and performance validation per Section 6.6.1 comprehensive performance
    testing requirements.
    
    Args:
        performance_test_config: Performance test configuration
        nodejs_baseline_data: Node.js baseline performance data
        performance_thresholds: Performance threshold configurations
        locust_client: Locust load testing client
        apache_bench_client: Apache Bench HTTP testing client
        performance_metrics_collector: Performance metrics collection system
        baseline_comparison_engine: Baseline comparison and validation engine
        performance_testcontainers_environment: Testcontainers testing environment
        performance_test_data_manager: Test data management system
        
    Returns:
        Comprehensive performance testing environment with all components integrated
    """
    performance_session_id = str(uuid.uuid4())
    
    # Comprehensive environment configuration
    environment_config = {
        'session_id': performance_session_id,
        'testing_mode': 'comprehensive_performance',
        'locust_enabled': LOCUST_AVAILABLE,
        'apache_bench_enabled': shutil.which('ab') is not None,
        'prometheus_enabled': PROMETHEUS_AVAILABLE,
        'testcontainers_enabled': True,
        'baseline_comparison_enabled': True,
        'automated_validation': True,
        'performance_reporting': True
    }
    
    # Initialize comprehensive environment
    comprehensive_env = {
        'config': environment_config,
        'session_info': {
            'session_id': performance_session_id,
            'started_at': datetime.now(timezone.utc),
            'testing_framework': 'pytest + locust + apache-bench',
            'baseline_version': nodejs_baseline_data.baseline_version,
            'variance_threshold': performance_test_config.PERFORMANCE_VARIANCE_THRESHOLD
        },
        
        # Component integration
        'performance_config': performance_test_config,
        'baseline_data': nodejs_baseline_data,
        'thresholds': performance_thresholds,
        'locust': locust_client,
        'apache_bench': apache_bench_client,
        'metrics_collector': performance_metrics_collector,
        'baseline_engine': baseline_comparison_engine,
        'containers': performance_testcontainers_environment,
        'data_manager': performance_test_data_manager,
        
        # High-level testing functions
        'run_load_test': None,
        'run_benchmark_test': None,
        'run_comprehensive_test': None,
        'validate_performance': None,
        'generate_final_report': None
    }
    
    def run_comprehensive_load_test(
        scenario: LoadTestScenario = LoadTestScenario.NORMAL_LOAD,
        duration_override: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Run comprehensive load test with Locust integration.
        
        Args:
            scenario: Load test scenario to execute
            duration_override: Optional duration override in seconds
            
        Returns:
            Comprehensive load test results with performance analysis
        """
        if not environment_config['locust_enabled']:
            return {
                'status': 'skipped',
                'reason': 'Locust not available',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        
        logger.info(f"Starting comprehensive load test: {scenario.value}")
        
        # Get load test configuration
        load_config = get_load_test_config(scenario, os.getenv('FLASK_ENV', 'testing'))
        if duration_override:
            load_config.duration = duration_override
        
        # Prepare test data
        data_manager = comprehensive_env['data_manager']
        data_manager['generate_users'](1000)
        data_manager['generate_projects'](500)
        data_manager['generate_sessions'](2000)
        
        # Load data to database and cache
        db_load_result = data_manager['load_to_database']()
        cache_load_result = data_manager['load_to_cache']()
        
        # Start metrics collection
        metrics_collector = comprehensive_env['metrics_collector']
        
        # Execute load test
        locust_client = comprehensive_env['locust']
        test_start_time = time.time()
        
        # Start load test
        start_success = locust_client['start_load_test'](load_config)
        if not start_success:
            return {
                'status': 'failed',
                'reason': 'Failed to start Locust load test',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        
        # Wait for test completion
        completion_success = locust_client['wait_for_completion'](load_config.duration + 60)
        
        # Stop load test
        locust_client['stop_load_test']()
        
        # Collect final statistics
        test_duration = time.time() - test_start_time
        locust_stats = locust_client['get_statistics']()
        performance_summary = metrics_collector['get_summary'](int(test_duration))
        
        # Perform baseline comparison
        baseline_engine = comprehensive_env['baseline_engine']
        
        # Map Locust results to baseline metrics
        baseline_metrics = {}
        if locust_stats.get('avg_response_time'):
            baseline_metrics['api_response_time_mean'] = locust_stats['avg_response_time']
        if locust_stats.get('percentiles', {}).get('p95'):
            baseline_metrics['api_response_time_p95'] = locust_stats['percentiles']['p95']
        if locust_stats.get('requests_per_second'):
            baseline_metrics['requests_per_second'] = locust_stats['requests_per_second']
        if locust_stats.get('failure_rate') is not None:
            baseline_metrics['error_rate_overall'] = locust_stats['failure_rate'] * 100
        
        # Add system metrics if available
        if 'system_stats' in performance_summary:
            baseline_metrics['cpu_utilization_average'] = performance_summary['system_stats']['cpu_usage_mean']
            baseline_metrics['memory_usage_mb'] = performance_summary['system_stats'].get('memory_usage_mean', 0) * 10  # Rough conversion
        
        baseline_comparison = baseline_engine['compare_with_baseline'](
            baseline_metrics,
            f"load_test_{scenario.value}_{performance_session_id[:8]}"
        )
        
        # Compile comprehensive results
        load_test_results = {
            'status': 'completed',
            'test_info': {
                'scenario': scenario.value,
                'session_id': performance_session_id,
                'duration': test_duration,
                'configuration': {
                    'users': load_config.users,
                    'spawn_rate': load_config.spawn_rate,
                    'target_duration': load_config.duration
                }
            },
            'locust_results': locust_stats,
            'performance_summary': performance_summary,
            'baseline_comparison': baseline_comparison,
            'data_preparation': {
                'database_load': db_load_result,
                'cache_load': cache_load_result
            },
            'validation_status': baseline_comparison.get('compliance_score', {}).get('overall_compliant', False),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        logger.info(
            "Comprehensive load test completed",
            scenario=scenario.value,
            duration=test_duration,
            validation_status=load_test_results['validation_status'],
            compliance_rate=baseline_comparison.get('compliance_score', {}).get('compliance_percentage', 0)
        )
        
        return load_test_results
    
    def run_comprehensive_benchmark_test(
        endpoints: List[str] = None,
        requests_per_endpoint: int = 1000,
        concurrency: int = 10
    ) -> Dict[str, Any]:
        """
        Run comprehensive benchmark test with Apache Bench integration.
        
        Args:
            endpoints: List of endpoints to benchmark
            requests_per_endpoint: Number of requests per endpoint
            concurrency: Concurrent request level
            
        Returns:
            Comprehensive benchmark test results with baseline comparison
        """
        if not environment_config['apache_bench_enabled']:
            return {
                'status': 'skipped',
                'reason': 'Apache Bench not available',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        
        if not endpoints:
            endpoints = ['/health', '/api/users', '/api/users/search']
        
        logger.info(f"Starting comprehensive benchmark test on {len(endpoints)} endpoints")
        
        # Prepare test data
        data_manager = comprehensive_env['data_manager']
        data_manager['generate_users'](500)
        db_load_result = data_manager['load_to_database']()
        
        apache_bench_client = comprehensive_env['apache_bench']
        host = performance_test_config.PERFORMANCE_TEST_HOST
        
        benchmark_results = {
            'status': 'completed',
            'test_info': {
                'session_id': performance_session_id,
                'endpoints_tested': len(endpoints),
                'requests_per_endpoint': requests_per_endpoint,
                'concurrency': concurrency,
                'host': host
            },
            'endpoint_results': {},
            'aggregated_metrics': {},
            'baseline_comparisons': {},
            'overall_validation': {},
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        all_response_times = []
        total_requests = 0
        total_failures = 0
        
        # Test each endpoint
        for endpoint in endpoints:
            url = urljoin(host, endpoint)
            
            logger.info(f"Benchmarking endpoint: {endpoint}")
            
            ab_result = apache_bench_client['run_benchmark'](
                url=url,
                requests=requests_per_endpoint,
                concurrency=concurrency,
                timeout=30
            )
            
            benchmark_results['endpoint_results'][endpoint] = ab_result
            
            if ab_result.get('success'):
                # Track aggregated metrics
                if 'time_per_request_mean' in ab_result:
                    all_response_times.append(ab_result['time_per_request_mean'])
                
                total_requests += ab_result.get('requests_completed', 0)
                total_failures += ab_result.get('requests_failed', 0)
                
                # Perform baseline comparison for this endpoint
                baseline_engine = comprehensive_env['baseline_engine']
                endpoint_metrics = {
                    'api_response_time_mean': ab_result.get('time_per_request_mean', 0),
                    'requests_per_second': ab_result.get('requests_per_second', 0),
                    'error_rate_overall': ab_result.get('failure_rate', 0) * 100 if ab_result.get('failure_rate') is not None else 0
                }
                
                if 'response_time_p95' in ab_result:
                    endpoint_metrics['api_response_time_p95'] = ab_result['response_time_p95']
                
                endpoint_comparison = baseline_engine['compare_with_baseline'](
                    endpoint_metrics,
                    f"benchmark_{endpoint.replace('/', '_')}_{performance_session_id[:8]}"
                )
                
                benchmark_results['baseline_comparisons'][endpoint] = endpoint_comparison
        
        # Calculate aggregated metrics
        if all_response_times:
            benchmark_results['aggregated_metrics'] = {
                'average_response_time': sum(all_response_times) / len(all_response_times),
                'min_response_time': min(all_response_times),
                'max_response_time': max(all_response_times),
                'total_requests': total_requests,
                'total_failures': total_failures,
                'overall_failure_rate': total_failures / total_requests if total_requests > 0 else 0,
                'endpoints_tested': len(endpoints)
            }
        
        # Overall validation
        all_compliant = all(
            comp.get('compliance_score', {}).get('overall_compliant', False)
            for comp in benchmark_results['baseline_comparisons'].values()
        )
        
        benchmark_results['overall_validation'] = {
            'all_endpoints_compliant': all_compliant,
            'compliant_endpoints': sum(
                1 for comp in benchmark_results['baseline_comparisons'].values()
                if comp.get('compliance_score', {}).get('overall_compliant', False)
            ),
            'total_endpoints': len(benchmark_results['baseline_comparisons']),
            'compliance_percentage': (
                sum(
                    1 for comp in benchmark_results['baseline_comparisons'].values()
                    if comp.get('compliance_score', {}).get('overall_compliant', False)
                ) / len(benchmark_results['baseline_comparisons']) * 100
                if benchmark_results['baseline_comparisons'] else 0
            )
        }
        
        logger.info(
            "Comprehensive benchmark test completed",
            endpoints_tested=len(endpoints),
            overall_compliant=all_compliant,
            compliance_percentage=benchmark_results['overall_validation']['compliance_percentage']
        )
        
        return benchmark_results
    
    def run_full_performance_validation() -> Dict[str, Any]:
        """
        Run complete performance validation including load and benchmark tests.
        
        Returns:
            Comprehensive performance validation results
        """
        logger.info("Starting full performance validation")
        
        validation_start_time = time.time()
        
        # Run load test with normal scenario
        load_test_results = run_comprehensive_load_test(LoadTestScenario.NORMAL_LOAD, 300)  # 5 minutes
        
        # Run benchmark test on key endpoints
        benchmark_results = run_comprehensive_benchmark_test(
            endpoints=['/health', '/api/users', '/api/users/search', '/api/auth/login'],
            requests_per_endpoint=500,
            concurrency=20
        )
        
        # Container performance validation
        container_validation = comprehensive_env['containers']['validate_container_performance']()
        
        # Comprehensive validation results
        validation_results = {
            'status': 'completed',
            'validation_info': {
                'session_id': performance_session_id,
                'validation_duration': time.time() - validation_start_time,
                'components_tested': ['load_testing', 'benchmarking', 'containers'],
                'baseline_version': nodejs_baseline_data.baseline_version,
                'variance_threshold': performance_test_config.PERFORMANCE_VARIANCE_THRESHOLD
            },
            'load_test_results': load_test_results,
            'benchmark_results': benchmark_results,
            'container_validation': container_validation,
            'overall_assessment': {},
            'recommendations': [],
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        # Overall assessment
        load_compliant = load_test_results.get('validation_status', False)
        benchmark_compliant = benchmark_results.get('overall_validation', {}).get('all_endpoints_compliant', False)
        container_compliant = container_validation.get('overall_status') == 'PASS'
        
        overall_compliant = load_compliant and benchmark_compliant and container_compliant
        
        validation_results['overall_assessment'] = {
            'overall_compliant': overall_compliant,
            'load_test_compliant': load_compliant,
            'benchmark_test_compliant': benchmark_compliant,
            'container_performance_compliant': container_compliant,
            'compliance_score': (
                sum([load_compliant, benchmark_compliant, container_compliant]) / 3.0 * 100
            )
        }
        
        # Generate recommendations
        if not overall_compliant:
            validation_results['recommendations'].append(
                "Performance optimization required to meet all baseline requirements"
            )
            
            if not load_compliant:
                validation_results['recommendations'].append(
                    "Load testing performance does not meet baseline requirements"
                )
            
            if not benchmark_compliant:
                validation_results['recommendations'].append(
                    "Individual endpoint performance requires optimization"
                )
            
            if not container_compliant:
                validation_results['recommendations'].append(
                    "Container infrastructure performance needs improvement"
                )
        else:
            validation_results['recommendations'].append(
                "All performance requirements met successfully"
            )
        
        logger.info(
            "Full performance validation completed",
            overall_compliant=overall_compliant,
            compliance_score=validation_results['overall_assessment']['compliance_score'],
            validation_duration=validation_results['validation_info']['validation_duration']
        )
        
        return validation_results
    
    def generate_comprehensive_performance_report(
        validation_results: Dict[str, Any],
        output_file: Optional[str] = None
    ) -> str:
        """
        Generate comprehensive performance testing report.
        
        Args:
            validation_results: Complete validation results
            output_file: Optional output file path
            
        Returns:
            Formatted comprehensive performance report
        """
        baseline_engine = comprehensive_env['baseline_engine']
        return baseline_engine['generate_report'](validation_results, output_file)
    
    # Attach high-level functions to environment
    comprehensive_env.update({
        'run_load_test': run_comprehensive_load_test,
        'run_benchmark_test': run_comprehensive_benchmark_test,
        'run_comprehensive_test': run_full_performance_validation,
        'validate_performance': run_full_performance_validation,
        'generate_final_report': generate_comprehensive_performance_report
    })
    
    logger.info(
        "Comprehensive performance environment initialized",
        session_id=performance_session_id,
        locust_enabled=environment_config['locust_enabled'],
        apache_bench_enabled=environment_config['apache_bench_enabled'],
        prometheus_enabled=environment_config['prometheus_enabled'],
        baseline_version=nodejs_baseline_data.baseline_version
    )
    
    yield comprehensive_env
    
    # Final cleanup and reporting
    try:
        session_duration = time.time() - comprehensive_env['session_info']['started_at'].timestamp()
        
        logger.info(
            "Comprehensive performance environment session completed",
            session_id=performance_session_id,
            session_duration=session_duration,
            testing_framework=comprehensive_env['session_info']['testing_framework']
        )
        
        # Data cleanup
        if 'data_manager' in comprehensive_env:
            comprehensive_env['data_manager']['cleanup_data']()
        
        # Metrics export if Prometheus is available
        if environment_config['prometheus_enabled'] and 'metrics_collector' in comprehensive_env:
            prometheus_gateway = os.getenv('PROMETHEUS_PUSHGATEWAY_URL')
            if prometheus_gateway:
                comprehensive_env['metrics_collector']['export_to_prometheus'](
                    prometheus_gateway,
                    f"performance_tests_{performance_session_id[:8]}"
                )
    
    except Exception as e:
        logger.error(f"Comprehensive performance environment cleanup error: {e}")


# =============================================================================
# Exported Fixtures and Utilities
# =============================================================================

__all__ = [
    # Performance configuration fixtures
    'performance_test_config',
    'nodejs_baseline_data',
    'performance_thresholds',
    
    # Load testing fixtures
    'locust_environment',
    'locust_client',
    'PerformanceTestUser',
    'PerformanceLoadTestShape',
    
    # HTTP benchmarking fixtures
    'apache_bench_client',
    
    # Performance monitoring fixtures
    'performance_metrics_collector',
    
    # Baseline comparison fixtures
    'baseline_comparison_engine',
    
    # Container testing fixtures
    'performance_testcontainers_environment',
    
    # Test data management fixtures
    'performance_test_data_manager',
    
    # Comprehensive testing environment
    'comprehensive_performance_environment'
]