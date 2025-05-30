"""
E2E-Specific pytest Configuration for Flask Application End-to-End Testing

This module provides comprehensive E2E testing configuration with Flask application setup,
performance monitoring integration, load testing infrastructure using locust and apache-bench,
and production-equivalent test environment preparation per Section 6.6.1 and 6.6.5.

Key Features:
- Flask application factory for end-to-end testing with production parity per Section 6.6.5
- Performance monitoring integration for E2E test metrics collection per Section 6.6.1
- locust and apache-bench integration fixtures per Section 6.6.1 performance testing tools
- Test environment with external service integration per Section 6.6.5
- Comprehensive test data setup and teardown automation per Section 4.6.1
- E2E test reporting and metrics collection per Section 6.6.2 test reporting requirements
- Production-equivalent test environment setup per Section 6.6.1

Architecture Integration:
- Section 6.6.1: Flask application testing with pytest-flask integration
- Section 6.6.1: Performance testing integration with locust and apache-bench
- Section 6.6.5: Test environment management for E2E scenarios with production parity
- Section 4.6.1: Comprehensive test data setup and teardown automation
- Section 6.6.2: E2E test reporting and metrics collection requirements

Dependencies:
- pytest 7.4+ with Flask testing patterns per Section 6.6.1
- pytest-flask for Flask-specific E2E testing patterns
- locust ≥2.x for load testing and throughput validation per Section 6.6.1
- apache-bench for HTTP server performance measurement per Section 6.6.1
- Testcontainers for production-equivalent service dependencies
- requests/httpx for external service integration testing
"""

import asyncio
import json
import logging
import os
import subprocess
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple, Union
from unittest.mock import Mock, patch, MagicMock

import pytest
import pytest_asyncio
from flask import Flask, g
from flask.testing import FlaskClient
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Performance testing imports
try:
    from locust import HttpUser, task, between
    from locust.env import Environment
    from locust.stats import stats_printer, stats_history
    from locust.log import setup_logging
    LOCUST_AVAILABLE = True
except ImportError:
    LOCUST_AVAILABLE = False
    logging.warning("Locust not available - load testing fixtures will be disabled")

# Import global fixtures and utilities
from tests.conftest import *  # Import all global fixtures
from tests.fixtures.database_fixtures import *  # Import database testing fixtures

# Application imports with fallback handling
try:
    from src.app import create_app
    from src.config.settings import TestingConfig, ProductionConfig, ConfigFactory
except ImportError:
    # Fallback for development scenarios
    logging.warning("Application modules not fully available - using fallback implementations")
    
    def create_app(config_name='testing'):
        """Fallback app factory"""
        from flask import Flask
        app = Flask(__name__)
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        return app
    
    class TestingConfig:
        TESTING = True
        WTF_CSRF_ENABLED = False
        SECRET_KEY = 'test-secret-key'

# Configure structured logging for E2E tests
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# E2E Test Configuration Constants
E2E_TEST_TIMEOUT_SECONDS = 300  # 5 minutes for complete E2E workflows
PERFORMANCE_BASELINE_THRESHOLD = 0.10  # ≤10% variance requirement per Section 0.1.1
LOAD_TEST_DURATION_SECONDS = 60  # Duration for load testing scenarios
CONCURRENT_USERS_MAX = 50  # Maximum concurrent users for load testing
DEFAULT_REQUEST_TIMEOUT = 30  # Default HTTP request timeout for E2E tests

# Node.js baseline performance metrics for comparison per Section 0.1.1
NODEJS_BASELINE_METRICS = {
    'response_times': {
        'health_check': 50,          # milliseconds
        'user_login': 200,           # milliseconds
        'user_registration': 300,    # milliseconds
        'user_profile': 150,         # milliseconds
        'api_endpoint_avg': 180,     # milliseconds
    },
    'throughput': {
        'requests_per_second': 100,  # baseline RPS
        'concurrent_users': 50,      # baseline concurrent capacity
    },
    'memory_usage': {
        'baseline_mb': 256,          # baseline memory usage
        'peak_mb': 512,              # peak memory usage
    }
}


@dataclass
class E2ETestConfig:
    """
    Comprehensive E2E test configuration for production-equivalent testing scenarios.
    
    Provides centralized configuration for E2E test execution including performance
    thresholds, external service integration, load testing parameters, and monitoring
    settings aligned with Section 6.6.5 test environment requirements.
    """
    
    # Flask application configuration
    app_config_name: str = field(default='testing')
    enable_production_parity: bool = field(default=True)
    external_services_enabled: bool = field(default=True)
    
    # Performance testing configuration per Section 6.6.1
    enable_performance_monitoring: bool = field(default=True)
    performance_variance_threshold: float = field(default=PERFORMANCE_BASELINE_THRESHOLD)
    nodejs_baseline_comparison: bool = field(default=True)
    
    # Load testing configuration with locust per Section 6.6.1
    enable_load_testing: bool = field(default=True)
    load_test_duration: int = field(default=LOAD_TEST_DURATION_SECONDS)
    max_concurrent_users: int = field(default=CONCURRENT_USERS_MAX)
    user_spawn_rate: float = field(default=2.0)  # users per second
    
    # Apache-bench configuration per Section 6.6.1
    enable_apache_bench: bool = field(default=True)
    apache_bench_requests: int = field(default=1000)
    apache_bench_concurrency: int = field(default=10)
    
    # External service integration per Section 6.6.5
    mock_auth0_service: bool = field(default=True)
    mock_aws_services: bool = field(default=True)
    mock_third_party_apis: bool = field(default=True)
    enable_circuit_breakers: bool = field(default=True)
    
    # Test data and environment configuration
    comprehensive_test_data: bool = field(default=True)
    cleanup_after_tests: bool = field(default=True)
    parallel_execution_safe: bool = field(default=True)
    
    # Reporting and metrics configuration per Section 6.6.2
    enable_detailed_reporting: bool = field(default=True)
    collect_performance_metrics: bool = field(default=True)
    generate_test_artifacts: bool = field(default=True)
    
    # Timeouts and reliability configuration
    test_timeout_seconds: int = field(default=E2E_TEST_TIMEOUT_SECONDS)
    request_timeout_seconds: int = field(default=DEFAULT_REQUEST_TIMEOUT)
    retry_failed_requests: bool = field(default=True)
    max_retries: int = field(default=3)
    
    def get_flask_config(self) -> Dict[str, Any]:
        """
        Generate Flask configuration optimized for E2E testing.
        
        Returns:
            Dictionary containing Flask configuration settings
        """
        base_config = {
            'TESTING': True,
            'WTF_CSRF_ENABLED': False,
            'DEBUG': False,
            'PRESERVE_CONTEXT_ON_EXCEPTION': False,
            'PROPAGATE_EXCEPTIONS': True,
            'LOGIN_DISABLED': False,  # Enable authentication for E2E tests
            'SERVER_NAME': 'localhost:5000',
            'APPLICATION_ROOT': '/',
            'PREFERRED_URL_SCHEME': 'http',
        }
        
        if self.enable_production_parity:
            # Add production-like settings for realistic testing
            base_config.update({
                'SESSION_COOKIE_SECURE': False,  # HTTP for testing
                'SESSION_COOKIE_HTTPONLY': True,
                'SESSION_COOKIE_SAMESITE': 'Lax',
                'PERMANENT_SESSION_LIFETIME': 3600,  # 1 hour for E2E tests
                'MAX_CONTENT_LENGTH': 16 * 1024 * 1024,  # 16MB
                'SEND_FILE_MAX_AGE_DEFAULT': 43200,  # 12 hours
            })
        
        return base_config
    
    def get_performance_thresholds(self) -> Dict[str, float]:
        """
        Get performance validation thresholds for E2E testing.
        
        Returns:
            Dictionary containing performance thresholds
        """
        return {
            'response_time_variance': self.performance_variance_threshold,
            'memory_usage_variance': 0.15,  # 15% variance for memory
            'throughput_variance': self.performance_variance_threshold,
            'error_rate_threshold': 0.01,  # 1% maximum error rate
        }


@dataclass
class PerformanceMetrics:
    """
    Performance metrics collection for E2E test validation.
    
    Tracks comprehensive performance data during E2E test execution including
    response times, throughput, resource usage, and comparison with Node.js
    baseline metrics per Section 0.1.1 requirements.
    """
    
    test_name: str
    start_time: float
    end_time: Optional[float] = None
    response_times: List[float] = field(default_factory=list)
    request_count: int = 0
    error_count: int = 0
    throughput_rps: float = 0.0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    
    # Performance comparison data
    baseline_comparison: Dict[str, Any] = field(default_factory=dict)
    variance_analysis: Dict[str, float] = field(default_factory=dict)
    compliance_status: bool = True
    
    def add_response_time(self, response_time_ms: float) -> None:
        """Add response time measurement to metrics collection."""
        self.response_times.append(response_time_ms)
        self.request_count += 1
    
    def add_error(self) -> None:
        """Increment error counter for failed requests."""
        self.error_count += 1
    
    def calculate_statistics(self) -> Dict[str, Any]:
        """
        Calculate comprehensive performance statistics.
        
        Returns:
            Dictionary containing calculated performance statistics
        """
        if not self.response_times:
            return {'error': 'No response time data available'}
        
        duration = (self.end_time or time.time()) - self.start_time
        
        stats = {
            'total_requests': self.request_count,
            'total_errors': self.error_count,
            'error_rate': self.error_count / max(self.request_count, 1),
            'test_duration_seconds': duration,
            'average_response_time_ms': sum(self.response_times) / len(self.response_times),
            'min_response_time_ms': min(self.response_times),
            'max_response_time_ms': max(self.response_times),
            'median_response_time_ms': sorted(self.response_times)[len(self.response_times) // 2],
            'throughput_rps': self.request_count / max(duration, 0.001),
            'memory_usage_mb': self.memory_usage_mb,
            'cpu_usage_percent': self.cpu_usage_percent,
        }
        
        # Calculate percentiles
        sorted_times = sorted(self.response_times)
        stats['p95_response_time_ms'] = sorted_times[int(0.95 * len(sorted_times))]
        stats['p99_response_time_ms'] = sorted_times[int(0.99 * len(sorted_times))]
        
        return stats
    
    def validate_against_baseline(self, baseline_metrics: Dict[str, Any]) -> bool:
        """
        Validate performance metrics against Node.js baseline per Section 0.1.1.
        
        Args:
            baseline_metrics: Node.js baseline performance metrics
            
        Returns:
            True if performance meets variance threshold requirements
        """
        if not self.response_times:
            return False
        
        stats = self.calculate_statistics()
        baseline_response_time = baseline_metrics.get('response_times', {}).get('api_endpoint_avg', 200)
        baseline_throughput = baseline_metrics.get('throughput', {}).get('requests_per_second', 100)
        
        # Calculate variance from baseline
        response_time_variance = (stats['average_response_time_ms'] - baseline_response_time) / baseline_response_time
        throughput_variance = (stats['throughput_rps'] - baseline_throughput) / baseline_throughput
        
        self.variance_analysis = {
            'response_time_variance': response_time_variance,
            'throughput_variance': throughput_variance,
            'error_rate': stats['error_rate'],
        }
        
        # Check compliance with ≤10% variance requirement
        self.compliance_status = (
            abs(response_time_variance) <= PERFORMANCE_BASELINE_THRESHOLD and
            abs(throughput_variance) <= PERFORMANCE_BASELINE_THRESHOLD and
            stats['error_rate'] <= 0.01  # 1% error threshold
        )
        
        self.baseline_comparison = {
            'baseline_response_time_ms': baseline_response_time,
            'measured_response_time_ms': stats['average_response_time_ms'],
            'baseline_throughput_rps': baseline_throughput,
            'measured_throughput_rps': stats['throughput_rps'],
            'compliance_status': self.compliance_status,
            'variance_analysis': self.variance_analysis,
        }
        
        return self.compliance_status


class E2ETestReporter:
    """
    Comprehensive E2E test reporting and metrics collection per Section 6.6.2.
    
    Provides detailed test execution reporting, performance metrics aggregation,
    and comprehensive test artifacts generation for E2E test analysis and
    continuous improvement of testing processes.
    """
    
    def __init__(self, output_dir: Optional[Path] = None):
        """
        Initialize E2E test reporter with output configuration.
        
        Args:
            output_dir: Directory for test artifacts output
        """
        self.output_dir = output_dir or Path(tempfile.gettempdir()) / 'e2e_test_reports'
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.test_results: List[Dict[str, Any]] = []
        self.performance_metrics: List[PerformanceMetrics] = []
        self.test_session_id = str(uuid.uuid4())
        self.session_start_time = time.time()
        
        logger.info(
            "E2E test reporter initialized",
            session_id=self.test_session_id,
            output_dir=str(self.output_dir)
        )
    
    def add_test_result(
        self,
        test_name: str,
        status: str,
        duration: float,
        metrics: Optional[PerformanceMetrics] = None,
        additional_data: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Add test result to reporting collection.
        
        Args:
            test_name: Name of the executed test
            status: Test execution status (passed, failed, skipped)
            duration: Test execution duration in seconds
            metrics: Optional performance metrics
            additional_data: Additional test data for reporting
        """
        result = {
            'test_name': test_name,
            'status': status,
            'duration_seconds': duration,
            'timestamp': time.time(),
            'session_id': self.test_session_id,
            'additional_data': additional_data or {}
        }
        
        if metrics:
            result['performance_metrics'] = metrics.calculate_statistics()
            result['baseline_comparison'] = metrics.baseline_comparison
            self.performance_metrics.append(metrics)
        
        self.test_results.append(result)
        
        logger.debug(
            "Test result added to reporter",
            test_name=test_name,
            status=status,
            duration=duration
        )
    
    def generate_comprehensive_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive E2E test execution report.
        
        Returns:
            Dictionary containing complete test execution analysis
        """
        session_duration = time.time() - self.session_start_time
        
        # Calculate overall statistics
        total_tests = len(self.test_results)
        passed_tests = len([r for r in self.test_results if r['status'] == 'passed'])
        failed_tests = len([r for r in self.test_results if r['status'] == 'failed'])
        skipped_tests = len([r for r in self.test_results if r['status'] == 'skipped'])
        
        # Performance analysis
        performance_summary = {}
        if self.performance_metrics:
            all_response_times = []
            all_throughput = []
            compliance_count = 0
            
            for metrics in self.performance_metrics:
                stats = metrics.calculate_statistics()
                all_response_times.extend(metrics.response_times)
                all_throughput.append(stats.get('throughput_rps', 0))
                
                if metrics.compliance_status:
                    compliance_count += 1
            
            if all_response_times:
                performance_summary = {
                    'total_performance_tests': len(self.performance_metrics),
                    'performance_compliance_rate': compliance_count / len(self.performance_metrics),
                    'overall_average_response_time_ms': sum(all_response_times) / len(all_response_times),
                    'overall_max_response_time_ms': max(all_response_times),
                    'overall_min_response_time_ms': min(all_response_times),
                    'average_throughput_rps': sum(all_throughput) / len(all_throughput) if all_throughput else 0,
                }
        
        report = {
            'session_info': {
                'session_id': self.test_session_id,
                'start_time': self.session_start_time,
                'duration_seconds': session_duration,
                'timestamp': time.time(),
            },
            'test_summary': {
                'total_tests': total_tests,
                'passed_tests': passed_tests,
                'failed_tests': failed_tests,
                'skipped_tests': skipped_tests,
                'success_rate': passed_tests / max(total_tests, 1),
                'average_test_duration': sum(r['duration_seconds'] for r in self.test_results) / max(total_tests, 1),
            },
            'performance_summary': performance_summary,
            'detailed_results': self.test_results,
            'compliance_analysis': {
                'nodejs_baseline_comparison': True,
                'variance_threshold': PERFORMANCE_BASELINE_THRESHOLD,
                'performance_requirements_met': performance_summary.get('performance_compliance_rate', 0) >= 0.9,
            }
        }
        
        return report
    
    def save_report_artifacts(self) -> Path:
        """
        Save comprehensive test artifacts to file system.
        
        Returns:
            Path to generated report file
        """
        report = self.generate_comprehensive_report()
        
        # Generate report filename with timestamp
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        report_filename = f"e2e_test_report_{timestamp}_{self.test_session_id[:8]}.json"
        report_path = self.output_dir / report_filename
        
        # Save JSON report
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # Generate summary log
        summary_path = self.output_dir / f"e2e_summary_{timestamp}.log"
        with open(summary_path, 'w') as f:
            f.write(f"E2E Test Session Summary\n")
            f.write(f"========================\n")
            f.write(f"Session ID: {self.test_session_id}\n")
            f.write(f"Duration: {report['session_info']['duration_seconds']:.2f} seconds\n")
            f.write(f"Total Tests: {report['test_summary']['total_tests']}\n")
            f.write(f"Passed: {report['test_summary']['passed_tests']}\n")
            f.write(f"Failed: {report['test_summary']['failed_tests']}\n")
            f.write(f"Success Rate: {report['test_summary']['success_rate']:.2%}\n")
            
            if report['performance_summary']:
                f.write(f"\nPerformance Summary:\n")
                f.write(f"Performance Tests: {report['performance_summary']['total_performance_tests']}\n")
                f.write(f"Compliance Rate: {report['performance_summary']['performance_compliance_rate']:.2%}\n")
                f.write(f"Avg Response Time: {report['performance_summary']['overall_average_response_time_ms']:.2f}ms\n")
        
        logger.info(
            "E2E test artifacts saved",
            report_path=str(report_path),
            summary_path=str(summary_path)
        )
        
        return report_path


# =============================================================================
# Locust Load Testing Integration per Section 6.6.1
# =============================================================================

if LOCUST_AVAILABLE:
    class E2ETestUser(HttpUser):
        """
        Locust user class for E2E load testing scenarios.
        
        Implements realistic user behavior patterns for load testing Flask
        application endpoints during E2E testing with comprehensive performance
        measurement and baseline comparison per Section 6.6.1.
        """
        
        wait_time = between(1, 3)  # Wait 1-3 seconds between requests
        
        def on_start(self):
            """Initialize user session for load testing."""
            self.test_session_id = str(uuid.uuid4())
            self.login_user()
        
        def login_user(self):
            """Perform user authentication for realistic load testing."""
            login_data = {
                'email': 'test@example.com',
                'password': 'testpassword123'
            }
            
            with self.client.post('/auth/login', json=login_data, catch_response=True) as response:
                if response.status_code == 200:
                    response.success()
                    self.auth_token = response.json().get('access_token')
                else:
                    response.failure(f"Login failed with status {response.status_code}")
        
        @task(3)
        def get_user_profile(self):
            """Load test user profile endpoint."""
            headers = {'Authorization': f'Bearer {getattr(self, "auth_token", "")}'} if hasattr(self, 'auth_token') else {}
            
            with self.client.get('/api/users/profile', headers=headers, catch_response=True) as response:
                if response.status_code == 200:
                    response.success()
                elif response.status_code == 401:
                    response.failure("Authentication required")
                else:
                    response.failure(f"Profile request failed with status {response.status_code}")
        
        @task(2)
        def list_projects(self):
            """Load test projects listing endpoint."""
            headers = {'Authorization': f'Bearer {getattr(self, "auth_token", "")}'} if hasattr(self, 'auth_token') else {}
            
            with self.client.get('/api/projects', headers=headers, catch_response=True) as response:
                if response.status_code == 200:
                    response.success()
                else:
                    response.failure(f"Projects list failed with status {response.status_code}")
        
        @task(1)
        def create_project(self):
            """Load test project creation endpoint."""
            headers = {'Authorization': f'Bearer {getattr(self, "auth_token", "")}'} if hasattr(self, 'auth_token') else {}
            
            project_data = {
                'name': f'Load Test Project {uuid.uuid4().hex[:8]}',
                'description': 'Project created during load testing',
                'category': 'test'
            }
            
            with self.client.post('/api/projects', json=project_data, headers=headers, catch_response=True) as response:
                if response.status_code in [200, 201]:
                    response.success()
                else:
                    response.failure(f"Project creation failed with status {response.status_code}")
        
        @task(4)
        def health_check(self):
            """Load test health check endpoint."""
            with self.client.get('/health', catch_response=True) as response:
                if response.status_code == 200:
                    response.success()
                else:
                    response.failure(f"Health check failed with status {response.status_code}")


class LocustLoadTester:
    """
    Locust load testing integration for E2E performance validation.
    
    Provides programmatic control over Locust load testing execution during
    E2E test scenarios with comprehensive metrics collection and performance
    validation against Node.js baseline per Section 6.6.1 requirements.
    """
    
    def __init__(self, base_url: str, config: E2ETestConfig):
        """
        Initialize Locust load tester with configuration.
        
        Args:
            base_url: Base URL for load testing target
            config: E2E test configuration settings
        """
        self.base_url = base_url
        self.config = config
        self.environment = None
        self.runner = None
        
        logger.info(
            "Locust load tester initialized",
            base_url=base_url,
            max_users=config.max_concurrent_users,
            duration=config.load_test_duration
        )
    
    def setup_environment(self) -> Environment:
        """
        Setup Locust testing environment with configuration.
        
        Returns:
            Configured Locust Environment instance
        """
        # Setup Locust logging
        setup_logging("INFO", None)
        
        # Create Locust environment
        self.environment = Environment(
            user_classes=[E2ETestUser],
            host=self.base_url
        )
        
        # Configure event listeners for metrics collection
        self.environment.events.request.add_listener(self._on_request)
        self.environment.events.test_start.add_listener(self._on_test_start)
        self.environment.events.test_stop.add_listener(self._on_test_stop)
        
        return self.environment
    
    def run_load_test(
        self,
        users: int = None,
        spawn_rate: float = None,
        duration: int = None
    ) -> Dict[str, Any]:
        """
        Execute load test with specified parameters.
        
        Args:
            users: Number of concurrent users (defaults to config)
            spawn_rate: User spawn rate per second (defaults to config)
            duration: Test duration in seconds (defaults to config)
            
        Returns:
            Dictionary containing load test results and metrics
        """
        if not self.environment:
            self.setup_environment()
        
        users = users or self.config.max_concurrent_users
        spawn_rate = spawn_rate or self.config.user_spawn_rate
        duration = duration or self.config.load_test_duration
        
        logger.info(
            "Starting Locust load test",
            users=users,
            spawn_rate=spawn_rate,
            duration=duration
        )
        
        # Start load test
        self.environment.runner.start(users, spawn_rate)
        
        # Run for specified duration
        time.sleep(duration)
        
        # Stop load test
        self.environment.runner.stop()
        
        # Collect and return results
        results = self._collect_results()
        
        logger.info(
            "Locust load test completed",
            total_requests=results.get('total_requests', 0),
            failure_rate=results.get('failure_rate', 0),
            average_response_time=results.get('average_response_time', 0)
        )
        
        return results
    
    def _on_request(self, request_type, name, response_time, response_length, response, context, exception, **kwargs):
        """Event handler for request completion tracking."""
        pass  # Metrics collected by Locust automatically
    
    def _on_test_start(self, **kwargs):
        """Event handler for test start."""
        logger.debug("Locust load test started")
    
    def _on_test_stop(self, **kwargs):
        """Event handler for test completion."""
        logger.debug("Locust load test stopped")
    
    def _collect_results(self) -> Dict[str, Any]:
        """
        Collect comprehensive load test results and metrics.
        
        Returns:
            Dictionary containing load test analysis
        """
        if not self.environment or not self.environment.runner:
            return {}
        
        stats = self.environment.runner.stats
        
        # Calculate aggregate statistics
        total_requests = stats.total.num_requests
        total_failures = stats.total.num_failures
        failure_rate = total_failures / max(total_requests, 1)
        
        results = {
            'total_requests': total_requests,
            'total_failures': total_failures,
            'failure_rate': failure_rate,
            'average_response_time': stats.total.avg_response_time,
            'min_response_time': stats.total.min_response_time,
            'max_response_time': stats.total.max_response_time,
            'median_response_time': stats.total.median_response_time,
            'percentile_95': stats.total.get_response_time_percentile(0.95),
            'percentile_99': stats.total.get_response_time_percentile(0.99),
            'requests_per_second': stats.total.total_rps,
            'avg_content_length': stats.total.avg_content_length,
        }
        
        # Add endpoint-specific statistics
        endpoint_stats = {}
        for name, entry in stats.entries.items():
            if name != 'Aggregated':
                endpoint_stats[name] = {
                    'requests': entry.num_requests,
                    'failures': entry.num_failures,
                    'avg_response_time': entry.avg_response_time,
                    'min_response_time': entry.min_response_time,
                    'max_response_time': entry.max_response_time,
                    'requests_per_second': entry.total_rps,
                }
        
        results['endpoint_statistics'] = endpoint_stats
        
        return results


# =============================================================================
# Apache Bench Integration per Section 6.6.1
# =============================================================================

class ApacheBenchTester:
    """
    Apache Bench (ab) integration for HTTP performance measurement.
    
    Provides HTTP server performance measurement and automated comparison
    with Node.js implementation using apache-bench for individual endpoint
    performance validation per Section 6.6.1 requirements.
    """
    
    def __init__(self, base_url: str, config: E2ETestConfig):
        """
        Initialize Apache Bench tester with configuration.
        
        Args:
            base_url: Base URL for performance testing target
            config: E2E test configuration settings
        """
        self.base_url = base_url.rstrip('/')
        self.config = config
        
        # Verify apache bench availability
        try:
            subprocess.run(['ab', '-V'], capture_output=True, check=True)
            self.available = True
            logger.info("Apache Bench available for performance testing")
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.available = False
            logger.warning("Apache Bench not available - performance testing will be limited")
    
    def run_benchmark(
        self,
        endpoint: str,
        requests: int = None,
        concurrency: int = None,
        headers: Optional[Dict[str, str]] = None,
        post_data: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Run Apache Bench performance test against specific endpoint.
        
        Args:
            endpoint: Endpoint path to test (e.g., '/api/users')
            requests: Total number of requests (defaults to config)
            concurrency: Concurrent request level (defaults to config)
            headers: Optional HTTP headers for requests
            post_data: Optional POST data for request body
            
        Returns:
            Dictionary containing benchmark results and analysis
        """
        if not self.available:
            logger.warning("Apache Bench not available - skipping benchmark")
            return {'error': 'Apache Bench not available'}
        
        requests = requests or self.config.apache_bench_requests
        concurrency = concurrency or self.config.apache_bench_concurrency
        
        # Construct full URL
        full_url = f"{self.base_url}{endpoint}"
        
        # Build apache bench command
        cmd = [
            'ab',
            '-n', str(requests),
            '-c', str(concurrency),
            '-g', '/dev/null',  # Suppress gnuplot output
            '-v', '2',  # Verbosity level
        ]
        
        # Add headers if provided
        if headers:
            for key, value in headers.items():
                cmd.extend(['-H', f'{key}: {value}'])
        
        # Add POST data if provided
        if post_data:
            cmd.extend(['-p', '-'])  # Read POST data from stdin
            cmd.extend(['-T', 'application/json'])  # Content type for JSON data
        
        cmd.append(full_url)
        
        logger.info(
            "Running Apache Bench test",
            endpoint=endpoint,
            requests=requests,
            concurrency=concurrency
        )
        
        try:
            # Execute apache bench
            input_data = post_data.encode() if post_data else None
            result = subprocess.run(
                cmd,
                input=input_data,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode != 0:
                logger.error(
                    "Apache Bench failed",
                    return_code=result.returncode,
                    stderr=result.stderr
                )
                return {'error': f'Apache Bench failed: {result.stderr}'}
            
            # Parse results
            benchmark_results = self._parse_ab_output(result.stdout)
            benchmark_results['endpoint'] = endpoint
            benchmark_results['configuration'] = {
                'requests': requests,
                'concurrency': concurrency,
                'full_url': full_url
            }
            
            logger.info(
                "Apache Bench test completed",
                endpoint=endpoint,
                requests_per_second=benchmark_results.get('requests_per_second', 0),
                mean_response_time=benchmark_results.get('mean_response_time_ms', 0)
            )
            
            return benchmark_results
            
        except subprocess.TimeoutExpired:
            logger.error("Apache Bench test timed out")
            return {'error': 'Apache Bench test timed out'}
        except Exception as e:
            logger.error(f"Apache Bench test failed: {e}")
            return {'error': f'Apache Bench test failed: {str(e)}'}
    
    def _parse_ab_output(self, output: str) -> Dict[str, Any]:
        """
        Parse Apache Bench output to extract performance metrics.
        
        Args:
            output: Raw Apache Bench output text
            
        Returns:
            Dictionary containing parsed performance metrics
        """
        results = {}
        
        for line in output.split('\n'):
            line = line.strip()
            
            if 'Requests per second:' in line:
                # Extract RPS: "Requests per second:    123.45 [#/sec] (mean)"
                parts = line.split()
                if len(parts) >= 4:
                    results['requests_per_second'] = float(parts[3])
            
            elif 'Time per request:' in line and 'mean' in line:
                # Extract mean response time: "Time per request:       8.123 [ms] (mean)"
                parts = line.split()
                if len(parts) >= 4:
                    results['mean_response_time_ms'] = float(parts[3])
            
            elif 'Time per request:' in line and 'concurrent' in line:
                # Extract concurrent response time: "Time per request:       0.812 [ms] (mean, across all concurrent requests)"
                parts = line.split()
                if len(parts) >= 4:
                    results['concurrent_response_time_ms'] = float(parts[3])
            
            elif 'Transfer rate:' in line:
                # Extract transfer rate: "Transfer rate:          123.45 [Kbytes/sec] received"
                parts = line.split()
                if len(parts) >= 3:
                    results['transfer_rate_kbps'] = float(parts[2])
            
            elif 'Complete requests:' in line:
                # Extract completed requests: "Complete requests:      1000"
                parts = line.split()
                if len(parts) >= 3:
                    results['completed_requests'] = int(parts[2])
            
            elif 'Failed requests:' in line:
                # Extract failed requests: "Failed requests:        0"
                parts = line.split()
                if len(parts) >= 3:
                    results['failed_requests'] = int(parts[2])
            
            elif 'Total transferred:' in line:
                # Extract total bytes: "Total transferred:      1234567 bytes"
                parts = line.split()
                if len(parts) >= 3:
                    results['total_transferred_bytes'] = int(parts[2])
            
            elif '50%' in line:
                # Parse percentile data
                percentiles = self._parse_percentile_line(line)
                results.update(percentiles)
        
        # Calculate additional metrics
        if 'completed_requests' in results and 'failed_requests' in results:
            total_requests = results['completed_requests'] + results['failed_requests']
            results['success_rate'] = results['completed_requests'] / max(total_requests, 1)
        
        return results
    
    def _parse_percentile_line(self, line: str) -> Dict[str, float]:
        """
        Parse percentile information from Apache Bench output.
        
        Args:
            line: Line containing percentile data
            
        Returns:
            Dictionary containing percentile response times
        """
        percentiles = {}
        
        # Look for patterns like "50%     12", "95%     45", etc.
        parts = line.split()
        for i, part in enumerate(parts):
            if '%' in part and i + 1 < len(parts):
                try:
                    percentile = part.replace('%', '')
                    value = float(parts[i + 1])
                    percentiles[f'p{percentile}_response_time_ms'] = value
                except (ValueError, IndexError):
                    continue
        
        return percentiles
    
    def compare_with_baseline(
        self,
        results: Dict[str, Any],
        baseline_metrics: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Compare Apache Bench results with Node.js baseline metrics.
        
        Args:
            results: Apache Bench test results
            baseline_metrics: Node.js baseline performance metrics
            
        Returns:
            Dictionary containing comparison analysis
        """
        if 'error' in results:
            return {'error': 'Cannot compare results with errors'}
        
        endpoint = results.get('endpoint', 'unknown')
        baseline_key = 'api_endpoint_avg'  # Default baseline key
        
        # Try to find specific baseline for endpoint
        if endpoint in baseline_metrics.get('response_times', {}):
            baseline_key = endpoint.replace('/', '_').replace('-', '_')
        
        baseline_response_time = baseline_metrics.get('response_times', {}).get(baseline_key, 200)
        baseline_throughput = baseline_metrics.get('throughput', {}).get('requests_per_second', 100)
        
        measured_response_time = results.get('mean_response_time_ms', 0)
        measured_throughput = results.get('requests_per_second', 0)
        
        # Calculate variance
        response_time_variance = (measured_response_time - baseline_response_time) / baseline_response_time if baseline_response_time > 0 else 0
        throughput_variance = (measured_throughput - baseline_throughput) / baseline_throughput if baseline_throughput > 0 else 0
        
        # Determine compliance
        compliance = (
            abs(response_time_variance) <= PERFORMANCE_BASELINE_THRESHOLD and
            abs(throughput_variance) <= PERFORMANCE_BASELINE_THRESHOLD and
            results.get('success_rate', 0) >= 0.99
        )
        
        comparison = {
            'endpoint': endpoint,
            'baseline_response_time_ms': baseline_response_time,
            'measured_response_time_ms': measured_response_time,
            'response_time_variance': response_time_variance,
            'response_time_variance_percent': response_time_variance * 100,
            'baseline_throughput_rps': baseline_throughput,
            'measured_throughput_rps': measured_throughput,
            'throughput_variance': throughput_variance,
            'throughput_variance_percent': throughput_variance * 100,
            'success_rate': results.get('success_rate', 0),
            'compliance_status': compliance,
            'variance_threshold': PERFORMANCE_BASELINE_THRESHOLD,
            'meets_requirements': compliance
        }
        
        logger.info(
            "Performance comparison completed",
            endpoint=endpoint,
            response_time_variance=f"{response_time_variance:.2%}",
            throughput_variance=f"{throughput_variance:.2%}",
            compliance=compliance
        )
        
        return comparison


# =============================================================================
# E2E-Specific Flask Application Fixtures
# =============================================================================

@pytest.fixture(scope="session")
def e2e_test_config() -> E2ETestConfig:
    """
    Session-scoped fixture providing E2E test configuration.
    
    Returns:
        E2ETestConfig instance with production-equivalent settings
    """
    config = E2ETestConfig(
        app_config_name='testing',
        enable_production_parity=True,
        enable_performance_monitoring=True,
        enable_load_testing=LOCUST_AVAILABLE,
        enable_apache_bench=True,
        nodejs_baseline_comparison=True,
        external_services_enabled=True,
        comprehensive_test_data=True,
        enable_detailed_reporting=True
    )
    
    logger.info(
        "E2E test configuration created",
        performance_monitoring=config.enable_performance_monitoring,
        load_testing=config.enable_load_testing,
        apache_bench=config.enable_apache_bench
    )
    
    return config


@pytest.fixture(scope="function")
def e2e_app(
    e2e_test_config: E2ETestConfig,
    mongodb_container: MongoDbTestContainer,
    redis_container: RedisTestContainer
) -> Flask:
    """
    Function-scoped fixture providing Flask application for E2E testing.
    
    Creates Flask application with production-equivalent configuration,
    Testcontainers integration, and comprehensive E2E testing capabilities
    per Section 6.6.5 production parity requirements.
    
    Args:
        e2e_test_config: E2E test configuration settings
        mongodb_container: MongoDB test container instance
        redis_container: Redis test container instance
        
    Returns:
        Configured Flask application for E2E testing
    """
    # Configure application for E2E testing
    app_config = e2e_test_config.get_flask_config()
    
    # Add Testcontainers database URIs
    app_config.update({
        'MONGODB_URI': mongodb_container.get_connection_url(),
        'REDIS_URL': redis_container.get_connection_url(),
        'SQLALCHEMY_DATABASE_URI': mongodb_container.get_connection_url(),  # If needed for compatibility
    })
    
    # Create Flask application
    app = create_app(e2e_test_config.app_config_name)
    
    # Apply E2E-specific configuration
    app.config.update(app_config)
    
    # Configure additional E2E testing settings
    if e2e_test_config.enable_production_parity:
        # Enable production-like behavior
        app.config.update({
            'ENV': 'production',
            'FLASK_ENV': 'production',
            'DEBUG': False,
            'TESTING': True,  # Keep testing flag for pytest
            'TRAP_HTTP_EXCEPTIONS': True,
            'TRAP_BAD_REQUEST_ERRORS': True,
        })
    
    # Add performance monitoring hooks if enabled
    if e2e_test_config.enable_performance_monitoring:
        @app.before_request
        def before_request():
            """Record request start time for performance monitoring."""
            g.start_time = time.time()
        
        @app.after_request
        def after_request(response):
            """Record request completion and performance metrics."""
            if hasattr(g, 'start_time'):
                duration = time.time() - g.start_time
                response.headers['X-Response-Time'] = f"{duration:.3f}"
                
                # Log performance data for analysis
                logger.debug(
                    "Request completed",
                    endpoint=request.endpoint,
                    method=request.method,
                    status_code=response.status_code,
                    duration_ms=duration * 1000
                )
            
            return response
    
    logger.info(
        "E2E Flask application created",
        config_name=e2e_test_config.app_config_name,
        production_parity=e2e_test_config.enable_production_parity,
        performance_monitoring=e2e_test_config.enable_performance_monitoring
    )
    
    return app


@pytest.fixture(scope="function")
def e2e_client(e2e_app: Flask) -> FlaskClient:
    """
    Function-scoped fixture providing Flask test client for E2E testing.
    
    Args:
        e2e_app: Flask application configured for E2E testing
        
    Returns:
        FlaskClient configured for comprehensive E2E testing scenarios
    """
    return e2e_app.test_client()


@pytest.fixture(scope="function")
def e2e_app_context(e2e_app: Flask):
    """
    Function-scoped fixture providing Flask application context for E2E tests.
    
    Args:
        e2e_app: Flask application configured for E2E testing
        
    Yields:
        Flask application context for E2E testing
    """
    with e2e_app.app_context():
        yield e2e_app


@pytest.fixture(scope="function")
def e2e_request_context(e2e_app: Flask):
    """
    Function-scoped fixture providing Flask request context for E2E tests.
    
    Args:
        e2e_app: Flask application configured for E2E testing
        
    Yields:
        Flask request context for E2E testing
    """
    with e2e_app.test_request_context():
        yield


# =============================================================================
# Performance Testing and Monitoring Fixtures
# =============================================================================

@pytest.fixture(scope="function")
def performance_monitor(e2e_test_config: E2ETestConfig) -> PerformanceMetrics:
    """
    Function-scoped fixture providing performance monitoring for E2E tests.
    
    Args:
        e2e_test_config: E2E test configuration settings
        
    Returns:
        PerformanceMetrics instance for test performance tracking
    """
    monitor = PerformanceMetrics(
        test_name=f"e2e_test_{uuid.uuid4().hex[:8]}",
        start_time=time.time()
    )
    
    logger.debug("Performance monitor created for E2E test")
    
    yield monitor
    
    # Finalize performance monitoring
    monitor.end_time = time.time()
    
    if e2e_test_config.nodejs_baseline_comparison:
        compliance = monitor.validate_against_baseline(NODEJS_BASELINE_METRICS)
        logger.info(
            "E2E performance validation completed",
            test_name=monitor.test_name,
            compliance_status=compliance,
            request_count=monitor.request_count,
            error_count=monitor.error_count
        )


@pytest.fixture(scope="function")
def locust_load_tester(
    e2e_app: Flask,
    e2e_test_config: E2ETestConfig
) -> Optional[LocustLoadTester]:
    """
    Function-scoped fixture providing Locust load testing integration.
    
    Args:
        e2e_app: Flask application for load testing
        e2e_test_config: E2E test configuration settings
        
    Returns:
        LocustLoadTester instance if available, None otherwise
    """
    if not LOCUST_AVAILABLE or not e2e_test_config.enable_load_testing:
        logger.warning("Locust load testing not available or disabled")
        yield None
        return
    
    # Get application base URL
    base_url = f"http://{e2e_app.config.get('SERVER_NAME', 'localhost:5000')}"
    
    load_tester = LocustLoadTester(base_url, e2e_test_config)
    load_tester.setup_environment()
    
    logger.debug(
        "Locust load tester created",
        base_url=base_url,
        max_users=e2e_test_config.max_concurrent_users
    )
    
    yield load_tester
    
    # Cleanup Locust environment
    if load_tester.environment:
        try:
            if load_tester.environment.runner:
                load_tester.environment.runner.stop()
            logger.debug("Locust load tester cleaned up")
        except Exception as e:
            logger.warning(f"Error cleaning up Locust load tester: {e}")


@pytest.fixture(scope="function")
def apache_bench_tester(
    e2e_app: Flask,
    e2e_test_config: E2ETestConfig
) -> ApacheBenchTester:
    """
    Function-scoped fixture providing Apache Bench performance testing.
    
    Args:
        e2e_app: Flask application for performance testing
        e2e_test_config: E2E test configuration settings
        
    Returns:
        ApacheBenchTester instance for HTTP performance measurement
    """
    # Get application base URL
    base_url = f"http://{e2e_app.config.get('SERVER_NAME', 'localhost:5000')}"
    
    ab_tester = ApacheBenchTester(base_url, e2e_test_config)
    
    logger.debug(
        "Apache Bench tester created",
        base_url=base_url,
        available=ab_tester.available
    )
    
    return ab_tester


# =============================================================================
# E2E Test Environment and Data Management Fixtures
# =============================================================================

@pytest.fixture(scope="function")
def e2e_test_reporter(e2e_test_config: E2ETestConfig) -> E2ETestReporter:
    """
    Function-scoped fixture providing E2E test reporting capabilities.
    
    Args:
        e2e_test_config: E2E test configuration settings
        
    Returns:
        E2ETestReporter instance for comprehensive test reporting
    """
    output_dir = None
    if e2e_test_config.generate_test_artifacts:
        output_dir = Path(tempfile.gettempdir()) / 'e2e_test_reports'
    
    reporter = E2ETestReporter(output_dir)
    
    logger.debug(
        "E2E test reporter created",
        session_id=reporter.test_session_id,
        output_dir=str(reporter.output_dir) if reporter.output_dir else None
    )
    
    yield reporter
    
    # Generate final report
    if e2e_test_config.enable_detailed_reporting:
        try:
            report_path = reporter.save_report_artifacts()
            logger.info(f"E2E test report saved: {report_path}")
        except Exception as e:
            logger.error(f"Failed to save E2E test report: {e}")


@pytest.fixture(scope="function")
def e2e_external_services(e2e_test_config: E2ETestConfig):
    """
    Function-scoped fixture providing external service mocking for E2E tests.
    
    Args:
        e2e_test_config: E2E test configuration settings
        
    Yields:
        Dictionary of mocked external services
    """
    mocks = {}
    patches = []
    
    try:
        # Mock Auth0 service
        if e2e_test_config.mock_auth0_service:
            auth0_patcher = patch('src.auth.auth0_client.Auth0Client')
            auth0_mock = auth0_patcher.start()
            patches.append(auth0_patcher)
            
            # Configure Auth0 mock responses
            auth0_instance = Mock()
            auth0_instance.validate_token.return_value = {
                'sub': 'auth0|e2e_test_user',
                'email': 'e2e@test.com',
                'email_verified': True,
                'exp': int(time.time()) + 3600
            }
            auth0_mock.return_value = auth0_instance
            mocks['auth0'] = auth0_instance
        
        # Mock AWS services
        if e2e_test_config.mock_aws_services:
            boto3_patcher = patch('boto3.client')
            boto3_mock = boto3_patcher.start()
            patches.append(boto3_patcher)
            
            # Configure AWS S3 mock
            s3_mock = Mock()
            s3_mock.upload_file.return_value = True
            s3_mock.download_file.return_value = True
            s3_mock.list_objects_v2.return_value = {'Contents': []}
            boto3_mock.return_value = s3_mock
            mocks['aws_s3'] = s3_mock
        
        # Mock external HTTP requests
        if e2e_test_config.mock_third_party_apis:
            requests_patcher = patch('requests.request')
            requests_mock = requests_patcher.start()
            patches.append(requests_patcher)
            
            # Configure successful HTTP responses
            response_mock = Mock()
            response_mock.status_code = 200
            response_mock.json.return_value = {'status': 'success'}
            response_mock.text = '{"status": "success"}'
            requests_mock.return_value = response_mock
            mocks['http_requests'] = requests_mock
        
        logger.debug(
            "E2E external services mocked",
            auth0=e2e_test_config.mock_auth0_service,
            aws=e2e_test_config.mock_aws_services,
            third_party=e2e_test_config.mock_third_party_apis
        )
        
        yield mocks
        
    finally:
        # Clean up all patches
        for patcher in patches:
            try:
                patcher.stop()
            except Exception as e:
                logger.warning(f"Error stopping mock patcher: {e}")


@pytest.fixture(scope="function")
def e2e_comprehensive_environment(
    e2e_app: Flask,
    e2e_client: FlaskClient,
    e2e_app_context,
    seeded_database: Dict[str, List[Dict[str, Any]]],
    performance_monitor: PerformanceMetrics,
    e2e_test_reporter: E2ETestReporter,
    locust_load_tester: Optional[LocustLoadTester],
    apache_bench_tester: ApacheBenchTester,
    e2e_external_services: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Function-scoped fixture providing comprehensive E2E testing environment.
    
    Creates complete E2E testing environment with Flask application, performance
    monitoring, load testing capabilities, external service mocking, and comprehensive
    reporting for end-to-end testing scenarios per Section 6.6.5.
    
    Returns:
        Dictionary containing complete E2E testing environment
    """
    environment = {
        'app': e2e_app,
        'client': e2e_client,
        'test_data': seeded_database,
        'performance': {
            'monitor': performance_monitor,
            'locust_tester': locust_load_tester,
            'apache_bench_tester': apache_bench_tester,
        },
        'external_services': e2e_external_services,
        'reporter': e2e_test_reporter,
        'baseline_metrics': NODEJS_BASELINE_METRICS,
        'environment_info': {
            'flask_version': e2e_app.config.get('FLASK_VERSION', 'unknown'),
            'server_name': e2e_app.config.get('SERVER_NAME', 'localhost:5000'),
            'testing_mode': e2e_app.config.get('TESTING', True),
            'production_parity': e2e_app.config.get('ENV', 'testing') == 'production',
            'performance_monitoring_enabled': bool(performance_monitor),
            'load_testing_available': locust_load_tester is not None,
            'apache_bench_available': apache_bench_tester.available,
        }
    }
    
    logger.info(
        "Comprehensive E2E environment created",
        flask_version=environment['environment_info']['flask_version'],
        performance_monitoring=environment['environment_info']['performance_monitoring_enabled'],
        load_testing=environment['environment_info']['load_testing_available'],
        apache_bench=environment['environment_info']['apache_bench_available'],
        total_test_users=len(seeded_database.get('users', [])),
        total_test_projects=len(seeded_database.get('projects', []))
    )
    
    return environment


# =============================================================================
# HTTP Client and Request Testing Fixtures
# =============================================================================

@pytest.fixture(scope="function")
def e2e_http_session(e2e_test_config: E2ETestConfig) -> requests.Session:
    """
    Function-scoped fixture providing configured HTTP session for E2E API testing.
    
    Args:
        e2e_test_config: E2E test configuration settings
        
    Returns:
        Configured requests.Session for external API testing
    """
    session = requests.Session()
    
    # Configure retry strategy for reliability
    if e2e_test_config.retry_failed_requests:
        retry_strategy = Retry(
            total=e2e_test_config.max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
    
    # Set default timeout
    session.timeout = e2e_test_config.request_timeout_seconds
    
    # Configure headers
    session.headers.update({
        'User-Agent': 'E2E-Test-Client/1.0',
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    })
    
    logger.debug(
        "E2E HTTP session created",
        timeout=e2e_test_config.request_timeout_seconds,
        retry_enabled=e2e_test_config.retry_failed_requests,
        max_retries=e2e_test_config.max_retries
    )
    
    yield session
    
    # Close session
    session.close()


# =============================================================================
# Test Execution Hooks and Event Handlers
# =============================================================================

@pytest.fixture(scope="function", autouse=True)
def e2e_test_lifecycle(
    request,
    e2e_test_reporter: E2ETestReporter,
    performance_monitor: PerformanceMetrics
):
    """
    Auto-use fixture managing E2E test lifecycle and reporting.
    
    Args:
        request: pytest request object
        e2e_test_reporter: E2E test reporter instance
        performance_monitor: Performance monitoring instance
    """
    test_name = request.node.name
    test_start_time = time.time()
    
    logger.info(f"Starting E2E test: {test_name}")
    
    # Pre-test setup
    performance_monitor.test_name = test_name
    
    yield  # Test execution happens here
    
    # Post-test reporting
    test_end_time = time.time()
    test_duration = test_end_time - test_start_time
    
    # Determine test status
    test_status = 'passed'
    if hasattr(request.node, 'rep_call'):
        if request.node.rep_call.failed:
            test_status = 'failed'
        elif request.node.rep_call.skipped:
            test_status = 'skipped'
    
    # Report test completion
    e2e_test_reporter.add_test_result(
        test_name=test_name,
        status=test_status,
        duration=test_duration,
        metrics=performance_monitor,
        additional_data={
            'node_id': request.node.nodeid,
            'test_function': request.function.__name__,
            'test_module': request.module.__name__ if request.module else 'unknown'
        }
    )
    
    logger.info(
        f"Completed E2E test: {test_name}",
        status=test_status,
        duration=f"{test_duration:.3f}s",
        requests=performance_monitor.request_count,
        errors=performance_monitor.error_count
    )


# Configure pytest for E2E test execution
def pytest_configure(config):
    """Pytest configuration hook for E2E test setup."""
    # Add E2E-specific markers
    config.addinivalue_line(
        "markers", "e2e: mark test as end-to-end integration test"
    )
    config.addinivalue_line(
        "markers", "performance: mark test for performance validation"
    )
    config.addinivalue_line(
        "markers", "load_test: mark test for load testing scenarios"
    )


def pytest_collection_modifyitems(config, items):
    """Modify collected test items for E2E test execution."""
    for item in items:
        # Add e2e marker to all tests in this module
        if "/e2e/" in str(item.fspath):
            item.add_marker(pytest.mark.e2e)
        
        # Add performance marker for performance tests
        if "performance" in item.name.lower():
            item.add_marker(pytest.mark.performance)
        
        # Add load_test marker for load testing
        if "load" in item.name.lower():
            item.add_marker(pytest.mark.load_test)


# Export key fixtures for E2E test modules
__all__ = [
    # Configuration
    'E2ETestConfig',
    'e2e_test_config',
    
    # Flask application fixtures
    'e2e_app',
    'e2e_client',
    'e2e_app_context',
    'e2e_request_context',
    
    # Performance testing fixtures
    'performance_monitor',
    'locust_load_tester',
    'apache_bench_tester',
    
    # Comprehensive environment
    'e2e_comprehensive_environment',
    'e2e_external_services',
    'e2e_test_reporter',
    'e2e_http_session',
    
    # Performance testing classes
    'PerformanceMetrics',
    'LocustLoadTester',
    'ApacheBenchTester',
    'E2ETestReporter',
    
    # Constants
    'NODEJS_BASELINE_METRICS',
    'PERFORMANCE_BASELINE_THRESHOLD'
]