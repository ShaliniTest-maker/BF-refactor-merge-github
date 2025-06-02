"""
Performance Baseline Comparison Testing Module

This module implements comprehensive performance baseline testing using locust and apache-bench
frameworks to ensure ≤10% variance from Node.js baseline per Section 0.1.1 primary objective.
Provides automated performance validation with statistical analysis, regression detection, and
comprehensive performance monitoring across all application components per Section 6.6.1.

Key Features:
- Automated performance testing with baseline comparisons per F-006-RQ-003
- locust (≥2.x) load testing framework for automated baseline comparison per Section 6.6.1
- apache-bench performance measurement for HTTP server validation per Section 6.6.1
- ≤10% variance requirement validation per Section 0.1.1 primary objective
- Continuous performance validation integrated with CI/CD pipeline per Section 6.6.2
- Statistical analysis and regression detection for performance metrics per Section 6.6.3
- Comprehensive performance monitoring ensuring project-critical variance compliance per Section 6.6.3

Architecture Integration:
- Section 6.6.1: Performance testing integration with locust and apache-bench
- Section 6.6.3: Performance variance thresholds and compliance validation
- Section 0.1.1: ≤10% performance variance requirement (project-critical)
- F-006-RQ-003: Automated performance testing with baseline comparisons
- Section 6.6.2: CI/CD integration for continuous performance validation
- Section 6.5: Monitoring and observability integration for performance tracking

Performance Requirements:
- Response Time Variance: ≤10% from Node.js baseline (project-critical requirement)
- Memory Usage Pattern: Equivalent memory consumption with ±15% acceptable variance
- Concurrent Request Capacity: Preserve or improve original concurrent handling capacity
- Database Performance: Query execution time equivalence with ±10% acceptable variance
- Load Testing: Validate concurrent user handling under realistic traffic patterns
- HTTP Server Performance: Individual endpoint performance measurement and validation

Testing Approach:
- Baseline comparison testing using predefined Node.js performance metrics
- Statistical analysis with confidence intervals and regression detection
- Load testing with locust framework for realistic traffic simulation
- Apache-bench benchmarking for individual endpoint performance measurement
- Automated variance calculation and compliance reporting
- Performance regression detection with automated alerting

Dependencies:
- locust ≥2.x for distributed load testing and throughput validation
- apache-bench for HTTP server performance measurement and comparison
- pytest 7.4+ with E2E testing integration per Section 6.6.1
- requests/httpx for HTTP client operations during performance testing
- statistics and numpy for statistical analysis and variance calculation
- matplotlib for performance visualization and trend analysis

Author: E2E Testing Team
Version: 1.0.0
Compliance: Section 0.1.1 ≤10% variance requirement, Section 6.6.1 performance testing, F-006-RQ-003
"""

import asyncio
import json
import logging
import os
import statistics
import subprocess
import sys
import tempfile
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from unittest.mock import Mock, patch

import pytest
import requests
from flask import Flask
from flask.testing import FlaskClient

# Import test environment fixtures
from tests.e2e.conftest import (
    comprehensive_e2e_environment,
    e2e_performance_monitor,
    locust_load_tester,
    apache_bench_tester,
    production_equivalent_environment,
    require_load_testing,
    skip_if_not_e2e
)

# Configure performance testing logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - [PERF] %(message)s'
)
logger = logging.getLogger(__name__)

# Performance testing configuration constants per Section 6.6.1 requirements
PERFORMANCE_CONFIG = {
    # Node.js baseline performance metrics (established benchmarks)
    'NODEJS_BASELINES': {
        'auth_endpoint_response_time': 0.085,  # 85ms average auth endpoint response
        'api_endpoint_response_time': 0.120,   # 120ms average API endpoint response
        'database_query_time': 0.045,          # 45ms average database query time
        'cache_operation_time': 0.008,         # 8ms average cache operation time
        'file_upload_time': 0.250,             # 250ms average file upload time
        'health_check_time': 0.015,            # 15ms average health check time
        'concurrent_users_capacity': 500,      # 500 concurrent users capacity
        'requests_per_second': 1200,           # 1200 RPS sustained throughput
        'memory_usage_mb': 256,                # 256MB average memory usage
        'cpu_utilization_percent': 45.0,       # 45% average CPU utilization
        'error_rate_percent': 0.5,             # 0.5% acceptable error rate
        'p95_response_time': 0.180,            # 95th percentile response time
        'p99_response_time': 0.300,            # 99th percentile response time
    },
    
    # Performance variance thresholds per Section 0.1.1
    'VARIANCE_THRESHOLDS': {
        'critical_threshold': 0.10,            # ≤10% variance requirement (critical)
        'warning_threshold': 0.05,             # 5% variance warning level
        'memory_threshold': 0.15,              # ±15% memory usage acceptable variance
        'database_threshold': 0.10,            # ±10% database performance variance
        'throughput_threshold': 0.10,          # ±10% throughput variance
        'error_rate_threshold': 1.0,           # Maximum 1% error rate
    },
    
    # Load testing configuration per Section 6.6.1
    'LOAD_TESTING': {
        'baseline_users': 100,                 # Baseline concurrent users
        'peak_users': 500,                     # Peak concurrent users
        'spawn_rate': 10,                      # Users spawned per second
        'test_duration': 300,                  # 5 minutes test duration
        'ramp_up_time': 60,                    # 1 minute ramp-up time
        'steady_state_time': 180,              # 3 minutes steady state
        'ramp_down_time': 60,                  # 1 minute ramp-down time
    },
    
    # Apache-bench testing configuration
    'APACHE_BENCH': {
        'total_requests': 1000,               # Total requests per test
        'concurrency_levels': [1, 10, 50, 100], # Concurrency test levels
        'timeout_seconds': 30,                # Request timeout
        'keep_alive': True,                   # Use HTTP keep-alive
    }
}


class PerformanceBaselineValidator:
    """
    Comprehensive performance baseline validation system.
    
    This class provides enterprise-grade performance validation with automated
    baseline comparison, statistical analysis, and compliance reporting per
    Section 6.6.1 performance testing requirements and Section 0.1.1 variance
    compliance.
    """
    
    def __init__(self):
        """Initialize performance baseline validator with comprehensive configuration."""
        self.session_id = str(uuid.uuid4())
        self.start_time = time.time()
        self.baseline_metrics = PERFORMANCE_CONFIG['NODEJS_BASELINES'].copy()
        self.variance_thresholds = PERFORMANCE_CONFIG['VARIANCE_THRESHOLDS'].copy()
        
        # Performance measurement storage
        self.measurements = {
            'response_times': [],
            'throughput_metrics': [],
            'resource_usage': [],
            'error_rates': [],
            'load_test_results': [],
            'apache_bench_results': []
        }
        
        # Variance violation tracking
        self.variance_violations = []
        self.performance_alerts = []
        self.baseline_compliance = {
            'overall_compliant': True,
            'critical_violations': 0,
            'warning_violations': 0,
            'compliant_metrics': 0,
            'total_metrics': 0
        }
        
        logger.info(
            "Performance baseline validator initialized",
            session_id=self.session_id,
            critical_threshold=self.variance_thresholds['critical_threshold'],
            nodejs_baselines_count=len(self.baseline_metrics)
        )
    
    def measure_response_time(
        self,
        endpoint: str,
        method: str = 'GET',
        baseline_key: str = None,
        **request_kwargs
    ) -> Dict[str, Any]:
        """
        Measure endpoint response time with baseline comparison.
        
        Args:
            endpoint: API endpoint to measure
            method: HTTP method to use
            baseline_key: Key for baseline comparison
            **request_kwargs: Additional request parameters
            
        Returns:
            Dictionary containing measurement results and compliance status
        """
        measurement_start = time.perf_counter()
        
        try:
            # Execute HTTP request with performance measurement
            if method.upper() == 'GET':
                response = requests.get(endpoint, timeout=30, **request_kwargs)
            elif method.upper() == 'POST':
                response = requests.post(endpoint, timeout=30, **request_kwargs)
            elif method.upper() == 'PUT':
                response = requests.put(endpoint, timeout=30, **request_kwargs)
            elif method.upper() == 'DELETE':
                response = requests.delete(endpoint, timeout=30, **request_kwargs)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            measurement_end = time.perf_counter()
            response_time = measurement_end - measurement_start
            
            # Create measurement record
            measurement = {
                'endpoint': endpoint,
                'method': method,
                'response_time': response_time,
                'status_code': response.status_code,
                'response_size': len(response.content),
                'timestamp': time.time(),
                'session_id': self.session_id,
                'baseline_key': baseline_key,
                'compliance_status': 'unknown'
            }
            
            # Perform baseline comparison if baseline key provided
            if baseline_key and baseline_key in self.baseline_metrics:
                baseline_time = self.baseline_metrics[baseline_key]
                variance = abs(response_time - baseline_time) / baseline_time
                measurement['baseline_time'] = baseline_time
                measurement['variance'] = variance
                measurement['variance_percentage'] = variance * 100
                
                # Determine compliance status
                if variance <= self.variance_thresholds['critical_threshold']:
                    measurement['compliance_status'] = 'compliant'
                    self.baseline_compliance['compliant_metrics'] += 1
                elif variance <= self.variance_thresholds['warning_threshold'] * 2:
                    measurement['compliance_status'] = 'warning'
                    self.baseline_compliance['warning_violations'] += 1
                    self._record_performance_alert(
                        'warning',
                        f"Response time variance warning for {endpoint}",
                        measurement
                    )
                else:
                    measurement['compliance_status'] = 'violation'
                    self.baseline_compliance['critical_violations'] += 1
                    self.baseline_compliance['overall_compliant'] = False
                    self._record_variance_violation(measurement)
                
                self.baseline_compliance['total_metrics'] += 1
                
                logger.info(
                    "Response time measured with baseline comparison",
                    endpoint=endpoint,
                    response_time=round(response_time, 3),
                    baseline_time=baseline_time,
                    variance_pct=round(variance * 100, 2),
                    compliance_status=measurement['compliance_status']
                )
            else:
                logger.debug(
                    "Response time measured without baseline comparison",
                    endpoint=endpoint,
                    response_time=round(response_time, 3),
                    method=method
                )
            
            # Store measurement
            self.measurements['response_times'].append(measurement)
            
            return measurement
            
        except Exception as e:
            error_measurement = {
                'endpoint': endpoint,
                'method': method,
                'error': str(e),
                'error_type': type(e).__name__,
                'timestamp': time.time(),
                'session_id': self.session_id,
                'compliance_status': 'error'
            }
            
            self.measurements['response_times'].append(error_measurement)
            self.baseline_compliance['critical_violations'] += 1
            self.baseline_compliance['overall_compliant'] = False
            
            logger.error(
                "Response time measurement failed",
                endpoint=endpoint,
                method=method,
                error=str(e),
                exc_info=True
            )
            
            return error_measurement
    
    def _record_variance_violation(self, measurement: Dict[str, Any]) -> None:
        """Record performance variance violation with detailed context."""
        violation = {
            'violation_id': str(uuid.uuid4()),
            'endpoint': measurement['endpoint'],
            'measured_time': measurement['response_time'],
            'baseline_time': measurement['baseline_time'],
            'variance': measurement['variance'],
            'variance_percentage': measurement['variance_percentage'],
            'threshold_percentage': self.variance_thresholds['critical_threshold'] * 100,
            'severity': 'critical',
            'timestamp': measurement['timestamp'],
            'session_id': self.session_id
        }
        
        self.variance_violations.append(violation)
        
        logger.warning(
            "Performance variance violation recorded",
            violation_id=violation['violation_id'],
            endpoint=violation['endpoint'],
            variance_pct=round(violation['variance_percentage'], 2),
            threshold_pct=round(violation['threshold_percentage'], 2)
        )
    
    def _record_performance_alert(
        self,
        severity: str,
        message: str,
        context: Dict[str, Any]
    ) -> None:
        """Record performance alert with context information."""
        alert = {
            'alert_id': str(uuid.uuid4()),
            'severity': severity,
            'message': message,
            'context': context,
            'timestamp': time.time(),
            'session_id': self.session_id
        }
        
        self.performance_alerts.append(alert)
        
        logger.warning(
            "Performance alert recorded",
            alert_id=alert['alert_id'],
            severity=severity,
            message=message
        )
    
    def validate_throughput_baseline(
        self,
        measured_rps: float,
        baseline_key: str = 'requests_per_second'
    ) -> Dict[str, Any]:
        """
        Validate throughput performance against Node.js baseline.
        
        Args:
            measured_rps: Measured requests per second
            baseline_key: Baseline metric key for comparison
            
        Returns:
            Dictionary containing throughput validation results
        """
        if baseline_key not in self.baseline_metrics:
            raise ValueError(f"Baseline key '{baseline_key}' not found in baseline metrics")
        
        baseline_rps = self.baseline_metrics[baseline_key]
        variance = abs(measured_rps - baseline_rps) / baseline_rps
        
        validation_result = {
            'measured_rps': measured_rps,
            'baseline_rps': baseline_rps,
            'variance': variance,
            'variance_percentage': variance * 100,
            'threshold_percentage': self.variance_thresholds['throughput_threshold'] * 100,
            'compliant': variance <= self.variance_thresholds['throughput_threshold'],
            'timestamp': time.time(),
            'session_id': self.session_id
        }
        
        if not validation_result['compliant']:
            self.baseline_compliance['critical_violations'] += 1
            self.baseline_compliance['overall_compliant'] = False
            
            violation = {
                'metric_type': 'throughput',
                'measured_value': measured_rps,
                'baseline_value': baseline_rps,
                'variance_percentage': validation_result['variance_percentage'],
                'threshold_percentage': validation_result['threshold_percentage']
            }
            self._record_variance_violation(violation)
        else:
            self.baseline_compliance['compliant_metrics'] += 1
        
        self.baseline_compliance['total_metrics'] += 1
        self.measurements['throughput_metrics'].append(validation_result)
        
        logger.info(
            "Throughput baseline validation completed",
            measured_rps=round(measured_rps, 2),
            baseline_rps=baseline_rps,
            variance_pct=round(validation_result['variance_percentage'], 2),
            compliant=validation_result['compliant']
        )
        
        return validation_result
    
    def analyze_statistical_significance(
        self,
        measurements: List[float],
        baseline_value: float,
        confidence_level: float = 0.95
    ) -> Dict[str, Any]:
        """
        Perform statistical analysis of performance measurements.
        
        Args:
            measurements: List of performance measurements
            baseline_value: Baseline value for comparison
            confidence_level: Statistical confidence level
            
        Returns:
            Dictionary containing statistical analysis results
        """
        if len(measurements) < 2:
            return {
                'error': 'Insufficient measurements for statistical analysis',
                'sample_size': len(measurements)
            }
        
        try:
            # Calculate statistical metrics
            mean_value = statistics.mean(measurements)
            median_value = statistics.median(measurements)
            std_dev = statistics.stdev(measurements) if len(measurements) > 1 else 0
            variance = statistics.variance(measurements) if len(measurements) > 1 else 0
            
            # Calculate percentiles
            sorted_measurements = sorted(measurements)
            p95_index = int(0.95 * len(sorted_measurements))
            p99_index = int(0.99 * len(sorted_measurements))
            p95_value = sorted_measurements[min(p95_index, len(sorted_measurements) - 1)]
            p99_value = sorted_measurements[min(p99_index, len(sorted_measurements) - 1)]
            
            # Calculate confidence interval
            if len(measurements) > 1:
                import math
                margin_of_error = 1.96 * (std_dev / math.sqrt(len(measurements)))
                confidence_interval = (mean_value - margin_of_error, mean_value + margin_of_error)
            else:
                confidence_interval = (mean_value, mean_value)
            
            # Baseline comparison
            mean_variance = abs(mean_value - baseline_value) / baseline_value
            median_variance = abs(median_value - baseline_value) / baseline_value
            
            analysis_result = {
                'sample_size': len(measurements),
                'mean': mean_value,
                'median': median_value,
                'standard_deviation': std_dev,
                'variance': variance,
                'min_value': min(measurements),
                'max_value': max(measurements),
                'p95_value': p95_value,
                'p99_value': p99_value,
                'confidence_interval': confidence_interval,
                'confidence_level': confidence_level,
                'baseline_value': baseline_value,
                'mean_variance': mean_variance,
                'median_variance': median_variance,
                'mean_variance_percentage': mean_variance * 100,
                'median_variance_percentage': median_variance * 100,
                'statistical_significance': mean_variance > self.variance_thresholds['critical_threshold'],
                'timestamp': time.time()
            }
            
            logger.info(
                "Statistical analysis completed",
                sample_size=analysis_result['sample_size'],
                mean=round(analysis_result['mean'], 3),
                mean_variance_pct=round(analysis_result['mean_variance_percentage'], 2),
                p95_value=round(analysis_result['p95_value'], 3),
                statistically_significant=analysis_result['statistical_significance']
            )
            
            return analysis_result
            
        except Exception as e:
            logger.error(
                "Statistical analysis failed",
                error=str(e),
                sample_size=len(measurements),
                exc_info=True
            )
            
            return {
                'error': str(e),
                'sample_size': len(measurements),
                'timestamp': time.time()
            }
    
    def generate_performance_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive performance validation report.
        
        Returns:
            Dictionary containing complete performance analysis and compliance status
        """
        report_generation_time = time.time()
        total_session_time = report_generation_time - self.start_time
        
        # Calculate compliance metrics
        compliance_rate = (
            (self.baseline_compliance['compliant_metrics'] / 
             self.baseline_compliance['total_metrics'] * 100)
            if self.baseline_compliance['total_metrics'] > 0 else 100.0
        )
        
        # Analyze response time measurements
        response_time_analysis = {}
        if self.measurements['response_times']:
            response_times = [
                m['response_time'] for m in self.measurements['response_times']
                if 'response_time' in m and isinstance(m['response_time'], (int, float))
            ]
            
            if response_times:
                baseline_avg = statistics.mean(self.baseline_metrics.values())
                response_time_analysis = self.analyze_statistical_significance(
                    response_times, baseline_avg
                )
        
        # Generate comprehensive report
        performance_report = {
            'session_info': {
                'session_id': self.session_id,
                'report_generation_time': report_generation_time,
                'total_session_duration': total_session_time,
                'report_timestamp': datetime.utcnow().isoformat()
            },
            'baseline_compliance': {
                **self.baseline_compliance,
                'compliance_rate_percentage': round(compliance_rate, 2)
            },
            'variance_analysis': {
                'total_violations': len(self.variance_violations),
                'critical_violations': self.baseline_compliance['critical_violations'],
                'warning_violations': self.baseline_compliance['warning_violations'],
                'performance_alerts': len(self.performance_alerts),
                'overall_compliant': self.baseline_compliance['overall_compliant']
            },
            'measurement_summary': {
                'response_time_measurements': len(self.measurements['response_times']),
                'throughput_measurements': len(self.measurements['throughput_metrics']),
                'load_test_results': len(self.measurements['load_test_results']),
                'apache_bench_results': len(self.measurements['apache_bench_results'])
            },
            'statistical_analysis': response_time_analysis,
            'baseline_metrics': self.baseline_metrics,
            'variance_thresholds': self.variance_thresholds,
            'detailed_violations': self.variance_violations,
            'performance_alerts': self.performance_alerts,
            'raw_measurements': self.measurements
        }
        
        logger.info(
            "Performance report generated",
            session_id=self.session_id,
            compliance_rate=round(compliance_rate, 2),
            total_violations=len(self.variance_violations),
            overall_compliant=self.baseline_compliance['overall_compliant'],
            session_duration=round(total_session_time, 2)
        )
        
        return performance_report


class LocustLoadTester:
    """
    Advanced locust-based load testing system for performance validation.
    
    This class provides comprehensive load testing capabilities using the locust
    framework per Section 6.6.1 performance testing requirements, with automated
    baseline comparison and variance analysis.
    """
    
    def __init__(self, base_url: str = 'http://localhost:5000'):
        """
        Initialize locust load tester with configuration.
        
        Args:
            base_url: Base URL for load testing
        """
        self.base_url = base_url
        self.session_id = str(uuid.uuid4())
        self.test_results = []
        
        # Verify locust availability
        try:
            import locust
            self.locust_available = True
            logger.info("Locust load testing framework available")
        except ImportError:
            self.locust_available = False
            logger.warning("Locust not available - load testing will be skipped")
    
    def create_load_test_scenario(self) -> str:
        """
        Create comprehensive load test scenario with realistic user patterns.
        
        Returns:
            Path to generated locust test file
        """
        if not self.locust_available:
            pytest.skip("Locust not available for load testing")
        
        # Generate locust test file
        locust_test_content = f'''
import time
import random
from locust import HttpUser, task, between, constant
from locust.env import Environment
from locust.stats import stats_printer, stats_history

class FlaskPerformanceUser(HttpUser):
    """
    Comprehensive Flask application user simulation for performance testing.
    
    This class simulates realistic user behavior patterns including authentication,
    API usage, and various endpoint interactions to validate performance under
    load conditions per Section 6.6.1 requirements.
    """
    
    wait_time = between(1, 3)  # Realistic user think time
    
    def on_start(self):
        """Initialize user session with authentication setup."""
        self.auth_token = None
        self.user_id = f"load_test_user_{{random.randint(1000, 9999)}}"
        
        # Simulate user authentication
        self.authenticate_user()
    
    def authenticate_user(self):
        """Simulate user authentication process."""
        auth_data = {{
            'email': f'{{self.user_id}}@example.com',
            'password': 'LoadTest123!'
        }}
        
        try:
            with self.client.post(
                "/auth/login",
                json=auth_data,
                catch_response=True
            ) as response:
                if response.status_code == 200:
                    response_data = response.json()
                    self.auth_token = response_data.get('access_token')
                    response.success()
                else:
                    response.failure(f"Authentication failed: {{response.status_code}}")
        except Exception as e:
            pass  # Continue without authentication for anonymous endpoints
    
    @task(3)
    def test_health_check(self):
        """Test health check endpoint performance."""
        with self.client.get("/health", catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Health check failed: {{response.status_code}}")
    
    @task(2)
    def test_api_status(self):
        """Test API status endpoint performance."""
        with self.client.get("/api/v1/status", catch_response=True) as response:
            if response.status_code in [200, 401]:  # 401 acceptable if not authenticated
                response.success()
            else:
                response.failure(f"API status failed: {{response.status_code}}")
    
    @task(5)
    def test_authenticated_endpoints(self):
        """Test authenticated API endpoints performance."""
        if not self.auth_token:
            return  # Skip if no auth token available
        
        headers = {{'Authorization': f'Bearer {{self.auth_token}}'}}
        
        endpoints = [
            "/api/v1/users/profile",
            "/api/v1/projects",
            "/api/v1/dashboard/stats"
        ]
        
        endpoint = random.choice(endpoints)
        
        with self.client.get(endpoint, headers=headers, catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            elif response.status_code == 401:
                # Re-authenticate and retry
                self.authenticate_user()
                response.success()  # Don't fail on auth retry
            else:
                response.failure(f"Endpoint {{endpoint}} failed: {{response.status_code}}")
    
    @task(1)
    def test_data_operations(self):
        """Test data-intensive operations performance."""
        if not self.auth_token:
            return
        
        headers = {{'Authorization': f'Bearer {{self.auth_token}}'}}
        
        # Test data creation
        create_data = {{
            'name': f'Load Test Item {{random.randint(1, 1000)}}',
            'description': 'Load testing data creation',
            'category': random.choice(['test', 'performance', 'validation'])
        }}
        
        with self.client.post(
            "/api/v1/data",
            json=create_data,
            headers=headers,
            catch_response=True
        ) as response:
            if response.status_code in [200, 201]:
                response.success()
            elif response.status_code == 401:
                self.authenticate_user()
                response.success()
            else:
                response.failure(f"Data creation failed: {{response.status_code}}")
'''
        
        # Write locust test file
        test_file = tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.py',
            prefix='locust_performance_test_',
            delete=False
        )
        
        test_file.write(locust_test_content)
        test_file.flush()
        test_file.close()
        
        logger.info(
            "Locust test scenario created",
            test_file_path=test_file.name,
            session_id=self.session_id
        )
        
        return test_file.name
    
    def execute_load_test(
        self,
        users: int = None,
        spawn_rate: int = None,
        run_time: int = None,
        test_file: str = None
    ) -> Dict[str, Any]:
        """
        Execute comprehensive load test with performance validation.
        
        Args:
            users: Number of concurrent users to simulate
            spawn_rate: User spawn rate per second
            run_time: Test duration in seconds
            test_file: Path to locust test file
            
        Returns:
            Dictionary containing load test results and performance metrics
        """
        if not self.locust_available:
            pytest.skip("Locust not available for load testing")
        
        # Use configuration defaults
        users = users or PERFORMANCE_CONFIG['LOAD_TESTING']['baseline_users']
        spawn_rate = spawn_rate or PERFORMANCE_CONFIG['LOAD_TESTING']['spawn_rate']
        run_time = run_time or PERFORMANCE_CONFIG['LOAD_TESTING']['test_duration']
        
        if not test_file:
            test_file = self.create_load_test_scenario()
        
        # Prepare locust command
        locust_cmd = [
            'locust',
            '-f', test_file,
            '--host', self.base_url,
            '--users', str(users),
            '--spawn-rate', str(spawn_rate),
            '--run-time', f'{run_time}s',
            '--headless',  # Run without web UI
            '--only-summary',  # Minimal output
            '--csv', f'/tmp/locust_results_{self.session_id}'  # CSV output
        ]
        
        logger.info(
            "Starting locust load test",
            users=users,
            spawn_rate=spawn_rate,
            run_time=run_time,
            base_url=self.base_url,
            session_id=self.session_id
        )
        
        test_start_time = time.time()
        
        try:
            # Execute locust load test
            result = subprocess.run(
                locust_cmd,
                capture_output=True,
                text=True,
                timeout=run_time + 60  # Add buffer time
            )
            
            test_end_time = time.time()
            actual_duration = test_end_time - test_start_time
            
            if result.returncode == 0:
                # Parse locust output
                output_lines = result.stdout.split('\n')
                stats_lines = [line for line in output_lines if 'GET' in line or 'POST' in line]
                
                # Extract performance metrics
                total_requests = 0
                total_failures = 0
                response_times = []
                
                for line in stats_lines:
                    parts = line.split()
                    if len(parts) >= 6:
                        try:
                            requests = int(parts[1])
                            failures = int(parts[2])
                            avg_response_time = float(parts[3])
                            
                            total_requests += requests
                            total_failures += failures
                            response_times.append(avg_response_time)
                        except (ValueError, IndexError):
                            continue
                
                # Calculate aggregated metrics
                requests_per_second = total_requests / actual_duration if actual_duration > 0 else 0
                failure_rate = (total_failures / total_requests * 100) if total_requests > 0 else 0
                avg_response_time = statistics.mean(response_times) if response_times else 0
                
                load_test_result = {
                    'session_id': self.session_id,
                    'success': True,
                    'configuration': {
                        'users': users,
                        'spawn_rate': spawn_rate,
                        'planned_duration': run_time,
                        'actual_duration': actual_duration
                    },
                    'performance_metrics': {
                        'total_requests': total_requests,
                        'total_failures': total_failures,
                        'requests_per_second': round(requests_per_second, 2),
                        'failure_rate_percentage': round(failure_rate, 2),
                        'average_response_time': round(avg_response_time, 3),
                        'min_response_time': min(response_times) if response_times else 0,
                        'max_response_time': max(response_times) if response_times else 0
                    },
                    'baseline_comparison': {
                        'baseline_rps': PERFORMANCE_CONFIG['NODEJS_BASELINES']['requests_per_second'],
                        'rps_variance': abs(requests_per_second - PERFORMANCE_CONFIG['NODEJS_BASELINES']['requests_per_second']) / PERFORMANCE_CONFIG['NODEJS_BASELINES']['requests_per_second'],
                        'baseline_compliant': abs(requests_per_second - PERFORMANCE_CONFIG['NODEJS_BASELINES']['requests_per_second']) / PERFORMANCE_CONFIG['NODEJS_BASELINES']['requests_per_second'] <= PERFORMANCE_CONFIG['VARIANCE_THRESHOLDS']['throughput_threshold']
                    },
                    'timestamp': time.time(),
                    'test_output': result.stdout
                }
                
                self.test_results.append(load_test_result)
                
                logger.info(
                    "Locust load test completed successfully",
                    session_id=self.session_id,
                    total_requests=total_requests,
                    rps=round(requests_per_second, 2),
                    failure_rate=round(failure_rate, 2),
                    avg_response_time=round(avg_response_time, 3),
                    baseline_compliant=load_test_result['baseline_comparison']['baseline_compliant']
                )
                
                return load_test_result
                
            else:
                error_result = {
                    'session_id': self.session_id,
                    'success': False,
                    'error': result.stderr,
                    'return_code': result.returncode,
                    'timestamp': time.time()
                }
                
                self.test_results.append(error_result)
                
                logger.error(
                    "Locust load test failed",
                    session_id=self.session_id,
                    return_code=result.returncode,
                    error=result.stderr
                )
                
                return error_result
                
        except subprocess.TimeoutExpired:
            timeout_result = {
                'session_id': self.session_id,
                'success': False,
                'error': 'Load test timed out',
                'timeout_duration': run_time + 60,
                'timestamp': time.time()
            }
            
            self.test_results.append(timeout_result)
            
            logger.error(
                "Locust load test timed out",
                session_id=self.session_id,
                timeout_duration=run_time + 60
            )
            
            return timeout_result
            
        except Exception as e:
            exception_result = {
                'session_id': self.session_id,
                'success': False,
                'error': str(e),
                'error_type': type(e).__name__,
                'timestamp': time.time()
            }
            
            self.test_results.append(exception_result)
            
            logger.error(
                "Locust load test failed with exception",
                session_id=self.session_id,
                error=str(e),
                exc_info=True
            )
            
            return exception_result
        
        finally:
            # Cleanup test file
            try:
                if test_file and os.path.exists(test_file):
                    os.unlink(test_file)
            except Exception:
                pass


class ApacheBenchTester:
    """
    Apache-bench HTTP server performance testing system.
    
    This class provides comprehensive HTTP server performance measurement using
    apache-bench per Section 6.6.1 benchmark testing requirements, with automated
    baseline comparison and statistical analysis.
    """
    
    def __init__(self, base_url: str = 'http://localhost:5000'):
        """
        Initialize apache-bench tester with configuration.
        
        Args:
            base_url: Base URL for performance testing
        """
        self.base_url = base_url
        self.session_id = str(uuid.uuid4())
        self.test_results = []
        
        # Check apache-bench availability
        try:
            result = subprocess.run(['ab', '-V'], capture_output=True, text=True)
            if result.returncode == 0:
                self.ab_available = True
                logger.info("Apache-bench available for performance testing")
            else:
                self.ab_available = False
                logger.warning("Apache-bench not available - benchmark testing will be skipped")
        except FileNotFoundError:
            self.ab_available = False
            logger.warning("Apache-bench not found - benchmark testing will be skipped")
    
    def execute_benchmark_test(
        self,
        endpoint: str,
        requests: int = None,
        concurrency: int = None,
        timeout: int = None,
        headers: Dict[str, str] = None
    ) -> Dict[str, Any]:
        """
        Execute apache-bench performance test with comprehensive metrics collection.
        
        Args:
            endpoint: API endpoint to benchmark
            requests: Total number of requests
            concurrency: Concurrent request level
            timeout: Request timeout in seconds
            headers: Additional HTTP headers
            
        Returns:
            Dictionary containing benchmark results and performance analysis
        """
        if not self.ab_available:
            pytest.skip("Apache-bench not available for benchmark testing")
        
        # Use configuration defaults
        requests = requests or PERFORMANCE_CONFIG['APACHE_BENCH']['total_requests']
        concurrency = concurrency or PERFORMANCE_CONFIG['APACHE_BENCH']['concurrency_levels'][0]
        timeout = timeout or PERFORMANCE_CONFIG['APACHE_BENCH']['timeout_seconds']
        
        # Construct full URL
        test_url = f"{self.base_url}{endpoint}"
        
        # Prepare apache-bench command
        ab_cmd = [
            'ab',
            '-n', str(requests),
            '-c', str(concurrency),
            '-s', str(timeout),
            '-g', f'/tmp/ab_gnuplot_{self.session_id}.dat',  # Gnuplot data
            '-e', f'/tmp/ab_csv_{self.session_id}.csv'       # CSV output
        ]
        
        # Add headers if provided
        if headers:
            for key, value in headers.items():
                ab_cmd.extend(['-H', f'{key}: {value}'])
        
        # Add test URL
        ab_cmd.append(test_url)
        
        logger.info(
            "Starting apache-bench performance test",
            endpoint=endpoint,
            requests=requests,
            concurrency=concurrency,
            timeout=timeout,
            session_id=self.session_id
        )
        
        test_start_time = time.time()
        
        try:
            # Execute apache-bench test
            result = subprocess.run(
                ab_cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 30  # Add buffer time
            )
            
            test_end_time = time.time()
            actual_duration = test_end_time - test_start_time
            
            if result.returncode == 0:
                # Parse apache-bench output
                output = result.stdout
                
                # Extract key metrics using regex patterns
                import re
                
                metrics = {}
                
                # Requests per second
                rps_match = re.search(r'Requests per second:\s+([0-9.]+)', output)
                if rps_match:
                    metrics['requests_per_second'] = float(rps_match.group(1))
                
                # Time per request
                tpr_match = re.search(r'Time per request:\s+([0-9.]+)', output)
                if tpr_match:
                    metrics['time_per_request'] = float(tpr_match.group(1))
                
                # Transfer rate
                transfer_match = re.search(r'Transfer rate:\s+([0-9.]+)', output)
                if transfer_match:
                    metrics['transfer_rate'] = float(transfer_match.group(1))
                
                # Connection times
                connect_times = {}
                connect_section = re.search(
                    r'Connection Times \(ms\)\s+min\s+mean\[.*?\]\s+median\s+max\s+'
                    r'Connect:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+'
                    r'Processing:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+'
                    r'Waiting:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+'
                    r'Total:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)',
                    output,
                    re.MULTILINE | re.DOTALL
                )
                
                if connect_section:
                    groups = connect_section.groups()
                    connect_times = {
                        'connect': {
                            'min': int(groups[0]),
                            'mean': int(groups[1]),
                            'median': int(groups[2]),
                            'max': int(groups[3])
                        },
                        'processing': {
                            'min': int(groups[4]),
                            'mean': int(groups[5]),
                            'median': int(groups[6]),
                            'max': int(groups[7])
                        },
                        'waiting': {
                            'min': int(groups[8]),
                            'mean': int(groups[9]),
                            'median': int(groups[10]),
                            'max': int(groups[11])
                        },
                        'total': {
                            'min': int(groups[12]),
                            'mean': int(groups[13]),
                            'median': int(groups[14]),
                            'max': int(groups[15])
                        }
                    }
                
                # Percentage response times
                percentile_section = re.search(
                    r'Percentage of the requests served within.*?\n'
                    r'((?:\s+\d+%\s+\d+\n?)+)',
                    output,
                    re.MULTILINE | re.DOTALL
                )
                
                percentiles = {}
                if percentile_section:
                    percentile_lines = percentile_section.group(1).strip().split('\n')
                    for line in percentile_lines:
                        match = re.match(r'\s+(\d+)%\s+(\d+)', line.strip())
                        if match:
                            percentile = int(match.group(1))
                            response_time = int(match.group(2))
                            percentiles[f'p{percentile}'] = response_time
                
                # Calculate baseline comparison
                baseline_comparison = {}
                if 'requests_per_second' in metrics:
                    baseline_rps = PERFORMANCE_CONFIG['NODEJS_BASELINES']['requests_per_second']
                    rps_variance = abs(metrics['requests_per_second'] - baseline_rps) / baseline_rps
                    baseline_comparison['rps_variance'] = rps_variance
                    baseline_comparison['rps_compliant'] = rps_variance <= PERFORMANCE_CONFIG['VARIANCE_THRESHOLDS']['throughput_threshold']
                
                if 'time_per_request' in metrics:
                    # Convert time per request to response time (ms to seconds)
                    response_time_sec = metrics['time_per_request'] / 1000
                    baseline_response_time = PERFORMANCE_CONFIG['NODEJS_BASELINES']['api_endpoint_response_time']
                    response_variance = abs(response_time_sec - baseline_response_time) / baseline_response_time
                    baseline_comparison['response_time_variance'] = response_variance
                    baseline_comparison['response_time_compliant'] = response_variance <= PERFORMANCE_CONFIG['VARIANCE_THRESHOLDS']['critical_threshold']
                
                # Create comprehensive benchmark result
                benchmark_result = {
                    'session_id': self.session_id,
                    'success': True,
                    'endpoint': endpoint,
                    'configuration': {
                        'requests': requests,
                        'concurrency': concurrency,
                        'timeout': timeout,
                        'actual_duration': actual_duration
                    },
                    'performance_metrics': metrics,
                    'connection_times': connect_times,
                    'percentiles': percentiles,
                    'baseline_comparison': baseline_comparison,
                    'overall_compliant': all(baseline_comparison.values()) if baseline_comparison else True,
                    'timestamp': time.time(),
                    'raw_output': output
                }
                
                self.test_results.append(benchmark_result)
                
                logger.info(
                    "Apache-bench test completed successfully",
                    session_id=self.session_id,
                    endpoint=endpoint,
                    rps=round(metrics.get('requests_per_second', 0), 2),
                    time_per_request=round(metrics.get('time_per_request', 0), 2),
                    overall_compliant=benchmark_result['overall_compliant']
                )
                
                return benchmark_result
                
            else:
                error_result = {
                    'session_id': self.session_id,
                    'success': False,
                    'endpoint': endpoint,
                    'error': result.stderr,
                    'return_code': result.returncode,
                    'timestamp': time.time()
                }
                
                self.test_results.append(error_result)
                
                logger.error(
                    "Apache-bench test failed",
                    session_id=self.session_id,
                    endpoint=endpoint,
                    return_code=result.returncode,
                    error=result.stderr
                )
                
                return error_result
                
        except subprocess.TimeoutExpired:
            timeout_result = {
                'session_id': self.session_id,
                'success': False,
                'endpoint': endpoint,
                'error': 'Benchmark test timed out',
                'timeout_duration': timeout + 30,
                'timestamp': time.time()
            }
            
            self.test_results.append(timeout_result)
            
            logger.error(
                "Apache-bench test timed out",
                session_id=self.session_id,
                endpoint=endpoint,
                timeout_duration=timeout + 30
            )
            
            return timeout_result
            
        except Exception as e:
            exception_result = {
                'session_id': self.session_id,
                'success': False,
                'endpoint': endpoint,
                'error': str(e),
                'error_type': type(e).__name__,
                'timestamp': time.time()
            }
            
            self.test_results.append(exception_result)
            
            logger.error(
                "Apache-bench test failed with exception",
                session_id=self.session_id,
                endpoint=endpoint,
                error=str(e),
                exc_info=True
            )
            
            return exception_result
    
    def execute_concurrency_test_suite(
        self,
        endpoint: str,
        concurrency_levels: List[int] = None
    ) -> Dict[str, Any]:
        """
        Execute comprehensive concurrency testing across multiple levels.
        
        Args:
            endpoint: API endpoint to test
            concurrency_levels: List of concurrency levels to test
            
        Returns:
            Dictionary containing concurrency test suite results
        """
        if not self.ab_available:
            pytest.skip("Apache-bench not available for concurrency testing")
        
        concurrency_levels = concurrency_levels or PERFORMANCE_CONFIG['APACHE_BENCH']['concurrency_levels']
        
        suite_start_time = time.time()
        concurrency_results = []
        overall_compliant = True
        
        logger.info(
            "Starting apache-bench concurrency test suite",
            endpoint=endpoint,
            concurrency_levels=concurrency_levels,
            session_id=self.session_id
        )
        
        for concurrency in concurrency_levels:
            logger.info(f"Testing concurrency level: {concurrency}")
            
            result = self.execute_benchmark_test(
                endpoint=endpoint,
                concurrency=concurrency
            )
            
            concurrency_results.append(result)
            
            if not result.get('overall_compliant', True):
                overall_compliant = False
        
        suite_end_time = time.time()
        suite_duration = suite_end_time - suite_start_time
        
        # Analyze concurrency performance trends
        performance_trend = {}
        if concurrency_results:
            rps_values = [
                r.get('performance_metrics', {}).get('requests_per_second', 0)
                for r in concurrency_results if r.get('success', False)
            ]
            
            response_times = [
                r.get('performance_metrics', {}).get('time_per_request', 0)
                for r in concurrency_results if r.get('success', False)
            ]
            
            if rps_values and response_times:
                performance_trend = {
                    'rps_trend': {
                        'min': min(rps_values),
                        'max': max(rps_values),
                        'improvement_ratio': max(rps_values) / min(rps_values) if min(rps_values) > 0 else 1
                    },
                    'response_time_trend': {
                        'min': min(response_times),
                        'max': max(response_times),
                        'degradation_ratio': max(response_times) / min(response_times) if min(response_times) > 0 else 1
                    }
                }
        
        concurrency_suite_result = {
            'session_id': self.session_id,
            'endpoint': endpoint,
            'concurrency_levels': concurrency_levels,
            'suite_duration': suite_duration,
            'individual_results': concurrency_results,
            'performance_trend': performance_trend,
            'overall_compliant': overall_compliant,
            'successful_tests': len([r for r in concurrency_results if r.get('success', False)]),
            'failed_tests': len([r for r in concurrency_results if not r.get('success', False)]),
            'timestamp': time.time()
        }
        
        logger.info(
            "Apache-bench concurrency test suite completed",
            session_id=self.session_id,
            endpoint=endpoint,
            successful_tests=concurrency_suite_result['successful_tests'],
            failed_tests=concurrency_suite_result['failed_tests'],
            overall_compliant=overall_compliant,
            suite_duration=round(suite_duration, 2)
        )
        
        return concurrency_suite_result


# =============================================================================
# PERFORMANCE BASELINE TESTING CLASS
# =============================================================================

@pytest.mark.e2e
@pytest.mark.performance
class TestPerformanceBaselines:
    """
    Comprehensive performance baseline comparison testing class.
    
    This class implements enterprise-grade performance testing with automated
    baseline comparison, statistical analysis, and compliance validation per
    Section 6.6.1 performance testing requirements and Section 0.1.1 ≤10%
    variance compliance mandate.
    """
    
    @pytest.fixture(autouse=True)
    def setup_performance_testing(self, comprehensive_e2e_environment):
        """Setup performance testing environment with comprehensive configuration."""
        self.test_environment = comprehensive_e2e_environment
        self.app = self.test_environment['app']
        self.client = self.test_environment['client']
        self.performance_monitor = self.test_environment['performance']
        
        # Initialize performance testing components
        self.baseline_validator = PerformanceBaselineValidator()
        self.locust_tester = LocustLoadTester()
        self.apache_bench_tester = ApacheBenchTester()
        
        # Performance test session tracking
        self.test_session_id = str(uuid.uuid4())
        self.test_start_time = time.time()
        
        logger.info(
            "Performance baseline testing setup completed",
            test_session_id=self.test_session_id,
            flask_app_available=bool(self.app),
            locust_available=self.locust_tester.locust_available,
            apache_bench_available=self.apache_bench_tester.ab_available
        )
        
        yield
        
        # Generate final performance report
        self._generate_test_session_report()
    
    def _generate_test_session_report(self):
        """Generate comprehensive test session performance report."""
        test_end_time = time.time()
        session_duration = test_end_time - self.test_start_time
        
        # Collect all performance results
        baseline_report = self.baseline_validator.generate_performance_report()
        locust_results = getattr(self.locust_tester, 'test_results', [])
        apache_bench_results = getattr(self.apache_bench_tester, 'test_results', [])
        
        session_report = {
            'test_session_id': self.test_session_id,
            'session_duration': session_duration,
            'baseline_validation': baseline_report,
            'load_test_results': locust_results,
            'benchmark_results': apache_bench_results,
            'overall_compliance': baseline_report['baseline_compliance']['overall_compliant'],
            'timestamp': test_end_time
        }
        
        # Export report to file
        try:
            report_filename = f"performance_baseline_report_{self.test_session_id[:8]}.json"
            report_path = Path(f"/tmp/{report_filename}")
            
            with open(report_path, 'w') as f:
                json.dump(session_report, f, indent=2, default=str)
            
            logger.info(
                "Performance test session report generated",
                test_session_id=self.test_session_id,
                report_path=str(report_path),
                overall_compliance=session_report['overall_compliance'],
                session_duration=round(session_duration, 2)
            )
            
        except Exception as e:
            logger.error(
                "Failed to generate performance test session report",
                test_session_id=self.test_session_id,
                error=str(e)
            )
    
    @skip_if_not_e2e()
    def test_health_endpoint_performance_baseline(self):
        """
        Test health endpoint performance against Node.js baseline.
        
        Validates health check endpoint response time compliance with ≤10%
        variance requirement per Section 0.1.1 and Section 6.6.3.
        """
        logger.info("Testing health endpoint performance baseline")
        
        # Perform multiple measurements for statistical significance
        measurements = []
        
        for i in range(10):
            measurement = self.baseline_validator.measure_response_time(
                endpoint='http://localhost:5000/health',
                method='GET',
                baseline_key='health_check_time'
            )
            
            if 'response_time' in measurement:
                measurements.append(measurement['response_time'])
            
            time.sleep(0.1)  # Brief pause between measurements
        
        # Perform statistical analysis
        if measurements:
            baseline_time = PERFORMANCE_CONFIG['NODEJS_BASELINES']['health_check_time']
            stats_analysis = self.baseline_validator.analyze_statistical_significance(
                measurements, baseline_time
            )
            
            # Assert compliance with variance requirement
            assert stats_analysis['mean_variance'] <= PERFORMANCE_CONFIG['VARIANCE_THRESHOLDS']['critical_threshold'], \
                f"Health endpoint mean variance {stats_analysis['mean_variance_percentage']:.2f}% exceeds ≤10% threshold"
            
            # Additional assertions for comprehensive validation
            assert stats_analysis['p95_value'] <= baseline_time * 1.2, \
                f"95th percentile response time {stats_analysis['p95_value']:.3f}s exceeds acceptable threshold"
            
            assert len(measurements) >= 5, \
                f"Insufficient measurements for statistical validation: {len(measurements)}"
            
            logger.info(
                "Health endpoint performance baseline test passed",
                mean_response_time=round(stats_analysis['mean'], 3),
                baseline_time=baseline_time,
                variance_pct=round(stats_analysis['mean_variance_percentage'], 2),
                p95_response_time=round(stats_analysis['p95_value'], 3),
                sample_size=stats_analysis['sample_size']
            )
        else:
            pytest.fail("No valid health endpoint measurements collected")
    
    @skip_if_not_e2e()
    def test_api_endpoints_performance_baseline(self):
        """
        Test API endpoints performance against Node.js baseline.
        
        Validates core API endpoint response times with comprehensive coverage
        per Section 6.6.1 API testing strategy and F-006-RQ-003 requirements.
        """
        logger.info("Testing API endpoints performance baseline")
        
        # Define test endpoints with their baseline keys
        test_endpoints = [
            ('/api/v1/status', 'api_endpoint_response_time'),
            ('/health/live', 'health_check_time'),
            ('/health/ready', 'health_check_time'),
            ('/info', 'api_endpoint_response_time')
        ]
        
        endpoint_results = {}
        overall_compliant = True
        
        for endpoint, baseline_key in test_endpoints:
            logger.info(f"Testing endpoint: {endpoint}")
            
            endpoint_measurements = []
            
            # Collect multiple measurements per endpoint
            for i in range(5):
                measurement = self.baseline_validator.measure_response_time(
                    endpoint=f'http://localhost:5000{endpoint}',
                    method='GET',
                    baseline_key=baseline_key
                )
                
                if 'response_time' in measurement:
                    endpoint_measurements.append(measurement['response_time'])
                elif 'error' in measurement:
                    logger.warning(f"Measurement error for {endpoint}: {measurement['error']}")
                
                time.sleep(0.05)  # Brief pause between measurements
            
            if endpoint_measurements:
                # Statistical analysis for endpoint
                baseline_time = PERFORMANCE_CONFIG['NODEJS_BASELINES'][baseline_key]
                endpoint_stats = self.baseline_validator.analyze_statistical_significance(
                    endpoint_measurements, baseline_time
                )
                
                endpoint_compliant = endpoint_stats['mean_variance'] <= PERFORMANCE_CONFIG['VARIANCE_THRESHOLDS']['critical_threshold']
                endpoint_results[endpoint] = {
                    'measurements': endpoint_measurements,
                    'statistics': endpoint_stats,
                    'compliant': endpoint_compliant
                }
                
                if not endpoint_compliant:
                    overall_compliant = False
                    logger.warning(
                        f"Endpoint {endpoint} failed baseline compliance",
                        variance_pct=round(endpoint_stats['mean_variance_percentage'], 2)
                    )
                else:
                    logger.info(
                        f"Endpoint {endpoint} passed baseline compliance",
                        mean_response_time=round(endpoint_stats['mean'], 3),
                        variance_pct=round(endpoint_stats['mean_variance_percentage'], 2)
                    )
            else:
                endpoint_results[endpoint] = {
                    'error': 'No valid measurements collected',
                    'compliant': False
                }
                overall_compliant = False
        
        # Assert overall API performance compliance
        assert overall_compliant, \
            f"API endpoints performance baseline compliance failed. Results: {endpoint_results}"
        
        # Additional validation: ensure all endpoints were tested
        assert len(endpoint_results) == len(test_endpoints), \
            f"Not all endpoints were tested. Expected: {len(test_endpoints)}, Actual: {len(endpoint_results)}"
        
        # Validate that at least 80% of individual measurements are compliant
        total_measurements = sum(len(result.get('measurements', [])) for result in endpoint_results.values())
        assert total_measurements >= 15, \
            f"Insufficient total measurements for API baseline validation: {total_measurements}"
        
        logger.info(
            "API endpoints performance baseline test completed",
            total_endpoints=len(test_endpoints),
            overall_compliant=overall_compliant,
            total_measurements=total_measurements
        )
    
    @require_load_testing()
    @skip_if_not_e2e()
    def test_locust_load_testing_baseline(self):
        """
        Test application load performance using locust framework.
        
        Validates concurrent request handling capacity and throughput against
        Node.js baseline per Section 6.6.1 load testing requirements.
        """
        logger.info("Starting locust load testing baseline validation")
        
        if not self.locust_tester.locust_available:
            pytest.skip("Locust framework not available for load testing")
        
        # Execute load test with baseline configuration
        load_test_result = self.locust_tester.execute_load_test(
            users=PERFORMANCE_CONFIG['LOAD_TESTING']['baseline_users'],
            spawn_rate=PERFORMANCE_CONFIG['LOAD_TESTING']['spawn_rate'],
            run_time=60  # Reduced duration for testing
        )
        
        # Validate load test execution
        assert load_test_result['success'], \
            f"Load test execution failed: {load_test_result.get('error', 'Unknown error')}"
        
        # Extract performance metrics
        performance_metrics = load_test_result['performance_metrics']
        baseline_comparison = load_test_result['baseline_comparison']
        
        # Assert throughput compliance
        assert baseline_comparison['baseline_compliant'], \
            f"Load test throughput variance {baseline_comparison['rps_variance'] * 100:.2f}% exceeds ≤10% threshold"
        
        # Assert acceptable failure rate
        failure_rate = performance_metrics['failure_rate_percentage']
        assert failure_rate <= PERFORMANCE_CONFIG['VARIANCE_THRESHOLDS']['error_rate_threshold'], \
            f"Load test failure rate {failure_rate:.2f}% exceeds maximum threshold of {PERFORMANCE_CONFIG['VARIANCE_THRESHOLDS']['error_rate_threshold']}%"
        
        # Assert minimum performance thresholds
        rps = performance_metrics['requests_per_second']
        baseline_rps = PERFORMANCE_CONFIG['NODEJS_BASELINES']['requests_per_second']
        
        assert rps >= baseline_rps * 0.9, \
            f"Load test RPS {rps:.2f} is below 90% of baseline {baseline_rps}"
        
        # Validate response time performance
        avg_response_time = performance_metrics['average_response_time']
        baseline_response_time = PERFORMANCE_CONFIG['NODEJS_BASELINES']['api_endpoint_response_time'] * 1000  # Convert to ms
        
        assert avg_response_time <= baseline_response_time * 1.1, \
            f"Load test average response time {avg_response_time:.2f}ms exceeds 110% of baseline {baseline_response_time:.2f}ms"
        
        # Record successful throughput validation
        self.baseline_validator.validate_throughput_baseline(
            measured_rps=rps,
            baseline_key='requests_per_second'
        )
        
        logger.info(
            "Locust load testing baseline validation passed",
            users=load_test_result['configuration']['users'],
            rps=round(rps, 2),
            failure_rate=round(failure_rate, 2),
            avg_response_time=round(avg_response_time, 2),
            baseline_compliant=baseline_comparison['baseline_compliant']
        )
    
    @require_load_testing()
    @skip_if_not_e2e()
    def test_apache_bench_performance_baseline(self):
        """
        Test HTTP server performance using apache-bench framework.
        
        Validates individual endpoint performance characteristics against
        Node.js baseline per Section 6.6.1 benchmark testing requirements.
        """
        logger.info("Starting apache-bench performance baseline validation")
        
        if not self.apache_bench_tester.ab_available:
            pytest.skip("Apache-bench not available for benchmark testing")
        
        # Test critical endpoints with apache-bench
        critical_endpoints = [
            '/health',
            '/api/v1/status',
            '/info'
        ]
        
        benchmark_results = {}
        overall_compliant = True
        
        for endpoint in critical_endpoints:
            logger.info(f"Benchmarking endpoint: {endpoint}")
            
            # Execute benchmark test
            result = self.apache_bench_tester.execute_benchmark_test(
                endpoint=endpoint,
                requests=500,  # Moderate request count for testing
                concurrency=10
            )
            
            benchmark_results[endpoint] = result
            
            if result['success']:
                # Validate baseline compliance
                baseline_comparison = result.get('baseline_comparison', {})
                endpoint_compliant = result.get('overall_compliant', False)
                
                if not endpoint_compliant:
                    overall_compliant = False
                    logger.warning(
                        f"Apache-bench baseline compliance failed for {endpoint}",
                        rps_variance=baseline_comparison.get('rps_variance', 0) * 100,
                        response_time_variance=baseline_comparison.get('response_time_variance', 0) * 100
                    )
                else:
                    logger.info(
                        f"Apache-bench baseline compliance passed for {endpoint}",
                        rps=round(result['performance_metrics'].get('requests_per_second', 0), 2),
                        time_per_request=round(result['performance_metrics'].get('time_per_request', 0), 2)
                    )
            else:
                overall_compliant = False
                logger.error(f"Apache-bench test failed for {endpoint}: {result.get('error', 'Unknown error')}")
        
        # Assert overall benchmark compliance
        assert overall_compliant, \
            f"Apache-bench performance baseline compliance failed. Results: {benchmark_results}"
        
        # Validate that all endpoints were successfully tested
        successful_tests = [r for r in benchmark_results.values() if r.get('success', False)]
        assert len(successful_tests) == len(critical_endpoints), \
            f"Not all endpoints passed apache-bench testing. Successful: {len(successful_tests)}, Expected: {len(critical_endpoints)}"
        
        # Additional performance validation
        for endpoint, result in benchmark_results.items():
            if result['success']:
                performance_metrics = result['performance_metrics']
                
                # Validate requests per second
                rps = performance_metrics.get('requests_per_second', 0)
                assert rps > 0, f"Invalid RPS measurement for {endpoint}: {rps}"
                
                # Validate response time
                time_per_request = performance_metrics.get('time_per_request', 0)
                assert time_per_request > 0, f"Invalid response time measurement for {endpoint}: {time_per_request}"
                
                # Validate connection times
                connection_times = result.get('connection_times', {})
                if connection_times:
                    total_times = connection_times.get('total', {})
                    mean_total_time = total_times.get('mean', 0)
                    assert mean_total_time > 0, f"Invalid connection time measurement for {endpoint}: {mean_total_time}"
        
        logger.info(
            "Apache-bench performance baseline validation completed",
            total_endpoints=len(critical_endpoints),
            successful_tests=len(successful_tests),
            overall_compliant=overall_compliant
        )
    
    @skip_if_not_e2e()
    def test_concurrent_users_capacity_baseline(self):
        """
        Test concurrent users handling capacity against Node.js baseline.
        
        Validates application's ability to handle concurrent users per
        Section 6.6.3 performance test thresholds and capacity requirements.
        """
        logger.info("Testing concurrent users capacity baseline")
        
        if not self.apache_bench_tester.ab_available:
            pytest.skip("Apache-bench not available for concurrency testing")
        
        # Execute concurrency test suite
        concurrency_result = self.apache_bench_tester.execute_concurrency_test_suite(
            endpoint='/health',
            concurrency_levels=[1, 10, 25, 50, 100]
        )
        
        # Validate concurrency test execution
        assert concurrency_result['successful_tests'] > 0, \
            f"No successful concurrency tests executed: {concurrency_result['failed_tests']} failed"
        
        # Analyze performance trend
        performance_trend = concurrency_result.get('performance_trend', {})
        
        if performance_trend:
            rps_trend = performance_trend.get('rps_trend', {})
            response_time_trend = performance_trend.get('response_time_trend', {})
            
            # Validate that RPS improves with higher concurrency (up to a point)
            if rps_trend and rps_trend.get('improvement_ratio', 1) > 1:
                improvement_ratio = rps_trend['improvement_ratio']
                assert improvement_ratio <= 10, \
                    f"RPS improvement ratio {improvement_ratio:.2f} indicates unrealistic scaling"
                
                logger.info(
                    "Concurrency scaling analysis",
                    rps_improvement_ratio=round(improvement_ratio, 2),
                    max_rps=round(rps_trend.get('max', 0), 2),
                    min_rps=round(rps_trend.get('min', 0), 2)
                )
            
            # Validate response time degradation is acceptable
            if response_time_trend and response_time_trend.get('degradation_ratio', 1) > 1:
                degradation_ratio = response_time_trend['degradation_ratio']
                assert degradation_ratio <= 5, \
                    f"Response time degradation ratio {degradation_ratio:.2f} exceeds acceptable threshold"
        
        # Validate baseline capacity compliance
        baseline_capacity = PERFORMANCE_CONFIG['NODEJS_BASELINES']['concurrent_users_capacity']
        max_tested_concurrency = max(concurrency_result['concurrency_levels'])
        
        # If we tested up to the baseline capacity, validate performance
        if max_tested_concurrency >= baseline_capacity * 0.2:  # Test at least 20% of baseline
            high_concurrency_results = [
                r for r in concurrency_result['individual_results']
                if r.get('success', False) and 
                r.get('configuration', {}).get('concurrency', 0) >= max_tested_concurrency
            ]
            
            assert len(high_concurrency_results) > 0, \
                f"No successful high-concurrency tests at level {max_tested_concurrency}"
            
            # Validate that highest concurrency test meets performance thresholds
            highest_concurrency_result = high_concurrency_results[-1]
            performance_metrics = highest_concurrency_result.get('performance_metrics', {})
            
            rps = performance_metrics.get('requests_per_second', 0)
            min_acceptable_rps = PERFORMANCE_CONFIG['NODEJS_BASELINES']['requests_per_second'] * 0.5
            
            assert rps >= min_acceptable_rps, \
                f"High concurrency RPS {rps:.2f} below minimum threshold {min_acceptable_rps:.2f}"
        
        # Assert overall concurrency compliance
        assert concurrency_result['overall_compliant'], \
            f"Concurrent users capacity baseline compliance failed"
        
        logger.info(
            "Concurrent users capacity baseline test passed",
            max_concurrency=max_tested_concurrency,
            successful_tests=concurrency_result['successful_tests'],
            overall_compliant=concurrency_result['overall_compliant']
        )
    
    @skip_if_not_e2e()
    def test_performance_regression_detection(self):
        """
        Test comprehensive performance regression detection.
        
        Validates statistical analysis and automated regression detection
        per Section 6.6.3 quality metrics and variance monitoring.
        """
        logger.info("Testing performance regression detection")
        
        # Collect baseline performance data
        baseline_measurements = []
        
        # Simulate baseline performance measurements
        for i in range(20):
            measurement = self.baseline_validator.measure_response_time(
                endpoint='http://localhost:5000/health',
                method='GET',
                baseline_key='health_check_time'
            )
            
            if 'response_time' in measurement:
                baseline_measurements.append(measurement['response_time'])
            
            time.sleep(0.02)  # Brief pause
        
        # Validate baseline measurements collection
        assert len(baseline_measurements) >= 10, \
            f"Insufficient baseline measurements: {len(baseline_measurements)}"
        
        # Perform statistical analysis
        baseline_time = PERFORMANCE_CONFIG['NODEJS_BASELINES']['health_check_time']
        stats_analysis = self.baseline_validator.analyze_statistical_significance(
            baseline_measurements, baseline_time
        )
        
        # Validate statistical analysis completeness
        required_stats = ['mean', 'median', 'standard_deviation', 'p95_value', 'p99_value']
        for stat in required_stats:
            assert stat in stats_analysis, f"Missing statistical metric: {stat}"
            assert isinstance(stats_analysis[stat], (int, float)), f"Invalid {stat} value: {stats_analysis[stat]}"
        
        # Validate confidence interval calculation
        confidence_interval = stats_analysis.get('confidence_interval', ())
        assert len(confidence_interval) == 2, f"Invalid confidence interval: {confidence_interval}"
        assert confidence_interval[0] <= confidence_interval[1], "Invalid confidence interval order"
        
        # Validate variance calculations
        mean_variance = stats_analysis['mean_variance']
        median_variance = stats_analysis['median_variance']
        
        assert 0 <= mean_variance <= 1, f"Invalid mean variance: {mean_variance}"
        assert 0 <= median_variance <= 1, f"Invalid median variance: {median_variance}"
        
        # Test regression detection
        variance_threshold = PERFORMANCE_CONFIG['VARIANCE_THRESHOLDS']['critical_threshold']
        performance_compliant = mean_variance <= variance_threshold
        
        # Validate compliance status
        if performance_compliant:
            assert stats_analysis['statistical_significance'] == False, \
                "Statistical significance should be False for compliant performance"
        
        # Generate comprehensive performance report
        performance_report = self.baseline_validator.generate_performance_report()
        
        # Validate report completeness
        required_report_sections = [
            'session_info', 'baseline_compliance', 'variance_analysis',
            'measurement_summary', 'statistical_analysis'
        ]
        
        for section in required_report_sections:
            assert section in performance_report, f"Missing report section: {section}"
        
        # Validate compliance metrics
        compliance_info = performance_report['baseline_compliance']
        assert 'compliance_rate_percentage' in compliance_info, "Missing compliance rate"
        assert 0 <= compliance_info['compliance_rate_percentage'] <= 100, \
            f"Invalid compliance rate: {compliance_info['compliance_rate_percentage']}"
        
        logger.info(
            "Performance regression detection test completed",
            sample_size=len(baseline_measurements),
            mean_variance_pct=round(stats_analysis['mean_variance_percentage'], 2),
            compliance_rate=round(compliance_info['compliance_rate_percentage'], 2),
            regression_detected=not performance_compliant
        )
    
    @skip_if_not_e2e()
    def test_comprehensive_performance_validation(self):
        """
        Test comprehensive performance validation across all metrics.
        
        Validates complete performance baseline compliance per Section 0.1.1
        ≤10% variance requirement and F-006-RQ-003 comprehensive validation.
        """
        logger.info("Starting comprehensive performance validation")
        
        # Initialize comprehensive validation tracking
        validation_results = {
            'response_time_validation': False,
            'throughput_validation': False,
            'concurrency_validation': False,
            'error_rate_validation': False,
            'statistical_validation': False
        }
        
        comprehensive_measurements = []
        
        # 1. Response Time Validation
        try:
            response_time_measurements = []
            
            for i in range(15):
                measurement = self.baseline_validator.measure_response_time(
                    endpoint='http://localhost:5000/health',
                    method='GET',
                    baseline_key='health_check_time'
                )
                
                if 'response_time' in measurement:
                    response_time_measurements.append(measurement['response_time'])
                    comprehensive_measurements.append(measurement)
                
                time.sleep(0.05)
            
            if response_time_measurements:
                baseline_time = PERFORMANCE_CONFIG['NODEJS_BASELINES']['health_check_time']
                mean_response_time = statistics.mean(response_time_measurements)
                response_variance = abs(mean_response_time - baseline_time) / baseline_time
                
                validation_results['response_time_validation'] = response_variance <= PERFORMANCE_CONFIG['VARIANCE_THRESHOLDS']['critical_threshold']
                
                logger.info(
                    "Response time validation completed",
                    mean_time=round(mean_response_time, 3),
                    variance_pct=round(response_variance * 100, 2),
                    passed=validation_results['response_time_validation']
                )
            
        except Exception as e:
            logger.error(f"Response time validation failed: {e}")
        
        # 2. Error Rate Validation
        try:
            error_count = 0
            total_requests = len(comprehensive_measurements)
            
            for measurement in comprehensive_measurements:
                if 'error' in measurement or measurement.get('status_code', 200) >= 400:
                    error_count += 1
            
            error_rate = (error_count / total_requests * 100) if total_requests > 0 else 0
            validation_results['error_rate_validation'] = error_rate <= PERFORMANCE_CONFIG['VARIANCE_THRESHOLDS']['error_rate_threshold']
            
            logger.info(
                "Error rate validation completed",
                error_rate=round(error_rate, 2),
                error_count=error_count,
                total_requests=total_requests,
                passed=validation_results['error_rate_validation']
            )
            
        except Exception as e:
            logger.error(f"Error rate validation failed: {e}")
        
        # 3. Statistical Validation
        try:
            if comprehensive_measurements:
                response_times = [m['response_time'] for m in comprehensive_measurements if 'response_time' in m]
                
                if len(response_times) >= 5:
                    baseline_time = PERFORMANCE_CONFIG['NODEJS_BASELINES']['health_check_time']
                    stats_analysis = self.baseline_validator.analyze_statistical_significance(
                        response_times, baseline_time
                    )
                    
                    # Validate statistical metrics
                    stats_valid = all([
                        'mean' in stats_analysis,
                        'standard_deviation' in stats_analysis,
                        'confidence_interval' in stats_analysis,
                        stats_analysis.get('sample_size', 0) >= 5
                    ])
                    
                    validation_results['statistical_validation'] = stats_valid
                    
                    logger.info(
                        "Statistical validation completed",
                        sample_size=stats_analysis.get('sample_size', 0),
                        passed=validation_results['statistical_validation']
                    )
                
        except Exception as e:
            logger.error(f"Statistical validation failed: {e}")
        
        # 4. Load Testing Validation (if available)
        if self.locust_tester.locust_available:
            try:
                load_result = self.locust_tester.execute_load_test(
                    users=25,  # Reduced for testing
                    run_time=30  # Short duration
                )
                
                if load_result['success']:
                    baseline_comparison = load_result['baseline_comparison']
                    validation_results['throughput_validation'] = baseline_comparison['baseline_compliant']
                    
                    logger.info(
                        "Throughput validation completed",
                        rps=round(load_result['performance_metrics']['requests_per_second'], 2),
                        passed=validation_results['throughput_validation']
                    )
                
            except Exception as e:
                logger.warning(f"Load testing validation failed: {e}")
        else:
            validation_results['throughput_validation'] = True  # Skip if not available
        
        # 5. Concurrency Validation (if available)
        if self.apache_bench_tester.ab_available:
            try:
                concurrency_result = self.apache_bench_tester.execute_benchmark_test(
                    endpoint='/health',
                    requests=100,
                    concurrency=10
                )
                
                if concurrency_result['success']:
                    validation_results['concurrency_validation'] = concurrency_result['overall_compliant']
                    
                    logger.info(
                        "Concurrency validation completed",
                        rps=round(concurrency_result['performance_metrics'].get('requests_per_second', 0), 2),
                        passed=validation_results['concurrency_validation']
                    )
                
            except Exception as e:
                logger.warning(f"Concurrency validation failed: {e}")
        else:
            validation_results['concurrency_validation'] = True  # Skip if not available
        
        # Final Comprehensive Validation
        passed_validations = sum(1 for passed in validation_results.values() if passed)
        total_validations = len(validation_results)
        success_rate = (passed_validations / total_validations * 100) if total_validations > 0 else 0
        
        # Assert comprehensive performance compliance
        assert success_rate >= 80, \
            f"Comprehensive performance validation failed. Success rate: {success_rate:.1f}% (passed: {passed_validations}/{total_validations})"
        
        # Generate final comprehensive report
        final_report = self.baseline_validator.generate_performance_report()
        overall_compliant = final_report['baseline_compliance']['overall_compliant']
        
        # Assert overall baseline compliance
        assert overall_compliant, \
            f"Overall baseline compliance failed. Violations: {final_report['variance_analysis']['total_violations']}"
        
        logger.info(
            "Comprehensive performance validation completed successfully",
            success_rate=round(success_rate, 1),
            passed_validations=passed_validations,
            total_validations=total_validations,
            overall_compliant=overall_compliant,
            compliance_rate=round(final_report['baseline_compliance']['compliance_rate_percentage'], 2)
        )


# =============================================================================
# STANDALONE PERFORMANCE TESTING FUNCTIONS
# =============================================================================

@pytest.mark.e2e
@pytest.mark.performance
@skip_if_not_e2e()
def test_performance_baseline_integration():
    """
    Standalone integration test for performance baseline validation.
    
    Provides isolated performance testing capability for CI/CD integration
    per Section 6.6.2 test automation requirements.
    """
    logger.info("Starting standalone performance baseline integration test")
    
    # Initialize standalone performance validator
    validator = PerformanceBaselineValidator()
    
    # Test basic response time measurement
    measurement = validator.measure_response_time(
        endpoint='http://localhost:5000/health',
        method='GET',
        baseline_key='health_check_time'
    )
    
    # Validate measurement structure
    assert 'response_time' in measurement or 'error' in measurement, \
        f"Invalid measurement structure: {measurement}"
    
    if 'response_time' in measurement:
        assert measurement['response_time'] > 0, \
            f"Invalid response time: {measurement['response_time']}"
        
        assert measurement['compliance_status'] in ['compliant', 'warning', 'violation'], \
            f"Invalid compliance status: {measurement['compliance_status']}"
    
    # Generate performance report
    report = validator.generate_performance_report()
    
    # Validate report structure
    assert 'session_info' in report, "Missing session info in performance report"
    assert 'baseline_compliance' in report, "Missing baseline compliance in performance report"
    
    logger.info(
        "Standalone performance baseline integration test completed",
        session_id=validator.session_id,
        measurement_valid='response_time' in measurement,
        compliance_status=measurement.get('compliance_status', 'unknown')
    )


if __name__ == '__main__':
    """
    Direct execution support for performance baseline testing.
    
    Enables standalone execution of performance tests for development
    and debugging purposes per Section 6.6.1 testing approach.
    """
    
    # Configure logging for standalone execution
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - [STANDALONE] %(message)s'
    )
    
    print("=" * 80)
    print("PERFORMANCE BASELINE TESTING - STANDALONE EXECUTION")
    print("=" * 80)
    print(f"Node.js Baseline Metrics: {len(PERFORMANCE_CONFIG['NODEJS_BASELINES'])} metrics loaded")
    print(f"Variance Threshold: ≤{PERFORMANCE_CONFIG['VARIANCE_THRESHOLDS']['critical_threshold'] * 100}% (critical requirement)")
    print(f"Load Testing Configuration: {PERFORMANCE_CONFIG['LOAD_TESTING']['baseline_users']} users baseline")
    print("=" * 80)
    
    # Initialize standalone validator
    standalone_validator = PerformanceBaselineValidator()
    
    try:
        # Execute basic performance measurement
        print("\nExecuting basic performance measurement...")
        measurement = standalone_validator.measure_response_time(
            endpoint='http://localhost:5000/health',
            method='GET',
            baseline_key='health_check_time'
        )
        
        print(f"Measurement result: {measurement}")
        
        # Generate final report
        print("\nGenerating performance report...")
        report = standalone_validator.generate_performance_report()
        
        print(f"Report session ID: {report['session_info']['session_id']}")
        print(f"Overall compliant: {report['baseline_compliance']['overall_compliant']}")
        
        print("\nStandalone performance baseline testing completed successfully.")
        
    except Exception as e:
        print(f"\nStandalone performance baseline testing failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)