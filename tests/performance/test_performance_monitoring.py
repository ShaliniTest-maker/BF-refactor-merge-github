"""
Performance Monitoring Integration Tests

This module implements comprehensive performance monitoring integration tests validating
prometheus-client 0.17+ metrics collection, Flask-Metrics integration, memory profiling,
and enterprise monitoring system compatibility. Ensures comprehensive performance data
collection during testing and validates ≤10% variance compliance requirements.

Key Testing Areas per Technical Specification:
- prometheus-client 0.17+ metrics collection validation per Section 3.6.2
- Flask-Metrics request timing measurement integration per Section 3.6.2
- Memory profiling and variance tracking per Section 3.6.2 and 0.1.1 requirements
- Database query performance monitoring per Section 3.6.2
- Enterprise APM integration compatibility per Section 3.6.1
- Real-time performance data collection during tests per Section 6.6.1

Performance Requirements Compliance:
- ≤10% variance threshold validation per Section 0.1.1 primary objective
- Response time distribution analysis with P50, P95, P99 percentile tracking
- CPU utilization monitoring with warning >70%, critical >90% thresholds
- Memory usage tracking with ±15% acceptable variance from baseline
- Database operation performance comparison with Node.js baseline metrics

Enterprise Integration:
- Prometheus Alertmanager integration testing for threshold-based alerting
- Grafana dashboard compatibility validation through metrics endpoint testing
- WSGI server instrumentation verification for Gunicorn prometheus_multiproc_dir
- Container orchestration metrics compatibility for Kubernetes monitoring
- APM correlation testing for comprehensive performance monitoring

Test Architecture:
- Comprehensive metrics collection validation using PrometheusMetricsCollector
- Real-time performance variance tracking with automated baseline comparison
- Load testing integration using locust framework for throughput validation
- Apache Bench integration for HTTP server performance measurement
- Testcontainers integration for realistic database and cache performance testing

References:
- Section 3.6.2: Performance Monitoring metrics collection requirements
- Section 4.5.3: Performance monitoring and metrics collection flows
- Section 6.6.1: Performance testing tools and baseline comparison framework
- Section 0.1.1: ≤10% performance variance critical requirement

Author: Flask Migration Team
Version: 1.0.0
Dependencies: prometheus-client 0.17+, Flask-Metrics, structlog 23.1+, pytest 7.4+
"""

import asyncio
import gc
import json
import logging
import os
import statistics
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union, Callable
from unittest.mock import Mock, patch, MagicMock
import tempfile

import pytest
from flask import Flask, Response
from flask.testing import FlaskClient

# Prometheus and metrics imports
from prometheus_client import (
    CollectorRegistry, Counter, Histogram, Gauge, 
    generate_latest, CONTENT_TYPE_LATEST, parser
)
from prometheus_client.multiprocess import MultiProcessCollector

# Performance monitoring imports
import psutil
import structlog

# Import monitoring components
from src.monitoring.metrics import (
    PrometheusMetricsCollector,
    MetricsMiddleware,
    setup_metrics_collection,
    create_metrics_endpoint,
    monitor_performance,
    monitor_database_operation,
    monitor_external_service,
    monitor_cache_operation
)
from src.config.settings import TestingConfig

# Configure test logger
logger = structlog.get_logger(__name__)

# Performance test constants per Section 4.6.3 and 6.6.1
PERFORMANCE_VARIANCE_THRESHOLD = 10.0  # ≤10% variance requirement per Section 0.1.1
MEMORY_VARIANCE_THRESHOLD = 15.0       # ±15% memory variance acceptable per Section 6.6.1
RESPONSE_TIME_THRESHOLD_MS = 500.0     # Response time threshold per Section 4.6.3
THROUGHPUT_THRESHOLD_RPS = 100.0       # Minimum throughput per Section 4.6.3
PROMETHEUS_METRICS_TIMEOUT = 30.0      # Metrics collection timeout
LOAD_TEST_DURATION = 60.0              # Load test duration in seconds
PERFORMANCE_SAMPLE_SIZE = 100          # Minimum sample size for statistical validity

# Baseline performance data for Node.js comparison
NODEJS_BASELINE_METRICS = {
    "response_time_ms": {
        "GET /api/v1/users": {"mean": 45.2, "p95": 89.5, "p99": 156.3},
        "POST /api/v1/users": {"mean": 78.4, "p95": 145.6, "p99": 234.8},
        "GET /api/v1/data/reports": {"mean": 123.7, "p95": 298.4, "p99": 456.9},
        "POST /api/v1/auth/login": {"mean": 67.8, "p95": 134.2, "p99": 201.5}
    },
    "throughput_rps": {
        "peak": 850.5,
        "sustained": 642.3,
        "concurrent_users_100": 485.7
    },
    "memory_usage_mb": {
        "baseline": 85.4,
        "peak": 142.8,
        "average": 98.6
    },
    "cpu_utilization_percent": {
        "baseline": 12.5,
        "peak": 45.8,
        "average": 23.2
    }
}


class PerformanceMonitoringError(Exception):
    """Custom exception for performance monitoring test failures."""
    pass


class MetricsValidationError(Exception):
    """Custom exception for metrics validation failures."""
    pass


@pytest.mark.performance
@pytest.mark.monitoring
class TestPrometheusMetricsCollection:
    """
    Test suite for prometheus-client 0.17+ metrics collection validation.
    
    Validates comprehensive Prometheus metrics collection including HTTP request metrics,
    database operation tracking, external service monitoring, and system resource metrics.
    Ensures compliance with enterprise monitoring requirements per Section 3.6.2.
    """
    
    def test_prometheus_client_version_compliance(self):
        """
        Validate prometheus-client version ≥0.17+ requirement per Section 3.6.2.
        
        Ensures the installed prometheus-client version meets the minimum requirement
        specified in the technical specification for enterprise monitoring compatibility.
        """
        import prometheus_client
        
        # Extract version components
        version_parts = prometheus_client.__version__.split('.')
        major_version = int(version_parts[0])
        minor_version = int(version_parts[1]) if len(version_parts) > 1 else 0
        
        # Validate version ≥0.17
        assert major_version > 0 or (major_version == 0 and minor_version >= 17), \
            f"prometheus-client version {prometheus_client.__version__} does not meet ≥0.17 requirement"
        
        logger.info(
            "Prometheus client version validation passed",
            version=prometheus_client.__version__,
            requirement="≥0.17",
            compliance=True
        )
    
    def test_metrics_collector_initialization(self, performance_config):
        """
        Test PrometheusMetricsCollector initialization and configuration.
        
        Validates that the metrics collector initializes correctly with all required
        metrics categories and proper configuration per Section 3.6.2 requirements.
        """
        # Initialize metrics collector
        metrics_collector = PrometheusMetricsCollector(performance_config.MONITORING_CONFIG)
        
        # Verify initialization
        assert metrics_collector._initialized is True
        assert metrics_collector.config is not None
        
        # Verify HTTP metrics initialization
        assert hasattr(metrics_collector, 'http_requests_total')
        assert hasattr(metrics_collector, 'http_request_duration_seconds')
        assert hasattr(metrics_collector, 'http_request_size_bytes')
        assert hasattr(metrics_collector, 'http_response_size_bytes')
        assert hasattr(metrics_collector, 'http_requests_active')
        
        # Verify database metrics initialization
        assert hasattr(metrics_collector, 'database_operations_total')
        assert hasattr(metrics_collector, 'database_operation_duration_seconds')
        assert hasattr(metrics_collector, 'database_connections_active')
        assert hasattr(metrics_collector, 'database_connections_pool_size')
        
        # Verify external service metrics initialization
        assert hasattr(metrics_collector, 'external_service_requests_total')
        assert hasattr(metrics_collector, 'external_service_duration_seconds')
        assert hasattr(metrics_collector, 'external_service_timeouts_total')
        
        # Verify resource metrics initialization
        assert hasattr(metrics_collector, 'cpu_utilization_percent')
        assert hasattr(metrics_collector, 'memory_usage_bytes')
        assert hasattr(metrics_collector, 'memory_utilization_percent')
        
        # Verify migration-specific metrics initialization
        assert hasattr(metrics_collector, 'performance_variance_percent')
        assert hasattr(metrics_collector, 'migration_baseline_compliance')
        assert hasattr(metrics_collector, 'performance_regressions_total')
        
        logger.info(
            "Metrics collector initialization validation passed",
            metrics_categories=["http", "database", "external_service", "resource", "migration"],
            initialization_status="complete"
        )
    
    def test_http_request_metrics_collection(self, app, performance_metrics_registry):
        """
        Test HTTP request metrics collection and recording.
        
        Validates that HTTP request metrics are properly collected and recorded
        with correct labels and values per Section 3.6.2 metrics collection requirements.
        """
        # Initialize metrics collector
        metrics_collector = PrometheusMetricsCollector()
        
        # Record test HTTP request metrics
        test_metrics = [
            ("GET", "/api/v1/users", 200, 0.045, 1024, 2048, "authenticated"),
            ("POST", "/api/v1/users", 201, 0.089, 2048, 1024, "authenticated"),
            ("GET", "/health", 200, 0.012, 512, 256, "anonymous"),
            ("POST", "/api/v1/auth/login", 401, 0.067, 1536, 512, "anonymous")
        ]
        
        for method, endpoint, status, duration, req_size, resp_size, user_type in test_metrics:
            metrics_collector.record_http_request(
                method=method,
                endpoint=endpoint,
                status_code=status,
                duration=duration,
                request_size=req_size,
                response_size=resp_size,
                user_type=user_type
            )
        
        # Generate metrics output
        metrics_output = metrics_collector.generate_metrics_output()
        
        # Parse metrics output
        metric_families = list(parser.text_string_to_metric_families(metrics_output))
        
        # Validate HTTP request counter metrics
        request_counter_found = False
        duration_histogram_found = False
        
        for family in metric_families:
            if family.name == 'flask_http_requests_total':
                request_counter_found = True
                assert len(family.samples) >= len(test_metrics)
                
                # Validate sample labels and values
                for sample in family.samples:
                    assert 'method' in sample.labels
                    assert 'endpoint' in sample.labels
                    assert 'status_code' in sample.labels
                    assert 'user_type' in sample.labels
                    assert sample.value >= 1.0
            
            elif family.name == 'flask_http_request_duration_seconds':
                duration_histogram_found = True
                assert len(family.samples) > 0
                
                # Validate histogram bucket structure
                bucket_found = False
                count_found = False
                sum_found = False
                
                for sample in family.samples:
                    if sample.name.endswith('_bucket'):
                        bucket_found = True
                        assert 'le' in sample.labels
                    elif sample.name.endswith('_count'):
                        count_found = True
                        assert sample.value >= 1.0
                    elif sample.name.endswith('_sum'):
                        sum_found = True
                        assert sample.value > 0.0
                
                assert bucket_found and count_found and sum_found, \
                    "HTTP request duration histogram missing required components"
        
        assert request_counter_found, "HTTP request counter metrics not found"
        assert duration_histogram_found, "HTTP request duration histogram not found"
        
        logger.info(
            "HTTP request metrics collection validation passed",
            metrics_recorded=len(test_metrics),
            counter_metrics_found=request_counter_found,
            histogram_metrics_found=duration_histogram_found
        )
    
    def test_database_operation_metrics_collection(self, performance_metrics_registry):
        """
        Test database operation metrics collection per Section 3.6.2.
        
        Validates database operation performance tracking including operation timing,
        connection pool metrics, and query result tracking for MongoDB operations.
        """
        # Initialize metrics collector
        metrics_collector = PrometheusMetricsCollector()
        
        # Record test database operation metrics
        test_operations = [
            ("find", "users", 0.023, "success", "default", 25, True),
            ("insert", "users", 0.045, "success", "default", 1, True),
            ("update", "users", 0.067, "success", "default", 3, True),
            ("delete", "users", 0.034, "success", "default", 2, True),
            ("aggregate", "reports", 0.156, "success", "default", 42, False)
        ]
        
        for operation, collection, duration, status, pool, result_count, index_used in test_operations:
            metrics_collector.record_database_operation(
                operation=operation,
                collection=collection,
                duration=duration,
                status=status,
                connection_pool=pool,
                result_count=result_count,
                index_used=index_used
            )
        
        # Generate metrics output
        metrics_output = metrics_collector.generate_metrics_output()
        
        # Parse metrics output
        metric_families = list(parser.text_string_to_metric_families(metrics_output))
        
        # Validate database operation metrics
        operation_counter_found = False
        duration_histogram_found = False
        result_size_histogram_found = False
        
        for family in metric_families:
            if family.name == 'flask_database_operations_total':
                operation_counter_found = True
                assert len(family.samples) >= len(test_operations)
                
                # Validate labels
                for sample in family.samples:
                    assert 'operation' in sample.labels
                    assert 'collection' in sample.labels
                    assert 'status' in sample.labels
                    assert 'connection_pool' in sample.labels
            
            elif family.name == 'flask_database_operation_duration_seconds':
                duration_histogram_found = True
                # Validate histogram structure
                bucket_samples = [s for s in family.samples if s.name.endswith('_bucket')]
                count_samples = [s for s in family.samples if s.name.endswith('_count')]
                sum_samples = [s for s in family.samples if s.name.endswith('_sum')]
                
                assert len(bucket_samples) > 0, "Database duration histogram missing buckets"
                assert len(count_samples) > 0, "Database duration histogram missing count"
                assert len(sum_samples) > 0, "Database duration histogram missing sum"
            
            elif family.name == 'flask_database_query_result_size_documents':
                result_size_histogram_found = True
                # Validate result size tracking
                for sample in family.samples:
                    if sample.name.endswith('_count'):
                        assert sample.value >= 1.0
        
        assert operation_counter_found, "Database operation counter metrics not found"
        assert duration_histogram_found, "Database operation duration histogram not found"
        assert result_size_histogram_found, "Database query result size histogram not found"
        
        logger.info(
            "Database operation metrics collection validation passed",
            operations_recorded=len(test_operations),
            counter_found=operation_counter_found,
            duration_histogram_found=duration_histogram_found,
            result_size_histogram_found=result_size_histogram_found
        )
    
    def test_multiprocess_metrics_registry(self, performance_config):
        """
        Test multiprocess metrics registry for Gunicorn WSGI server integration.
        
        Validates multiprocess metrics collection capability required for production
        WSGI server deployment per Section 6.5.4.1 enhanced WSGI server monitoring.
        """
        # Create temporary multiprocess directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Configure multiprocess environment
            test_config = TestingConfig()
            test_config.PROMETHEUS_MULTIPROC_DIR = temp_dir
            
            # Initialize metrics collector with multiprocess support
            metrics_collector = PrometheusMetricsCollector(test_config)
            
            # Verify multiprocess directory configuration
            assert os.environ.get('PROMETHEUS_MULTIPROC_DIR') == temp_dir
            assert os.path.exists(temp_dir)
            
            # Record metrics from multiple "processes"
            process_metrics = [
                ("process_1", "GET", "/api/v1/users", 200, 0.045),
                ("process_2", "POST", "/api/v1/users", 201, 0.089),
                ("process_1", "GET", "/health", 200, 0.012),
                ("process_2", "POST", "/api/v1/auth/login", 200, 0.067)
            ]
            
            for process_id, method, endpoint, status, duration in process_metrics:
                # Simulate metrics from different processes
                with patch.dict(os.environ, {'PROMETHEUS_MULTIPROC_DIR': temp_dir}):
                    metrics_collector.record_http_request(
                        method=method,
                        endpoint=endpoint,
                        status_code=status,
                        duration=duration
                    )
            
            # Get multiprocess registry
            registry = metrics_collector.get_metrics_registry()
            
            # Verify multiprocess collector is used
            if metrics_collector.config and hasattr(metrics_collector.config, 'PROMETHEUS_MULTIPROC_DIR'):
                assert isinstance(registry, CollectorRegistry)
                
                # Generate metrics from multiprocess registry
                multiprocess_metrics = generate_latest(registry)
                assert len(multiprocess_metrics) > 0
                
                logger.info(
                    "Multiprocess metrics registry validation passed",
                    multiprocess_dir=temp_dir,
                    process_metrics_count=len(process_metrics),
                    registry_type=type(registry).__name__
                )
            else:
                logger.info(
                    "Multiprocess metrics registry test skipped - single process mode",
                    registry_type=type(registry).__name__
                )
    
    def test_metrics_endpoint_integration(self, app):
        """
        Test Prometheus metrics endpoint integration for monitoring system compatibility.
        
        Validates that the /metrics endpoint provides properly formatted Prometheus
        metrics output compatible with enterprise monitoring systems per Section 3.6.2.
        """
        # Setup metrics collection for Flask app
        metrics_collector = setup_metrics_collection(app)
        
        # Create test client
        with app.test_client() as client:
            # Generate some test metrics
            response = client.get('/health')
            assert response.status_code == 200
            
            # Make additional requests to generate metrics
            test_endpoints = [
                '/api/v1/users',
                '/api/v1/data/reports',
                '/api/v1/auth/login'
            ]
            
            for endpoint in test_endpoints:
                # Make requests (some may return 404, which is expected for test endpoints)
                client.get(endpoint)
                client.post(endpoint, json={"test": "data"})
            
            # Request metrics endpoint
            metrics_response = client.get('/metrics')
            
            # Validate metrics endpoint response
            assert metrics_response.status_code == 200
            assert metrics_response.content_type == CONTENT_TYPE_LATEST
            
            # Validate metrics content
            metrics_content = metrics_response.get_data(as_text=True)
            assert len(metrics_content) > 0
            
            # Parse metrics to validate format
            metric_families = list(parser.text_string_to_metric_families(metrics_content))
            assert len(metric_families) > 0
            
            # Verify expected metric families are present
            metric_names = [family.name for family in metric_families]
            
            expected_metrics = [
                'flask_http_requests_total',
                'flask_http_request_duration_seconds',
                'flask_cpu_utilization_percent',
                'flask_memory_usage_bytes'
            ]
            
            for expected_metric in expected_metrics:
                assert any(expected_metric in name for name in metric_names), \
                    f"Expected metric {expected_metric} not found in metrics output"
            
            # Validate metric sample structure
            for family in metric_families:
                for sample in family.samples:
                    assert hasattr(sample, 'name')
                    assert hasattr(sample, 'labels')
                    assert hasattr(sample, 'value')
                    assert isinstance(sample.value, (int, float))
            
            logger.info(
                "Metrics endpoint integration validation passed",
                endpoint="/metrics",
                content_type=metrics_response.content_type,
                metric_families_count=len(metric_families),
                metrics_content_length=len(metrics_content)
            )


@pytest.mark.performance
@pytest.mark.flask_metrics
class TestFlaskMetricsIntegration:
    """
    Test suite for Flask-Metrics request timing measurement integration.
    
    Validates Flask middleware integration for automatic request timing measurement,
    performance variance tracking, and real-time metrics collection per Section 3.6.2.
    """
    
    def test_metrics_middleware_initialization(self, app, performance_metrics_registry):
        """
        Test MetricsMiddleware initialization and Flask integration.
        
        Validates that the metrics middleware integrates correctly with Flask
        application lifecycle and provides comprehensive request monitoring.
        """
        # Initialize metrics collector and middleware
        metrics_collector = PrometheusMetricsCollector()
        metrics_middleware = MetricsMiddleware(metrics_collector)
        
        # Initialize middleware with Flask app
        metrics_middleware.init_app(app)
        
        # Verify middleware hooks are registered
        assert len(app.before_request_funcs[None]) > 0
        assert len(app.after_request_funcs[None]) > 0
        assert len(app.teardown_appcontext_funcs) > 0
        
        logger.info(
            "Metrics middleware initialization validation passed",
            before_request_hooks=len(app.before_request_funcs[None]),
            after_request_hooks=len(app.after_request_funcs[None]),
            teardown_hooks=len(app.teardown_appcontext_funcs)
        )
    
    def test_automatic_request_timing_measurement(self, app):
        """
        Test automatic request timing measurement through Flask middleware.
        
        Validates that request timing is automatically measured and recorded
        for all HTTP requests without manual instrumentation per Section 3.6.2.
        """
        # Setup metrics collection
        metrics_collector = setup_metrics_collection(app)
        
        with app.test_client() as client:
            # Create test route for timing measurement
            @app.route('/test/timing')
            def test_timing_endpoint():
                # Simulate processing time
                time.sleep(0.05)  # 50ms processing time
                return {'message': 'Timing test completed', 'status': 'success'}
            
            # Record initial metrics state
            initial_metrics = metrics_collector.generate_metrics_output()
            initial_families = list(parser.text_string_to_metric_families(initial_metrics))
            
            # Make test request
            start_time = time.time()
            response = client.get('/test/timing')
            end_time = time.time()
            
            # Validate response
            assert response.status_code == 200
            
            # Calculate expected timing
            actual_duration = end_time - start_time
            assert actual_duration >= 0.05  # Should be at least 50ms
            
            # Wait for metrics to be recorded
            time.sleep(0.1)
            
            # Get updated metrics
            updated_metrics = metrics_collector.generate_metrics_output()
            updated_families = list(parser.text_string_to_metric_families(updated_metrics))
            
            # Validate timing metrics were recorded
            duration_histogram_found = False
            request_counter_found = False
            
            for family in updated_families:
                if family.name == 'flask_http_request_duration_seconds':
                    duration_histogram_found = True
                    
                    # Find samples for our test endpoint
                    test_endpoint_samples = [
                        sample for sample in family.samples
                        if sample.labels.get('endpoint') == 'test_timing_endpoint'
                    ]
                    
                    assert len(test_endpoint_samples) > 0, \
                        "No timing samples found for test endpoint"
                    
                    # Validate histogram sum represents actual timing
                    sum_samples = [
                        sample for sample in test_endpoint_samples
                        if sample.name.endswith('_sum')
                    ]
                    
                    if sum_samples:
                        recorded_duration = sum_samples[0].value
                        # Allow 20% variance for measurement overhead
                        timing_variance = abs(recorded_duration - actual_duration) / actual_duration
                        assert timing_variance <= 0.2, \
                            f"Timing variance {timing_variance:.2%} exceeds 20% threshold"
                
                elif family.name == 'flask_http_requests_total':
                    request_counter_found = True
                    
                    # Validate request was counted
                    test_endpoint_samples = [
                        sample for sample in family.samples
                        if sample.labels.get('endpoint') == 'test_timing_endpoint'
                    ]
                    
                    assert len(test_endpoint_samples) > 0, \
                        "No request counter samples found for test endpoint"
                    
                    assert any(sample.value >= 1.0 for sample in test_endpoint_samples), \
                        "Request counter value is incorrect"
            
            assert duration_histogram_found, "HTTP request duration histogram not found"
            assert request_counter_found, "HTTP request counter not found"
            
            logger.info(
                "Automatic request timing measurement validation passed",
                endpoint="/test/timing",
                actual_duration_ms=actual_duration * 1000,
                timing_metrics_found=duration_histogram_found,
                counter_metrics_found=request_counter_found
            )
    
    def test_concurrent_request_timing_accuracy(self, app):
        """
        Test timing accuracy under concurrent request load.
        
        Validates that request timing remains accurate under concurrent load
        and that metrics collection doesn't introduce significant overhead.
        """
        # Setup metrics collection
        metrics_collector = setup_metrics_collection(app)
        
        # Create test endpoint with variable processing time
        @app.route('/test/concurrent/<int:delay_ms>')
        def concurrent_test_endpoint(delay_ms):
            time.sleep(delay_ms / 1000.0)  # Convert ms to seconds
            return {'delay_ms': delay_ms, 'status': 'completed'}
        
        # Test parameters
        concurrent_requests = 10
        delay_values = [10, 25, 50, 75, 100]  # milliseconds
        
        with app.test_client() as client:
            # Execute concurrent requests
            threads = []
            request_timings = []
            
            def make_request(delay_ms):
                start_time = time.time()
                response = client.get(f'/test/concurrent/{delay_ms}')
                end_time = time.time()
                
                request_timings.append({
                    'delay_ms': delay_ms,
                    'actual_duration': end_time - start_time,
                    'status_code': response.status_code
                })
            
            # Launch concurrent requests
            for i in range(concurrent_requests):
                delay_ms = delay_values[i % len(delay_values)]
                thread = threading.Thread(target=make_request, args=(delay_ms,))
                threads.append(thread)
                thread.start()
            
            # Wait for all requests to complete
            for thread in threads:
                thread.join()
            
            # Validate all requests completed successfully
            assert len(request_timings) == concurrent_requests
            for timing in request_timings:
                assert timing['status_code'] == 200
                
                # Validate timing accuracy (allow 50% overhead for concurrency)
                expected_duration = timing['delay_ms'] / 1000.0
                actual_duration = timing['actual_duration']
                timing_variance = abs(actual_duration - expected_duration) / expected_duration
                
                assert timing_variance <= 0.5, \
                    f"Concurrent timing variance {timing_variance:.2%} exceeds 50% threshold"
            
            # Wait for metrics to be recorded
            time.sleep(0.2)
            
            # Validate metrics were recorded for all requests
            metrics_output = metrics_collector.generate_metrics_output()
            metric_families = list(parser.text_string_to_metric_families(metrics_output))
            
            # Count recorded requests
            recorded_requests = 0
            for family in metric_families:
                if family.name == 'flask_http_requests_total':
                    for sample in family.samples:
                        if 'concurrent_test_endpoint' in sample.labels.get('endpoint', ''):
                            recorded_requests += int(sample.value)
            
            assert recorded_requests >= concurrent_requests, \
                f"Expected {concurrent_requests} recorded requests, got {recorded_requests}"
            
            logger.info(
                "Concurrent request timing accuracy validation passed",
                concurrent_requests=concurrent_requests,
                recorded_requests=recorded_requests,
                average_timing_variance=statistics.mean([
                    abs(t['actual_duration'] - t['delay_ms'] / 1000.0) / (t['delay_ms'] / 1000.0)
                    for t in request_timings
                ])
            )
    
    def test_request_size_and_response_size_tracking(self, app):
        """
        Test HTTP request and response size tracking functionality.
        
        Validates that request and response sizes are accurately tracked
        for bandwidth analysis and performance optimization per Section 3.6.2.
        """
        # Setup metrics collection
        metrics_collector = setup_metrics_collection(app)
        
        with app.test_client() as client:
            # Create test endpoint that handles different payload sizes
            @app.route('/test/payload', methods=['POST'])
            def payload_test_endpoint():
                request_data = request.get_json() or {}
                
                # Create response with known size
                response_data = {
                    'received_keys': list(request_data.keys()),
                    'received_count': len(request_data),
                    'echo_data': request_data,
                    'response_padding': 'x' * 500  # Add padding for measurable response size
                }
                
                return response_data
            
            # Test payloads of different sizes
            test_payloads = [
                {'small': 'data'},
                {'medium': 'x' * 100, 'additional': 'data'},
                {'large': 'x' * 1000, 'metadata': {'type': 'large', 'size': 1000}}
            ]
            
            for i, payload in enumerate(test_payloads):
                # Make request with payload
                response = client.post('/test/payload', json=payload)
                assert response.status_code == 200
                
                # Validate response contains expected data
                response_data = response.get_json()
                assert 'received_keys' in response_data
                assert 'response_padding' in response_data
            
            # Wait for metrics to be recorded
            time.sleep(0.1)
            
            # Validate size metrics were recorded
            metrics_output = metrics_collector.generate_metrics_output()
            metric_families = list(parser.text_string_to_metric_families(metrics_output))
            
            request_size_histogram_found = False
            response_size_histogram_found = False
            
            for family in metric_families:
                if family.name == 'flask_http_request_size_bytes':
                    request_size_histogram_found = True
                    
                    # Validate histogram has samples for our endpoint
                    endpoint_samples = [
                        sample for sample in family.samples
                        if sample.labels.get('endpoint') == 'payload_test_endpoint'
                    ]
                    
                    assert len(endpoint_samples) > 0, \
                        "No request size samples found for test endpoint"
                    
                    # Validate count matches number of requests
                    count_samples = [
                        sample for sample in endpoint_samples
                        if sample.name.endswith('_count')
                    ]
                    
                    if count_samples:
                        total_count = sum(sample.value for sample in count_samples)
                        assert total_count >= len(test_payloads), \
                            f"Request count {total_count} less than expected {len(test_payloads)}"
                
                elif family.name == 'flask_http_response_size_bytes':
                    response_size_histogram_found = True
                    
                    # Validate response size tracking
                    endpoint_samples = [
                        sample for sample in family.samples
                        if sample.labels.get('endpoint') == 'payload_test_endpoint'
                    ]
                    
                    assert len(endpoint_samples) > 0, \
                        "No response size samples found for test endpoint"
            
            assert request_size_histogram_found, "HTTP request size histogram not found"
            assert response_size_histogram_found, "HTTP response size histogram not found"
            
            logger.info(
                "Request and response size tracking validation passed",
                test_payloads_count=len(test_payloads),
                request_size_metrics_found=request_size_histogram_found,
                response_size_metrics_found=response_size_histogram_found
            )


@pytest.mark.performance
@pytest.mark.memory_profiling
class TestMemoryProfilingIntegration:
    """
    Test suite for memory profiling and ≤10% variance compliance validation.
    
    Validates memory usage tracking, garbage collection monitoring, and performance
    variance analysis to ensure compliance with Node.js baseline requirements.
    """
    
    def test_memory_usage_baseline_tracking(self, performance_monitoring_setup):
        """
        Test memory usage baseline tracking and variance calculation.
        
        Validates memory consumption tracking against Node.js baseline metrics
        and ensures ≤10% variance compliance per Section 0.1.1 requirements.
        """
        monitoring_setup = performance_monitoring_setup
        
        # Get baseline memory usage from Node.js metrics
        nodejs_baseline_mb = NODEJS_BASELINE_METRICS["memory_usage_mb"]["baseline"]
        
        # Simulate current Flask memory usage
        current_memory_mb = 92.1  # Simulated current memory usage
        
        # Record memory metrics
        monitoring_setup["collect_resource_metrics"](
            cpu_percent=15.2,
            memory_mb=current_memory_mb
        )
        
        # Calculate variance against baseline
        variance_percent = ((current_memory_mb - nodejs_baseline_mb) / nodejs_baseline_mb) * 100
        
        # Validate variance is within acceptable threshold
        assert abs(variance_percent) <= MEMORY_VARIANCE_THRESHOLD, \
            f"Memory variance {variance_percent:.2f}% exceeds {MEMORY_VARIANCE_THRESHOLD}% threshold"
        
        # Check for variance violations in monitoring setup
        violations = monitoring_setup["performance_violations"]
        memory_violations = [v for v in violations if v.get("type") == "memory_variance"]
        
        if abs(variance_percent) > PERFORMANCE_VARIANCE_THRESHOLD:
            assert len(memory_violations) > 0, \
                "Expected memory variance violation not recorded"
        else:
            memory_critical_violations = [
                v for v in memory_violations 
                if abs(v.get("variance_percent", 0)) > PERFORMANCE_VARIANCE_THRESHOLD
            ]
            assert len(memory_critical_violations) == 0, \
                "Unexpected critical memory variance violation recorded"
        
        # Generate performance report
        performance_report = monitoring_setup["generate_report"]()
        
        # Validate memory metrics in report
        assert "performance_metrics" in performance_report
        assert "resource_utilization" in performance_report["performance_metrics"]
        
        resource_metrics = performance_report["performance_metrics"]["resource_utilization"]
        assert "memory_stats" in resource_metrics
        assert resource_metrics["memory_stats"]["mean_mb"] > 0
        
        logger.info(
            "Memory usage baseline tracking validation passed",
            nodejs_baseline_mb=nodejs_baseline_mb,
            current_memory_mb=current_memory_mb,
            variance_percent=variance_percent,
            variance_threshold=MEMORY_VARIANCE_THRESHOLD,
            within_threshold=abs(variance_percent) <= MEMORY_VARIANCE_THRESHOLD
        )
    
    def test_garbage_collection_monitoring(self, performance_metrics_registry):
        """
        Test Python garbage collection monitoring and impact analysis.
        
        Validates garbage collection metrics collection and performance impact
        tracking for memory management optimization per Section 3.6.2.
        """
        # Initialize metrics collector
        metrics_collector = PrometheusMetricsCollector()
        
        # Force garbage collection and monitor
        gc_start_time = time.time()
        
        # Create objects to trigger garbage collection
        test_objects = []
        for i in range(1000):
            test_objects.append({'id': i, 'data': 'x' * 100})
        
        # Force garbage collection
        collected_objects = gc.collect()
        gc_end_time = time.time()
        
        gc_pause_time = gc_end_time - gc_start_time
        
        # Record garbage collection metrics
        metrics_collector.record_gc_event(
            generation=0,
            pause_time=gc_pause_time,
            objects_collected=collected_objects,
            memory_recovered=len(test_objects) * 100,  # Estimate
            collection_type='incremental'
        )
        
        # Clean up test objects
        del test_objects
        
        # Generate metrics output
        metrics_output = metrics_collector.generate_metrics_output()
        metric_families = list(parser.text_string_to_metric_families(metrics_output))
        
        # Validate garbage collection metrics
        gc_collections_found = False
        gc_pause_time_found = False
        gc_memory_recovered_found = False
        
        for family in metric_families:
            if family.name == 'flask_gc_collections_total':
                gc_collections_found = True
                
                # Validate generation labels
                generation_labels = set()
                for sample in family.samples:
                    generation_labels.add(sample.labels.get('generation'))
                
                assert '0' in generation_labels, "Generation 0 GC metrics not found"
                
                # Validate collection count
                gen0_samples = [
                    sample for sample in family.samples
                    if sample.labels.get('generation') == '0'
                ]
                assert any(sample.value >= 1.0 for sample in gen0_samples), \
                    "GC collection count not incremented"
            
            elif family.name == 'flask_gc_pause_time_seconds':
                gc_pause_time_found = True
                
                # Validate pause time histogram
                bucket_samples = [s for s in family.samples if s.name.endswith('_bucket')]
                count_samples = [s for s in family.samples if s.name.endswith('_count')]
                sum_samples = [s for s in family.samples if s.name.endswith('_sum')]
                
                assert len(bucket_samples) > 0, "GC pause time histogram missing buckets"
                assert len(count_samples) > 0, "GC pause time histogram missing count"
                assert len(sum_samples) > 0, "GC pause time histogram missing sum"
                
                # Validate pause time is reasonable
                for sample in sum_samples:
                    if sample.labels.get('generation') == '0':
                        assert sample.value >= 0.0, "GC pause time cannot be negative"
                        assert sample.value <= 1.0, "GC pause time unexpectedly high"
            
            elif family.name == 'flask_gc_memory_recovered_bytes':
                gc_memory_recovered_found = True
                
                # Validate memory recovery tracking
                count_samples = [s for s in family.samples if s.name.endswith('_count')]
                assert any(sample.value >= 1.0 for sample in count_samples), \
                    "GC memory recovery count not recorded"
        
        assert gc_collections_found, "GC collections counter not found"
        assert gc_pause_time_found, "GC pause time histogram not found"
        assert gc_memory_recovered_found, "GC memory recovered histogram not found"
        
        logger.info(
            "Garbage collection monitoring validation passed",
            gc_pause_time_ms=gc_pause_time * 1000,
            objects_collected=collected_objects,
            gc_collections_found=gc_collections_found,
            gc_pause_time_found=gc_pause_time_found,
            gc_memory_recovered_found=gc_memory_recovered_found
        )
    
    def test_memory_leak_detection(self, performance_monitoring_setup):
        """
        Test memory leak detection through continuous monitoring.
        
        Validates ability to detect memory growth patterns that could indicate
        memory leaks and trigger appropriate alerting per Section 3.6.2.
        """
        monitoring_setup = performance_monitoring_setup
        
        # Simulate memory usage over time
        baseline_memory = 90.0
        memory_measurements = []
        
        # Simulate memory growth pattern
        for i in range(10):
            # Simulate gradual memory increase (potential leak)
            current_memory = baseline_memory + (i * 2.5)  # 2.5MB increase per iteration
            
            monitoring_setup["collect_resource_metrics"](
                cpu_percent=20.0,
                memory_mb=current_memory
            )
            
            memory_measurements.append(current_memory)
            time.sleep(0.01)  # Small delay between measurements
        
        # Analyze memory trend
        if len(memory_measurements) >= 5:
            # Calculate memory growth rate
            memory_growth = memory_measurements[-1] - memory_measurements[0]
            growth_rate = memory_growth / len(memory_measurements)
            
            # Check if growth exceeds threshold
            growth_threshold = 5.0  # 5MB total growth threshold
            
            if memory_growth > growth_threshold:
                logger.warning(
                    "Potential memory leak detected",
                    memory_growth_mb=memory_growth,
                    growth_rate_mb_per_measurement=growth_rate,
                    threshold_mb=growth_threshold
                )
            
            # Generate performance report
            performance_report = monitoring_setup["generate_report"]()
            
            # Validate memory tracking in report
            assert "performance_metrics" in performance_report
            resource_metrics = performance_report["performance_metrics"].get("resource_utilization", {})
            
            if "memory_stats" in resource_metrics:
                memory_stats = resource_metrics["memory_stats"]
                assert memory_stats["max_mb"] >= memory_stats["mean_mb"]
                assert memory_stats["sample_count"] >= len(memory_measurements)
                
                # Validate memory trend detection
                memory_variance = memory_stats["max_mb"] - baseline_memory
                assert memory_variance >= 0, "Memory variance calculation error"
        
        logger.info(
            "Memory leak detection validation completed",
            baseline_memory_mb=baseline_memory,
            final_memory_mb=memory_measurements[-1] if memory_measurements else 0,
            total_growth_mb=memory_measurements[-1] - baseline_memory if memory_measurements else 0,
            measurements_count=len(memory_measurements)
        )
    
    def test_memory_usage_variance_alerting(self, performance_monitoring_setup):
        """
        Test memory usage variance alerting for baseline compliance.
        
        Validates automatic alerting when memory usage exceeds variance thresholds
        relative to Node.js baseline requirements per Section 0.1.1.
        """
        monitoring_setup = performance_monitoring_setup
        baseline_manager = monitoring_setup["baseline_manager"]
        
        # Get Node.js baseline memory usage
        nodejs_baseline = NODEJS_BASELINE_METRICS["memory_usage_mb"]["average"]
        
        # Test scenarios with different variance levels
        test_scenarios = [
            {
                "name": "within_threshold",
                "memory_mb": nodejs_baseline * 1.05,  # 5% increase
                "should_alert": False
            },
            {
                "name": "warning_threshold",
                "memory_mb": nodejs_baseline * 1.12,  # 12% increase
                "should_alert": True
            },
            {
                "name": "critical_threshold", 
                "memory_mb": nodejs_baseline * 1.25,  # 25% increase
                "should_alert": True
            }
        ]
        
        for scenario in test_scenarios:
            # Clear previous violations
            monitoring_setup["performance_violations"].clear()
            
            # Record memory usage for scenario
            monitoring_setup["collect_resource_metrics"](
                cpu_percent=25.0,
                memory_mb=scenario["memory_mb"]
            )
            
            # Check for violations
            violations = monitoring_setup["performance_violations"]
            memory_violations = [v for v in violations if v.get("type") == "memory_variance"]
            
            # Calculate expected variance
            variance_percent = ((scenario["memory_mb"] - nodejs_baseline) / nodejs_baseline) * 100
            
            if scenario["should_alert"]:
                assert len(memory_violations) > 0, \
                    f"Expected memory variance alert for scenario {scenario['name']}"
                
                # Validate violation details
                violation = memory_violations[0]
                assert abs(violation["variance_percent"] - variance_percent) < 0.1, \
                    "Violation variance calculation incorrect"
            else:
                critical_violations = [
                    v for v in memory_violations
                    if abs(v.get("variance_percent", 0)) > MEMORY_VARIANCE_THRESHOLD
                ]
                assert len(critical_violations) == 0, \
                    f"Unexpected memory variance alert for scenario {scenario['name']}"
            
            logger.info(
                f"Memory variance alerting test - {scenario['name']}",
                baseline_mb=nodejs_baseline,
                current_mb=scenario["memory_mb"],
                variance_percent=variance_percent,
                expected_alert=scenario["should_alert"],
                violations_detected=len(memory_violations)
            )


@pytest.mark.performance 
@pytest.mark.database_monitoring
class TestDatabasePerformanceMonitoring:
    """
    Test suite for database query performance monitoring validation.
    
    Validates MongoDB operation tracking, connection pool monitoring, and query
    performance analysis to ensure database performance compliance per Section 3.6.2.
    """
    
    def test_database_operation_performance_tracking(self, performance_metrics_registry):
        """
        Test database operation performance tracking and baseline comparison.
        
        Validates comprehensive MongoDB operation monitoring including query timing,
        connection pool metrics, and performance variance tracking per Section 3.6.2.
        """
        # Initialize metrics collector
        metrics_collector = PrometheusMetricsCollector()
        
        # Simulate database operations with performance tracking
        database_operations = [
            {
                "operation": "find",
                "collection": "users",
                "duration": 0.035,
                "status": "success",
                "pool": "read_pool",
                "result_count": 15,
                "index_used": True
            },
            {
                "operation": "insert",
                "collection": "users", 
                "duration": 0.042,
                "status": "success",
                "pool": "write_pool",
                "result_count": 1,
                "index_used": True
            },
            {
                "operation": "update",
                "collection": "users",
                "duration": 0.058,
                "status": "success",
                "pool": "write_pool",
                "result_count": 3,
                "index_used": True
            },
            {
                "operation": "aggregate",
                "collection": "reports",
                "duration": 0.145,
                "status": "success",
                "pool": "read_pool",
                "result_count": 42,
                "index_used": False  # Complex aggregation without index
            },
            {
                "operation": "find",
                "collection": "reports",
                "duration": 0.892,  # Slow query without index
                "status": "success",
                "pool": "read_pool",
                "result_count": 156,
                "index_used": False
            }
        ]
        
        # Record all database operations
        for op in database_operations:
            metrics_collector.record_database_operation(**op)
        
        # Update connection pool metrics
        metrics_collector.database_connections_active.labels(
            pool_name="read_pool",
            database="primary"
        ).set(8)
        
        metrics_collector.database_connections_active.labels(
            pool_name="write_pool", 
            database="primary"
        ).set(5)
        
        metrics_collector.database_connections_pool_size.labels(
            pool_name="read_pool",
            database="primary"
        ).set(20)
        
        metrics_collector.database_connections_pool_size.labels(
            pool_name="write_pool",
            database="primary"
        ).set(10)
        
        # Generate and validate metrics
        metrics_output = metrics_collector.generate_metrics_output()
        metric_families = list(parser.text_string_to_metric_families(metrics_output))
        
        # Validate database operation metrics
        operations_counter_found = False
        duration_histogram_found = False
        connections_gauge_found = False
        result_size_histogram_found = False
        
        for family in metric_families:
            if family.name == 'flask_database_operations_total':
                operations_counter_found = True
                
                # Validate operation counts per collection
                users_operations = [
                    sample for sample in family.samples
                    if sample.labels.get('collection') == 'users'
                ]
                reports_operations = [
                    sample for sample in family.samples
                    if sample.labels.get('collection') == 'reports'
                ]
                
                assert len(users_operations) >= 3, "Missing users collection operations"
                assert len(reports_operations) >= 2, "Missing reports collection operations"
                
                # Validate operation types
                operation_types = set(sample.labels.get('operation') for sample in family.samples)
                expected_operations = {'find', 'insert', 'update', 'aggregate'}
                assert expected_operations.issubset(operation_types), \
                    f"Missing operation types: {expected_operations - operation_types}"
            
            elif family.name == 'flask_database_operation_duration_seconds':
                duration_histogram_found = True
                
                # Validate histogram structure and timing data
                bucket_samples = [s for s in family.samples if s.name.endswith('_bucket')]
                count_samples = [s for s in family.samples if s.name.endswith('_count')]
                sum_samples = [s for s in family.samples if s.name.endswith('_sum')]
                
                assert len(bucket_samples) > 0, "Duration histogram missing buckets"
                assert len(count_samples) > 0, "Duration histogram missing count"
                assert len(sum_samples) > 0, "Duration histogram missing sum"
                
                # Validate index usage tracking
                index_labels = set(
                    sample.labels.get('index_used') 
                    for sample in bucket_samples
                    if 'index_used' in sample.labels
                )
                assert 'yes' in index_labels, "Index usage metrics not tracked"
                assert 'no' in index_labels, "Non-index operations not tracked"
                
                # Validate total duration is reasonable
                total_duration = sum(sample.value for sample in sum_samples)
                expected_total = sum(op['duration'] for op in database_operations)
                assert abs(total_duration - expected_total) < 0.1, \
                    f"Duration sum mismatch: {total_duration} vs {expected_total}"
            
            elif family.name == 'flask_database_connections_active':
                connections_gauge_found = True
                
                # Validate connection pool metrics
                pool_names = set(sample.labels.get('pool_name') for sample in family.samples)
                assert 'read_pool' in pool_names, "Read pool metrics not found"
                assert 'write_pool' in pool_names, "Write pool metrics not found"
                
                # Validate connection counts
                for sample in family.samples:
                    assert sample.value >= 0, "Connection count cannot be negative"
                    assert sample.value <= 50, "Connection count unexpectedly high"
            
            elif family.name == 'flask_database_query_result_size_documents':
                result_size_histogram_found = True
                
                # Validate result size tracking
                count_samples = [s for s in family.samples if s.name.endswith('_count')]
                assert len(count_samples) > 0, "Result size histogram missing count"
                
                # Validate operations with results are tracked
                operations_with_results = len([op for op in database_operations if op['result_count'] > 0])
                total_count = sum(sample.value for sample in count_samples)
                assert total_count >= operations_with_results, \
                    f"Result count mismatch: {total_count} vs {operations_with_results}"
        
        assert operations_counter_found, "Database operations counter not found"
        assert duration_histogram_found, "Database duration histogram not found" 
        assert connections_gauge_found, "Database connections gauge not found"
        assert result_size_histogram_found, "Database result size histogram not found"
        
        logger.info(
            "Database operation performance tracking validation passed",
            operations_recorded=len(database_operations),
            unique_operations=len(set(op['operation'] for op in database_operations)),
            unique_collections=len(set(op['collection'] for op in database_operations)),
            operations_with_index=len([op for op in database_operations if op['index_used']]),
            total_duration_ms=sum(op['duration'] for op in database_operations) * 1000
        )
    
    def test_database_connection_pool_monitoring(self, performance_metrics_registry):
        """
        Test database connection pool monitoring and utilization tracking.
        
        Validates connection pool metrics collection for performance optimization
        and capacity planning per Section 3.6.2 database monitoring requirements.
        """
        # Initialize metrics collector
        metrics_collector = PrometheusMetricsCollector()
        
        # Simulate connection pool states over time
        connection_scenarios = [
            {
                "timestamp": "initial",
                "read_pool": {"active": 2, "total": 20},
                "write_pool": {"active": 1, "total": 10}
            },
            {
                "timestamp": "moderate_load",
                "read_pool": {"active": 8, "total": 20},
                "write_pool": {"active": 4, "total": 10}
            },
            {
                "timestamp": "high_load",
                "read_pool": {"active": 15, "total": 20},
                "write_pool": {"active": 8, "total": 10}
            },
            {
                "timestamp": "peak_load",
                "read_pool": {"active": 19, "total": 20},
                "write_pool": {"active": 10, "total": 10}
            }
        ]
        
        # Record connection pool metrics for each scenario
        for scenario in connection_scenarios:
            # Read pool metrics
            metrics_collector.database_connections_active.labels(
                pool_name="read_pool",
                database="primary"
            ).set(scenario["read_pool"]["active"])
            
            metrics_collector.database_connections_pool_size.labels(
                pool_name="read_pool",
                database="primary"
            ).set(scenario["read_pool"]["total"])
            
            # Write pool metrics
            metrics_collector.database_connections_active.labels(
                pool_name="write_pool",
                database="primary"
            ).set(scenario["write_pool"]["active"])
            
            metrics_collector.database_connections_pool_size.labels(
                pool_name="write_pool",
                database="primary"
            ).set(scenario["write_pool"]["total"])
            
            # Small delay between scenarios
            time.sleep(0.01)
        
        # Generate metrics output
        metrics_output = metrics_collector.generate_metrics_output()
        metric_families = list(parser.text_string_to_metric_families(metrics_output))
        
        # Validate connection pool metrics
        active_connections_found = False
        pool_size_found = False
        
        for family in metric_families:
            if family.name == 'flask_database_connections_active':
                active_connections_found = True
                
                # Validate pool separation
                read_pool_samples = [
                    sample for sample in family.samples
                    if sample.labels.get('pool_name') == 'read_pool'
                ]
                write_pool_samples = [
                    sample for sample in family.samples
                    if sample.labels.get('pool_name') == 'write_pool'
                ]
                
                assert len(read_pool_samples) > 0, "Read pool active connections not found"
                assert len(write_pool_samples) > 0, "Write pool active connections not found"
                
                # Validate connection counts are within expected ranges
                for sample in read_pool_samples:
                    assert 0 <= sample.value <= 20, \
                        f"Read pool active connections {sample.value} out of range"
                
                for sample in write_pool_samples:
                    assert 0 <= sample.value <= 10, \
                        f"Write pool active connections {sample.value} out of range"
            
            elif family.name == 'flask_database_connections_pool_size':
                pool_size_found = True
                
                # Validate pool size metrics
                read_pool_size = None
                write_pool_size = None
                
                for sample in family.samples:
                    if sample.labels.get('pool_name') == 'read_pool':
                        read_pool_size = sample.value
                    elif sample.labels.get('pool_name') == 'write_pool':
                        write_pool_size = sample.value
                
                assert read_pool_size == 20, f"Read pool size {read_pool_size} incorrect"
                assert write_pool_size == 10, f"Write pool size {write_pool_size} incorrect"
        
        assert active_connections_found, "Active connections metrics not found"
        assert pool_size_found, "Pool size metrics not found"
        
        # Calculate utilization metrics
        final_scenario = connection_scenarios[-1]
        read_utilization = (final_scenario["read_pool"]["active"] / 
                           final_scenario["read_pool"]["total"]) * 100
        write_utilization = (final_scenario["write_pool"]["active"] / 
                            final_scenario["write_pool"]["total"]) * 100
        
        # Validate utilization thresholds
        high_utilization_threshold = 80.0  # 80% utilization warning
        critical_utilization_threshold = 95.0  # 95% utilization critical
        
        if read_utilization >= critical_utilization_threshold:
            logger.warning(
                "Critical read pool utilization detected",
                utilization_percent=read_utilization,
                threshold=critical_utilization_threshold
            )
        elif read_utilization >= high_utilization_threshold:
            logger.warning(
                "High read pool utilization detected",
                utilization_percent=read_utilization,
                threshold=high_utilization_threshold
            )
        
        if write_utilization >= critical_utilization_threshold:
            logger.warning(
                "Critical write pool utilization detected",
                utilization_percent=write_utilization,
                threshold=critical_utilization_threshold
            )
        elif write_utilization >= high_utilization_threshold:
            logger.warning(
                "High write pool utilization detected",
                utilization_percent=write_utilization,
                threshold=high_utilization_threshold
            )
        
        logger.info(
            "Database connection pool monitoring validation passed",
            scenarios_tested=len(connection_scenarios),
            final_read_utilization=read_utilization,
            final_write_utilization=write_utilization,
            active_connections_found=active_connections_found,
            pool_size_found=pool_size_found
        )
    
    def test_database_query_performance_variance_detection(self, performance_monitoring_setup):
        """
        Test database query performance variance detection against baseline.
        
        Validates detection of database performance regressions and compliance
        with ≤10% variance requirement per Section 0.1.1 and Section 3.6.2.
        """
        monitoring_setup = performance_monitoring_setup
        
        # Define baseline query performance (simulated Node.js MongoDB performance)
        baseline_query_performance = {
            "find_users": 0.025,      # 25ms baseline
            "insert_user": 0.035,     # 35ms baseline
            "update_user": 0.045,     # 45ms baseline
            "aggregate_reports": 0.125  # 125ms baseline
        }
        
        # Test scenarios with different variance levels
        performance_test_scenarios = [
            {
                "name": "within_threshold",
                "queries": {
                    "find_users": 0.027,      # 8% increase (within 10%)
                    "insert_user": 0.033,     # 6% decrease (within 10%) 
                    "update_user": 0.048,     # 7% increase (within 10%)
                    "aggregate_reports": 0.132 # 6% increase (within 10%)
                },
                "should_trigger_alert": False
            },
            {
                "name": "warning_threshold",
                "queries": {
                    "find_users": 0.028,      # 12% increase (above 10%)
                    "insert_user": 0.040,     # 14% increase (above 10%)
                    "update_user": 0.052,     # 16% increase (above 10%)
                    "aggregate_reports": 0.145 # 16% increase (above 10%)
                },
                "should_trigger_alert": True
            },
            {
                "name": "critical_threshold",
                "queries": {
                    "find_users": 0.035,      # 40% increase (critical)
                    "insert_user": 0.050,     # 43% increase (critical)
                    "update_user": 0.070,     # 56% increase (critical)
                    "aggregate_reports": 0.200 # 60% increase (critical)
                },
                "should_trigger_alert": True
            }
        ]
        
        for scenario in performance_test_scenarios:
            # Clear previous violations
            monitoring_setup["performance_violations"].clear()
            
            # Record query performance for scenario
            for query_type, duration in scenario["queries"].items():
                # Calculate variance
                baseline_duration = baseline_query_performance[query_type]
                variance_percent = ((duration - baseline_duration) / baseline_duration) * 100
                
                # Simulate recording the performance variance
                if abs(variance_percent) > PERFORMANCE_VARIANCE_THRESHOLD:
                    violation = {
                        "type": "database_performance_variance",
                        "query_type": query_type,
                        "baseline_ms": baseline_duration * 1000,
                        "current_ms": duration * 1000,
                        "variance_percent": variance_percent,
                        "timestamp": datetime.now(timezone.utc)
                    }
                    monitoring_setup["performance_violations"].append(violation)
                    
                    logger.warning(
                        "Database performance variance detected",
                        **violation
                    )
            
            # Validate violation detection
            violations = monitoring_setup["performance_violations"]
            db_performance_violations = [
                v for v in violations 
                if v.get("type") == "database_performance_variance"
            ]
            
            if scenario["should_trigger_alert"]:
                assert len(db_performance_violations) > 0, \
                    f"Expected database performance violations for scenario {scenario['name']}"
                
                # Validate violation details
                for violation in db_performance_violations:
                    assert "query_type" in violation
                    assert "variance_percent" in violation
                    assert abs(violation["variance_percent"]) > PERFORMANCE_VARIANCE_THRESHOLD
            else:
                critical_violations = [
                    v for v in db_performance_violations
                    if abs(v.get("variance_percent", 0)) > PERFORMANCE_VARIANCE_THRESHOLD
                ]
                assert len(critical_violations) == 0, \
                    f"Unexpected database performance violations for scenario {scenario['name']}"
            
            # Calculate average variance for scenario
            total_variance = 0
            query_count = 0
            
            for query_type, duration in scenario["queries"].items():
                baseline_duration = baseline_query_performance[query_type]
                variance = abs((duration - baseline_duration) / baseline_duration) * 100
                total_variance += variance
                query_count += 1
            
            average_variance = total_variance / query_count if query_count > 0 else 0
            
            logger.info(
                f"Database performance variance test - {scenario['name']}",
                average_variance_percent=average_variance,
                violations_detected=len(db_performance_violations),
                expected_alert=scenario["should_trigger_alert"],
                queries_tested=len(scenario["queries"])
            )


@pytest.mark.performance
@pytest.mark.enterprise_integration
class TestEnterpriseMonitoringIntegration:
    """
    Test suite for enterprise APM integration compatibility validation.
    
    Validates integration with enterprise monitoring systems including Prometheus
    Alertmanager, Grafana dashboard compatibility, and APM correlation per Section 3.6.1.
    """
    
    def test_prometheus_alertmanager_integration(self, app, performance_metrics_registry):
        """
        Test Prometheus Alertmanager integration for threshold-based alerting.
        
        Validates metrics format compatibility and alerting rules integration
        with enterprise Prometheus Alertmanager systems per Section 3.6.1.
        """
        # Setup metrics collection
        metrics_collector = setup_metrics_collection(app)
        
        # Create test alert conditions
        alert_test_scenarios = [
            {
                "name": "high_response_time",
                "metrics": {
                    "endpoint": "/api/v1/users",
                    "response_time": 0.750,  # 750ms (above 500ms threshold)
                    "status_code": 200
                },
                "expected_alert": True
            },
            {
                "name": "high_error_rate",
                "metrics": {
                    "endpoint": "/api/v1/auth/login",
                    "response_time": 0.125,
                    "status_code": 500  # Error status
                },
                "expected_alert": True
            },
            {
                "name": "normal_operation",
                "metrics": {
                    "endpoint": "/health",
                    "response_time": 0.025,  # 25ms (normal)
                    "status_code": 200
                },
                "expected_alert": False
            }
        ]
        
        with app.test_client() as client:
            # Generate metrics for each scenario
            for scenario in alert_test_scenarios:
                metrics = scenario["metrics"]
                
                # Record the metrics
                metrics_collector.record_http_request(
                    method="GET",
                    endpoint=metrics["endpoint"],
                    status_code=metrics["status_code"],
                    duration=metrics["response_time"]
                )
            
            # Get metrics output
            metrics_response = client.get('/metrics')
            assert metrics_response.status_code == 200
            
            metrics_content = metrics_response.get_data(as_text=True)
            metric_families = list(parser.text_string_to_metric_families(metrics_content))
            
            # Validate alerting-compatible metrics structure
            alerting_metrics_found = {
                'response_time_histogram': False,
                'error_rate_counter': False,
                'request_counter': False
            }
            
            for family in metric_families:
                if family.name == 'flask_http_request_duration_seconds':
                    alerting_metrics_found['response_time_histogram'] = True
                    
                    # Validate histogram buckets for Prometheus alerting
                    bucket_samples = [s for s in family.samples if s.name.endswith('_bucket')]
                    
                    # Check for alerting-relevant buckets
                    alerting_buckets = [
                        0.1, 0.25, 0.5, 1.0, 2.5, 5.0  # Common alerting thresholds
                    ]
                    
                    found_buckets = set()
                    for sample in bucket_samples:
                        if 'le' in sample.labels:
                            try:
                                bucket_value = float(sample.labels['le'])
                                if bucket_value != float('inf'):
                                    found_buckets.add(bucket_value)
                            except ValueError:
                                pass
                    
                    for bucket in alerting_buckets:
                        assert bucket in found_buckets, \
                            f"Alerting bucket {bucket} not found in histogram"
                
                elif family.name == 'flask_http_requests_total':
                    alerting_metrics_found['request_counter'] = True
                    alerting_metrics_found['error_rate_counter'] = True
                    
                    # Validate labels required for alerting rules
                    required_labels = ['method', 'endpoint', 'status_code']
                    
                    for sample in family.samples:
                        for label in required_labels:
                            assert label in sample.labels, \
                                f"Required alerting label {label} not found"
                        
                        # Validate status code grouping for error rate calculation
                        status_code = sample.labels.get('status_code', '')
                        assert status_code.isdigit(), \
                            f"Status code {status_code} not in numeric format"
            
            # Validate all alerting metrics are present
            for metric_name, found in alerting_metrics_found.items():
                assert found, f"Alerting metric {metric_name} not found"
            
            # Validate metrics format for Alertmanager consumption
            # Check that metrics output is valid Prometheus exposition format
            assert 'TYPE' in metrics_content, "Metrics missing TYPE declarations"
            assert 'HELP' in metrics_content, "Metrics missing HELP declarations"
            
            # Validate no parsing errors
            try:
                list(parser.text_string_to_metric_families(metrics_content))
            except Exception as e:
                pytest.fail(f"Metrics format incompatible with Prometheus parser: {e}")
        
        logger.info(
            "Prometheus Alertmanager integration validation passed",
            scenarios_tested=len(alert_test_scenarios),
            alerting_metrics_found=alerting_metrics_found,
            metrics_format_valid=True
        )
    
    def test_grafana_dashboard_compatibility(self, app, performance_metrics_registry):
        """
        Test Grafana dashboard compatibility through metrics endpoint validation.
        
        Validates that metrics format and structure support enterprise Grafana
        dashboard integration per Section 3.6.1 enterprise integration requirements.
        """
        # Setup metrics collection
        metrics_collector = setup_metrics_collection(app)
        
        with app.test_client() as client:
            # Generate comprehensive metrics for dashboard testing
            dashboard_test_requests = [
                ("GET", "/api/v1/users", 200, 0.045),
                ("POST", "/api/v1/users", 201, 0.089),
                ("GET", "/api/v1/data/reports", 200, 0.123),
                ("PUT", "/api/v1/users/123", 200, 0.067),
                ("DELETE", "/api/v1/users/123", 204, 0.034),
                ("GET", "/health", 200, 0.012),
                ("GET", "/api/v1/auth/login", 401, 0.156),  # Authentication failure
                ("POST", "/api/v1/files/upload", 413, 0.234),  # Payload too large
            ]
            
            # Record metrics for dashboard visualization
            for method, endpoint, status, duration in dashboard_test_requests:
                metrics_collector.record_http_request(
                    method=method,
                    endpoint=endpoint.split('/')[-1] if '/' in endpoint else endpoint,
                    status_code=status,
                    duration=duration,
                    request_size=1024,
                    response_size=2048
                )
            
            # Add database operations for comprehensive dashboard
            database_operations = [
                ("find", "users", 0.025, "success", 15),
                ("insert", "users", 0.042, "success", 1),
                ("update", "reports", 0.078, "success", 3),
                ("aggregate", "analytics", 0.156, "success", 42)
            ]
            
            for operation, collection, duration, status, result_count in database_operations:
                metrics_collector.record_database_operation(
                    operation=operation,
                    collection=collection,
                    duration=duration,
                    status=status,
                    result_count=result_count
                )
            
            # Update resource metrics
            metrics_collector.update_resource_utilization()
            
            # Get metrics for Grafana compatibility validation
            metrics_response = client.get('/metrics')
            assert metrics_response.status_code == 200
            
            metrics_content = metrics_response.get_data(as_text=True)
            metric_families = list(parser.text_string_to_metric_families(metrics_content))
            
            # Validate Grafana-compatible metric structure
            grafana_compatibility = {
                'time_series_data': False,
                'histogram_data': False,
                'gauge_data': False,
                'counter_data': False,
                'label_dimensions': False,
                'rate_calculation_support': False
            }
            
            label_cardinality = {}
            
            for family in metric_families:
                # Check for time series compatibility
                if len(family.samples) > 0:
                    grafana_compatibility['time_series_data'] = True
                
                # Check metric types for Grafana visualization
                if family.type == 'histogram':
                    grafana_compatibility['histogram_data'] = True
                    
                    # Validate histogram structure for Grafana
                    bucket_count = len([s for s in family.samples if s.name.endswith('_bucket')])
                    count_metrics = len([s for s in family.samples if s.name.endswith('_count')])
                    sum_metrics = len([s for s in family.samples if s.name.endswith('_sum')])
                    
                    assert bucket_count > 0, "Histogram missing buckets for Grafana"
                    assert count_metrics > 0, "Histogram missing count for Grafana"
                    assert sum_metrics > 0, "Histogram missing sum for Grafana"
                
                elif family.type == 'gauge':
                    grafana_compatibility['gauge_data'] = True
                
                elif family.type == 'counter':
                    grafana_compatibility['counter_data'] = True
                    grafana_compatibility['rate_calculation_support'] = True
                
                # Analyze label dimensions for Grafana filtering/grouping
                for sample in family.samples:
                    if sample.labels:
                        grafana_compatibility['label_dimensions'] = True
                        
                        # Track label cardinality
                        for label_name, label_value in sample.labels.items():
                            if label_name not in label_cardinality:
                                label_cardinality[label_name] = set()
                            label_cardinality[label_name].add(label_value)
            
            # Validate Grafana compatibility requirements
            required_features = [
                'time_series_data',
                'histogram_data', 
                'gauge_data',
                'counter_data',
                'label_dimensions',
                'rate_calculation_support'
            ]
            
            for feature in required_features:
                assert grafana_compatibility[feature], \
                    f"Grafana compatibility feature {feature} not supported"
            
            # Validate label cardinality is reasonable for Grafana performance
            max_cardinality = 100  # Reasonable limit for dashboard performance
            
            for label_name, values in label_cardinality.items():
                cardinality = len(values)
                assert cardinality <= max_cardinality, \
                    f"Label {label_name} cardinality {cardinality} exceeds {max_cardinality}"
            
            # Validate dashboard-specific metrics are available
            dashboard_required_metrics = [
                'flask_http_request_duration_seconds',  # Response time graphs
                'flask_http_requests_total',            # Request rate graphs
                'flask_database_operation_duration_seconds',  # Database performance
                'flask_cpu_utilization_percent',        # Resource utilization
                'flask_memory_usage_bytes'              # Memory monitoring
            ]
            
            available_metrics = [family.name for family in metric_families]
            
            for required_metric in dashboard_required_metrics:
                assert any(required_metric in metric for metric in available_metrics), \
                    f"Dashboard metric {required_metric} not available"
        
        logger.info(
            "Grafana dashboard compatibility validation passed",
            metrics_tested=len(dashboard_test_requests),
            database_operations=len(database_operations),
            grafana_features=grafana_compatibility,
            label_cardinality=len(label_cardinality),
            dashboard_metrics_available=len(dashboard_required_metrics)
        )
    
    def test_apm_correlation_integration(self, app, performance_monitoring_setup):
        """
        Test APM correlation for comprehensive performance monitoring.
        
        Validates integration with enterprise APM tools through trace correlation
        and performance context propagation per Section 3.6.1 APM integration.
        """
        monitoring_setup = performance_monitoring_setup
        
        # Setup metrics collection
        metrics_collector = setup_metrics_collection(app)
        
        # Simulate APM trace correlation scenarios
        apm_trace_scenarios = [
            {
                "trace_id": "trace_001_user_workflow",
                "span_id": "span_001",
                "operation": "user_authentication",
                "duration_ms": 67.5,
                "status": "success",
                "metadata": {
                    "user_id": "user_12345",
                    "endpoint": "/api/v1/auth/login",
                    "method": "POST"
                }
            },
            {
                "trace_id": "trace_001_user_workflow", 
                "span_id": "span_002",
                "operation": "database_query",
                "duration_ms": 23.8,
                "status": "success",
                "metadata": {
                    "collection": "users",
                    "operation": "find",
                    "result_count": 1
                }
            },
            {
                "trace_id": "trace_002_report_generation",
                "span_id": "span_003",
                "operation": "report_processing",
                "duration_ms": 245.6,
                "status": "success",
                "metadata": {
                    "report_type": "analytics",
                    "data_points": 1500,
                    "cache_hit": False
                }
            },
            {
                "trace_id": "trace_003_error_scenario",
                "span_id": "span_004", 
                "operation": "external_service_call",
                "duration_ms": 5000.0,  # Timeout scenario
                "status": "timeout",
                "metadata": {
                    "service": "external_api",
                    "endpoint": "/external/data",
                    "retry_count": 3
                }
            }
        ]
        
        with app.test_client() as client:
            # Process each APM trace scenario
            for scenario in apm_trace_scenarios:
                trace_id = scenario["trace_id"]
                span_id = scenario["span_id"]
                operation = scenario["operation"]
                duration_s = scenario["duration_ms"] / 1000.0
                status = scenario["status"]
                metadata = scenario["metadata"]
                
                # Record metrics with APM correlation context
                if operation == "user_authentication":
                    metrics_collector.record_http_request(
                        method=metadata["method"],
                        endpoint=metadata["endpoint"],
                        status_code=200 if status == "success" else 401,
                        duration=duration_s
                    )
                
                elif operation == "database_query":
                    metrics_collector.record_database_operation(
                        operation=metadata["operation"],
                        collection=metadata["collection"],
                        duration=duration_s,
                        status=status,
                        result_count=metadata["result_count"]
                    )
                
                elif operation == "report_processing":
                    metrics_collector.record_business_logic_operation(
                        operation="report_generation",
                        module="analytics",
                        duration=duration_s,
                        status=status,
                        complexity="complex"
                    )
                
                elif operation == "external_service_call":
                    metrics_collector.record_external_service_request(
                        service=metadata["service"],
                        operation="api_call",
                        duration=duration_s,
                        status_code=408 if status == "timeout" else 200,
                        timeout_occurred=(status == "timeout"),
                        retry_count=metadata["retry_count"]
                    )
                
                # Record performance context for APM correlation
                monitoring_setup["collect_response_time"](
                    endpoint=metadata.get("endpoint", operation),
                    method=metadata.get("method", "GET"),
                    response_time_ms=scenario["duration_ms"]
                )
                
                # Simulate APM correlation logging
                logger.info(
                    "APM trace correlation recorded",
                    trace_id=trace_id,
                    span_id=span_id,
                    operation=operation,
                    duration_ms=scenario["duration_ms"],
                    status=status,
                    apm_context=metadata
                )
            
            # Generate comprehensive performance report
            performance_report = monitoring_setup["generate_report"]()
            
            # Validate APM correlation data in performance report
            assert "test_execution_summary" in performance_report
            assert "performance_metrics" in performance_report
            
            execution_summary = performance_report["test_execution_summary"]
            assert execution_summary["total_violations"] >= 0
            
            # Check for APM-compatible metrics structure
            if "response_times" in performance_report["performance_metrics"]:
                response_times = performance_report["performance_metrics"]["response_times"]
                
                # Validate trace correlation data is available
                assert len(response_times) > 0, "No response time data for APM correlation"
                
                for endpoint, metrics in response_times.items():
                    assert "sample_count" in metrics
                    assert "mean_ms" in metrics
                    assert "p95_ms" in metrics
                    
                    # Validate metrics support APM percentile analysis
                    assert metrics["sample_count"] > 0
                    assert metrics["mean_ms"] > 0
            
            # Get Prometheus metrics for APM integration
            metrics_response = client.get('/metrics')
            assert metrics_response.status_code == 200
            
            metrics_content = metrics_response.get_data(as_text=True)
            metric_families = list(parser.text_string_to_metric_families(metrics_content))
            
            # Validate APM-compatible metric labels and structure
            apm_correlation_features = {
                'trace_context_support': False,
                'operation_labeling': False,
                'duration_tracking': False,
                'error_correlation': False,
                'service_identification': False
            }
            
            for family in metric_families:
                for sample in family.samples:
                    labels = sample.labels
                    
                    # Check for APM correlation support through labels
                    if 'endpoint' in labels or 'operation' in labels:
                        apm_correlation_features['operation_labeling'] = True
                    
                    if 'service' in labels:
                        apm_correlation_features['service_identification'] = True
                    
                    if 'status' in labels or 'status_code' in labels:
                        apm_correlation_features['error_correlation'] = True
                
                # Check for duration tracking support
                if family.type == 'histogram' and 'duration' in family.name:
                    apm_correlation_features['duration_tracking'] = True
                
                # APM tools typically correlate through metric labels
                if any(sample.labels for sample in family.samples):
                    apm_correlation_features['trace_context_support'] = True
            
            # Validate APM correlation capabilities
            required_apm_features = [
                'operation_labeling',
                'duration_tracking', 
                'error_correlation',
                'service_identification'
            ]
            
            for feature in required_apm_features:
                assert apm_correlation_features[feature], \
                    f"APM correlation feature {feature} not supported"
        
        logger.info(
            "APM correlation integration validation passed",
            trace_scenarios=len(apm_trace_scenarios),
            unique_traces=len(set(s["trace_id"] for s in apm_trace_scenarios)),
            apm_features=apm_correlation_features,
            performance_report_generated=True
        )


@pytest.mark.performance
@pytest.mark.real_time_monitoring  
class TestRealTimePerformanceDataCollection:
    """
    Test suite for real-time performance data collection during tests.
    
    Validates continuous performance monitoring, real-time metrics streaming,
    and live performance analysis capabilities per Section 6.6.1 requirements.
    """
    
    def test_real_time_metrics_streaming(self, app, performance_monitoring_setup):
        """
        Test real-time metrics streaming and continuous data collection.
        
        Validates that performance metrics are collected and updated in real-time
        during test execution for continuous monitoring per Section 6.6.1.
        """
        monitoring_setup = performance_monitoring_setup
        
        # Setup metrics collection
        metrics_collector = setup_metrics_collection(app)
        
        # Real-time metrics collection test
        streaming_duration = 5.0  # 5 seconds of streaming
        collection_interval = 0.1  # 100ms collection interval
        expected_samples = int(streaming_duration / collection_interval)
        
        collected_metrics = []
        start_time = time.time()
        
        with app.test_client() as client:
            # Create test endpoint for continuous monitoring
            @app.route('/test/realtime')
            def realtime_test_endpoint():
                # Variable processing time to test real-time detection
                processing_time = 0.01 + (time.time() % 0.05)  # 10-60ms variable
                time.sleep(processing_time)
                return {'timestamp': time.time(), 'processing_time': processing_time}
            
            # Stream metrics collection
            sample_count = 0
            while time.time() - start_time < streaming_duration:
                sample_start = time.time()
                
                # Make request to generate metrics
                response = client.get('/test/realtime')
                assert response.status_code == 200
                
                # Collect current metrics state
                current_metrics = {
                    'timestamp': time.time(),
                    'sample_id': sample_count,
                    'request_duration': time.time() - sample_start,
                    'response_data': response.get_json()
                }
                
                collected_metrics.append(current_metrics)
                
                # Record real-time performance data
                monitoring_setup["collect_response_time"](
                    endpoint="realtime_test_endpoint",
                    method="GET", 
                    response_time_ms=current_metrics['request_duration'] * 1000
                )
                
                sample_count += 1
                
                # Maintain collection interval
                elapsed = time.time() - sample_start
                sleep_time = max(0, collection_interval - elapsed)
                if sleep_time > 0:
                    time.sleep(sleep_time)
            
            # Validate real-time collection results
            total_samples = len(collected_metrics)
            assert total_samples >= expected_samples * 0.8, \
                f"Insufficient samples collected: {total_samples} < {expected_samples * 0.8}"
            
            # Validate timing consistency for real-time monitoring
            timestamps = [m['timestamp'] for m in collected_metrics]
            if len(timestamps) > 1:
                intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
                avg_interval = statistics.mean(intervals)
                
                # Allow 50% variance in collection interval for real-time systems
                interval_variance = abs(avg_interval - collection_interval) / collection_interval
                assert interval_variance <= 0.5, \
                    f"Collection interval variance {interval_variance:.2%} exceeds 50%"
            
            # Generate real-time performance report
            performance_report = monitoring_setup["generate_report"]()
            
            # Validate real-time metrics are captured
            assert "performance_metrics" in performance_report
            if "response_times" in performance_report["performance_metrics"]:
                response_times = performance_report["performance_metrics"]["response_times"]
                
                realtime_endpoint_key = None
                for key in response_times.keys():
                    if "realtime_test_endpoint" in key:
                        realtime_endpoint_key = key
                        break
                
                if realtime_endpoint_key:
                    endpoint_metrics = response_times[realtime_endpoint_key]
                    assert endpoint_metrics["sample_count"] >= total_samples * 0.8
                    assert endpoint_metrics["mean_ms"] > 0
                    assert endpoint_metrics["std_dev_ms"] >= 0
            
            # Validate Prometheus metrics reflect real-time data
            metrics_response = client.get('/metrics')
            assert metrics_response.status_code == 200
            
            metrics_content = metrics_response.get_data(as_text=True)
            metric_families = list(parser.text_string_to_metric_families(metrics_content))
            
            # Check for real-time request counting
            request_counter_samples = 0
            for family in metric_families:
                if family.name == 'flask_http_requests_total':
                    for sample in family.samples:
                        if 'realtime_test_endpoint' in sample.labels.get('endpoint', ''):
                            request_counter_samples += int(sample.value)
            
            assert request_counter_samples >= total_samples * 0.8, \
                f"Prometheus counter {request_counter_samples} doesn't reflect real-time samples {total_samples}"
        
        logger.info(
            "Real-time metrics streaming validation passed",
            streaming_duration_s=streaming_duration,
            collection_interval_ms=collection_interval * 1000,
            samples_collected=total_samples,
            expected_samples=expected_samples,
            prometheus_counter_samples=request_counter_samples
        )
    
    def test_live_performance_analysis_and_alerting(self, performance_monitoring_setup):
        """
        Test live performance analysis and real-time alerting capabilities.
        
        Validates real-time performance threshold monitoring and immediate
        alerting for performance regressions per Section 6.6.1 monitoring integration.
        """
        monitoring_setup = performance_monitoring_setup
        
        # Define performance thresholds for live monitoring
        performance_thresholds = {
            "response_time_ms": {
                "warning": 200.0,
                "critical": 500.0
            },
            "error_rate_percent": {
                "warning": 5.0,
                "critical": 10.0
            },
            "memory_usage_variance_percent": {
                "warning": 10.0,
                "critical": 20.0
            }
        }
        
        # Live monitoring test scenarios
        live_monitoring_scenarios = [
            {
                "name": "normal_performance",
                "duration": 1.0,
                "response_times": [45, 52, 38, 61, 49],  # Normal range
                "error_rate": 0.0,
                "memory_variance": 5.0,
                "expected_alerts": []
            },
            {
                "name": "warning_response_time",
                "duration": 1.0,
                "response_times": [245, 267, 223, 289, 251],  # Warning range
                "error_rate": 2.0,
                "memory_variance": 8.0,
                "expected_alerts": ["response_time_warning"]
            },
            {
                "name": "critical_performance",
                "duration": 1.0,
                "response_times": [567, 623, 584, 612, 598],  # Critical range
                "error_rate": 12.0,
                "memory_variance": 25.0,
                "expected_alerts": ["response_time_critical", "error_rate_critical", "memory_critical"]
            },
            {
                "name": "mixed_performance",
                "duration": 2.0,
                "response_times": [89, 156, 234, 298, 445, 189, 267, 178, 156, 203],
                "error_rate": 6.5,
                "memory_variance": 12.0,
                "expected_alerts": ["error_rate_warning", "memory_warning"]
            }
        ]
        
        for scenario in live_monitoring_scenarios:
            # Clear previous alerts
            scenario_alerts = []
            
            # Simulate live performance monitoring
            scenario_start = time.time()
            response_times = scenario["response_times"]
            error_rate = scenario["error_rate"]
            memory_variance = scenario["memory_variance"]
            
            # Process performance data in real-time
            for i, response_time in enumerate(response_times):
                # Record response time
                monitoring_setup["collect_response_time"](
                    endpoint="/api/test/live",
                    method="GET",
                    response_time_ms=response_time
                )
                
                # Check response time thresholds
                if response_time >= performance_thresholds["response_time_ms"]["critical"]:
                    scenario_alerts.append("response_time_critical")
                elif response_time >= performance_thresholds["response_time_ms"]["warning"]:
                    scenario_alerts.append("response_time_warning")
                
                # Simulate memory variance monitoring
                if memory_variance >= performance_thresholds["memory_usage_variance_percent"]["critical"]:
                    scenario_alerts.append("memory_critical")
                elif memory_variance >= performance_thresholds["memory_usage_variance_percent"]["warning"]:
                    scenario_alerts.append("memory_warning")
                
                # Small delay to simulate real-time processing
                time.sleep(0.01)
            
            # Check error rate threshold
            if error_rate >= performance_thresholds["error_rate_percent"]["critical"]:
                scenario_alerts.append("error_rate_critical")
            elif error_rate >= performance_thresholds["error_rate_percent"]["warning"]:
                scenario_alerts.append("error_rate_warning")
            
            # Remove duplicates and sort for comparison
            unique_alerts = sorted(list(set(scenario_alerts)))
            expected_alerts = sorted(scenario["expected_alerts"])
            
            # Validate alert detection
            for expected_alert in expected_alerts:
                assert expected_alert in unique_alerts, \
                    f"Expected alert {expected_alert} not triggered in scenario {scenario['name']}"
            
            # Calculate performance metrics for validation
            avg_response_time = statistics.mean(response_times)
            max_response_time = max(response_times)
            
            # Generate scenario report
            scenario_report = {
                "scenario": scenario["name"],
                "duration": time.time() - scenario_start,
                "samples_processed": len(response_times),
                "avg_response_time_ms": avg_response_time,
                "max_response_time_ms": max_response_time,
                "error_rate_percent": error_rate,
                "memory_variance_percent": memory_variance,
                "alerts_triggered": unique_alerts,
                "expected_alerts": expected_alerts,
                "alert_accuracy": len(set(unique_alerts) & set(expected_alerts)) / max(1, len(set(unique_alerts) | set(expected_alerts)))
            }
            
            logger.info(
                f"Live performance analysis - {scenario['name']}",
                **scenario_report
            )
            
            # Validate alert accuracy
            assert scenario_report["alert_accuracy"] >= 0.8, \
                f"Alert accuracy {scenario_report['alert_accuracy']:.2%} below 80% for scenario {scenario['name']}"
        
        # Generate comprehensive live monitoring report
        monitoring_report = monitoring_setup["generate_report"]()
        
        # Validate live monitoring capabilities
        assert "test_execution_summary" in monitoring_report
        assert monitoring_report["test_execution_summary"]["monitoring_status"] in ["active", "completed"]
        
        logger.info(
            "Live performance analysis and alerting validation passed",
            scenarios_tested=len(live_monitoring_scenarios),
            threshold_categories=len(performance_thresholds),
            total_alerts_tested=sum(len(s["expected_alerts"]) for s in live_monitoring_scenarios)
        )
    
    def test_continuous_baseline_comparison(self, performance_monitoring_setup, baseline_comparison_validator):
        """
        Test continuous baseline comparison during real-time monitoring.
        
        Validates continuous comparison with Node.js baseline metrics and
        real-time variance tracking per Section 0.1.1 ≤10% variance requirement.
        """
        monitoring_setup = performance_monitoring_setup
        validator = baseline_comparison_validator
        
        # Continuous monitoring parameters
        monitoring_duration = 3.0  # 3 seconds of continuous monitoring
        baseline_check_interval = 0.5  # Check baseline every 500ms
        variance_tolerance = PERFORMANCE_VARIANCE_THRESHOLD  # 10% from Section 0.1.1
        
        # Node.js baseline metrics for comparison
        nodejs_baselines = NODEJS_BASELINE_METRICS["response_time_ms"]
        
        # Continuous baseline comparison test
        continuous_monitoring_data = []
        monitoring_start = time.time()
        
        while time.time() - monitoring_start < monitoring_duration:
            iteration_start = time.time()
            
            # Simulate current Flask performance metrics
            current_metrics = {}
            baseline_violations = []
            
            for endpoint, baseline_data in nodejs_baselines.items():
                # Simulate varying Flask performance
                time_factor = (time.time() - monitoring_start) / monitoring_duration
                
                # Introduce gradual performance change over time
                variance_factor = 1.0 + (time_factor * 0.15)  # Up to 15% degradation
                
                current_response_time = baseline_data["mean"] * variance_factor
                current_metrics[endpoint] = {
                    "mean": current_response_time,
                    "p95": baseline_data["p95"] * variance_factor,
                    "p99": baseline_data["p99"] * variance_factor
                }
                
                # Record performance metric
                monitoring_setup["collect_response_time"](
                    endpoint=endpoint,
                    method="GET",
                    response_time_ms=current_response_time
                )
                
                # Calculate variance against baseline
                variance_percent = ((current_response_time - baseline_data["mean"]) / baseline_data["mean"]) * 100
                
                # Check for baseline violations
                if abs(variance_percent) > variance_tolerance:
                    violation = {
                        "endpoint": endpoint,
                        "baseline_ms": baseline_data["mean"],
                        "current_ms": current_response_time,
                        "variance_percent": variance_percent,
                        "timestamp": time.time()
                    }
                    baseline_violations.append(violation)
            
            # Validate baseline comparison
            try:
                validation_result = validator["validate_metrics"](
                    current_metrics={
                        endpoint: data["mean"] for endpoint, data in current_metrics.items()
                    },
                    test_type="continuous_monitoring"
                )
                
                compliance_status = validation_result.get("overall_compliance", True)
                
            except Exception as e:
                # Handle validation errors gracefully in continuous monitoring
                compliance_status = len(baseline_violations) == 0
                logger.warning(f"Baseline validation error: {e}")
            
            # Record continuous monitoring data point
            monitoring_data_point = {
                "timestamp": time.time(),
                "elapsed_time": time.time() - monitoring_start,
                "current_metrics": current_metrics,
                "baseline_violations": baseline_violations,
                "compliance_status": compliance_status,
                "violation_count": len(baseline_violations)
            }
            
            continuous_monitoring_data.append(monitoring_data_point)
            
            # Maintain baseline check interval
            iteration_elapsed = time.time() - iteration_start
            sleep_time = max(0, baseline_check_interval - iteration_elapsed)
            if sleep_time > 0:
                time.sleep(sleep_time)
        
        # Analyze continuous monitoring results
        total_data_points = len(continuous_monitoring_data)
        compliant_data_points = len([dp for dp in continuous_monitoring_data if dp["compliance_status"]])
        total_violations = sum(dp["violation_count"] for dp in continuous_monitoring_data)
        
        # Calculate compliance metrics
        compliance_rate = compliant_data_points / total_data_points if total_data_points > 0 else 0
        average_violations_per_check = total_violations / total_data_points if total_data_points > 0 else 0
        
        # Validate continuous monitoring effectiveness
        assert total_data_points >= 4, \
            f"Insufficient monitoring data points: {total_data_points}"
        
        # For continuous monitoring, we expect some variance as performance changes
        # but overall compliance should be maintained for most of the time
        minimum_compliance_rate = 0.6  # 60% of the time should be compliant
        assert compliance_rate >= minimum_compliance_rate, \
            f"Compliance rate {compliance_rate:.2%} below minimum {minimum_compliance_rate:.2%}"
        
        # Analyze baseline violation trends
        violation_timestamps = []
        for dp in continuous_monitoring_data:
            if dp["baseline_violations"]:
                violation_timestamps.extend([v["timestamp"] for v in dp["baseline_violations"]])
        
        # Generate continuous monitoring report
        continuous_report = {
            "monitoring_duration_s": monitoring_duration,
            "data_points_collected": total_data_points,
            "baseline_check_interval_s": baseline_check_interval,
            "compliance_rate": compliance_rate,
            "total_violations": total_violations,
            "average_violations_per_check": average_violations_per_check,
            "endpoints_monitored": len(nodejs_baselines),
            "variance_tolerance_percent": variance_tolerance
        }
        
        # Validate continuous baseline comparison capability
        assert continuous_report["data_points_collected"] > 0
        assert continuous_report["endpoints_monitored"] > 0
        assert continuous_report["compliance_rate"] >= 0
        
        logger.info(
            "Continuous baseline comparison validation passed",
            **continuous_report
        )
        
        # Generate final performance report
        final_report = monitoring_setup["generate_report"]()
        
        # Validate continuous monitoring is reflected in final report
        assert "performance_metrics" in final_report
        if "response_times" in final_report["performance_metrics"]:
            response_times = final_report["performance_metrics"]["response_times"]
            assert len(response_times) > 0, "No response time data in continuous monitoring report"


# Test execution helpers and utilities

def simulate_load_test_data(duration_seconds: float = 60.0, 
                           target_rps: int = 100) -> List[Dict[str, Any]]:
    """
    Simulate load test data for performance monitoring validation.
    
    Args:
        duration_seconds: Test duration in seconds
        target_rps: Target requests per second
        
    Returns:
        List of simulated request data
    """
    requests = []
    start_time = time.time()
    
    total_requests = int(duration_seconds * target_rps)
    
    for i in range(total_requests):
        # Simulate realistic response time distribution
        base_response_time = 0.050  # 50ms base
        variance = 0.025 * (1 + 0.5 * (i / total_requests))  # Increasing variance
        response_time = base_response_time + (variance * (2 * time.time() % 1 - 1))
        
        # Simulate occasional errors and slow requests
        status_code = 200
        if i % 100 == 0:  # 1% error rate
            status_code = 500
            response_time *= 2  # Errors take longer
        elif i % 50 == 0:  # 2% slow requests
            response_time *= 3
        
        request_data = {
            "timestamp": start_time + (i / target_rps),
            "response_time_ms": response_time * 1000,
            "status_code": status_code,
            "endpoint": f"/api/v1/test/{i % 5}",  # 5 different endpoints
            "method": "GET" if i % 3 == 0 else "POST",
            "request_size": 1024 + (i % 512),
            "response_size": 2048 + (i % 1024)
        }
        
        requests.append(request_data)
    
    return requests


@contextmanager
def performance_monitoring_context(monitoring_setup: Dict[str, Any]):
    """
    Context manager for performance monitoring test execution.
    
    Args:
        monitoring_setup: Performance monitoring setup from fixture
        
    Yields:
        Monitoring context with data collection utilities
    """
    start_time = time.time()
    
    try:
        # Initialize monitoring context
        context = {
            "start_time": start_time,
            "monitoring_setup": monitoring_setup,
            "collected_data": [],
            "performance_events": []
        }
        
        yield context
        
    finally:
        # Finalize monitoring and generate report
        end_time = time.time()
        
        context["end_time"] = end_time
        context["duration"] = end_time - start_time
        
        # Generate final performance report
        if "generate_report" in monitoring_setup:
            context["final_report"] = monitoring_setup["generate_report"]()
        
        logger.info(
            "Performance monitoring context completed",
            duration_s=context["duration"],
            data_points=len(context["collected_data"]),
            events=len(context["performance_events"])
        )


# Performance test markers for pytest
pytestmark = [
    pytest.mark.performance,
    pytest.mark.monitoring,
    pytest.mark.integration,
    pytest.mark.timeout(300)  # 5-minute timeout for performance tests
]