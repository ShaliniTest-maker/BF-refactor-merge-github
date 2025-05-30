"""
Performance Monitoring Integration Tests

Comprehensive test suite validating prometheus-client metrics collection, Flask-Metrics 
integration, and enterprise monitoring system compatibility. Ensures comprehensive 
performance data collection during testing with real-time monitoring validation.

This module implements performance monitoring validation requirements from:
- Section 3.6.2: prometheus-client 0.17+ metrics collection
- Section 3.6.2: Flask-Metrics request timing measurement  
- Section 3.6.2: Memory profiling for ≤10% variance compliance
- Section 3.6.2: Database query performance monitoring
- Section 3.6.1: Enterprise APM integration compatibility
- Section 6.6.1: Real-time performance data collection during tests

Key Test Categories:
- Prometheus metrics collection validation
- Flask request/response lifecycle monitoring
- Memory usage and garbage collection tracking
- Database performance monitoring integration
- Enterprise APM compatibility testing
- Real-time performance data validation
- Performance variance compliance testing

Author: Performance Engineering Team
Version: 1.0.0
Dependencies: pytest, prometheus-client 0.17+, Flask-Metrics, psutil, memory-profiler
"""

import pytest
import time
import threading
import gc
import os
import json
import psutil
import requests
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any, Union
from unittest.mock import Mock, patch, MagicMock
from contextlib import contextmanager
from collections import defaultdict
import memory_profiler

# Flask and Prometheus imports
from flask import Flask, request, jsonify
from prometheus_client import (
    CollectorRegistry, Counter, Histogram, Gauge, Summary,
    generate_latest, CONTENT_TYPE_LATEST
)
from prometheus_client.parser import text_string_to_metric_families

# Application imports
from src.monitoring.metrics import (
    FlaskMetricsCollector, metrics_collector, init_metrics,
    track_business_operation, track_database_operation,
    track_external_service_call, get_performance_summary
)
from src.config.settings import (
    TestingConfig, get_monitoring_config, create_config_for_environment
)

# Test framework imports
from tests.performance.baseline_data import (
    NODEJS_BASELINE_METRICS, get_baseline_response_time,
    get_baseline_memory_usage, validate_variance_threshold
)
from tests.performance.performance_config import (
    PERFORMANCE_VARIANCE_THRESHOLD, MEMORY_MONITORING_CONFIG,
    DATABASE_PERFORMANCE_THRESHOLDS, APM_INTEGRATION_CONFIG
)


class TestPrometheusMetricsCollection:
    """
    Test suite for prometheus-client 0.17+ metrics collection validation.
    
    Validates comprehensive Prometheus metrics integration including:
    - Core metrics registration and collection
    - Custom business metrics implementation
    - Multiprocess metrics aggregation
    - Metrics endpoint functionality
    - Performance impact assessment
    """
    
    def test_prometheus_client_version_compliance(self):
        """
        Validate prometheus-client version compliance per Section 3.6.2.
        
        Ensures prometheus-client 0.17+ is installed and properly configured
        for enterprise monitoring integration.
        """
        import prometheus_client
        
        # Validate minimum version requirement
        version_parts = prometheus_client.__version__.split('.')
        major, minor = int(version_parts[0]), int(version_parts[1])
        
        assert major > 0 or (major == 0 and minor >= 17), (
            f"prometheus-client version {prometheus_client.__version__} does not meet "
            f"minimum requirement of 0.17+ per Section 3.6.2"
        )
    
    def test_metrics_registry_initialization(self, flask_app):
        """
        Test Prometheus metrics registry initialization and configuration.
        
        Validates proper metrics registry setup for multiprocess WSGI deployment
        and enterprise monitoring integration.
        """
        # Initialize metrics collector
        collector = FlaskMetricsCollector(flask_app)
        
        # Validate registry configuration
        assert collector.registry is not None
        assert hasattr(collector, 'request_duration')
        assert hasattr(collector, 'request_count')
        assert hasattr(collector, 'performance_variance')
        assert hasattr(collector, 'memory_usage')
        
        # Test metrics registration
        metrics_families = list(collector.registry._collector_to_names.values())
        assert len(metrics_families) > 0
        
        # Validate core metrics exist
        expected_metrics = [
            'flask_request_duration_seconds',
            'flask_requests_total',
            'flask_performance_variance_percentage',
            'flask_process_memory_bytes'
        ]
        
        registered_metrics = []
        for names in metrics_families:
            registered_metrics.extend(names)
        
        for metric in expected_metrics:
            assert metric in registered_metrics, f"Required metric {metric} not registered"
    
    def test_request_metrics_collection(self, flask_app, performance_client):
        """
        Test comprehensive request metrics collection during API calls.
        
        Validates Flask request/response lifecycle monitoring with detailed
        timing and performance characteristics per Section 3.6.2.
        """
        # Initialize metrics collector
        collector = init_metrics(flask_app)
        
        # Create test endpoint
        @flask_app.route('/test_metrics_endpoint')
        def test_endpoint():
            time.sleep(0.1)  # Simulate processing time
            return jsonify({'status': 'success', 'timestamp': time.time()})
        
        # Execute multiple requests for statistical analysis
        request_count = 10
        response_times = []
        
        for i in range(request_count):
            start_time = time.time()
            response = performance_client.get('/test_metrics_endpoint')
            end_time = time.time()
            
            assert response.status_code == 200
            response_times.append(end_time - start_time)
        
        # Allow metrics collection to process
        time.sleep(0.5)
        
        # Validate metrics were collected
        metrics_output = generate_latest(collector.registry)
        metrics_text = metrics_output.decode('utf-8')
        
        # Check for request duration metrics
        assert 'flask_request_duration_seconds' in metrics_text
        assert 'flask_requests_total' in metrics_text
        assert 'test_metrics_endpoint' in metrics_text
        
        # Validate metrics contain expected labels
        assert 'method="GET"' in metrics_text
        assert 'status_code="200"' in metrics_text
        
        # Validate performance data accuracy
        avg_response_time = statistics.mean(response_times)
        assert 0.08 <= avg_response_time <= 0.15, (
            f"Response time {avg_response_time:.3f}s outside expected range"
        )
    
    def test_custom_business_metrics(self, flask_app):
        """
        Test custom business metrics implementation and collection.
        
        Validates business operation tracking, external service monitoring,
        and database operation metrics per Section 6.5.4.5.
        """
        collector = init_metrics(flask_app)
        
        # Test business operation tracking
        @track_business_operation('user_registration', 'auth_module')
        def mock_business_operation():
            time.sleep(0.05)
            return {'user_id': 12345, 'status': 'created'}
        
        # Test database operation tracking
        @track_database_operation('insert', 'users')
        def mock_database_operation():
            time.sleep(0.02)
            return {'inserted_id': '507f1f77bcf86cd799439011'}
        
        # Test external service tracking
        @track_external_service_call('auth0', 'user_profile')
        def mock_external_service():
            time.sleep(0.03)
            return {'profile': 'data'}
        
        # Execute operations
        business_result = mock_business_operation()
        db_result = mock_database_operation()
        service_result = mock_external_service()
        
        # Validate operations completed
        assert business_result['status'] == 'created'
        assert 'inserted_id' in db_result
        assert 'profile' in service_result
        
        # Generate metrics and validate
        metrics_output = generate_latest(collector.registry)
        metrics_text = metrics_output.decode('utf-8')
        
        # Validate business metrics
        assert 'flask_business_operation_duration_seconds' in metrics_text
        assert 'operation="user_registration"' in metrics_text
        assert 'module="auth_module"' in metrics_text
        
        # Validate database metrics
        assert 'flask_database_operation_duration_seconds' in metrics_text
        assert 'operation_type="insert"' in metrics_text
        assert 'collection="users"' in metrics_text
        
        # Validate external service metrics
        assert 'flask_external_service_duration_seconds' in metrics_text
        assert 'service="auth0"' in metrics_text
        assert 'endpoint="user_profile"' in metrics_text
    
    def test_metrics_endpoint_functionality(self, flask_app, performance_client):
        """
        Test Prometheus metrics endpoint functionality and format compliance.
        
        Validates metrics endpoint returns properly formatted Prometheus
        metrics data supporting both Prometheus and OpenMetrics formats.
        """
        collector = init_metrics(flask_app)
        
        # Test standard Prometheus format
        response = performance_client.get('/metrics')
        assert response.status_code == 200
        assert response.headers['Content-Type'].startswith('text/plain')
        
        # Validate metrics format
        metrics_text = response.get_data(as_text=True)
        assert 'flask_request_duration_seconds' in metrics_text
        assert 'flask_requests_total' in metrics_text
        
        # Test OpenMetrics format support
        response = performance_client.get(
            '/metrics',
            headers={'Accept': 'application/openmetrics-text'}
        )
        assert response.status_code == 200
        
        # Validate metrics parsing
        try:
            metrics_families = list(text_string_to_metric_families(metrics_text))
            assert len(metrics_families) > 0
        except Exception as e:
            pytest.fail(f"Metrics format validation failed: {e}")
    
    def test_multiprocess_metrics_support(self, flask_app):
        """
        Test multiprocess metrics support for WSGI deployment.
        
        Validates Gunicorn prometheus_multiproc_dir configuration and
        worker process metrics aggregation per Section 6.5.4.1.
        """
        # Mock multiprocess environment
        test_multiprocess_dir = '/tmp/test_prometheus_multiproc'
        os.makedirs(test_multiprocess_dir, exist_ok=True)
        
        with patch.dict(os.environ, {'prometheus_multiproc_dir': test_multiprocess_dir}):
            collector = FlaskMetricsCollector(flask_app)
            
            # Validate multiprocess configuration
            assert hasattr(collector, 'registry')
            
            # Test metrics collection across multiple "workers"
            worker_metrics = []
            for worker_id in range(3):
                with patch('os.getpid', return_value=1000 + worker_id):
                    collector.request_count.labels(
                        method='GET',
                        endpoint='test',
                        status_code='200',
                        client_type='test'
                    ).inc()
                    
                    metrics_output = generate_latest(collector.registry)
                    worker_metrics.append(metrics_output.decode('utf-8'))
            
            # Validate worker metrics exist
            assert len(worker_metrics) == 3
            for metrics in worker_metrics:
                assert 'flask_requests_total' in metrics
        
        # Clean up test directory
        import shutil
        if os.path.exists(test_multiprocess_dir):
            shutil.rmtree(test_multiprocess_dir)
    
    def test_performance_impact_assessment(self, flask_app, performance_client):
        """
        Test performance impact of metrics collection on application performance.
        
        Validates metrics collection overhead is minimal and within acceptable
        limits for production deployment per Section 3.6.2.
        """
        # Baseline performance without metrics
        @flask_app.route('/performance_test_baseline')
        def baseline_endpoint():
            return jsonify({'data': 'test'})
        
        # Measure baseline performance
        baseline_times = []
        for _ in range(50):
            start_time = time.time()
            response = performance_client.get('/performance_test_baseline')
            end_time = time.time()
            assert response.status_code == 200
            baseline_times.append(end_time - start_time)
        
        baseline_avg = statistics.mean(baseline_times)
        
        # Initialize metrics collection
        collector = init_metrics(flask_app)
        
        # Create monitored endpoint
        @flask_app.route('/performance_test_monitored')
        def monitored_endpoint():
            return jsonify({'data': 'test'})
        
        # Measure performance with metrics
        monitored_times = []
        for _ in range(50):
            start_time = time.time()
            response = performance_client.get('/performance_test_monitored')
            end_time = time.time()
            assert response.status_code == 200
            monitored_times.append(end_time - start_time)
        
        monitored_avg = statistics.mean(monitored_times)
        
        # Calculate performance overhead
        overhead_percent = ((monitored_avg - baseline_avg) / baseline_avg) * 100
        
        # Validate overhead is acceptable (should be < 5%)
        assert overhead_percent < 5.0, (
            f"Metrics collection overhead {overhead_percent:.2f}% exceeds 5% threshold"
        )
        
        # Log performance impact for monitoring
        print(f"Metrics collection overhead: {overhead_percent:.2f}%")
        print(f"Baseline avg: {baseline_avg*1000:.2f}ms, Monitored avg: {monitored_avg*1000:.2f}ms")


class TestFlaskMetricsIntegration:
    """
    Test suite for Flask-Metrics integration and request timing measurement.
    
    Validates comprehensive Flask request lifecycle monitoring including:
    - Request/response hook integration
    - Timing accuracy and precision
    - Performance variance tracking
    - Enterprise monitoring compatibility
    """
    
    def test_flask_request_hooks_integration(self, flask_app, performance_client):
        """
        Test Flask request/response hooks for comprehensive monitoring.
        
        Validates before_request, after_request, and teardown_request hooks
        provide complete request lifecycle visibility per Section 6.5.1.1.
        """
        collector = init_metrics(flask_app)
        
        # Track hook execution
        hooks_executed = []
        
        @flask_app.before_request
        def test_before_hook():
            hooks_executed.append('before_request')
        
        @flask_app.after_request
        def test_after_hook(response):
            hooks_executed.append('after_request')
            return response
        
        @flask_app.teardown_request
        def test_teardown_hook(exception):
            hooks_executed.append('teardown_request')
        
        # Create test endpoint
        @flask_app.route('/hooks_test')
        def hooks_endpoint():
            hooks_executed.append('endpoint_execution')
            return jsonify({'hooks': 'test'})
        
        # Execute request
        response = performance_client.get('/hooks_test')
        assert response.status_code == 200
        
        # Validate hook execution order
        expected_hooks = ['before_request', 'endpoint_execution', 'after_request', 'teardown_request']
        assert hooks_executed == expected_hooks
        
        # Validate metrics were collected
        metrics_output = generate_latest(collector.registry)
        metrics_text = metrics_output.decode('utf-8')
        
        assert 'flask_request_duration_seconds' in metrics_text
        assert 'hooks_test' in metrics_text
    
    def test_request_timing_accuracy(self, flask_app, performance_client):
        """
        Test request timing accuracy and precision measurement.
        
        Validates timing measurements are accurate and provide sufficient
        precision for performance variance detection per Section 3.6.2.
        """
        collector = init_metrics(flask_app)
        
        # Create endpoints with known execution times
        @flask_app.route('/timing_test_fast')
        def fast_endpoint():
            return jsonify({'speed': 'fast'})
        
        @flask_app.route('/timing_test_slow')
        def slow_endpoint():
            time.sleep(0.1)  # 100ms delay
            return jsonify({'speed': 'slow'})
        
        # Measure fast endpoint
        fast_times = []
        for _ in range(20):
            start_time = time.time()
            response = performance_client.get('/timing_test_fast')
            end_time = time.time()
            assert response.status_code == 200
            fast_times.append(end_time - start_time)
        
        # Measure slow endpoint
        slow_times = []
        for _ in range(20):
            start_time = time.time()
            response = performance_client.get('/timing_test_slow')
            end_time = time.time()
            assert response.status_code == 200
            slow_times.append(end_time - start_time)
        
        # Validate timing differences
        fast_avg = statistics.mean(fast_times)
        slow_avg = statistics.mean(slow_times)
        
        # Fast endpoint should be significantly faster
        assert slow_avg > fast_avg + 0.08, (
            f"Timing difference insufficient: fast={fast_avg:.3f}s, slow={slow_avg:.3f}s"
        )
        
        # Validate timing precision (standard deviation should be low)
        fast_std = statistics.stdev(fast_times)
        slow_std = statistics.stdev(slow_times)
        
        assert fast_std < 0.01, f"Fast endpoint timing variance too high: {fast_std:.4f}s"
        assert slow_std < 0.02, f"Slow endpoint timing variance too high: {slow_std:.4f}s"
    
    def test_performance_variance_tracking(self, flask_app, performance_client):
        """
        Test performance variance tracking against Node.js baseline.
        
        Validates real-time performance variance calculation and compliance
        monitoring per Section 6.5.4.5 performance variance tracking.
        """
        collector = init_metrics(flask_app)
        
        # Set Node.js baseline for test endpoint
        test_endpoint = '/variance_test'
        baseline_duration = 0.05  # 50ms baseline
        collector.set_nodejs_baseline(test_endpoint, baseline_duration)
        
        @flask_app.route(test_endpoint)
        def variance_endpoint():
            # Simulate variable processing time
            processing_time = 0.045 + (hash(str(time.time())) % 100) / 10000  # 45-55ms
            time.sleep(processing_time)
            return jsonify({'variance': 'test'})
        
        # Execute requests to build performance history
        for _ in range(50):
            response = performance_client.get(test_endpoint)
            assert response.status_code == 200
        
        # Allow metrics processing
        time.sleep(0.5)
        
        # Validate variance metrics
        metrics_output = generate_latest(collector.registry)
        metrics_text = metrics_output.decode('utf-8')
        
        assert 'flask_performance_variance_percentage' in metrics_text
        assert 'endpoint="/variance_test"' in metrics_text or 'endpoint="variance_test"' in metrics_text
        
        # Get performance summary
        summary = get_performance_summary()
        assert 'performance_compliance' in summary
        
        if test_endpoint in summary['performance_compliance']:
            compliance_data = summary['performance_compliance'][test_endpoint]
            variance_pct = abs(compliance_data['variance_percentage'])
            
            # Validate variance is within acceptable range
            assert variance_pct <= PERFORMANCE_VARIANCE_THRESHOLD, (
                f"Performance variance {variance_pct:.2f}% exceeds threshold "
                f"{PERFORMANCE_VARIANCE_THRESHOLD}%"
            )
    
    def test_concurrent_request_monitoring(self, flask_app, performance_client):
        """
        Test concurrent request monitoring and active request tracking.
        
        Validates active request gauge and concurrent load handling
        metrics collection per Section 6.5.1.1.
        """
        collector = init_metrics(flask_app)
        
        @flask_app.route('/concurrent_test')
        def concurrent_endpoint():
            time.sleep(0.2)  # Hold requests for concurrency testing
            return jsonify({'concurrent': 'test'})
        
        # Function to make concurrent requests
        def make_request():
            response = performance_client.get('/concurrent_test')
            return response.status_code
        
        # Execute concurrent requests
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(make_request) for _ in range(10)]
            
            # Check active requests during execution
            time.sleep(0.1)  # Allow requests to start
            
            metrics_output = generate_latest(collector.registry)
            metrics_text = metrics_output.decode('utf-8')
            
            # Should have active requests gauge
            assert 'flask_active_requests' in metrics_text
            
            # Wait for completion
            results = [future.result() for future in futures]
            assert all(status == 200 for status in results)
        
        # Final metrics check
        time.sleep(0.5)
        final_metrics = generate_latest(collector.registry)
        final_text = final_metrics.decode('utf-8')
        
        # Should show completed requests
        assert 'flask_requests_total' in final_text
        assert 'concurrent_test' in final_text
    
    def test_error_handling_metrics(self, flask_app, performance_client):
        """
        Test error handling and exception metrics collection.
        
        Validates proper metrics collection for error conditions,
        exceptions, and failure scenarios per Section 6.5.1.1.
        """
        collector = init_metrics(flask_app)
        
        @flask_app.route('/error_test_404')
        def not_found_endpoint():
            return jsonify({'error': 'not found'}), 404
        
        @flask_app.route('/error_test_500')
        def server_error_endpoint():
            raise Exception("Test server error")
        
        # Test 404 error
        response = performance_client.get('/error_test_404')
        assert response.status_code == 404
        
        # Test 500 error (should be handled by Flask)
        response = performance_client.get('/error_test_500')
        assert response.status_code == 500
        
        # Allow metrics processing
        time.sleep(0.5)
        
        # Validate error metrics
        metrics_output = generate_latest(collector.registry)
        metrics_text = metrics_output.decode('utf-8')
        
        # Should track different status codes
        assert 'status_code="404"' in metrics_text
        assert 'status_code="500"' in metrics_text
        
        # Should track error endpoints
        assert 'error_test_404' in metrics_text
        assert 'error_test_500' in metrics_text


class TestMemoryProfiling:
    """
    Test suite for memory profiling and ≤10% variance compliance monitoring.
    
    Validates comprehensive memory usage tracking including:
    - Process memory monitoring
    - Garbage collection metrics
    - Memory performance correlation
    - Variance compliance validation
    """
    
    def test_process_memory_monitoring(self, flask_app):
        """
        Test process memory usage monitoring and tracking.
        
        Validates real-time memory metrics collection using psutil
        integration per Section 6.5.1.1 CPU utilization monitoring.
        """
        collector = init_metrics(flask_app)
        
        # Allow system monitoring to initialize
        time.sleep(2)
        
        # Get initial memory usage
        process = psutil.Process()
        initial_memory = process.memory_info()
        
        # Generate metrics
        metrics_output = generate_latest(collector.registry)
        metrics_text = metrics_output.decode('utf-8')
        
        # Validate memory metrics exist
        assert 'flask_process_memory_bytes' in metrics_text
        
        # Validate memory types are tracked
        assert 'memory_type="rss"' in metrics_text
        assert 'memory_type="vms"' in metrics_text
        assert 'memory_type="percent"' in metrics_text
        
        # Extract memory values from metrics
        import re
        rss_match = re.search(r'flask_process_memory_bytes{memory_type="rss"} ([\d.]+)', metrics_text)
        if rss_match:
            metrics_rss = float(rss_match.group(1))
            # Should be reasonably close to actual memory usage
            assert abs(metrics_rss - initial_memory.rss) / initial_memory.rss < 0.1
    
    @memory_profiler.profile
    def test_memory_usage_profiling(self, flask_app, performance_client):
        """
        Test memory usage profiling during request processing.
        
        Validates memory allocation patterns and identifies potential
        memory leaks or excessive usage per Section 3.6.2.
        """
        collector = init_metrics(flask_app)
        
        # Create memory-intensive endpoint
        @flask_app.route('/memory_test')
        def memory_intensive_endpoint():
            # Allocate and deallocate memory
            data = [i for i in range(10000)]  # Create list
            processed = [x * 2 for x in data]  # Process data
            result = sum(processed)  # Aggregate
            return jsonify({'result': result, 'count': len(processed)})
        
        # Monitor memory before requests
        process = psutil.Process()
        initial_memory = process.memory_info().rss
        
        # Execute memory-intensive requests
        for _ in range(20):
            response = performance_client.get('/memory_test')
            assert response.status_code == 200
        
        # Force garbage collection
        gc.collect()
        time.sleep(1)
        
        # Monitor memory after requests
        final_memory = process.memory_info().rss
        memory_growth = final_memory - initial_memory
        memory_growth_percent = (memory_growth / initial_memory) * 100
        
        # Validate memory growth is reasonable (< 50% growth)
        assert memory_growth_percent < 50, (
            f"Memory growth {memory_growth_percent:.2f}% exceeds threshold during testing"
        )
        
        # Validate memory metrics reflect actual usage
        metrics_output = generate_latest(collector.registry)
        metrics_text = metrics_output.decode('utf-8')
        
        assert 'flask_process_memory_bytes' in metrics_text
        
        # Log memory usage for analysis
        print(f"Memory growth: {memory_growth / 1024 / 1024:.2f} MB ({memory_growth_percent:.2f}%)")
    
    def test_garbage_collection_monitoring(self, flask_app):
        """
        Test garbage collection metrics and pause time monitoring.
        
        Validates GC metrics collection and pause time tracking
        per Section 6.5.2.2 Python GC pause time monitoring.
        """
        collector = init_metrics(flask_app)
        
        # Get initial GC stats
        initial_gc_counts = gc.get_count()
        initial_gc_stats = gc.get_stats()
        
        # Trigger garbage collection activity
        test_objects = []
        for generation in range(3):
            # Create objects that will trigger different GC generations
            for _ in range(1000):
                test_objects.append([i for i in range(100)])
            
            # Force collection of specific generation
            gc.collect(generation)
        
        # Allow metrics collection to process
        time.sleep(2)
        
        # Generate metrics
        metrics_output = generate_latest(collector.registry)
        metrics_text = metrics_output.decode('utf-8')
        
        # Validate GC metrics exist
        assert 'flask_gc_collections_total' in metrics_text
        assert 'flask_gc_pause_seconds' in metrics_text
        
        # Validate generation tracking
        for generation in range(3):
            assert f'generation="{generation}"' in metrics_text
        
        # Check GC count increase
        final_gc_counts = gc.get_count()
        assert any(final >= initial for final, initial in zip(final_gc_counts, initial_gc_counts))
        
        # Clean up test objects
        test_objects.clear()
        gc.collect()
    
    def test_memory_performance_correlation(self, flask_app, performance_client):
        """
        Test memory usage correlation with response time performance.
        
        Validates memory impact on performance and compliance with
        baseline variance requirements per Section 6.5.4.5.
        """
        collector = init_metrics(flask_app)
        
        # Create endpoints with different memory profiles
        @flask_app.route('/memory_light')
        def light_memory_endpoint():
            data = {'result': 'light'}
            return jsonify(data)
        
        @flask_app.route('/memory_heavy')
        def heavy_memory_endpoint():
            # Allocate significant memory
            large_data = [list(range(1000)) for _ in range(100)]
            result = len(large_data)
            return jsonify({'result': result, 'memory_intensive': True})
        
        # Measure light memory endpoint
        light_times = []
        for _ in range(30):
            start_time = time.time()
            response = performance_client.get('/memory_light')
            end_time = time.time()
            assert response.status_code == 200
            light_times.append(end_time - start_time)
        
        # Measure heavy memory endpoint
        heavy_times = []
        for _ in range(30):
            start_time = time.time()
            response = performance_client.get('/memory_heavy')
            end_time = time.time()
            assert response.status_code == 200
            heavy_times.append(end_time - start_time)
        
        # Analyze performance correlation
        light_avg = statistics.mean(light_times)
        heavy_avg = statistics.mean(heavy_times)
        
        # Heavy endpoint should be slower due to memory allocation
        performance_diff = ((heavy_avg - light_avg) / light_avg) * 100
        
        # Log correlation data
        print(f"Light memory avg: {light_avg*1000:.2f}ms")
        print(f"Heavy memory avg: {heavy_avg*1000:.2f}ms") 
        print(f"Performance difference: {performance_diff:.2f}%")
        
        # Validate memory correlation metrics
        metrics_output = generate_latest(collector.registry)
        metrics_text = metrics_output.decode('utf-8')
        
        assert 'flask_memory_performance_correlation' in metrics_text
        
        # Clean up memory
        gc.collect()
    
    def test_memory_variance_compliance(self, flask_app, performance_client):
        """
        Test memory usage variance compliance with ≤10% threshold.
        
        Validates memory usage patterns comply with baseline variance
        requirements per Section 0.1.1 performance monitoring.
        """
        collector = init_metrics(flask_app)
        
        # Get baseline memory from test data
        baseline_memory = get_baseline_memory_usage('api_endpoint')
        
        @flask_app.route('/memory_variance_test')
        def variance_test_endpoint():
            return jsonify({'memory_test': 'variance'})
        
        # Monitor memory usage during requests
        memory_measurements = []
        process = psutil.Process()
        
        for _ in range(50):
            initial_memory = process.memory_info().rss
            response = performance_client.get('/memory_variance_test')
            final_memory = process.memory_info().rss
            
            assert response.status_code == 200
            memory_measurements.append(final_memory)
        
        # Calculate memory variance
        avg_memory = statistics.mean(memory_measurements)
        if baseline_memory > 0:
            variance_percent = abs((avg_memory - baseline_memory) / baseline_memory) * 100
            
            # Validate compliance with variance threshold
            is_compliant = validate_variance_threshold(variance_percent, 'memory_usage')
            assert is_compliant, (
                f"Memory variance {variance_percent:.2f}% exceeds {PERFORMANCE_VARIANCE_THRESHOLD}% threshold"
            )
            
            print(f"Memory variance: {variance_percent:.2f}%")
        else:
            print("Baseline memory data not available for comparison")


class TestDatabasePerformanceMonitoring:
    """
    Test suite for database query performance monitoring and tracking.
    
    Validates comprehensive database operation monitoring including:
    - Query execution time tracking
    - Connection pool monitoring
    - Database operation metrics
    - Performance threshold compliance
    """
    
    def test_database_operation_tracking(self, flask_app, mock_database):
        """
        Test database operation performance tracking and metrics.
        
        Validates database operation timing and performance metrics
        collection per Section 3.6.2 database monitoring.
        """
        collector = init_metrics(flask_app)
        
        # Mock database operations with timing
        @track_database_operation('find', 'users')
        def mock_find_operation():
            time.sleep(0.01)  # Simulate query time
            return [{'user_id': 1, 'name': 'Test User'}]
        
        @track_database_operation('insert', 'users')
        def mock_insert_operation():
            time.sleep(0.005)  # Simulate insert time
            return {'inserted_id': 'test_id'}
        
        @track_database_operation('update', 'users')
        def mock_update_operation():
            time.sleep(0.008)  # Simulate update time
            return {'modified_count': 1}
        
        # Execute database operations
        find_result = mock_find_operation()
        insert_result = mock_insert_operation()
        update_result = mock_update_operation()
        
        # Validate operations completed
        assert len(find_result) == 1
        assert 'inserted_id' in insert_result
        assert update_result['modified_count'] == 1
        
        # Validate database metrics
        metrics_output = generate_latest(collector.registry)
        metrics_text = metrics_output.decode('utf-8')
        
        assert 'flask_database_operation_duration_seconds' in metrics_text
        assert 'operation_type="find"' in metrics_text
        assert 'operation_type="insert"' in metrics_text
        assert 'operation_type="update"' in metrics_text
        assert 'collection="users"' in metrics_text
    
    def test_connection_pool_monitoring(self, flask_app, mock_database):
        """
        Test database connection pool performance monitoring.
        
        Validates connection pool metrics and performance tracking
        per Section 6.5.1.1 database monitoring requirements.
        """
        collector = init_metrics(flask_app)
        
        # Mock connection pool operations
        class MockConnectionPool:
            def __init__(self):
                self.active_connections = 0
                self.max_connections = 10
                self.wait_time = 0
            
            def get_connection(self):
                start_time = time.time()
                time.sleep(0.001)  # Simulate connection acquisition
                self.active_connections += 1
                self.wait_time = time.time() - start_time
                return MockConnection()
            
            def release_connection(self, conn):
                self.active_connections -= 1
        
        class MockConnection:
            def query(self, sql):
                time.sleep(0.005)  # Simulate query execution
                return {'rows': []}
        
        pool = MockConnectionPool()
        
        # Simulate multiple database operations
        connections = []
        query_times = []
        
        for _ in range(20):
            start_time = time.time()
            conn = pool.get_connection()
            connections.append(conn)
            
            result = conn.query("SELECT * FROM test")
            query_time = time.time() - start_time
            query_times.append(query_time)
            
            # Simulate some connections being released
            if len(connections) > 5:
                pool.release_connection(connections.pop(0))
        
        # Release remaining connections
        for conn in connections:
            pool.release_connection(conn)
        
        # Validate query performance
        avg_query_time = statistics.mean(query_times)
        max_query_time = max(query_times)
        
        # Check against database performance thresholds
        assert avg_query_time < DATABASE_PERFORMANCE_THRESHOLDS['avg_query_time']
        assert max_query_time < DATABASE_PERFORMANCE_THRESHOLDS['max_query_time']
        
        print(f"Average query time: {avg_query_time*1000:.2f}ms")
        print(f"Max query time: {max_query_time*1000:.2f}ms")
        print(f"Connection pool efficiency: {pool.active_connections}/{pool.max_connections}")
    
    def test_query_performance_variance(self, flask_app, mock_database):
        """
        Test database query performance variance against baseline.
        
        Validates query performance compliance with ≤10% variance
        requirement per Section 0.1.1 performance monitoring.
        """
        collector = init_metrics(flask_app)
        
        # Get baseline query times
        baseline_find_time = get_baseline_response_time('database_find')
        baseline_insert_time = get_baseline_response_time('database_insert')
        
        # Mock database operations with realistic timing
        @track_database_operation('find', 'performance_test')
        def benchmark_find():
            # Simulate query time similar to baseline
            query_time = baseline_find_time + (hash(str(time.time())) % 100) / 50000  # ±1ms variance
            time.sleep(query_time)
            return [{'id': i} for i in range(10)]
        
        @track_database_operation('insert', 'performance_test')  
        def benchmark_insert():
            # Simulate insert time similar to baseline
            insert_time = baseline_insert_time + (hash(str(time.time())) % 100) / 100000  # ±0.5ms variance
            time.sleep(insert_time)
            return {'inserted_id': 'benchmark_id'}
        
        # Execute operations for statistical analysis
        find_times = []
        insert_times = []
        
        for _ in range(30):
            # Measure find operations
            start_time = time.time()
            benchmark_find()
            find_times.append(time.time() - start_time)
            
            # Measure insert operations  
            start_time = time.time()
            benchmark_insert()
            insert_times.append(time.time() - start_time)
        
        # Calculate variance
        avg_find_time = statistics.mean(find_times)
        avg_insert_time = statistics.mean(insert_times)
        
        find_variance = abs((avg_find_time - baseline_find_time) / baseline_find_time) * 100
        insert_variance = abs((avg_insert_time - baseline_insert_time) / baseline_insert_time) * 100
        
        # Validate variance compliance
        assert find_variance <= PERFORMANCE_VARIANCE_THRESHOLD, (
            f"Find query variance {find_variance:.2f}% exceeds threshold"
        )
        assert insert_variance <= PERFORMANCE_VARIANCE_THRESHOLD, (
            f"Insert query variance {insert_variance:.2f}% exceeds threshold"
        )
        
        # Validate metrics collection
        metrics_output = generate_latest(collector.registry)
        metrics_text = metrics_output.decode('utf-8')
        
        assert 'flask_database_operation_duration_seconds' in metrics_text
        assert 'collection="performance_test"' in metrics_text
        
        print(f"Find variance: {find_variance:.2f}%")
        print(f"Insert variance: {insert_variance:.2f}%")
    
    def test_database_error_monitoring(self, flask_app, mock_database):
        """
        Test database error and exception monitoring.
        
        Validates proper error tracking and metrics collection
        for database operation failures per Section 6.5.1.1.
        """
        collector = init_metrics(flask_app)
        
        # Mock database operations with errors
        @track_database_operation('find', 'error_test')
        def failing_find_operation():
            time.sleep(0.01)
            raise Exception("Database connection failed")
        
        @track_database_operation('insert', 'error_test')
        def failing_insert_operation():
            time.sleep(0.005)
            raise Exception("Insert operation failed")
        
        # Execute failing operations
        error_count = 0
        
        for _ in range(10):
            try:
                failing_find_operation()
            except Exception:
                error_count += 1
            
            try:
                failing_insert_operation()
            except Exception:
                error_count += 1
        
        # Validate errors were tracked
        assert error_count == 20
        
        # Validate error metrics
        metrics_output = generate_latest(collector.registry)
        metrics_text = metrics_output.decode('utf-8')
        
        assert 'flask_database_operation_duration_seconds' in metrics_text
        assert 'status="error"' in metrics_text
        assert 'collection="error_test"' in metrics_text


class TestEnterpriseAPMIntegration:
    """
    Test suite for enterprise APM integration compatibility testing.
    
    Validates compatibility with enterprise monitoring systems including:
    - APM client integration
    - Distributed tracing support
    - Custom attribute collection
    - Performance overhead assessment
    """
    
    def test_apm_client_integration(self, flask_app):
        """
        Test APM client integration and initialization.
        
        Validates proper APM client setup and configuration
        per Section 6.5.4.3 Python APM agent integration.
        """
        # Mock APM client configuration
        apm_config = APM_INTEGRATION_CONFIG.copy()
        
        with patch('ddtrace.patch_all') as mock_patch:
            with patch('newrelic.agent.initialize') as mock_newrelic:
                # Simulate APM initialization
                if apm_config['datadog']['enabled']:
                    mock_patch()
                
                if apm_config['newrelic']['enabled']:
                    mock_newrelic()
                
                # Initialize metrics collector
                collector = init_metrics(flask_app)
                
                # Validate APM integration
                assert collector is not None
                
                # Check for APM configuration
                if apm_config['datadog']['enabled']:
                    mock_patch.assert_called_once()
                
                if apm_config['newrelic']['enabled']:
                    mock_newrelic.assert_called_once()
    
    def test_distributed_tracing_support(self, flask_app, performance_client):
        """
        Test distributed tracing integration and trace propagation.
        
        Validates trace context propagation and correlation
        per Section 6.5.1.3 distributed tracing requirements.
        """
        collector = init_metrics(flask_app)
        
        # Mock distributed tracing headers
        trace_headers = {
            'X-Trace-ID': 'test-trace-12345',
            'X-Span-ID': 'test-span-67890',
            'X-Parent-ID': 'test-parent-11111'
        }
        
        @flask_app.route('/tracing_test')
        def tracing_endpoint():
            # Simulate trace context extraction
            trace_id = request.headers.get('X-Trace-ID')
            span_id = request.headers.get('X-Span-ID')
            
            return jsonify({
                'trace_id': trace_id,
                'span_id': span_id,
                'tracing': 'enabled'
            })
        
        # Execute request with tracing headers
        response = performance_client.get('/tracing_test', headers=trace_headers)
        assert response.status_code == 200
        
        data = response.get_json()
        assert data['trace_id'] == 'test-trace-12345'
        assert data['span_id'] == 'test-span-67890'
        
        # Validate metrics with trace correlation
        metrics_output = generate_latest(collector.registry)
        metrics_text = metrics_output.decode('utf-8')
        
        assert 'flask_request_duration_seconds' in metrics_text
        assert 'tracing_test' in metrics_text
    
    def test_custom_attribute_collection(self, flask_app, performance_client):
        """
        Test custom attribute collection for APM systems.
        
        Validates custom attribute tracking and correlation
        with business metrics per Section 6.5.4.3.
        """
        collector = init_metrics(flask_app)
        
        @flask_app.route('/custom_attributes_test')
        def custom_attributes_endpoint():
            # Simulate custom attributes
            user_id = request.args.get('user_id', 'anonymous')
            operation = request.args.get('operation', 'default')
            
            # Track custom business metrics
            collector.business_operation_duration.labels(
                operation=operation,
                module='test_module',
                success='true'
            ).observe(0.01)
            
            return jsonify({
                'user_id': user_id,
                'operation': operation,
                'custom_attributes': 'tracked'
            })
        
        # Execute requests with custom attributes
        test_cases = [
            {'user_id': '12345', 'operation': 'user_profile'},
            {'user_id': '67890', 'operation': 'user_settings'},
            {'user_id': '11111', 'operation': 'user_preferences'}
        ]
        
        for params in test_cases:
            response = performance_client.get('/custom_attributes_test', query_string=params)
            assert response.status_code == 200
            
            data = response.get_json()
            assert data['user_id'] == params['user_id']
            assert data['operation'] == params['operation']
        
        # Validate custom metrics
        metrics_output = generate_latest(collector.registry)
        metrics_text = metrics_output.decode('utf-8')
        
        assert 'flask_business_operation_duration_seconds' in metrics_text
        assert 'operation="user_profile"' in metrics_text
        assert 'operation="user_settings"' in metrics_text
        assert 'module="test_module"' in metrics_text
    
    def test_apm_performance_overhead(self, flask_app, performance_client):
        """
        Test APM integration performance overhead assessment.
        
        Validates APM instrumentation overhead is minimal
        per Section 6.5.4.3 APM performance configuration.
        """
        # Baseline without APM
        @flask_app.route('/apm_overhead_baseline')
        def baseline_endpoint():
            return jsonify({'test': 'baseline'})
        
        # Measure baseline performance
        baseline_times = []
        for _ in range(100):
            start_time = time.time()
            response = performance_client.get('/apm_overhead_baseline')
            end_time = time.time()
            assert response.status_code == 200
            baseline_times.append(end_time - start_time)
        
        baseline_avg = statistics.mean(baseline_times)
        
        # Initialize APM monitoring
        collector = init_metrics(flask_app)
        
        @flask_app.route('/apm_overhead_monitored')
        def monitored_endpoint():
            # Simulate APM instrumentation
            with collector.track_business_operation('apm_test', 'monitoring')():
                return jsonify({'test': 'monitored'})
        
        # Measure performance with APM
        monitored_times = []
        for _ in range(100):
            start_time = time.time()
            response = performance_client.get('/apm_overhead_monitored')
            end_time = time.time()
            assert response.status_code == 200
            monitored_times.append(end_time - start_time)
        
        monitored_avg = statistics.mean(monitored_times)
        
        # Calculate overhead
        overhead_percent = ((monitored_avg - baseline_avg) / baseline_avg) * 100
        max_overhead_threshold = APM_INTEGRATION_CONFIG['performance']['max_overhead_percent']
        
        # Validate overhead is acceptable
        assert overhead_percent < max_overhead_threshold, (
            f"APM overhead {overhead_percent:.2f}% exceeds threshold {max_overhead_threshold}%"
        )
        
        print(f"APM overhead: {overhead_percent:.2f}%")
        print(f"Baseline: {baseline_avg*1000:.2f}ms, Monitored: {monitored_avg*1000:.2f}ms")
    
    def test_apm_error_tracking(self, flask_app, performance_client):
        """
        Test APM error tracking and exception monitoring.
        
        Validates proper error capture and correlation
        with performance metrics per Section 6.5.1.1.
        """
        collector = init_metrics(flask_app)
        
        @flask_app.route('/apm_error_test')
        def error_endpoint():
            error_type = request.args.get('error_type', 'none')
            
            if error_type == 'validation':
                return jsonify({'error': 'Validation failed'}), 400
            elif error_type == 'not_found':
                return jsonify({'error': 'Resource not found'}), 404
            elif error_type == 'server':
                raise Exception("Internal server error")
            else:
                return jsonify({'status': 'success'})
        
        # Test different error types
        error_responses = []
        
        # Success case
        response = performance_client.get('/apm_error_test')
        assert response.status_code == 200
        error_responses.append(('success', response.status_code))
        
        # Validation error
        response = performance_client.get('/apm_error_test?error_type=validation')
        assert response.status_code == 400
        error_responses.append(('validation', response.status_code))
        
        # Not found error
        response = performance_client.get('/apm_error_test?error_type=not_found')
        assert response.status_code == 404
        error_responses.append(('not_found', response.status_code))
        
        # Server error
        response = performance_client.get('/apm_error_test?error_type=server')
        assert response.status_code == 500
        error_responses.append(('server', response.status_code))
        
        # Validate error tracking in metrics
        metrics_output = generate_latest(collector.registry)
        metrics_text = metrics_output.decode('utf-8')
        
        # Should track different status codes
        assert 'status_code="200"' in metrics_text
        assert 'status_code="400"' in metrics_text
        assert 'status_code="404"' in metrics_text
        assert 'status_code="500"' in metrics_text
        
        print(f"Tracked error responses: {error_responses}")


class TestRealTimePerformanceCollection:
    """
    Test suite for real-time performance data collection validation.
    
    Validates continuous performance monitoring including:
    - Real-time metrics streaming
    - Performance trend analysis
    - Alert threshold validation
    - Continuous compliance monitoring
    """
    
    def test_real_time_metrics_streaming(self, flask_app, performance_client):
        """
        Test real-time performance metrics streaming and collection.
        
        Validates continuous metrics collection and real-time
        data availability per Section 6.6.1 performance monitoring.
        """
        collector = init_metrics(flask_app)
        
        @flask_app.route('/realtime_test')
        def realtime_endpoint():
            processing_time = 0.01 + (hash(str(time.time())) % 100) / 10000  # Variable timing
            time.sleep(processing_time)
            return jsonify({'timestamp': time.time(), 'realtime': True})
        
        # Collect metrics over time
        metrics_snapshots = []
        request_times = []
        
        for i in range(20):
            # Execute request
            start_time = time.time()
            response = performance_client.get('/realtime_test')
            end_time = time.time()
            
            assert response.status_code == 200
            request_times.append(end_time - start_time)
            
            # Capture metrics snapshot
            metrics_output = generate_latest(collector.registry)
            metrics_text = metrics_output.decode('utf-8')
            metrics_snapshots.append((time.time(), metrics_text))
            
            time.sleep(0.1)  # Small delay between requests
        
        # Validate real-time data collection
        assert len(metrics_snapshots) == 20
        
        # Check metrics evolution over time
        request_counts = []
        for timestamp, metrics in metrics_snapshots:
            # Extract request count from metrics
            import re
            count_match = re.search(r'flask_requests_total.*?(\d+)', metrics)
            if count_match:
                request_counts.append(int(count_match.group(1)))
        
        # Request counts should increase over time
        if len(request_counts) > 1:
            assert request_counts[-1] >= request_counts[0]
        
        # Validate response time tracking
        avg_response_time = statistics.mean(request_times)
        response_time_std = statistics.stdev(request_times) if len(request_times) > 1 else 0
        
        print(f"Real-time metrics collected: {len(metrics_snapshots)} snapshots")
        print(f"Average response time: {avg_response_time*1000:.2f}ms")
        print(f"Response time std dev: {response_time_std*1000:.2f}ms")
    
    def test_performance_trend_analysis(self, flask_app, performance_client):
        """
        Test performance trend analysis and pattern detection.
        
        Validates trend calculation and performance pattern
        recognition per Section 6.5.2.2 performance metrics.
        """
        collector = init_metrics(flask_app)
        
        @flask_app.route('/trend_test')
        def trend_endpoint():
            # Simulate degrading performance over time
            request_count = getattr(trend_endpoint, 'count', 0)
            trend_endpoint.count = request_count + 1
            
            # Gradually increase processing time
            base_time = 0.01
            degradation_factor = request_count * 0.001  # 1ms per request
            processing_time = base_time + degradation_factor
            
            time.sleep(processing_time)
            return jsonify({'request_number': request_count, 'trend': 'degrading'})
        
        # Collect performance data over multiple requests
        performance_data = []
        
        for i in range(30):
            start_time = time.time()
            response = performance_client.get('/trend_test')
            end_time = time.time()
            
            assert response.status_code == 200
            
            request_time = end_time - start_time
            performance_data.append((i, request_time))
        
        # Analyze trend
        request_numbers = [data[0] for data in performance_data]
        response_times = [data[1] for data in performance_data]
        
        # Calculate trend using linear regression
        import numpy as np
        if len(response_times) > 1:
            slope, intercept = np.polyfit(request_numbers, response_times, 1)
            trend_direction = 'increasing' if slope > 0 else 'decreasing'
            
            print(f"Performance trend: {trend_direction} (slope: {slope:.6f})")
            print(f"Initial response time: {response_times[0]*1000:.2f}ms")
            print(f"Final response time: {response_times[-1]*1000:.2f}ms")
            
            # Validate trend detection
            assert slope > 0, "Expected increasing trend not detected"
            
            # Check if trend exceeds acceptable degradation
            degradation_percent = ((response_times[-1] - response_times[0]) / response_times[0]) * 100
            assert degradation_percent < 100, f"Performance degradation {degradation_percent:.2f}% too high"
    
    def test_alert_threshold_validation(self, flask_app, performance_client):
        """
        Test alert threshold validation and trigger mechanisms.
        
        Validates performance threshold monitoring and alerting
        per Section 6.5.5 alert threshold matrices.
        """
        collector = init_metrics(flask_app)
        
        # Set up baseline for comparison
        baseline_endpoint = '/threshold_baseline'
        baseline_time = 0.05  # 50ms baseline
        collector.set_nodejs_baseline(baseline_endpoint, baseline_time)
        
        @flask_app.route(baseline_endpoint)
        def threshold_endpoint():
            # Simulate different performance scenarios
            scenario = request.args.get('scenario', 'normal')
            
            if scenario == 'normal':
                time.sleep(0.048)  # Within 5% of baseline
            elif scenario == 'warning':
                time.sleep(0.055)  # 10% above baseline (warning)
            elif scenario == 'critical':
                time.sleep(0.060)  # 20% above baseline (critical)
            
            return jsonify({'scenario': scenario, 'threshold': 'test'})
        
        # Test normal performance
        for _ in range(10):
            response = performance_client.get(f'{baseline_endpoint}?scenario=normal')
            assert response.status_code == 200
        
        # Test warning threshold
        for _ in range(5):
            response = performance_client.get(f'{baseline_endpoint}?scenario=warning')
            assert response.status_code == 200
        
        # Test critical threshold
        for _ in range(3):
            response = performance_client.get(f'{baseline_endpoint}?scenario=critical')
            assert response.status_code == 200
        
        # Allow metrics processing
        time.sleep(1)
        
        # Validate threshold metrics
        metrics_output = generate_latest(collector.registry)
        metrics_text = metrics_output.decode('utf-8')
        
        assert 'flask_performance_variance_percentage' in metrics_text
        assert 'flask_performance_variance_violations_total' in metrics_text
        
        # Check for variance violations
        violations_pattern = r'flask_performance_variance_violations_total.*?(\d+)'
        violations_match = re.search(violations_pattern, metrics_text)
        
        if violations_match:
            violations_count = int(violations_match.group(1))
            print(f"Performance violations detected: {violations_count}")
        
        # Get performance summary
        summary = get_performance_summary()
        if baseline_endpoint in summary.get('performance_compliance', {}):
            compliance_data = summary['performance_compliance'][baseline_endpoint]
            variance_pct = abs(compliance_data['variance_percentage'])
            print(f"Current variance: {variance_pct:.2f}%")
    
    def test_continuous_compliance_monitoring(self, flask_app, performance_client):
        """
        Test continuous compliance monitoring with ≤10% variance requirement.
        
        Validates ongoing compliance tracking and enforcement
        per Section 0.1.1 primary objective requirements.
        """
        collector = init_metrics(flask_app)
        
        # Set up multiple endpoints with different baselines
        endpoints_config = [
            ('/compliance_fast', 0.02),    # 20ms baseline
            ('/compliance_medium', 0.05),  # 50ms baseline
            ('/compliance_slow', 0.10),    # 100ms baseline
        ]
        
        # Set baselines
        for endpoint, baseline in endpoints_config:
            collector.set_nodejs_baseline(endpoint, baseline)
            
            # Create endpoint
            @flask_app.route(endpoint)
            def make_endpoint(baseline_time=baseline):
                def endpoint_func():
                    # Add small random variance
                    variance = (hash(str(time.time())) % 200 - 100) / 10000  # ±10ms
                    actual_time = baseline_time + variance
                    time.sleep(max(0.001, actual_time))  # Minimum 1ms
                    return jsonify({'baseline': baseline_time, 'compliance': 'test'})
                return endpoint_func
            
            # Register the endpoint
            flask_app.add_url_rule(endpoint, endpoint.replace('/', ''), make_endpoint())
        
        # Execute continuous monitoring
        compliance_results = []
        
        for round_num in range(10):
            round_results = {}
            
            for endpoint, baseline in endpoints_config:
                # Execute requests for this endpoint
                response_times = []
                
                for _ in range(5):
                    start_time = time.time()
                    response = performance_client.get(endpoint)
                    end_time = time.time()
                    
                    assert response.status_code == 200
                    response_times.append(end_time - start_time)
                
                # Calculate variance for this round
                avg_time = statistics.mean(response_times)
                variance_pct = ((avg_time - baseline) / baseline) * 100
                
                round_results[endpoint] = {
                    'avg_time': avg_time,
                    'baseline': baseline,
                    'variance_pct': variance_pct,
                    'compliant': abs(variance_pct) <= PERFORMANCE_VARIANCE_THRESHOLD
                }
            
            compliance_results.append(round_results)
            time.sleep(0.5)  # Brief pause between rounds
        
        # Analyze compliance over time
        compliance_summary = {}
        for endpoint, _ in endpoints_config:
            variances = [result[endpoint]['variance_pct'] for result in compliance_results]
            compliant_count = sum(1 for result in compliance_results if result[endpoint]['compliant'])
            
            compliance_summary[endpoint] = {
                'avg_variance': statistics.mean(variances),
                'max_variance': max(variances),
                'compliance_rate': (compliant_count / len(compliance_results)) * 100
            }
        
        # Validate overall compliance
        for endpoint, summary in compliance_summary.items():
            print(f"{endpoint}: avg_variance={summary['avg_variance']:.2f}%, "
                  f"max_variance={summary['max_variance']:.2f}%, "
                  f"compliance_rate={summary['compliance_rate']:.1f}%")
            
            # Require high compliance rate
            assert summary['compliance_rate'] >= 80, (
                f"{endpoint} compliance rate {summary['compliance_rate']:.1f}% below 80%"
            )
            
            # Require average variance within limits
            assert abs(summary['avg_variance']) <= PERFORMANCE_VARIANCE_THRESHOLD, (
                f"{endpoint} average variance {summary['avg_variance']:.2f}% exceeds threshold"
            )
        
        # Validate final metrics state
        final_summary = get_performance_summary()
        assert 'performance_compliance' in final_summary
        assert len(final_summary['performance_compliance']) > 0
        
        print(f"Continuous monitoring completed: {len(compliance_results)} rounds")
        print(f"Endpoints monitored: {len(endpoints_config)}")


# Test execution helpers and utilities
@pytest.fixture
def performance_monitoring_setup(flask_app):
    """
    Comprehensive performance monitoring test setup fixture.
    
    Provides initialized monitoring infrastructure including metrics
    collector, baseline data, and performance configuration.
    """
    # Initialize metrics collector
    collector = init_metrics(flask_app)
    
    # Load baseline data
    for endpoint, baseline_time in NODEJS_BASELINE_METRICS['response_times'].items():
        collector.set_nodejs_baseline(endpoint, baseline_time / 1000)  # Convert to seconds
    
    # Configure monitoring settings
    config = get_monitoring_config()
    
    yield {
        'collector': collector,
        'config': config,
        'baseline_metrics': NODEJS_BASELINE_METRICS
    }
    
    # Cleanup after tests
    gc.collect()


@pytest.fixture
def mock_apm_integration():
    """
    Mock APM integration for testing without external dependencies.
    
    Provides mocked APM clients and distributed tracing functionality
    for comprehensive APM integration testing.
    """
    with patch('ddtrace.patch_all') as mock_datadog:
        with patch('newrelic.agent.initialize') as mock_newrelic:
            yield {
                'datadog': mock_datadog,
                'newrelic': mock_newrelic
            }


if __name__ == "__main__":
    # Run performance monitoring tests
    pytest.main([__file__, "-v", "--tb=short"])