"""
Performance Testing Fixtures for Node.js to Python Flask Migration

This module provides comprehensive performance testing fixtures including baseline data generation,
load testing utilities, performance monitoring setup, and benchmark comparison tools for validating
the ≤10% variance requirement from the Node.js implementation per Section 0.1.1 performance 
optimization requirements.

Key Components:
- Performance baseline data generators with Node.js comparison metrics per Section 6.6.3
- Load testing data generation and utilities for locust integration per Section 6.6.1
- Performance monitoring fixtures with Prometheus metrics collection per Section 6.6.1
- Concurrent request testing fixtures for throughput validation per Section 6.6.3
- Database performance fixtures with PyMongo and Motor timing per Section 6.2.4
- Cache performance fixtures for Redis hit/miss ratio testing per Section 3.4.5
- Response time variance validation fixtures per Section 6.6.3 performance requirements

Performance Requirements Compliance:
- Response Time Variance: ≤10% from Node.js baseline (project-critical requirement)
- Load Testing Framework: locust (≥2.x) for performance validation
- HTTP Performance Measurement: apache-bench for server performance testing
- Database Performance: PyMongo/Motor operation timing and optimization
- Cache Performance: Redis operation latency and hit/miss ratio optimization
- Monitoring Integration: Prometheus metrics collection and APM integration

Architecture Integration:
- Flask application factory pattern integration per Section 6.1.1
- Database testing with Testcontainers MongoDB/Redis per Section 6.6.1 enhanced mocking
- Authentication testing with Auth0 service mocking per Section 6.6.1
- External service mocking for performance isolation per Section 6.6.1
- Performance monitoring with enterprise APM integration per Section 6.5.1

Testing Strategy Integration:
- pytest 7.4+ framework integration with performance-specific markers
- Performance test organization structure per Section 6.6.1
- Parallel test execution optimization with pytest-xdist per Section 6.6.1
- CI/CD integration with GitHub Actions performance validation
- Performance baseline comparison with automated variance detection

Usage Examples:
    # Basic performance baseline testing
    def test_api_performance_baseline(performance_baseline_fixture):
        baseline = performance_baseline_fixture['api_endpoints']['user_profile']
        # Test implementation with baseline comparison
    
    # Load testing with locust integration
    def test_concurrent_load_performance(locust_load_generator):
        load_test_result = locust_load_generator.run_load_test(
            endpoint='/api/users',
            concurrent_users=100,
            duration_seconds=60
        )
        assert load_test_result['response_time_variance'] <= 0.10
    
    # Database performance validation
    def test_database_performance(database_performance_fixture):
        async_timing = database_performance_fixture.measure_async_operation(
            collection='users',
            operation='find_many',
            query_size=1000
        )
        assert async_timing['variance_from_baseline'] <= 0.10

References:
- Section 0.1.1: Performance optimization to ensure ≤10% variance from Node.js baseline
- Section 6.6.1: Load testing framework locust (≥2.x) and apache-bench requirements
- Section 6.6.3: Performance test thresholds and variance validation requirements
- Section 6.2.4: Database performance optimization with connection pooling
- Section 3.4.5: Redis caching layer performance requirements and monitoring
- Section 6.5.1: Monitoring and observability integration with Prometheus metrics

Author: Flask Migration Team
Version: 1.0.0
Compliance: ≤10% performance variance requirement, enterprise monitoring integration
"""

import asyncio
import json
import os
import random
import statistics
import subprocess
import threading
import time
import uuid
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager, asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, Callable, Generator, AsyncGenerator, Tuple
from unittest.mock import Mock, patch, MagicMock

import pytest
import pytest_asyncio
from flask import Flask
from flask.testing import FlaskClient

# Performance monitoring and metrics imports
try:
    import prometheus_client
    from prometheus_client import CollectorRegistry, Counter, Histogram, Gauge, Summary
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

# Load testing framework imports
try:
    import locust
    from locust import HttpUser, task, between
    from locust.env import Environment
    from locust.stats import stats_printer, stats_history
    from locust.log import setup_logging
    LOCUST_AVAILABLE = True
except ImportError:
    LOCUST_AVAILABLE = False

# Database and cache imports with fallback handling
try:
    import pymongo
    from pymongo import MongoClient
    from pymongo.collection import Collection
    from pymongo.database import Database
    PYMONGO_AVAILABLE = True
except ImportError:
    PYMONGO_AVAILABLE = False

try:
    from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase, AsyncIOMotorCollection
    MOTOR_AVAILABLE = True
except ImportError:
    MOTOR_AVAILABLE = False

try:
    import redis
    from redis import Redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

# Application dependencies with fallback
try:
    from src.app import create_app
    from src.monitoring import get_monitoring_manager, get_metrics_collector
    from src.cache import get_default_redis_client, get_cache_health
    from src.data import get_database_services, get_mongodb_client, get_motor_client
    from tests.conftest import (
        comprehensive_test_environment,
        performance_monitoring,
        test_metrics_collector
    )
    APP_DEPENDENCIES_AVAILABLE = True
except ImportError:
    APP_DEPENDENCIES_AVAILABLE = False

# Configure performance testing logger
import logging
logger = logging.getLogger(__name__)


# =============================================================================
# Performance Baseline Data Structures
# =============================================================================

@dataclass
class NodeJSPerformanceBaseline:
    """
    Node.js performance baseline data structure for comparison testing.
    
    Contains comprehensive performance metrics from the original Node.js
    implementation for validating ≤10% variance requirement per Section 0.1.1.
    """
    
    # API endpoint performance baselines (milliseconds)
    api_response_times: Dict[str, float] = field(default_factory=lambda: {
        'auth_login': 120.0,           # Authentication endpoint
        'auth_refresh': 85.0,          # Token refresh endpoint
        'user_profile': 95.0,          # User profile retrieval
        'user_update': 140.0,          # User profile update
        'project_list': 180.0,         # Project listing with pagination
        'project_create': 220.0,       # Project creation
        'project_update': 190.0,       # Project modification
        'project_delete': 110.0,       # Project deletion
        'file_upload': 850.0,          # File upload to S3
        'file_download': 450.0,        # File download from S3
        'search_users': 160.0,         # User search with filters
        'search_projects': 210.0,      # Project search with pagination
        'analytics_dashboard': 380.0,  # Dashboard data aggregation
        'admin_users': 240.0,          # Admin user management
        'admin_analytics': 420.0       # Admin analytics queries
    })
    
    # Database operation baselines (milliseconds)
    database_operations: Dict[str, float] = field(default_factory=lambda: {
        'find_one': 8.5,               # Single document retrieval
        'find_many': 45.0,             # Multiple document query
        'insert_one': 12.0,            # Single document insertion
        'insert_many': 85.0,           # Bulk document insertion
        'update_one': 15.0,            # Single document update
        'update_many': 120.0,          # Bulk document update
        'delete_one': 10.0,            # Single document deletion
        'delete_many': 95.0,           # Bulk document deletion
        'aggregate_simple': 35.0,      # Simple aggregation pipeline
        'aggregate_complex': 180.0,    # Complex aggregation with joins
        'transaction': 45.0,           # Transaction operation
        'index_query': 18.0,           # Indexed query performance
        'full_text_search': 85.0,      # Text search operation
        'geospatial_query': 120.0,     # Geospatial query performance
        'count_documents': 25.0        # Document counting operation
    })
    
    # Cache operation baselines (milliseconds)
    cache_operations: Dict[str, float] = field(default_factory=lambda: {
        'get': 1.2,                    # Cache retrieval
        'set': 1.8,                    # Cache storage
        'delete': 1.5,                 # Cache deletion
        'exists': 0.9,                 # Cache key existence check
        'expire': 1.1,                 # TTL setting
        'incr': 1.4,                   # Increment operation
        'decr': 1.3,                   # Decrement operation
        'hget': 1.6,                   # Hash field retrieval
        'hset': 2.1,                   # Hash field storage
        'lpush': 1.7,                  # List push operation
        'rpop': 1.8,                   # List pop operation
        'sadd': 1.9,                   # Set addition
        'smembers': 3.2,               # Set members retrieval
        'pipeline': 4.5,               # Pipeline operation
        'transaction': 5.8             # Redis transaction
    })
    
    # Concurrent load performance baselines
    load_performance: Dict[str, Dict[str, float]] = field(default_factory=lambda: {
        '10_users': {
            'avg_response_time': 125.0,
            'max_response_time': 280.0,
            'requests_per_second': 78.5,
            'error_rate': 0.002,           # 0.2% error rate
            'cpu_usage': 0.25,             # 25% CPU usage
            'memory_usage': 0.35           # 35% memory usage
        },
        '50_users': {
            'avg_response_time': 165.0,
            'max_response_time': 420.0,
            'requests_per_second': 285.2,
            'error_rate': 0.008,           # 0.8% error rate
            'cpu_usage': 0.48,             # 48% CPU usage
            'memory_usage': 0.52           # 52% memory usage
        },
        '100_users': {
            'avg_response_time': 210.0,
            'max_response_time': 580.0,
            'requests_per_second': 445.8,
            'error_rate': 0.015,           # 1.5% error rate
            'cpu_usage': 0.72,             # 72% CPU usage
            'memory_usage': 0.68           # 68% memory usage
        },
        '200_users': {
            'avg_response_time': 285.0,
            'max_response_time': 820.0,
            'requests_per_second': 650.4,
            'error_rate': 0.025,           # 2.5% error rate
            'cpu_usage': 0.85,             # 85% CPU usage
            'memory_usage': 0.78           # 78% memory usage
        }
    })
    
    # Performance variance thresholds
    variance_thresholds: Dict[str, float] = field(default_factory=lambda: {
        'acceptable_variance': 0.10,    # ≤10% variance requirement
        'warning_variance': 0.08,       # Warning threshold at 8%
        'critical_variance': 0.12,      # Critical threshold at 12%
        'memory_variance': 0.15,        # Memory usage variance threshold
        'cpu_variance': 0.20,           # CPU usage variance threshold
        'error_rate_variance': 0.05     # Error rate variance threshold
    })
    
    def get_baseline_value(self, category: str, operation: str) -> Optional[float]:
        """
        Get baseline value for specific operation category.
        
        Args:
            category: Performance category (api, database, cache, load)
            operation: Specific operation name
            
        Returns:
            Baseline value in milliseconds or None if not found
        """
        category_map = {
            'api': self.api_response_times,
            'database': self.database_operations,
            'cache': self.cache_operations,
            'load': self.load_performance
        }
        
        if category in category_map:
            return category_map[category].get(operation)
        return None
    
    def calculate_variance(self, measured_value: float, baseline_value: float) -> float:
        """
        Calculate performance variance from baseline.
        
        Args:
            measured_value: Measured performance value
            baseline_value: Baseline performance value
            
        Returns:
            Variance as decimal (0.10 = 10% variance)
        """
        if baseline_value == 0:
            return float('inf')
        
        return abs(measured_value - baseline_value) / baseline_value
    
    def is_within_threshold(self, measured_value: float, baseline_value: float, 
                          threshold_type: str = 'acceptable_variance') -> bool:
        """
        Check if measured value is within acceptable variance threshold.
        
        Args:
            measured_value: Measured performance value
            baseline_value: Baseline performance value
            threshold_type: Type of threshold to check against
            
        Returns:
            True if within threshold, False otherwise
        """
        variance = self.calculate_variance(measured_value, baseline_value)
        threshold = self.variance_thresholds.get(threshold_type, 0.10)
        
        return variance <= threshold


@dataclass
class PerformanceMeasurement:
    """
    Individual performance measurement data structure.
    
    Captures comprehensive performance metrics for a single operation
    including timing, resource usage, and context information.
    """
    
    operation_name: str
    category: str                      # api, database, cache, load
    measured_value: float              # Primary metric (response time, etc.)
    baseline_value: Optional[float] = None
    variance: Optional[float] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # Extended metrics
    cpu_usage: Optional[float] = None
    memory_usage: Optional[float] = None
    error_count: int = 0
    request_count: int = 1
    
    # Context information
    endpoint: Optional[str] = None
    http_method: Optional[str] = None
    status_code: Optional[int] = None
    user_agent: Optional[str] = None
    
    # Database-specific metrics
    collection_name: Optional[str] = None
    query_type: Optional[str] = None
    document_count: Optional[int] = None
    
    # Cache-specific metrics
    cache_key: Optional[str] = None
    cache_hit: Optional[bool] = None
    ttl: Optional[int] = None
    
    # Load testing metrics
    concurrent_users: Optional[int] = None
    requests_per_second: Optional[float] = None
    error_rate: Optional[float] = None
    
    def calculate_variance(self, baseline: NodeJSPerformanceBaseline) -> float:
        """Calculate variance from Node.js baseline."""
        if self.baseline_value is None:
            self.baseline_value = baseline.get_baseline_value(self.category, self.operation_name)
        
        if self.baseline_value is not None:
            self.variance = baseline.calculate_variance(self.measured_value, self.baseline_value)
            return self.variance
        
        return float('inf')
    
    def is_compliant(self, baseline: NodeJSPerformanceBaseline) -> bool:
        """Check if measurement is compliant with ≤10% variance requirement."""
        if self.variance is None:
            self.calculate_variance(baseline)
        
        return baseline.is_within_threshold(
            self.measured_value, 
            self.baseline_value or 0.0
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert measurement to dictionary for serialization."""
        return {
            'operation_name': self.operation_name,
            'category': self.category,
            'measured_value': self.measured_value,
            'baseline_value': self.baseline_value,
            'variance': self.variance,
            'timestamp': self.timestamp.isoformat(),
            'cpu_usage': self.cpu_usage,
            'memory_usage': self.memory_usage,
            'error_count': self.error_count,
            'request_count': self.request_count,
            'endpoint': self.endpoint,
            'http_method': self.http_method,
            'status_code': self.status_code,
            'collection_name': self.collection_name,
            'query_type': self.query_type,
            'document_count': self.document_count,
            'cache_key': self.cache_key,
            'cache_hit': self.cache_hit,
            'ttl': self.ttl,
            'concurrent_users': self.concurrent_users,
            'requests_per_second': self.requests_per_second,
            'error_rate': self.error_rate,
            'compliant': self.is_compliant(NodeJSPerformanceBaseline())
        }


# =============================================================================
# Performance Monitoring and Measurement Infrastructure
# =============================================================================

class PerformanceMonitor:
    """
    Comprehensive performance monitoring system for Flask migration testing.
    
    Provides performance measurement, baseline comparison, and variance tracking
    with integration to Prometheus metrics and enterprise APM systems per
    Section 6.5.1 monitoring and observability requirements.
    """
    
    def __init__(self, baseline: Optional[NodeJSPerformanceBaseline] = None,
                 enable_prometheus: bool = True, enable_apm: bool = False):
        """
        Initialize performance monitor with comprehensive measurement capabilities.
        
        Args:
            baseline: Node.js performance baseline for comparison
            enable_prometheus: Enable Prometheus metrics collection
            enable_apm: Enable APM integration (requires APM configuration)
        """
        self.baseline = baseline or NodeJSPerformanceBaseline()
        self.measurements: List[PerformanceMeasurement] = []
        self.measurement_history: deque = deque(maxlen=10000)
        self.enable_prometheus = enable_prometheus and PROMETHEUS_AVAILABLE
        self.enable_apm = enable_apm
        
        # Performance tracking collections
        self.api_measurements = defaultdict(list)
        self.database_measurements = defaultdict(list)
        self.cache_measurements = defaultdict(list)
        self.load_measurements = defaultdict(list)
        
        # Variance violation tracking
        self.variance_violations: List[PerformanceMeasurement] = []
        self.compliance_stats = {
            'total_measurements': 0,
            'compliant_measurements': 0,
            'violation_count': 0,
            'compliance_rate': 1.0
        }
        
        # Prometheus metrics setup
        if self.enable_prometheus:
            self._setup_prometheus_metrics()
        
        # Thread safety for concurrent testing
        self._lock = threading.Lock()
        
        logger.info(
            "Performance monitor initialized",
            prometheus_enabled=self.enable_prometheus,
            apm_enabled=self.enable_apm,
            baseline_endpoints=len(self.baseline.api_response_times)
        )
    
    def _setup_prometheus_metrics(self):
        """Setup Prometheus metrics for performance monitoring."""
        try:
            self.registry = CollectorRegistry()
            
            # Response time metrics
            self.response_time_histogram = Histogram(
                'flask_request_duration_seconds',
                'Flask request duration in seconds',
                ['method', 'endpoint', 'status_code'],
                registry=self.registry,
                buckets=(0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0)
            )
            
            # Performance variance metrics
            self.variance_gauge = Gauge(
                'flask_performance_variance_ratio',
                'Performance variance from Node.js baseline',
                ['operation', 'category'],
                registry=self.registry
            )
            
            # Compliance metrics
            self.compliance_gauge = Gauge(
                'flask_performance_compliance_rate',
                'Performance compliance rate (≤10% variance)',
                registry=self.registry
            )
            
            # Database operation metrics
            self.database_operation_histogram = Histogram(
                'flask_database_operation_duration_seconds',
                'Database operation duration in seconds',
                ['operation_type', 'collection'],
                registry=self.registry
            )
            
            # Cache operation metrics
            self.cache_operation_histogram = Histogram(
                'flask_cache_operation_duration_seconds',
                'Cache operation duration in seconds',
                ['operation_type', 'cache_hit'],
                registry=self.registry
            )
            
            # Load testing metrics
            self.load_test_summary = Summary(
                'flask_load_test_response_time_seconds',
                'Load test response time summary',
                ['concurrent_users'],
                registry=self.registry
            )
            
            logger.info("Prometheus metrics configured successfully")
            
        except Exception as e:
            logger.warning(f"Failed to setup Prometheus metrics: {e}")
            self.enable_prometheus = False
    
    @contextmanager
    def measure_operation(self, operation_name: str, category: str, **kwargs):
        """
        Context manager for measuring operation performance.
        
        Args:
            operation_name: Name of the operation being measured
            category: Performance category (api, database, cache, load)
            **kwargs: Additional context information
            
        Yields:
            Performance measurement context
        """
        start_time = time.perf_counter()
        start_cpu = self._get_cpu_usage()
        start_memory = self._get_memory_usage()
        
        measurement = PerformanceMeasurement(
            operation_name=operation_name,
            category=category,
            measured_value=0.0,
            **kwargs
        )
        
        try:
            yield measurement
            
        except Exception as e:
            measurement.error_count += 1
            logger.error(f"Error during performance measurement: {e}")
            raise
            
        finally:
            end_time = time.perf_counter()
            end_cpu = self._get_cpu_usage()
            end_memory = self._get_memory_usage()
            
            # Calculate performance metrics
            duration_seconds = end_time - start_time
            measurement.measured_value = duration_seconds * 1000  # Convert to milliseconds
            measurement.cpu_usage = end_cpu - start_cpu if start_cpu and end_cpu else None
            measurement.memory_usage = end_memory - start_memory if start_memory and end_memory else None
            
            # Calculate variance and compliance
            measurement.calculate_variance(self.baseline)
            
            # Record measurement
            self._record_measurement(measurement)
    
    def _record_measurement(self, measurement: PerformanceMeasurement):
        """Record performance measurement with comprehensive tracking."""
        with self._lock:
            # Add to measurement collections
            self.measurements.append(measurement)
            self.measurement_history.append(measurement)
            
            # Categorize measurements
            if measurement.category == 'api':
                self.api_measurements[measurement.operation_name].append(measurement)
            elif measurement.category == 'database':
                self.database_measurements[measurement.operation_name].append(measurement)
            elif measurement.category == 'cache':
                self.cache_measurements[measurement.operation_name].append(measurement)
            elif measurement.category == 'load':
                self.load_measurements[measurement.operation_name].append(measurement)
            
            # Track compliance statistics
            self.compliance_stats['total_measurements'] += 1
            
            if measurement.is_compliant(self.baseline):
                self.compliance_stats['compliant_measurements'] += 1
            else:
                self.variance_violations.append(measurement)
                self.compliance_stats['violation_count'] += 1
                
                logger.warning(
                    "Performance variance violation detected",
                    operation=measurement.operation_name,
                    category=measurement.category,
                    measured_value=measurement.measured_value,
                    baseline_value=measurement.baseline_value,
                    variance=measurement.variance,
                    threshold=self.baseline.variance_thresholds['acceptable_variance']
                )
            
            # Update compliance rate
            self.compliance_stats['compliance_rate'] = (
                self.compliance_stats['compliant_measurements'] / 
                self.compliance_stats['total_measurements']
            )
            
            # Update Prometheus metrics
            if self.enable_prometheus:
                self._update_prometheus_metrics(measurement)
    
    def _update_prometheus_metrics(self, measurement: PerformanceMeasurement):
        """Update Prometheus metrics with measurement data."""
        try:
            duration_seconds = measurement.measured_value / 1000.0
            
            # Update response time metrics
            if measurement.category == 'api' and measurement.endpoint:
                self.response_time_histogram.labels(
                    method=measurement.http_method or 'GET',
                    endpoint=measurement.endpoint,
                    status_code=measurement.status_code or 200
                ).observe(duration_seconds)
            
            # Update variance metrics
            if measurement.variance is not None:
                self.variance_gauge.labels(
                    operation=measurement.operation_name,
                    category=measurement.category
                ).set(measurement.variance)
            
            # Update compliance rate
            self.compliance_gauge.set(self.compliance_stats['compliance_rate'])
            
            # Update database metrics
            if measurement.category == 'database':
                self.database_operation_histogram.labels(
                    operation_type=measurement.query_type or measurement.operation_name,
                    collection=measurement.collection_name or 'unknown'
                ).observe(duration_seconds)
            
            # Update cache metrics
            if measurement.category == 'cache':
                self.cache_operation_histogram.labels(
                    operation_type=measurement.operation_name,
                    cache_hit=str(measurement.cache_hit) if measurement.cache_hit is not None else 'unknown'
                ).observe(duration_seconds)
            
            # Update load test metrics
            if measurement.category == 'load' and measurement.concurrent_users:
                self.load_test_summary.labels(
                    concurrent_users=str(measurement.concurrent_users)
                ).observe(duration_seconds)
                
        except Exception as e:
            logger.warning(f"Failed to update Prometheus metrics: {e}")
    
    def _get_cpu_usage(self) -> Optional[float]:
        """Get current CPU usage percentage."""
        try:
            import psutil
            return psutil.cpu_percent(interval=0.1)
        except ImportError:
            return None
    
    def _get_memory_usage(self) -> Optional[float]:
        """Get current memory usage percentage."""
        try:
            import psutil
            return psutil.virtual_memory().percent
        except ImportError:
            return None
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """
        Get comprehensive performance summary with variance analysis.
        
        Returns:
            Dictionary containing performance statistics and compliance metrics
        """
        with self._lock:
            summary = {
                'measurement_summary': {
                    'total_measurements': len(self.measurements),
                    'api_measurements': len(self.api_measurements),
                    'database_measurements': len(self.database_measurements),
                    'cache_measurements': len(self.cache_measurements),
                    'load_measurements': len(self.load_measurements)
                },
                'compliance_summary': self.compliance_stats.copy(),
                'variance_violations': len(self.variance_violations),
                'category_performance': {},
                'top_violations': [],
                'performance_trends': {}
            }
            
            # Category-specific performance analysis
            for category in ['api', 'database', 'cache', 'load']:
                measurements = getattr(self, f'{category}_measurements')
                if measurements:
                    category_stats = self._calculate_category_stats(measurements)
                    summary['category_performance'][category] = category_stats
            
            # Top variance violations
            sorted_violations = sorted(
                self.variance_violations,
                key=lambda x: x.variance or 0,
                reverse=True
            )
            summary['top_violations'] = [
                {
                    'operation': v.operation_name,
                    'category': v.category,
                    'variance': v.variance,
                    'measured_value': v.measured_value,
                    'baseline_value': v.baseline_value
                }
                for v in sorted_violations[:10]
            ]
            
            # Performance trends (last 100 measurements)
            recent_measurements = list(self.measurement_history)[-100:]
            if recent_measurements:
                summary['performance_trends'] = self._calculate_performance_trends(recent_measurements)
            
            return summary
    
    def _calculate_category_stats(self, measurements_dict: Dict[str, List[PerformanceMeasurement]]) -> Dict[str, Any]:
        """Calculate statistics for a performance category."""
        all_measurements = []
        for operation_measurements in measurements_dict.values():
            all_measurements.extend(operation_measurements)
        
        if not all_measurements:
            return {}
        
        measured_values = [m.measured_value for m in all_measurements]
        variances = [m.variance for m in all_measurements if m.variance is not None]
        compliant_count = sum(1 for m in all_measurements if m.is_compliant(self.baseline))
        
        stats = {
            'measurement_count': len(all_measurements),
            'avg_response_time': statistics.mean(measured_values),
            'median_response_time': statistics.median(measured_values),
            'min_response_time': min(measured_values),
            'max_response_time': max(measured_values),
            'compliance_rate': compliant_count / len(all_measurements) if all_measurements else 0,
            'avg_variance': statistics.mean(variances) if variances else None,
            'max_variance': max(variances) if variances else None
        }
        
        # Add standard deviation if enough measurements
        if len(measured_values) > 1:
            stats['std_deviation'] = statistics.stdev(measured_values)
        
        return stats
    
    def _calculate_performance_trends(self, measurements: List[PerformanceMeasurement]) -> Dict[str, Any]:
        """Calculate performance trends from recent measurements."""
        if len(measurements) < 2:
            return {}
        
        # Group measurements by time windows
        time_windows = {}
        for measurement in measurements:
            # 5-minute time windows
            window_key = measurement.timestamp.replace(second=0, microsecond=0)
            window_key = window_key.replace(minute=window_key.minute // 5 * 5)
            
            if window_key not in time_windows:
                time_windows[window_key] = []
            time_windows[window_key].append(measurement)
        
        # Calculate trend statistics
        window_stats = []
        for window_time, window_measurements in sorted(time_windows.items()):
            measured_values = [m.measured_value for m in window_measurements]
            compliance_count = sum(1 for m in window_measurements if m.is_compliant(self.baseline))
            
            window_stats.append({
                'timestamp': window_time.isoformat(),
                'measurement_count': len(window_measurements),
                'avg_response_time': statistics.mean(measured_values),
                'compliance_rate': compliance_count / len(window_measurements)
            })
        
        # Calculate trend direction
        if len(window_stats) >= 2:
            recent_avg = window_stats[-1]['avg_response_time']
            previous_avg = window_stats[-2]['avg_response_time']
            trend_direction = 'improving' if recent_avg < previous_avg else 'degrading'
        else:
            trend_direction = 'stable'
        
        return {
            'window_stats': window_stats,
            'trend_direction': trend_direction,
            'window_count': len(window_stats)
        }
    
    def export_prometheus_metrics(self) -> str:
        """Export Prometheus metrics in text format."""
        if not self.enable_prometheus:
            return "# Prometheus metrics not enabled"
        
        try:
            from prometheus_client import generate_latest
            return generate_latest(self.registry).decode('utf-8')
        except Exception as e:
            logger.error(f"Failed to export Prometheus metrics: {e}")
            return f"# Error exporting metrics: {e}"
    
    def reset_measurements(self):
        """Reset all performance measurements and statistics."""
        with self._lock:
            self.measurements.clear()
            self.measurement_history.clear()
            self.api_measurements.clear()
            self.database_measurements.clear()
            self.cache_measurements.clear()
            self.load_measurements.clear()
            self.variance_violations.clear()
            
            self.compliance_stats = {
                'total_measurements': 0,
                'compliant_measurements': 0,
                'violation_count': 0,
                'compliance_rate': 1.0
            }
            
            logger.info("Performance measurements reset")


# =============================================================================
# Load Testing Utilities with Locust Integration
# =============================================================================

if LOCUST_AVAILABLE:
    
    class FlaskLoadTestUser(HttpUser):
        """
        Locust user class for Flask application load testing.
        
        Implements comprehensive load testing scenarios for API endpoints,
        authentication flows, and database operations per Section 6.6.1
        load testing framework requirements.
        """
        
        wait_time = between(1, 3)  # Wait 1-3 seconds between requests
        
        def on_start(self):
            """Initialize user session with authentication."""
            # Authenticate user for load testing
            response = self.client.post("/auth/login", json={
                "email": f"loadtest_{uuid.uuid4().hex[:8]}@example.com",
                "password": "loadtest_password"
            })
            
            if response.status_code == 200:
                self.auth_token = response.json().get("access_token")
                self.client.headers.update({
                    "Authorization": f"Bearer {self.auth_token}"
                })
        
        @task(3)
        def get_user_profile(self):
            """Test user profile retrieval performance."""
            self.client.get("/api/users/profile")
        
        @task(2)
        def list_projects(self):
            """Test project listing performance."""
            self.client.get("/api/projects?page=1&limit=20")
        
        @task(1)
        def search_users(self):
            """Test user search performance."""
            search_term = random.choice(['john', 'admin', 'test', 'user'])
            self.client.get(f"/api/users/search?q={search_term}")
        
        @task(1)
        def update_profile(self):
            """Test profile update performance."""
            self.client.put("/api/users/profile", json={
                "display_name": f"Load Test User {random.randint(1, 1000)}"
            })
        
        @task(1)
        def create_project(self):
            """Test project creation performance."""
            self.client.post("/api/projects", json={
                "name": f"Load Test Project {uuid.uuid4().hex[:8]}",
                "description": "Project created during load testing"
            })


class LoadTestGenerator:
    """
    Comprehensive load testing generator using Locust framework.
    
    Provides programmatic load testing capabilities with performance
    measurement and baseline comparison per Section 6.6.1 requirements.
    """
    
    def __init__(self, performance_monitor: PerformanceMonitor,
                 base_url: str = "http://localhost:5000"):
        """
        Initialize load test generator.
        
        Args:
            performance_monitor: Performance monitoring instance
            base_url: Base URL for Flask application
        """
        self.performance_monitor = performance_monitor
        self.base_url = base_url
        self.test_results: List[Dict[str, Any]] = []
        
        if not LOCUST_AVAILABLE:
            logger.warning("Locust not available, load testing disabled")
        
        logger.info(f"Load test generator initialized for {base_url}")
    
    def run_load_test(self, concurrent_users: int = 10, duration_seconds: int = 60,
                     spawn_rate: int = 1, endpoints: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Run comprehensive load test with performance measurement.
        
        Args:
            concurrent_users: Number of concurrent users to simulate
            duration_seconds: Duration of load test in seconds
            spawn_rate: Rate of spawning new users per second
            endpoints: Specific endpoints to test (None for all)
            
        Returns:
            Load test results with performance metrics
        """
        if not LOCUST_AVAILABLE:
            return {
                'error': 'Locust not available for load testing',
                'concurrent_users': concurrent_users,
                'duration_seconds': duration_seconds
            }
        
        try:
            # Setup Locust environment
            env = Environment(user_classes=[FlaskLoadTestUser])
            env.create_local_runner()
            
            # Configure test parameters
            env.runner.start(concurrent_users, spawn_rate=spawn_rate)
            
            # Measure load test performance
            start_time = time.time()
            
            with self.performance_monitor.measure_operation(
                operation_name=f"load_test_{concurrent_users}_users",
                category="load",
                concurrent_users=concurrent_users,
                endpoint="load_test"
            ) as measurement:
                
                # Run load test
                time.sleep(duration_seconds)
                
                # Stop test and collect results
                env.runner.stop()
                
                # Calculate performance metrics
                stats = env.runner.stats.total
                
                measurement.requests_per_second = stats.total_rps
                measurement.error_rate = stats.fail_ratio
                measurement.measured_value = stats.avg_response_time
                
                # Collect detailed results
                results = {
                    'test_parameters': {
                        'concurrent_users': concurrent_users,
                        'duration_seconds': duration_seconds,
                        'spawn_rate': spawn_rate,
                        'base_url': self.base_url
                    },
                    'performance_metrics': {
                        'total_requests': stats.num_requests,
                        'failed_requests': stats.num_failures,
                        'requests_per_second': stats.total_rps,
                        'avg_response_time': stats.avg_response_time,
                        'min_response_time': stats.min_response_time,
                        'max_response_time': stats.max_response_time,
                        'median_response_time': stats.median_response_time,
                        'error_rate': stats.fail_ratio,
                        'total_content_length': stats.total_content_length
                    },
                    'baseline_comparison': {},
                    'compliance_status': {}
                }
                
                # Compare with Node.js baseline
                baseline_key = f"{concurrent_users}_users"
                if baseline_key in self.performance_monitor.baseline.load_performance:
                    baseline_data = self.performance_monitor.baseline.load_performance[baseline_key]
                    
                    response_time_variance = self.performance_monitor.baseline.calculate_variance(
                        stats.avg_response_time, baseline_data['avg_response_time']
                    )
                    
                    rps_variance = self.performance_monitor.baseline.calculate_variance(
                        stats.total_rps, baseline_data['requests_per_second']
                    )
                    
                    error_rate_variance = self.performance_monitor.baseline.calculate_variance(
                        stats.fail_ratio, baseline_data['error_rate']
                    )
                    
                    results['baseline_comparison'] = {
                        'response_time_baseline': baseline_data['avg_response_time'],
                        'response_time_variance': response_time_variance,
                        'rps_baseline': baseline_data['requests_per_second'],
                        'rps_variance': rps_variance,
                        'error_rate_baseline': baseline_data['error_rate'],
                        'error_rate_variance': error_rate_variance
                    }
                    
                    # Determine compliance status
                    results['compliance_status'] = {
                        'response_time_compliant': response_time_variance <= 0.10,
                        'rps_compliant': rps_variance <= 0.15,  # Slightly higher tolerance for RPS
                        'error_rate_compliant': error_rate_variance <= 0.05,
                        'overall_compliant': (
                            response_time_variance <= 0.10 and
                            rps_variance <= 0.15 and
                            error_rate_variance <= 0.05
                        )
                    }
                
                # Record test results
                self.test_results.append(results)
                
                logger.info(
                    "Load test completed",
                    concurrent_users=concurrent_users,
                    duration=duration_seconds,
                    total_requests=stats.num_requests,
                    avg_response_time=stats.avg_response_time,
                    requests_per_second=stats.total_rps,
                    error_rate=stats.fail_ratio,
                    compliant=results['compliance_status'].get('overall_compliant', False)
                )
                
                return results
                
        except Exception as e:
            logger.error(f"Load test failed: {e}")
            return {
                'error': str(e),
                'concurrent_users': concurrent_users,
                'duration_seconds': duration_seconds
            }
    
    def run_stress_test(self, max_users: int = 200, step_duration: int = 30) -> List[Dict[str, Any]]:
        """
        Run progressive stress test with increasing user load.
        
        Args:
            max_users: Maximum number of concurrent users
            step_duration: Duration of each load step in seconds
            
        Returns:
            List of load test results for each step
        """
        user_steps = [10, 25, 50, 75, 100, 150, 200]
        user_steps = [step for step in user_steps if step <= max_users]
        
        stress_test_results = []
        
        for user_count in user_steps:
            logger.info(f"Running stress test step: {user_count} users")
            
            step_result = self.run_load_test(
                concurrent_users=user_count,
                duration_seconds=step_duration,
                spawn_rate=min(user_count // 5, 10)  # Gradual spawn rate
            )
            
            step_result['stress_test_step'] = user_count
            stress_test_results.append(step_result)
            
            # Brief pause between steps
            time.sleep(5)
        
        return stress_test_results
    
    def analyze_load_test_trends(self) -> Dict[str, Any]:
        """Analyze trends across multiple load test runs."""
        if not self.test_results:
            return {'error': 'No load test results available for analysis'}
        
        # Extract trend data
        user_counts = []
        response_times = []
        rps_values = []
        error_rates = []
        compliance_rates = []
        
        for result in self.test_results:
            params = result['test_parameters']
            metrics = result['performance_metrics']
            compliance = result.get('compliance_status', {})
            
            user_counts.append(params['concurrent_users'])
            response_times.append(metrics['avg_response_time'])
            rps_values.append(metrics['requests_per_second'])
            error_rates.append(metrics['error_rate'])
            compliance_rates.append(1.0 if compliance.get('overall_compliant', False) else 0.0)
        
        # Calculate trend analysis
        analysis = {
            'test_count': len(self.test_results),
            'user_range': {'min': min(user_counts), 'max': max(user_counts)},
            'response_time_trend': {
                'values': response_times,
                'avg': statistics.mean(response_times),
                'min': min(response_times),
                'max': max(response_times)
            },
            'throughput_trend': {
                'values': rps_values,
                'avg': statistics.mean(rps_values),
                'min': min(rps_values),
                'max': max(rps_values)
            },
            'error_rate_trend': {
                'values': error_rates,
                'avg': statistics.mean(error_rates),
                'min': min(error_rates),
                'max': max(error_rates)
            },
            'compliance_trend': {
                'overall_compliance_rate': statistics.mean(compliance_rates),
                'compliant_tests': sum(compliance_rates),
                'total_tests': len(compliance_rates)
            }
        }
        
        return analysis


# =============================================================================
# Database Performance Testing Fixtures
# =============================================================================

class DatabasePerformanceTester:
    """
    Comprehensive database performance testing for PyMongo and Motor operations.
    
    Provides performance measurement for MongoDB operations with baseline
    comparison and variance tracking per Section 6.2.4 database performance
    optimization requirements.
    """
    
    def __init__(self, performance_monitor: PerformanceMonitor,
                 mongodb_client: Optional[MongoClient] = None,
                 motor_client: Optional['AsyncIOMotorClient'] = None):
        """
        Initialize database performance tester.
        
        Args:
            performance_monitor: Performance monitoring instance
            mongodb_client: PyMongo synchronous client
            motor_client: Motor asynchronous client
        """
        self.performance_monitor = performance_monitor
        self.mongodb_client = mongodb_client
        self.motor_client = motor_client
        
        # Test data generators
        self.test_collections = ['users', 'projects', 'sessions', 'analytics']
        self.sample_data = self._generate_sample_data()
        
        logger.info(
            "Database performance tester initialized",
            pymongo_available=self.mongodb_client is not None,
            motor_available=self.motor_client is not None
        )
    
    def _generate_sample_data(self) -> Dict[str, List[Dict[str, Any]]]:
        """Generate sample data for database performance testing."""
        sample_data = {}
        
        # User documents
        sample_data['users'] = [
            {
                '_id': f"user_{i}",
                'email': f"user{i}@example.com",
                'username': f"user{i}",
                'display_name': f"User {i}",
                'created_at': datetime.utcnow() - timedelta(days=random.randint(1, 365)),
                'profile': {
                    'bio': f"Bio for user {i}",
                    'location': random.choice(['NYC', 'SF', 'LA', 'Chicago', 'Boston']),
                    'preferences': {
                        'theme': random.choice(['light', 'dark']),
                        'notifications': random.choice([True, False])
                    }
                },
                'metrics': {
                    'login_count': random.randint(1, 100),
                    'last_login': datetime.utcnow() - timedelta(days=random.randint(1, 30))
                }
            }
            for i in range(1000)
        ]
        
        # Project documents
        sample_data['projects'] = [
            {
                '_id': f"project_{i}",
                'name': f"Project {i}",
                'description': f"Description for project {i}",
                'owner_id': f"user_{random.randint(1, 100)}",
                'created_at': datetime.utcnow() - timedelta(days=random.randint(1, 180)),
                'status': random.choice(['active', 'inactive', 'archived']),
                'tags': random.sample(['python', 'flask', 'mongodb', 'testing', 'api', 'web'], 3),
                'metrics': {
                    'views': random.randint(1, 1000),
                    'collaborators': random.randint(1, 10)
                }
            }
            for i in range(500)
        ]
        
        # Session documents
        sample_data['sessions'] = [
            {
                '_id': f"session_{i}",
                'user_id': f"user_{random.randint(1, 100)}",
                'session_token': f"token_{uuid.uuid4().hex}",
                'created_at': datetime.utcnow() - timedelta(hours=random.randint(1, 24)),
                'expires_at': datetime.utcnow() + timedelta(hours=24),
                'ip_address': f"192.168.1.{random.randint(1, 254)}",
                'user_agent': 'Mozilla/5.0 (Test Browser)'
            }
            for i in range(200)
        ]
        
        return sample_data
    
    def measure_find_operations(self, collection_name: str = 'users') -> Dict[str, PerformanceMeasurement]:
        """Measure find operation performance."""
        results = {}
        
        if self.mongodb_client:
            collection = self.mongodb_client.get_default_database()[collection_name]
            
            # Find one operation
            with self.performance_monitor.measure_operation(
                operation_name='find_one',
                category='database',
                collection_name=collection_name,
                query_type='find_one'
            ) as measurement:
                document = collection.find_one({'_id': 'user_1'})
                measurement.document_count = 1 if document else 0
                results['find_one'] = measurement
            
            # Find many operation
            with self.performance_monitor.measure_operation(
                operation_name='find_many',
                category='database',
                collection_name=collection_name,
                query_type='find_many'
            ) as measurement:
                documents = list(collection.find().limit(100))
                measurement.document_count = len(documents)
                results['find_many'] = measurement
            
            # Indexed query
            with self.performance_monitor.measure_operation(
                operation_name='index_query',
                category='database',
                collection_name=collection_name,
                query_type='indexed_query'
            ) as measurement:
                documents = list(collection.find({'email': 'user1@example.com'}))
                measurement.document_count = len(documents)
                results['index_query'] = measurement
            
            # Aggregation query
            with self.performance_monitor.measure_operation(
                operation_name='aggregate_simple',
                category='database',
                collection_name=collection_name,
                query_type='aggregation'
            ) as measurement:
                pipeline = [
                    {'$match': {'profile.location': 'NYC'}},
                    {'$group': {'_id': '$profile.location', 'count': {'$sum': 1}}}
                ]
                documents = list(collection.aggregate(pipeline))
                measurement.document_count = len(documents)
                results['aggregate_simple'] = measurement
        
        return results
    
    def measure_write_operations(self, collection_name: str = 'test_performance') -> Dict[str, PerformanceMeasurement]:
        """Measure write operation performance."""
        results = {}
        
        if self.mongodb_client:
            collection = self.mongodb_client.get_default_database()[collection_name]
            
            # Insert one operation
            with self.performance_monitor.measure_operation(
                operation_name='insert_one',
                category='database',
                collection_name=collection_name,
                query_type='insert_one'
            ) as measurement:
                test_doc = {
                    '_id': f"test_{uuid.uuid4().hex}",
                    'created_at': datetime.utcnow(),
                    'test_data': 'performance_test'
                }
                result = collection.insert_one(test_doc)
                measurement.document_count = 1 if result.inserted_id else 0
                results['insert_one'] = measurement
            
            # Insert many operation
            with self.performance_monitor.measure_operation(
                operation_name='insert_many',
                category='database',
                collection_name=collection_name,
                query_type='insert_many'
            ) as measurement:
                test_docs = [
                    {
                        '_id': f"bulk_{i}_{uuid.uuid4().hex[:8]}",
                        'created_at': datetime.utcnow(),
                        'bulk_index': i
                    }
                    for i in range(100)
                ]
                result = collection.insert_many(test_docs)
                measurement.document_count = len(result.inserted_ids)
                results['insert_many'] = measurement
            
            # Update one operation
            with self.performance_monitor.measure_operation(
                operation_name='update_one',
                category='database',
                collection_name=collection_name,
                query_type='update_one'
            ) as measurement:
                result = collection.update_one(
                    {'test_data': 'performance_test'},
                    {'$set': {'updated_at': datetime.utcnow()}}
                )
                measurement.document_count = result.modified_count
                results['update_one'] = measurement
            
            # Delete operations (cleanup)
            collection.delete_many({'_id': {'$regex': '^(test_|bulk_)'}})
        
        return results
    
    async def measure_async_operations(self, collection_name: str = 'users') -> Dict[str, PerformanceMeasurement]:
        """Measure Motor async operation performance."""
        results = {}
        
        if not self.motor_client:
            logger.warning("Motor client not available for async operations")
            return results
        
        try:
            collection = self.motor_client.get_default_database()[collection_name]
            
            # Async find one operation
            with self.performance_monitor.measure_operation(
                operation_name='async_find_one',
                category='database',
                collection_name=collection_name,
                query_type='async_find_one'
            ) as measurement:
                document = await collection.find_one({'_id': 'user_1'})
                measurement.document_count = 1 if document else 0
                results['async_find_one'] = measurement
            
            # Async find many operation
            with self.performance_monitor.measure_operation(
                operation_name='async_find_many',
                category='database',
                collection_name=collection_name,
                query_type='async_find_many'
            ) as measurement:
                cursor = collection.find().limit(100)
                documents = await cursor.to_list(length=100)
                measurement.document_count = len(documents)
                results['async_find_many'] = measurement
            
            # Async aggregation
            with self.performance_monitor.measure_operation(
                operation_name='async_aggregate',
                category='database',
                collection_name=collection_name,
                query_type='async_aggregation'
            ) as measurement:
                pipeline = [
                    {'$match': {'profile.location': 'SF'}},
                    {'$group': {'_id': '$profile.location', 'count': {'$sum': 1}}}
                ]
                cursor = collection.aggregate(pipeline)
                documents = await cursor.to_list(length=None)
                measurement.document_count = len(documents)
                results['async_aggregate'] = measurement
                
        except Exception as e:
            logger.error(f"Async database operations failed: {e}")
        
        return results
    
    def run_comprehensive_database_performance_test(self) -> Dict[str, Any]:
        """Run comprehensive database performance test suite."""
        logger.info("Starting comprehensive database performance test")
        
        test_results = {
            'sync_operations': {},
            'async_operations': {},
            'performance_summary': {},
            'compliance_status': {}
        }
        
        # Test synchronous operations
        for collection_name in ['users', 'projects']:
            find_results = self.measure_find_operations(collection_name)
            write_results = self.measure_write_operations(f"test_{collection_name}")
            
            test_results['sync_operations'][collection_name] = {
                'find_operations': find_results,
                'write_operations': write_results
            }
        
        # Test asynchronous operations
        if self.motor_client:
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                for collection_name in ['users', 'projects']:
                    async_results = loop.run_until_complete(
                        self.measure_async_operations(collection_name)
                    )
                    test_results['async_operations'][collection_name] = async_results
            finally:
                loop.close()
        
        # Calculate performance summary
        test_results['performance_summary'] = self._calculate_database_performance_summary()
        
        # Check compliance status
        test_results['compliance_status'] = self._check_database_compliance()
        
        logger.info("Comprehensive database performance test completed")
        return test_results
    
    def _calculate_database_performance_summary(self) -> Dict[str, Any]:
        """Calculate database performance summary from measurements."""
        db_measurements = self.performance_monitor.database_measurements
        
        if not db_measurements:
            return {'error': 'No database measurements available'}
        
        operation_stats = {}
        
        for operation_name, measurements in db_measurements.items():
            if measurements:
                measured_values = [m.measured_value for m in measurements]
                variances = [m.variance for m in measurements if m.variance is not None]
                
                operation_stats[operation_name] = {
                    'measurement_count': len(measurements),
                    'avg_response_time': statistics.mean(measured_values),
                    'min_response_time': min(measured_values),
                    'max_response_time': max(measured_values),
                    'avg_variance': statistics.mean(variances) if variances else None,
                    'compliance_rate': sum(
                        1 for m in measurements 
                        if m.is_compliant(self.performance_monitor.baseline)
                    ) / len(measurements)
                }
        
        return operation_stats
    
    def _check_database_compliance(self) -> Dict[str, Any]:
        """Check database operation compliance with performance requirements."""
        db_measurements = self.performance_monitor.database_measurements
        
        compliance_status = {
            'total_operations': 0,
            'compliant_operations': 0,
            'violation_count': 0,
            'compliance_rate': 0.0,
            'violations': []
        }
        
        for operation_name, measurements in db_measurements.items():
            for measurement in measurements:
                compliance_status['total_operations'] += 1
                
                if measurement.is_compliant(self.performance_monitor.baseline):
                    compliance_status['compliant_operations'] += 1
                else:
                    compliance_status['violation_count'] += 1
                    compliance_status['violations'].append({
                        'operation': operation_name,
                        'measured_value': measurement.measured_value,
                        'baseline_value': measurement.baseline_value,
                        'variance': measurement.variance,
                        'collection': measurement.collection_name
                    })
        
        if compliance_status['total_operations'] > 0:
            compliance_status['compliance_rate'] = (
                compliance_status['compliant_operations'] / 
                compliance_status['total_operations']
            )
        
        return compliance_status


# =============================================================================
# Cache Performance Testing Fixtures
# =============================================================================

class CachePerformanceTester:
    """
    Comprehensive Redis cache performance testing with hit/miss ratio analysis.
    
    Provides cache operation performance measurement with baseline comparison
    and Redis-specific metrics per Section 3.4.5 caching requirements.
    """
    
    def __init__(self, performance_monitor: PerformanceMonitor,
                 redis_client: Optional[Redis] = None):
        """
        Initialize cache performance tester.
        
        Args:
            performance_monitor: Performance monitoring instance
            redis_client: Redis client instance
        """
        self.performance_monitor = performance_monitor
        self.redis_client = redis_client
        
        # Cache testing configuration
        self.test_keys = [f"perf_test:{i}" for i in range(1000)]
        self.test_data = {
            'small': 'small_value',
            'medium': 'medium_value_' + 'x' * 100,
            'large': 'large_value_' + 'x' * 1000
        }
        
        # Hit/miss tracking
        self.cache_hit_count = 0
        self.cache_miss_count = 0
        
        logger.info(
            "Cache performance tester initialized",
            redis_available=self.redis_client is not None,
            test_keys=len(self.test_keys)
        )
    
    def measure_basic_operations(self) -> Dict[str, PerformanceMeasurement]:
        """Measure basic Redis operation performance."""
        results = {}
        
        if not self.redis_client:
            logger.warning("Redis client not available for cache testing")
            return results
        
        try:
            # Set operation
            with self.performance_monitor.measure_operation(
                operation_name='set',
                category='cache',
                cache_key='test_key'
            ) as measurement:
                self.redis_client.set('test_key', self.test_data['medium'], ex=300)
                measurement.cache_hit = None  # Set operation doesn't have hit/miss
                measurement.ttl = 300
                results['set'] = measurement
            
            # Get operation (cache hit)
            with self.performance_monitor.measure_operation(
                operation_name='get',
                category='cache',
                cache_key='test_key'
            ) as measurement:
                value = self.redis_client.get('test_key')
                measurement.cache_hit = value is not None
                if measurement.cache_hit:
                    self.cache_hit_count += 1
                else:
                    self.cache_miss_count += 1
                results['get_hit'] = measurement
            
            # Get operation (cache miss)
            with self.performance_monitor.measure_operation(
                operation_name='get',
                category='cache',
                cache_key='nonexistent_key'
            ) as measurement:
                value = self.redis_client.get('nonexistent_key')
                measurement.cache_hit = value is not None
                if measurement.cache_hit:
                    self.cache_hit_count += 1
                else:
                    self.cache_miss_count += 1
                results['get_miss'] = measurement
            
            # Delete operation
            with self.performance_monitor.measure_operation(
                operation_name='delete',
                category='cache',
                cache_key='test_key'
            ) as measurement:
                deleted_count = self.redis_client.delete('test_key')
                measurement.cache_hit = deleted_count > 0
                results['delete'] = measurement
            
            # Exists operation
            with self.performance_monitor.measure_operation(
                operation_name='exists',
                category='cache',
                cache_key='test_key'
            ) as measurement:
                exists = self.redis_client.exists('test_key')
                measurement.cache_hit = exists > 0
                results['exists'] = measurement
            
        except Exception as e:
            logger.error(f"Basic cache operations failed: {e}")
        
        return results
    
    def measure_advanced_operations(self) -> Dict[str, PerformanceMeasurement]:
        """Measure advanced Redis operation performance."""
        results = {}
        
        if not self.redis_client:
            return results
        
        try:
            # Hash operations
            with self.performance_monitor.measure_operation(
                operation_name='hset',
                category='cache',
                cache_key='test_hash'
            ) as measurement:
                self.redis_client.hset('test_hash', 'field1', 'value1')
                results['hset'] = measurement
            
            with self.performance_monitor.measure_operation(
                operation_name='hget',
                category='cache',
                cache_key='test_hash'
            ) as measurement:
                value = self.redis_client.hget('test_hash', 'field1')
                measurement.cache_hit = value is not None
                results['hget'] = measurement
            
            # List operations
            with self.performance_monitor.measure_operation(
                operation_name='lpush',
                category='cache',
                cache_key='test_list'
            ) as measurement:
                self.redis_client.lpush('test_list', 'item1', 'item2', 'item3')
                results['lpush'] = measurement
            
            with self.performance_monitor.measure_operation(
                operation_name='rpop',
                category='cache',
                cache_key='test_list'
            ) as measurement:
                item = self.redis_client.rpop('test_list')
                measurement.cache_hit = item is not None
                results['rpop'] = measurement
            
            # Set operations
            with self.performance_monitor.measure_operation(
                operation_name='sadd',
                category='cache',
                cache_key='test_set'
            ) as measurement:
                self.redis_client.sadd('test_set', 'member1', 'member2', 'member3')
                results['sadd'] = measurement
            
            with self.performance_monitor.measure_operation(
                operation_name='smembers',
                category='cache',
                cache_key='test_set'
            ) as measurement:
                members = self.redis_client.smembers('test_set')
                measurement.cache_hit = len(members) > 0
                results['smembers'] = measurement
            
            # Pipeline operation
            with self.performance_monitor.measure_operation(
                operation_name='pipeline',
                category='cache',
                cache_key='pipeline_test'
            ) as measurement:
                pipe = self.redis_client.pipeline()
                for i in range(10):
                    pipe.set(f'pipe_key_{i}', f'value_{i}')
                pipe.execute()
                results['pipeline'] = measurement
            
            # Cleanup
            cleanup_keys = ['test_hash', 'test_list', 'test_set'] + [f'pipe_key_{i}' for i in range(10)]
            self.redis_client.delete(*cleanup_keys)
            
        except Exception as e:
            logger.error(f"Advanced cache operations failed: {e}")
        
        return results
    
    def measure_cache_hit_miss_ratio(self, test_keys_count: int = 1000) -> Dict[str, Any]:
        """Measure cache hit/miss ratio under various scenarios."""
        if not self.redis_client:
            return {'error': 'Redis client not available'}
        
        results = {
            'scenario_results': {},
            'overall_metrics': {}
        }
        
        try:
            # Scenario 1: Cold cache (all misses)
            scenario1_results = self._test_cache_scenario(
                'cold_cache',
                test_keys_count,
                pre_populate=False
            )
            results['scenario_results']['cold_cache'] = scenario1_results
            
            # Scenario 2: Warm cache (all hits)
            scenario2_results = self._test_cache_scenario(
                'warm_cache',
                test_keys_count,
                pre_populate=True
            )
            results['scenario_results']['warm_cache'] = scenario2_results
            
            # Scenario 3: Mixed cache (50% hit rate)
            scenario3_results = self._test_cache_scenario(
                'mixed_cache',
                test_keys_count,
                pre_populate=True,
                hit_rate=0.5
            )
            results['scenario_results']['mixed_cache'] = scenario3_results
            
            # Calculate overall metrics
            total_hits = sum(s['cache_hits'] for s in results['scenario_results'].values())
            total_requests = sum(s['total_requests'] for s in results['scenario_results'].values())
            
            results['overall_metrics'] = {
                'total_cache_hits': total_hits,
                'total_cache_requests': total_requests,
                'overall_hit_rate': total_hits / total_requests if total_requests > 0 else 0,
                'cache_efficiency': self._calculate_cache_efficiency()
            }
            
        except Exception as e:
            logger.error(f"Cache hit/miss ratio testing failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _test_cache_scenario(self, scenario_name: str, key_count: int,
                           pre_populate: bool = False, hit_rate: float = 1.0) -> Dict[str, Any]:
        """Test specific cache scenario."""
        scenario_results = {
            'scenario_name': scenario_name,
            'total_requests': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'avg_response_time': 0.0,
            'response_times': []
        }
        
        test_keys = [f"scenario_{scenario_name}:{i}" for i in range(key_count)]
        
        # Pre-populate cache if required
        if pre_populate:
            for key in test_keys:
                self.redis_client.set(key, f"value_for_{key}", ex=300)
        
        # Determine which keys to test based on hit rate
        if hit_rate < 1.0:
            hit_keys = random.sample(test_keys, int(len(test_keys) * hit_rate))
            miss_keys = [key + "_miss" for key in test_keys if key not in hit_keys]
            test_keys = hit_keys + miss_keys[:len(test_keys) - len(hit_keys)]
        
        # Perform cache operations
        response_times = []
        
        for key in test_keys:
            with self.performance_monitor.measure_operation(
                operation_name='get',
                category='cache',
                cache_key=key
            ) as measurement:
                start_time = time.perf_counter()
                value = self.redis_client.get(key)
                end_time = time.perf_counter()
                
                response_time = (end_time - start_time) * 1000  # Convert to milliseconds
                response_times.append(response_time)
                
                scenario_results['total_requests'] += 1
                
                if value is not None:
                    scenario_results['cache_hits'] += 1
                    measurement.cache_hit = True
                else:
                    scenario_results['cache_misses'] += 1
                    measurement.cache_hit = False
        
        # Calculate scenario metrics
        scenario_results['response_times'] = response_times
        scenario_results['avg_response_time'] = statistics.mean(response_times) if response_times else 0
        scenario_results['hit_rate'] = (
            scenario_results['cache_hits'] / scenario_results['total_requests']
            if scenario_results['total_requests'] > 0 else 0
        )
        
        # Cleanup test keys
        if pre_populate:
            cleanup_keys = [key for key in test_keys if not key.endswith('_miss')]
            if cleanup_keys:
                self.redis_client.delete(*cleanup_keys)
        
        return scenario_results
    
    def _calculate_cache_efficiency(self) -> Dict[str, float]:
        """Calculate cache efficiency metrics."""
        cache_measurements = self.performance_monitor.cache_measurements.get('get', [])
        
        if not cache_measurements:
            return {'error': 'No cache measurements available'}
        
        hit_times = []
        miss_times = []
        
        for measurement in cache_measurements:
            if measurement.cache_hit is True:
                hit_times.append(measurement.measured_value)
            elif measurement.cache_hit is False:
                miss_times.append(measurement.measured_value)
        
        efficiency_metrics = {
            'hit_count': len(hit_times),
            'miss_count': len(miss_times),
            'hit_rate': len(hit_times) / (len(hit_times) + len(miss_times)) if (len(hit_times) + len(miss_times)) > 0 else 0
        }
        
        if hit_times:
            efficiency_metrics['avg_hit_time'] = statistics.mean(hit_times)
        
        if miss_times:
            efficiency_metrics['avg_miss_time'] = statistics.mean(miss_times)
        
        if hit_times and miss_times:
            efficiency_metrics['hit_miss_ratio'] = statistics.mean(hit_times) / statistics.mean(miss_times)
        
        return efficiency_metrics
    
    def run_comprehensive_cache_performance_test(self) -> Dict[str, Any]:
        """Run comprehensive cache performance test suite."""
        logger.info("Starting comprehensive cache performance test")
        
        test_results = {
            'basic_operations': {},
            'advanced_operations': {},
            'hit_miss_analysis': {},
            'performance_summary': {},
            'compliance_status': {}
        }
        
        # Test basic operations
        test_results['basic_operations'] = self.measure_basic_operations()
        
        # Test advanced operations
        test_results['advanced_operations'] = self.measure_advanced_operations()
        
        # Test hit/miss ratio scenarios
        test_results['hit_miss_analysis'] = self.measure_cache_hit_miss_ratio()
        
        # Calculate performance summary
        test_results['performance_summary'] = self._calculate_cache_performance_summary()
        
        # Check compliance status
        test_results['compliance_status'] = self._check_cache_compliance()
        
        logger.info("Comprehensive cache performance test completed")
        return test_results
    
    def _calculate_cache_performance_summary(self) -> Dict[str, Any]:
        """Calculate cache performance summary from measurements."""
        cache_measurements = self.performance_monitor.cache_measurements
        
        if not cache_measurements:
            return {'error': 'No cache measurements available'}
        
        operation_stats = {}
        
        for operation_name, measurements in cache_measurements.items():
            if measurements:
                measured_values = [m.measured_value for m in measurements]
                variances = [m.variance for m in measurements if m.variance is not None]
                hit_rate = sum(1 for m in measurements if m.cache_hit is True) / len(measurements)
                
                operation_stats[operation_name] = {
                    'measurement_count': len(measurements),
                    'avg_response_time': statistics.mean(measured_values),
                    'min_response_time': min(measured_values),
                    'max_response_time': max(measured_values),
                    'avg_variance': statistics.mean(variances) if variances else None,
                    'cache_hit_rate': hit_rate,
                    'compliance_rate': sum(
                        1 for m in measurements 
                        if m.is_compliant(self.performance_monitor.baseline)
                    ) / len(measurements)
                }
        
        return operation_stats
    
    def _check_cache_compliance(self) -> Dict[str, Any]:
        """Check cache operation compliance with performance requirements."""
        cache_measurements = self.performance_monitor.cache_measurements
        
        compliance_status = {
            'total_operations': 0,
            'compliant_operations': 0,
            'violation_count': 0,
            'compliance_rate': 0.0,
            'violations': []
        }
        
        for operation_name, measurements in cache_measurements.items():
            for measurement in measurements:
                compliance_status['total_operations'] += 1
                
                if measurement.is_compliant(self.performance_monitor.baseline):
                    compliance_status['compliant_operations'] += 1
                else:
                    compliance_status['violation_count'] += 1
                    compliance_status['violations'].append({
                        'operation': operation_name,
                        'measured_value': measurement.measured_value,
                        'baseline_value': measurement.baseline_value,
                        'variance': measurement.variance,
                        'cache_hit': measurement.cache_hit
                    })
        
        if compliance_status['total_operations'] > 0:
            compliance_status['compliance_rate'] = (
                compliance_status['compliant_operations'] / 
                compliance_status['total_operations']
            )
        
        return compliance_status


# =============================================================================
# Apache Bench Integration for HTTP Performance Testing
# =============================================================================

class ApacheBenchTester:
    """
    Apache Bench (ab) integration for HTTP server performance measurement.
    
    Provides HTTP performance testing with apache-bench integration per
    Section 6.6.1 performance testing tool requirements.
    """
    
    def __init__(self, performance_monitor: PerformanceMonitor,
                 base_url: str = "http://localhost:5000"):
        """
        Initialize Apache Bench tester.
        
        Args:
            performance_monitor: Performance monitoring instance
            base_url: Base URL for HTTP testing
        """
        self.performance_monitor = performance_monitor
        self.base_url = base_url.rstrip('/')
        self.ab_available = self._check_ab_availability()
        
        logger.info(
            "Apache Bench tester initialized",
            base_url=self.base_url,
            ab_available=self.ab_available
        )
    
    def _check_ab_availability(self) -> bool:
        """Check if Apache Bench (ab) is available."""
        try:
            result = subprocess.run(['ab', '-V'], capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.warning("Apache Bench (ab) not available")
            return False
    
    def run_ab_test(self, endpoint: str, requests: int = 1000, concurrency: int = 10,
                   timeout: int = 30, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Run Apache Bench performance test.
        
        Args:
            endpoint: API endpoint to test (e.g., '/api/users')
            requests: Total number of requests to perform
            concurrency: Number of concurrent requests
            timeout: Request timeout in seconds
            headers: Optional HTTP headers
            
        Returns:
            Apache Bench test results with performance metrics
        """
        if not self.ab_available:
            return {
                'error': 'Apache Bench (ab) not available',
                'endpoint': endpoint,
                'requests': requests,
                'concurrency': concurrency
            }
        
        url = f"{self.base_url}{endpoint}"
        
        # Build ab command
        ab_command = [
            'ab',
            '-n', str(requests),
            '-c', str(concurrency),
            '-s', str(timeout),
            '-g', '/tmp/ab_gnuplot.tsv',  # Gnuplot output
            '-e', '/tmp/ab_csv.csv'      # CSV output
        ]
        
        # Add headers if provided
        if headers:
            for header_name, header_value in headers.items():
                ab_command.extend(['-H', f'{header_name}: {header_value}'])
        
        ab_command.append(url)
        
        try:
            with self.performance_monitor.measure_operation(
                operation_name='ab_test',
                category='api',
                endpoint=endpoint,
                concurrent_users=concurrency
            ) as measurement:
                
                logger.info(f"Running Apache Bench test: {' '.join(ab_command)}")
                
                # Run Apache Bench
                start_time = time.time()
                result = subprocess.run(
                    ab_command,
                    capture_output=True,
                    text=True,
                    timeout=timeout + 60  # Extra time for ab to complete
                )
                end_time = time.time()
                
                if result.returncode != 0:
                    return {
                        'error': f'Apache Bench failed with return code {result.returncode}',
                        'stderr': result.stderr,
                        'command': ' '.join(ab_command)
                    }
                
                # Parse ab output
                ab_results = self._parse_ab_output(result.stdout)
                
                # Update measurement with results
                measurement.measured_value = ab_results.get('mean_response_time', 0)
                measurement.requests_per_second = ab_results.get('requests_per_second', 0)
                measurement.error_rate = ab_results.get('failed_requests', 0) / requests if requests > 0 else 0
                
                # Add test parameters and results
                ab_results.update({
                    'test_parameters': {
                        'endpoint': endpoint,
                        'url': url,
                        'total_requests': requests,
                        'concurrency': concurrency,
                        'timeout': timeout,
                        'headers': headers
                    },
                    'test_duration': end_time - start_time,
                    'baseline_comparison': {},
                    'compliance_status': {}
                })
                
                # Compare with baseline
                baseline_value = self.performance_monitor.baseline.get_baseline_value('api', 'ab_test')
                if baseline_value:
                    variance = self.performance_monitor.baseline.calculate_variance(
                        ab_results['mean_response_time'], baseline_value
                    )
                    
                    ab_results['baseline_comparison'] = {
                        'baseline_response_time': baseline_value,
                        'measured_response_time': ab_results['mean_response_time'],
                        'variance': variance,
                        'variance_percentage': variance * 100
                    }
                    
                    ab_results['compliance_status'] = {
                        'compliant': variance <= 0.10,
                        'variance_threshold': 0.10,
                        'within_threshold': variance <= 0.10
                    }
                
                return ab_results
                
        except subprocess.TimeoutExpired:
            logger.error(f"Apache Bench test timeout after {timeout + 60} seconds")
            return {
                'error': 'Test timeout',
                'timeout_seconds': timeout + 60,
                'endpoint': endpoint
            }
        except Exception as e:
            logger.error(f"Apache Bench test failed: {e}")
            return {
                'error': str(e),
                'endpoint': endpoint
            }
    
    def _parse_ab_output(self, ab_output: str) -> Dict[str, Any]:
        """Parse Apache Bench output to extract performance metrics."""
        results = {}
        
        lines = ab_output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Parse key metrics
            if 'Complete requests:' in line:
                results['complete_requests'] = int(line.split(':')[1].strip())
            elif 'Failed requests:' in line:
                results['failed_requests'] = int(line.split(':')[1].strip())
            elif 'Requests per second:' in line:
                # Format: "Requests per second:    X.XX [#/sec] (mean)"
                rps_part = line.split(':')[1].strip()
                results['requests_per_second'] = float(rps_part.split()[0])
            elif 'Time per request:' in line and 'mean' in line:
                # Format: "Time per request:       X.XXX [ms] (mean)"
                time_part = line.split(':')[1].strip()
                results['mean_response_time'] = float(time_part.split()[0])
            elif 'Time per request:' in line and 'across all concurrent requests' in line:
                # Format: "Time per request:       X.XXX [ms] (mean, across all concurrent requests)"
                time_part = line.split(':')[1].strip()
                results['mean_response_time_concurrent'] = float(time_part.split()[0])
            elif 'Transfer rate:' in line:
                # Format: "Transfer rate:          X.XX [Kbytes/sec] received"
                transfer_part = line.split(':')[1].strip()
                results['transfer_rate_kbps'] = float(transfer_part.split()[0])
            elif 'Connection Times (ms)' in line:
                # Start parsing connection times section
                continue
            elif line.startswith('              min  mean[+/-sd] median   max'):
                # Header for connection times table
                continue
            elif line.startswith('Connect:'):
                connect_times = line.split()[1:]
                results['connect_times'] = {
                    'min': float(connect_times[0]),
                    'mean': float(connect_times[1]),
                    'median': float(connect_times[2]),
                    'max': float(connect_times[3])
                }
            elif line.startswith('Processing:'):
                processing_times = line.split()[1:]
                results['processing_times'] = {
                    'min': float(processing_times[0]),
                    'mean': float(processing_times[1]),
                    'median': float(processing_times[2]),
                    'max': float(processing_times[3])
                }
            elif line.startswith('Waiting:'):
                waiting_times = line.split()[1:]
                results['waiting_times'] = {
                    'min': float(waiting_times[0]),
                    'mean': float(waiting_times[1]),
                    'median': float(waiting_times[2]),
                    'max': float(waiting_times[3])
                }
            elif line.startswith('Total:'):
                total_times = line.split()[1:]
                results['total_times'] = {
                    'min': float(total_times[0]),
                    'mean': float(total_times[1]),
                    'median': float(total_times[2]),
                    'max': float(total_times[3])
                }
            elif 'Percentage of the requests served within a certain time (ms)' in line:
                # Start parsing percentile data
                continue
            elif '%' in line and 'ms' in line.replace('%', ''):
                # Parse percentile lines like "  50%     XX"
                parts = line.split()
                if len(parts) >= 2:
                    percentile = parts[0].replace('%', '')
                    time_ms = parts[1]
                    if 'percentiles' not in results:
                        results['percentiles'] = {}
                    try:
                        results['percentiles'][f'p{percentile}'] = float(time_ms)
                    except ValueError:
                        continue
        
        return results
    
    def run_endpoint_performance_suite(self, endpoints: List[str],
                                     requests_per_endpoint: int = 1000,
                                     concurrency_levels: List[int] = None) -> Dict[str, Any]:
        """
        Run comprehensive performance test suite across multiple endpoints.
        
        Args:
            endpoints: List of API endpoints to test
            requests_per_endpoint: Number of requests per endpoint
            concurrency_levels: List of concurrency levels to test
            
        Returns:
            Comprehensive performance test results
        """
        if concurrency_levels is None:
            concurrency_levels = [1, 5, 10, 20]
        
        suite_results = {
            'test_parameters': {
                'endpoints': endpoints,
                'requests_per_endpoint': requests_per_endpoint,
                'concurrency_levels': concurrency_levels
            },
            'endpoint_results': {},
            'performance_summary': {},
            'compliance_summary': {}
        }
        
        total_tests = len(endpoints) * len(concurrency_levels)
        completed_tests = 0
        
        logger.info(f"Starting endpoint performance suite: {total_tests} tests")
        
        for endpoint in endpoints:
            suite_results['endpoint_results'][endpoint] = {}
            
            for concurrency in concurrency_levels:
                logger.info(f"Testing {endpoint} with concurrency {concurrency}")
                
                test_result = self.run_ab_test(
                    endpoint=endpoint,
                    requests=requests_per_endpoint,
                    concurrency=concurrency
                )
                
                suite_results['endpoint_results'][endpoint][f'concurrency_{concurrency}'] = test_result
                
                completed_tests += 1
                logger.info(f"Completed {completed_tests}/{total_tests} tests")
        
        # Calculate suite-level summaries
        suite_results['performance_summary'] = self._calculate_suite_performance_summary(
            suite_results['endpoint_results']
        )
        
        suite_results['compliance_summary'] = self._calculate_suite_compliance_summary(
            suite_results['endpoint_results']
        )
        
        logger.info("Endpoint performance suite completed")
        return suite_results
    
    def _calculate_suite_performance_summary(self, endpoint_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate performance summary across all endpoint tests."""
        all_response_times = []
        all_rps_values = []
        all_error_rates = []
        compliant_tests = 0
        total_tests = 0
        
        for endpoint, concurrency_results in endpoint_results.items():
            for concurrency_level, test_result in concurrency_results.items():
                if 'error' not in test_result:
                    total_tests += 1
                    
                    # Collect metrics
                    if 'mean_response_time' in test_result:
                        all_response_times.append(test_result['mean_response_time'])
                    
                    if 'requests_per_second' in test_result:
                        all_rps_values.append(test_result['requests_per_second'])
                    
                    if 'failed_requests' in test_result and 'complete_requests' in test_result:
                        error_rate = (
                            test_result['failed_requests'] / test_result['complete_requests']
                            if test_result['complete_requests'] > 0 else 0
                        )
                        all_error_rates.append(error_rate)
                    
                    # Check compliance
                    if test_result.get('compliance_status', {}).get('compliant', False):
                        compliant_tests += 1
        
        summary = {
            'total_tests': total_tests,
            'compliant_tests': compliant_tests,
            'compliance_rate': compliant_tests / total_tests if total_tests > 0 else 0
        }
        
        if all_response_times:
            summary['response_time_stats'] = {
                'mean': statistics.mean(all_response_times),
                'median': statistics.median(all_response_times),
                'min': min(all_response_times),
                'max': max(all_response_times),
                'std_dev': statistics.stdev(all_response_times) if len(all_response_times) > 1 else 0
            }
        
        if all_rps_values:
            summary['throughput_stats'] = {
                'mean': statistics.mean(all_rps_values),
                'median': statistics.median(all_rps_values),
                'min': min(all_rps_values),
                'max': max(all_rps_values)
            }
        
        if all_error_rates:
            summary['error_rate_stats'] = {
                'mean': statistics.mean(all_error_rates),
                'median': statistics.median(all_error_rates),
                'min': min(all_error_rates),
                'max': max(all_error_rates)
            }
        
        return summary
    
    def _calculate_suite_compliance_summary(self, endpoint_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate compliance summary across all endpoint tests."""
        endpoint_compliance = {}
        
        for endpoint, concurrency_results in endpoint_results.items():
            endpoint_compliance[endpoint] = {
                'total_tests': 0,
                'compliant_tests': 0,
                'compliance_rate': 0.0,
                'violations': []
            }
            
            for concurrency_level, test_result in concurrency_results.items():
                if 'error' not in test_result:
                    endpoint_compliance[endpoint]['total_tests'] += 1
                    
                    compliance_status = test_result.get('compliance_status', {})
                    if compliance_status.get('compliant', False):
                        endpoint_compliance[endpoint]['compliant_tests'] += 1
                    else:
                        baseline_comparison = test_result.get('baseline_comparison', {})
                        endpoint_compliance[endpoint]['violations'].append({
                            'concurrency_level': concurrency_level,
                            'variance': baseline_comparison.get('variance'),
                            'measured_response_time': baseline_comparison.get('measured_response_time'),
                            'baseline_response_time': baseline_comparison.get('baseline_response_time')
                        })
            
            # Calculate compliance rate
            if endpoint_compliance[endpoint]['total_tests'] > 0:
                endpoint_compliance[endpoint]['compliance_rate'] = (
                    endpoint_compliance[endpoint]['compliant_tests'] / 
                    endpoint_compliance[endpoint]['total_tests']
                )
        
        return endpoint_compliance


# =============================================================================
# Performance Testing Fixtures for pytest Integration
# =============================================================================

@pytest.fixture(scope="session")
def nodejs_performance_baseline():
    """
    Session-scoped fixture providing Node.js performance baseline data.
    
    Returns:
        NodeJSPerformanceBaseline instance with comprehensive baseline metrics
    """
    baseline = NodeJSPerformanceBaseline()
    
    logger.info(
        "Node.js performance baseline loaded",
        api_endpoints=len(baseline.api_response_times),
        database_operations=len(baseline.database_operations),
        cache_operations=len(baseline.cache_operations),
        load_scenarios=len(baseline.load_performance)
    )
    
    return baseline


@pytest.fixture(scope="function")
def performance_monitor(nodejs_performance_baseline):
    """
    Function-scoped fixture providing performance monitoring capabilities.
    
    Args:
        nodejs_performance_baseline: Node.js baseline data
        
    Returns:
        PerformanceMonitor instance configured for comprehensive monitoring
    """
    monitor = PerformanceMonitor(
        baseline=nodejs_performance_baseline,
        enable_prometheus=PROMETHEUS_AVAILABLE,
        enable_apm=False  # Disabled for testing
    )
    
    yield monitor
    
    # Log performance summary at end of test
    summary = monitor.get_performance_summary()
    logger.info(
        "Performance test completed",
        total_measurements=summary['measurement_summary']['total_measurements'],
        compliance_rate=summary['compliance_summary']['compliance_rate'],
        violations=summary['variance_violations']
    )


@pytest.fixture(scope="function")
def load_test_generator(performance_monitor):
    """
    Function-scoped fixture providing load testing capabilities.
    
    Args:
        performance_monitor: Performance monitoring instance
        
    Returns:
        LoadTestGenerator configured for Flask application testing
    """
    if not LOCUST_AVAILABLE:
        pytest.skip("Locust not available for load testing")
    
    generator = LoadTestGenerator(performance_monitor)
    return generator


@pytest.fixture(scope="function")
def database_performance_tester(performance_monitor, comprehensive_test_environment):
    """
    Function-scoped fixture providing database performance testing.
    
    Args:
        performance_monitor: Performance monitoring instance
        comprehensive_test_environment: Complete test environment
        
    Returns:
        DatabasePerformanceTester configured with MongoDB clients
    """
    db_env = comprehensive_test_environment.get('database', {})
    
    tester = DatabasePerformanceTester(
        performance_monitor=performance_monitor,
        mongodb_client=db_env.get('pymongo_client'),
        motor_client=db_env.get('motor_client')
    )
    
    return tester


@pytest.fixture(scope="function")
def cache_performance_tester(performance_monitor, comprehensive_test_environment):
    """
    Function-scoped fixture providing cache performance testing.
    
    Args:
        performance_monitor: Performance monitoring instance
        comprehensive_test_environment: Complete test environment
        
    Returns:
        CachePerformanceTester configured with Redis client
    """
    db_env = comprehensive_test_environment.get('database', {})
    
    tester = CachePerformanceTester(
        performance_monitor=performance_monitor,
        redis_client=db_env.get('redis_client')
    )
    
    return tester


@pytest.fixture(scope="function")
def apache_bench_tester(performance_monitor, flask_app):
    """
    Function-scoped fixture providing Apache Bench HTTP performance testing.
    
    Args:
        performance_monitor: Performance monitoring instance
        flask_app: Flask application instance
        
    Returns:
        ApacheBenchTester configured for HTTP performance testing
    """
    # Start Flask test server
    base_url = "http://localhost:5000"
    
    tester = ApacheBenchTester(
        performance_monitor=performance_monitor,
        base_url=base_url
    )
    
    if not tester.ab_available:
        pytest.skip("Apache Bench (ab) not available")
    
    return tester


@pytest.fixture(scope="function")
def performance_validation_context(performance_monitor, nodejs_performance_baseline):
    """
    Function-scoped fixture providing performance validation context.
    
    This fixture provides utilities for validating performance measurements
    against the ≤10% variance requirement with comprehensive reporting.
    
    Args:
        performance_monitor: Performance monitoring instance
        nodejs_performance_baseline: Node.js baseline data
        
    Returns:
        Dictionary with performance validation utilities
    """
    validation_context = {
        'monitor': performance_monitor,
        'baseline': nodejs_performance_baseline,
        'violations': [],
        'compliance_rate': 1.0
    }
    
    def validate_measurement(measurement: PerformanceMeasurement) -> bool:
        """Validate a single performance measurement."""
        is_compliant = measurement.is_compliant(nodejs_performance_baseline)
        
        if not is_compliant:
            validation_context['violations'].append({
                'operation': measurement.operation_name,
                'category': measurement.category,
                'measured_value': measurement.measured_value,
                'baseline_value': measurement.baseline_value,
                'variance': measurement.variance,
                'timestamp': measurement.timestamp.isoformat()
            })
        
        # Update compliance rate
        total_measurements = len(performance_monitor.measurements)
        compliant_measurements = len([
            m for m in performance_monitor.measurements 
            if m.is_compliant(nodejs_performance_baseline)
        ])
        
        validation_context['compliance_rate'] = (
            compliant_measurements / total_measurements if total_measurements > 0 else 1.0
        )
        
        return is_compliant
    
    def assert_performance_compliance(min_compliance_rate: float = 0.90):
        """Assert that performance compliance meets minimum threshold."""
        current_rate = validation_context['compliance_rate']
        
        if current_rate < min_compliance_rate:
            violation_summary = '\n'.join([
                f"  - {v['operation']} ({v['category']}): {v['variance']:.2%} variance"
                for v in validation_context['violations'][:10]  # Show top 10 violations
            ])
            
            pytest.fail(
                f"Performance compliance rate {current_rate:.2%} below threshold {min_compliance_rate:.2%}\n"
                f"Violations ({len(validation_context['violations'])}):\n{violation_summary}"
            )
    
    def get_performance_report() -> Dict[str, Any]:
        """Get comprehensive performance validation report."""
        return {
            'compliance_rate': validation_context['compliance_rate'],
            'total_measurements': len(performance_monitor.measurements),
            'violations': validation_context['violations'],
            'summary': performance_monitor.get_performance_summary()
        }
    
    validation_context.update({
        'validate_measurement': validate_measurement,
        'assert_performance_compliance': assert_performance_compliance,
        'get_performance_report': get_performance_report
    })
    
    return validation_context


@pytest.fixture(scope="function")
def concurrent_request_tester(performance_monitor, client):
    """
    Function-scoped fixture providing concurrent request testing utilities.
    
    Args:
        performance_monitor: Performance monitoring instance
        client: Flask test client
        
    Returns:
        Concurrent request testing utilities
    """
    
    def test_concurrent_requests(endpoint: str, concurrent_users: int = 10,
                                requests_per_user: int = 5,
                                headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Test concurrent request performance using ThreadPoolExecutor.
        
        Args:
            endpoint: API endpoint to test
            concurrent_users: Number of concurrent threads
            requests_per_user: Requests per thread
            headers: Optional HTTP headers
            
        Returns:
            Concurrent request test results
        """
        results = {
            'test_parameters': {
                'endpoint': endpoint,
                'concurrent_users': concurrent_users,
                'requests_per_user': requests_per_user,
                'total_requests': concurrent_users * requests_per_user
            },
            'response_times': [],
            'status_codes': [],
            'errors': [],
            'performance_metrics': {}
        }
        
        def make_request(user_id: int) -> List[Dict[str, Any]]:
            """Make requests for a single user."""
            user_results = []
            
            for request_id in range(requests_per_user):
                with performance_monitor.measure_operation(
                    operation_name='concurrent_request',
                    category='api',
                    endpoint=endpoint,
                    concurrent_users=concurrent_users
                ) as measurement:
                    
                    start_time = time.perf_counter()
                    
                    try:
                        response = client.get(endpoint, headers=headers)
                        end_time = time.perf_counter()
                        
                        response_time = (end_time - start_time) * 1000
                        
                        user_results.append({
                            'user_id': user_id,
                            'request_id': request_id,
                            'response_time': response_time,
                            'status_code': response.status_code,
                            'success': 200 <= response.status_code < 300
                        })
                        
                        measurement.status_code = response.status_code
                        
                    except Exception as e:
                        end_time = time.perf_counter()
                        response_time = (end_time - start_time) * 1000
                        
                        user_results.append({
                            'user_id': user_id,
                            'request_id': request_id,
                            'response_time': response_time,
                            'status_code': 500,
                            'success': False,
                            'error': str(e)
                        })
                        
                        measurement.error_count += 1
            
            return user_results
        
        # Execute concurrent requests
        with ThreadPoolExecutor(max_workers=concurrent_users) as executor:
            start_time = time.time()
            
            futures = [
                executor.submit(make_request, user_id)
                for user_id in range(concurrent_users)
            ]
            
            # Collect results
            all_request_results = []
            for future in as_completed(futures):
                try:
                    user_results = future.result()
                    all_request_results.extend(user_results)
                except Exception as e:
                    results['errors'].append(str(e))
            
            end_time = time.time()
        
        # Process results
        response_times = [r['response_time'] for r in all_request_results]
        status_codes = [r['status_code'] for r in all_request_results]
        successful_requests = [r for r in all_request_results if r['success']]
        
        results['response_times'] = response_times
        results['status_codes'] = status_codes
        
        # Calculate performance metrics
        if response_times:
            results['performance_metrics'] = {
                'total_duration': end_time - start_time,
                'requests_per_second': len(all_request_results) / (end_time - start_time),
                'avg_response_time': statistics.mean(response_times),
                'median_response_time': statistics.median(response_times),
                'min_response_time': min(response_times),
                'max_response_time': max(response_times),
                'success_rate': len(successful_requests) / len(all_request_results),
                'error_rate': 1 - (len(successful_requests) / len(all_request_results))
            }
            
            if len(response_times) > 1:
                results['performance_metrics']['std_deviation'] = statistics.stdev(response_times)
        
        return results
    
    return {
        'test_concurrent_requests': test_concurrent_requests
    }


# Export comprehensive fixtures and utilities
__all__ = [
    # Core data structures
    'NodeJSPerformanceBaseline',
    'PerformanceMeasurement',
    
    # Performance monitoring
    'PerformanceMonitor',
    
    # Load testing
    'LoadTestGenerator',
    'FlaskLoadTestUser',
    
    # Database testing
    'DatabasePerformanceTester',
    
    # Cache testing
    'CachePerformanceTester',
    
    # HTTP performance testing
    'ApacheBenchTester',
    
    # pytest fixtures
    'nodejs_performance_baseline',
    'performance_monitor',
    'load_test_generator',
    'database_performance_tester',
    'cache_performance_tester',
    'apache_bench_tester',
    'performance_validation_context',
    'concurrent_request_tester',
    
    # Availability flags
    'PROMETHEUS_AVAILABLE',
    'LOCUST_AVAILABLE',
    'PYMONGO_AVAILABLE',
    'MOTOR_AVAILABLE',
    'REDIS_AVAILABLE',
    'APP_DEPENDENCIES_AVAILABLE'
]