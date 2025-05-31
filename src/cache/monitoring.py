"""
Cache Performance Monitoring and Observability Module

This module implements comprehensive cache performance monitoring with Prometheus metrics collection,
cache hit/miss ratio tracking, Redis connection health monitoring, and cache operation latency
measurement. Provides enterprise-grade observability for cache performance optimization and
seamless integration with the Flask application monitoring infrastructure.

Key Features:
- prometheus-client 0.17+ metrics collection for cache performance monitoring
- Cache hit rate monitoring and effectiveness measurement per Section 3.4.5
- Redis memory usage tracking and alerting per Section 3.4.5
- Cache operation latency measurement for performance optimization
- Redis connection health monitoring per Section 6.1.3
- Enterprise monitoring integration per Section 6.1.1 Flask application factory pattern

Architecture Integration:
- Seamless integration with src/config/monitoring.py PrometheusMetrics infrastructure
- Flask application factory pattern compatibility for centralized configuration
- Circuit breaker integration for Redis connectivity resilience monitoring
- Health check endpoint integration for Kubernetes probe support
- Performance variance tracking against Node.js baseline cache performance

Performance Requirements:
- Cache hit rate effectiveness monitoring: ≥80% hit rate target with alerts <70%
- Redis operation latency tracking: ≤5ms average latency with warnings >10ms
- Memory usage monitoring: Warning >80%, Critical >95% Redis memory utilization
- Connection pool health: ≥95% pool availability with alerts <90%
- Performance parity compliance: ≤10% variance from Node.js cache performance

References:
- Section 6.1.1: prometheus-client 0.17+ integration and Flask application factory pattern
- Section 3.4.5: Cache performance management and Redis memory usage tracking
- Section 6.1.3: Health check and monitoring endpoints for enterprise integration
- Section 6.5: MONITORING AND OBSERVABILITY comprehensive monitoring infrastructure
"""

import gc
import json
import time
import traceback
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Dict, List, Optional, Union, Callable, Tuple
from threading import Lock
from contextlib import contextmanager

import redis
import structlog
from flask import Flask, g, current_app
from prometheus_client import (
    Counter, 
    Histogram, 
    Gauge, 
    Info,
    Summary,
    CollectorRegistry,
    REGISTRY
)

# Import monitoring configuration for enterprise integration
from src.config.monitoring import (
    MonitoringConfig,
    PrometheusMetrics,
    StructuredLogger
)


class CachePerformanceMetrics:
    """
    Comprehensive cache performance metrics collection implementing Prometheus
    metrics for cache operations, hit/miss ratios, Redis connection health,
    and operation latency measurement with Node.js baseline comparison.
    
    Provides enterprise-grade cache observability including:
    - Cache hit/miss ratio tracking with effectiveness measurement
    - Redis operation latency monitoring with performance thresholds
    - Redis memory usage tracking and alerting integration
    - Connection pool health monitoring with availability metrics
    - Cache key space analysis and optimization insights
    """
    
    def __init__(self, registry: CollectorRegistry = REGISTRY):
        """Initialize cache performance metrics with Prometheus integration."""
        self._registry = registry
        self._lock = Lock()
        self._metrics_initialized = False
        
        # Cache Operation Metrics
        self.cache_operations_total = Counter(
            'flask_cache_operations_total',
            'Total number of cache operations',
            ['operation', 'cache_type', 'status'],
            registry=self._registry
        )
        
        self.cache_operation_duration_seconds = Histogram(
            'flask_cache_operation_duration_seconds',
            'Cache operation duration in seconds',
            ['operation', 'cache_type'],
            buckets=[0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5],
            registry=self._registry
        )
        
        # Cache Hit/Miss Ratio Metrics
        self.cache_hits_total = Counter(
            'flask_cache_hits_total',
            'Total number of cache hits',
            ['cache_type', 'key_pattern'],
            registry=self._registry
        )
        
        self.cache_misses_total = Counter(
            'flask_cache_misses_total',
            'Total number of cache misses',
            ['cache_type', 'key_pattern'],
            registry=self._registry
        )
        
        self.cache_hit_ratio = Gauge(
            'flask_cache_hit_ratio',
            'Current cache hit ratio percentage',
            ['cache_type', 'time_window'],
            registry=self._registry
        )
        
        # Redis Connection Health Metrics
        self.redis_connections_active = Gauge(
            'flask_redis_connections_active',
            'Number of active Redis connections',
            ['pool_name'],
            registry=self._registry
        )
        
        self.redis_connections_available = Gauge(
            'flask_redis_connections_available',
            'Number of available Redis connections in pool',
            ['pool_name'],
            registry=self._registry
        )
        
        self.redis_connection_pool_utilization = Gauge(
            'flask_redis_connection_pool_utilization_percent',
            'Redis connection pool utilization percentage',
            ['pool_name'],
            registry=self._registry
        )
        
        # Redis Memory Usage Metrics
        self.redis_memory_usage_bytes = Gauge(
            'flask_redis_memory_usage_bytes',
            'Redis memory usage in bytes',
            ['memory_type'],  # used, peak, rss, lua
            registry=self._registry
        )
        
        self.redis_memory_utilization_percent = Gauge(
            'flask_redis_memory_utilization_percent',
            'Redis memory utilization percentage',
            registry=self._registry
        )
        
        self.redis_keyspace_hits_total = Counter(
            'flask_redis_keyspace_hits_total',
            'Total Redis keyspace hits',
            registry=self._registry
        )
        
        self.redis_keyspace_misses_total = Counter(
            'flask_redis_keyspace_misses_total',
            'Total Redis keyspace misses',
            registry=self._registry
        )
        
        # Cache Performance Effectiveness Metrics
        self.cache_effectiveness_score = Gauge(
            'flask_cache_effectiveness_score',
            'Cache effectiveness score (0-100)',
            ['cache_type'],
            registry=self._registry
        )
        
        self.cache_evictions_total = Counter(
            'flask_cache_evictions_total',
            'Total number of cache evictions',
            ['cache_type', 'eviction_reason'],
            registry=self._registry
        )
        
        self.cache_key_count = Gauge(
            'flask_cache_key_count',
            'Number of keys in cache',
            ['cache_type', 'key_pattern'],
            registry=self._registry
        )
        
        # Cache Operation Performance Metrics
        self.cache_latency_summary = Summary(
            'flask_cache_latency_summary_seconds',
            'Cache operation latency summary',
            ['operation', 'cache_type'],
            registry=self._registry
        )
        
        self.cache_throughput = Gauge(
            'flask_cache_throughput_ops_per_second',
            'Cache operations per second',
            ['operation', 'cache_type'],
            registry=self._registry
        )
        
        # Redis Circuit Breaker Metrics
        self.redis_circuit_breaker_state = Gauge(
            'flask_redis_circuit_breaker_state',
            'Redis circuit breaker state (0=closed, 1=open, 2=half-open)',
            ['connection_pool'],
            registry=self._registry
        )
        
        self.redis_connection_failures_total = Counter(
            'flask_redis_connection_failures_total',
            'Total Redis connection failures',
            ['failure_type', 'connection_pool'],
            registry=self._registry
        )
        
        # Node.js Baseline Comparison Metrics
        self.cache_performance_variance_percent = Gauge(
            'flask_cache_performance_variance_percent',
            'Cache performance variance from Node.js baseline',
            ['operation', 'metric_type'],
            registry=self._registry
        )
        
        self.nodejs_cache_baseline_operations_total = Counter(
            'nodejs_cache_baseline_operations_total',
            'Node.js baseline cache operations for comparison',
            ['operation'],
            registry=self._registry
        )
        
        # Cache Configuration Information
        self.cache_config_info = Info(
            'flask_cache_config',
            'Cache configuration information',
            registry=self._registry
        )
        
        # Internal tracking for hit rate calculation
        self._hit_miss_tracking = {
            'hits': 0,
            'misses': 0,
            'last_reset': time.time(),
            'window_size': 300  # 5 minutes
        }
        
        self._metrics_initialized = True
    
    def record_cache_operation(self, operation: str, cache_type: str, duration: float, 
                             status: str, key_pattern: Optional[str] = None):
        """
        Record cache operation metrics with comprehensive performance tracking.
        
        Args:
            operation: Cache operation type (get, set, delete, exists)
            cache_type: Cache type (redis, memory, session)
            duration: Operation duration in seconds
            status: Operation status (success, error, timeout)
            key_pattern: Cache key pattern for categorization
        """
        # Record operation count
        self.cache_operations_total.labels(
            operation=operation,
            cache_type=cache_type,
            status=status
        ).inc()
        
        # Record operation duration
        self.cache_operation_duration_seconds.labels(
            operation=operation,
            cache_type=cache_type
        ).observe(duration)
        
        # Record latency summary
        self.cache_latency_summary.labels(
            operation=operation,
            cache_type=cache_type
        ).observe(duration)
        
        # Update cache throughput tracking
        self._update_throughput_metrics(operation, cache_type)
    
    def record_cache_hit(self, cache_type: str, key_pattern: Optional[str] = None):
        """
        Record cache hit with hit ratio calculation.
        
        Args:
            cache_type: Cache type (redis, memory, session)
            key_pattern: Cache key pattern for categorization
        """
        key_pattern = key_pattern or 'unknown'
        
        # Record cache hit
        self.cache_hits_total.labels(
            cache_type=cache_type,
            key_pattern=key_pattern
        ).inc()
        
        # Update internal tracking
        with self._lock:
            self._hit_miss_tracking['hits'] += 1
            self._update_hit_ratio(cache_type)
    
    def record_cache_miss(self, cache_type: str, key_pattern: Optional[str] = None):
        """
        Record cache miss with hit ratio calculation.
        
        Args:
            cache_type: Cache type (redis, memory, session)
            key_pattern: Cache key pattern for categorization
        """
        key_pattern = key_pattern or 'unknown'
        
        # Record cache miss
        self.cache_misses_total.labels(
            cache_type=cache_type,
            key_pattern=key_pattern
        ).inc()
        
        # Update internal tracking
        with self._lock:
            self._hit_miss_tracking['misses'] += 1
            self._update_hit_ratio(cache_type)
    
    def _update_hit_ratio(self, cache_type: str):
        """Update cache hit ratio metrics."""
        current_time = time.time()
        window_size = self._hit_miss_tracking['window_size']
        
        # Reset tracking if window expired
        if current_time - self._hit_miss_tracking['last_reset'] > window_size:
            self._hit_miss_tracking = {
                'hits': 0,
                'misses': 0,
                'last_reset': current_time,
                'window_size': window_size
            }
        
        total_operations = self._hit_miss_tracking['hits'] + self._hit_miss_tracking['misses']
        if total_operations > 0:
            hit_ratio = (self._hit_miss_tracking['hits'] / total_operations) * 100
            self.cache_hit_ratio.labels(
                cache_type=cache_type,
                time_window=f'{window_size}s'
            ).set(hit_ratio)
    
    def _update_throughput_metrics(self, operation: str, cache_type: str):
        """Update cache throughput metrics."""
        # This would typically use a sliding window counter
        # For simplicity, we'll update based on recent operation rate
        pass
    
    def update_redis_connection_metrics(self, redis_client: redis.Redis, pool_name: str = 'default'):
        """
        Update Redis connection pool metrics.
        
        Args:
            redis_client: Redis client instance
            pool_name: Connection pool identifier
        """
        try:
            pool = redis_client.connection_pool
            
            # Connection pool metrics
            created_connections = pool.created_connections
            available_connections = len(pool._available_connections)
            in_use_connections = created_connections - available_connections
            
            self.redis_connections_active.labels(
                pool_name=pool_name
            ).set(in_use_connections)
            
            self.redis_connections_available.labels(
                pool_name=pool_name
            ).set(available_connections)
            
            # Calculate utilization percentage
            max_connections = pool.max_connections
            if max_connections > 0:
                utilization = (in_use_connections / max_connections) * 100
                self.redis_connection_pool_utilization.labels(
                    pool_name=pool_name
                ).set(utilization)
        
        except Exception as e:
            # Log error but don't fail
            structlog.get_logger().warning(
                "Failed to update Redis connection metrics",
                error=str(e),
                pool_name=pool_name
            )
    
    def update_redis_memory_metrics(self, redis_client: redis.Redis):
        """
        Update Redis memory usage metrics from Redis INFO command.
        
        Args:
            redis_client: Redis client instance
        """
        try:
            info = redis_client.info('memory')
            
            # Memory usage metrics
            self.redis_memory_usage_bytes.labels(
                memory_type='used'
            ).set(info.get('used_memory', 0))
            
            self.redis_memory_usage_bytes.labels(
                memory_type='peak'
            ).set(info.get('used_memory_peak', 0))
            
            self.redis_memory_usage_bytes.labels(
                memory_type='rss'
            ).set(info.get('used_memory_rss', 0))
            
            self.redis_memory_usage_bytes.labels(
                memory_type='lua'
            ).set(info.get('used_memory_lua', 0))
            
            # Memory utilization percentage
            max_memory = info.get('maxmemory', 0)
            used_memory = info.get('used_memory', 0)
            if max_memory > 0:
                utilization = (used_memory / max_memory) * 100
                self.redis_memory_utilization_percent.set(utilization)
            
            # Keyspace statistics
            keyspace_info = redis_client.info('keyspace')
            total_hits = info.get('keyspace_hits', 0)
            total_misses = info.get('keyspace_misses', 0)
            
            # Update keyspace metrics (these are cumulative from Redis)
            self.redis_keyspace_hits_total._value._value = total_hits
            self.redis_keyspace_misses_total._value._value = total_misses
        
        except Exception as e:
            # Log error but don't fail
            structlog.get_logger().warning(
                "Failed to update Redis memory metrics",
                error=str(e)
            )
    
    def record_cache_eviction(self, cache_type: str, eviction_reason: str):
        """
        Record cache eviction event.
        
        Args:
            cache_type: Cache type (redis, memory, session)
            eviction_reason: Eviction reason (ttl, memory, manual)
        """
        self.cache_evictions_total.labels(
            cache_type=cache_type,
            eviction_reason=eviction_reason
        ).inc()
    
    def update_cache_key_count(self, cache_type: str, key_pattern: str, count: int):
        """
        Update cache key count metrics.
        
        Args:
            cache_type: Cache type (redis, memory, session)
            key_pattern: Key pattern category
            count: Number of keys
        """
        self.cache_key_count.labels(
            cache_type=cache_type,
            key_pattern=key_pattern
        ).set(count)
    
    def calculate_cache_effectiveness(self, cache_type: str) -> float:
        """
        Calculate cache effectiveness score based on hit ratio and performance.
        
        Args:
            cache_type: Cache type to calculate effectiveness for
            
        Returns:
            Effectiveness score (0-100)
        """
        try:
            # Get hit ratio metrics
            hit_ratio_metric = self.cache_hit_ratio.labels(
                cache_type=cache_type,
                time_window='300s'
            )
            
            # Simple effectiveness calculation based on hit ratio
            # In a real implementation, this would consider latency, memory usage, etc.
            effectiveness = getattr(hit_ratio_metric._value, '_value', 0)
            
            self.cache_effectiveness_score.labels(
                cache_type=cache_type
            ).set(effectiveness)
            
            return effectiveness
        
        except Exception:
            return 0.0
    
    def record_circuit_breaker_state(self, connection_pool: str, state: int):
        """
        Record Redis circuit breaker state.
        
        Args:
            connection_pool: Connection pool identifier
            state: Circuit breaker state (0=closed, 1=open, 2=half-open)
        """
        self.redis_circuit_breaker_state.labels(
            connection_pool=connection_pool
        ).set(state)
    
    def record_connection_failure(self, failure_type: str, connection_pool: str):
        """
        Record Redis connection failure.
        
        Args:
            failure_type: Type of failure (timeout, connection_error, auth_error)
            connection_pool: Connection pool identifier
        """
        self.redis_connection_failures_total.labels(
            failure_type=failure_type,
            connection_pool=connection_pool
        ).inc()
    
    def record_performance_variance(self, operation: str, metric_type: str, variance_percent: float):
        """
        Record cache performance variance from Node.js baseline.
        
        Args:
            operation: Cache operation (get, set, delete)
            metric_type: Metric type (latency, throughput, hit_ratio)
            variance_percent: Variance percentage from baseline
        """
        self.cache_performance_variance_percent.labels(
            operation=operation,
            metric_type=metric_type
        ).set(variance_percent)
    
    def record_nodejs_baseline_operation(self, operation: str):
        """
        Record Node.js baseline operation for comparison.
        
        Args:
            operation: Cache operation type
        """
        self.nodejs_cache_baseline_operations_total.labels(
            operation=operation
        ).inc()
    
    def set_cache_configuration(self, config: Dict[str, Any]):
        """
        Set cache configuration information metrics.
        
        Args:
            config: Cache configuration dictionary
        """
        # Convert config to string values for Info metric
        config_info = {
            key: str(value) for key, value in config.items()
        }
        self.cache_config_info.info(config_info)
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get comprehensive cache metrics summary for monitoring dashboard."""
        try:
            return {
                'cache_hit_ratio': {
                    'redis': getattr(
                        self.cache_hit_ratio.labels(cache_type='redis', time_window='300s')._value,
                        '_value', 0
                    ),
                    'memory': getattr(
                        self.cache_hit_ratio.labels(cache_type='memory', time_window='300s')._value,
                        '_value', 0
                    )
                },
                'effectiveness_scores': {
                    'redis': self.calculate_cache_effectiveness('redis'),
                    'memory': self.calculate_cache_effectiveness('memory')
                },
                'connection_pool_utilization': getattr(
                    self.redis_connection_pool_utilization.labels(pool_name='default')._value,
                    '_value', 0
                ),
                'memory_utilization': getattr(
                    self.redis_memory_utilization_percent._value,
                    '_value', 0
                ),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        except Exception as e:
            structlog.get_logger().error(
                "Failed to generate cache metrics summary",
                error=str(e)
            )
            return {'error': str(e)}


class CacheHealthMonitor:
    """
    Cache health monitoring for Redis connectivity and service availability
    with circuit breaker integration and Kubernetes health probe support.
    
    Provides comprehensive cache health monitoring including:
    - Redis connection health validation with timeout handling
    - Circuit breaker state monitoring and failure tracking
    - Cache service availability assessment for health probes
    - Performance degradation detection and alerting
    - Enterprise health check integration for monitoring systems
    """
    
    def __init__(self, redis_client: redis.Redis, metrics: CachePerformanceMetrics):
        """
        Initialize cache health monitor with Redis client and metrics integration.
        
        Args:
            redis_client: Redis client instance for health checks
            metrics: Cache performance metrics instance
        """
        self.redis_client = redis_client
        self.metrics = metrics
        self.logger = structlog.get_logger("cache.health")
        
        # Health check configuration
        self.health_check_timeout = 5.0  # seconds
        self.health_check_interval = 30.0  # seconds
        self.failure_threshold = 3
        self.recovery_threshold = 2
        
        # Health state tracking
        self.consecutive_failures = 0
        self.consecutive_successes = 0
        self.last_health_check = None
        self.last_health_status = None
        self.circuit_breaker_state = 0  # 0=closed, 1=open, 2=half-open
    
    def check_redis_health(self) -> Tuple[bool, Dict[str, Any]]:
        """
        Perform comprehensive Redis health check with detailed diagnostics.
        
        Returns:
            Tuple of (is_healthy, health_details)
        """
        health_details = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'service': 'redis',
            'status': 'unknown',
            'connection_pool': {},
            'memory_usage': {},
            'response_time': None,
            'errors': []
        }
        
        try:
            start_time = time.perf_counter()
            
            # Basic connectivity test
            ping_result = self.redis_client.ping()
            if not ping_result:
                health_details['errors'].append('Redis PING failed')
                return False, health_details
            
            # Measure response time
            response_time = time.perf_counter() - start_time
            health_details['response_time'] = response_time
            
            # Connection pool health
            pool = self.redis_client.connection_pool
            health_details['connection_pool'] = {
                'created_connections': pool.created_connections,
                'available_connections': len(pool._available_connections),
                'max_connections': pool.max_connections,
                'in_use_connections': pool.created_connections - len(pool._available_connections)
            }
            
            # Memory usage information
            try:
                memory_info = self.redis_client.info('memory')
                health_details['memory_usage'] = {
                    'used_memory': memory_info.get('used_memory', 0),
                    'used_memory_peak': memory_info.get('used_memory_peak', 0),
                    'maxmemory': memory_info.get('maxmemory', 0),
                    'memory_utilization_percent': (
                        (memory_info.get('used_memory', 0) / memory_info.get('maxmemory', 1)) * 100
                        if memory_info.get('maxmemory', 0) > 0 else 0
                    )
                }
            except Exception as e:
                health_details['errors'].append(f'Memory info failed: {str(e)}')
            
            # Performance thresholds
            if response_time > 0.1:  # 100ms threshold
                health_details['errors'].append(f'High response time: {response_time:.3f}s')
            
            # Determine overall health
            is_healthy = len(health_details['errors']) == 0
            health_details['status'] = 'healthy' if is_healthy else 'degraded'
            
            # Update health state tracking
            if is_healthy:
                self.consecutive_failures = 0
                self.consecutive_successes += 1
                if self.circuit_breaker_state == 2 and self.consecutive_successes >= self.recovery_threshold:
                    self.circuit_breaker_state = 0  # Close circuit breaker
            else:
                self.consecutive_successes = 0
                self.consecutive_failures += 1
                if self.consecutive_failures >= self.failure_threshold:
                    self.circuit_breaker_state = 1  # Open circuit breaker
            
            # Record metrics
            self.metrics.record_circuit_breaker_state('default', self.circuit_breaker_state)
            
            return is_healthy, health_details
        
        except redis.ConnectionError as e:
            health_details['status'] = 'connection_error'
            health_details['errors'].append(f'Connection error: {str(e)}')
            self.metrics.record_connection_failure('connection_error', 'default')
            return False, health_details
        
        except redis.TimeoutError as e:
            health_details['status'] = 'timeout'
            health_details['errors'].append(f'Timeout error: {str(e)}')
            self.metrics.record_connection_failure('timeout', 'default')
            return False, health_details
        
        except redis.AuthenticationError as e:
            health_details['status'] = 'auth_error'
            health_details['errors'].append(f'Authentication error: {str(e)}')
            self.metrics.record_connection_failure('auth_error', 'default')
            return False, health_details
        
        except Exception as e:
            health_details['status'] = 'error'
            health_details['errors'].append(f'Unexpected error: {str(e)}')
            self.metrics.record_connection_failure('unknown_error', 'default')
            return False, health_details
        
        finally:
            self.last_health_check = time.time()
            self.last_health_status = health_details['status']
    
    def is_circuit_breaker_open(self) -> bool:
        """Check if circuit breaker is open (preventing cache operations)."""
        return self.circuit_breaker_state == 1
    
    def attempt_circuit_breaker_test(self) -> bool:
        """
        Attempt to test circuit breaker recovery (half-open state).
        
        Returns:
            True if test should be attempted
        """
        if self.circuit_breaker_state == 1:  # Open
            # Transition to half-open for testing
            self.circuit_breaker_state = 2
            self.metrics.record_circuit_breaker_state('default', self.circuit_breaker_state)
            return True
        return False
    
    def get_health_summary(self) -> Dict[str, Any]:
        """Get health summary for monitoring dashboard integration."""
        return {
            'redis_healthy': self.last_health_status in ['healthy'],
            'circuit_breaker_state': self.circuit_breaker_state,
            'consecutive_failures': self.consecutive_failures,
            'consecutive_successes': self.consecutive_successes,
            'last_health_check': self.last_health_check,
            'health_check_interval': self.health_check_interval
        }


class CacheMonitoringManager:
    """
    Centralized cache monitoring management providing unified access to
    cache performance metrics, health monitoring, and enterprise integration.
    
    Integrates with Flask application factory pattern and provides:
    - Unified cache monitoring interface for all cache operations
    - Automatic metrics collection and health monitoring
    - Performance variance tracking against Node.js baseline
    - Enterprise monitoring system integration
    - Circuit breaker coordination and alerting
    """
    
    def __init__(self, app: Optional[Flask] = None):
        """
        Initialize cache monitoring manager with optional Flask app integration.
        
        Args:
            app: Flask application instance for factory pattern integration
        """
        self.app = app
        self.metrics: Optional[CachePerformanceMetrics] = None
        self.health_monitor: Optional[CacheHealthMonitor] = None
        self.logger = structlog.get_logger("cache.monitoring")
        self._initialized = False
        
        if app:
            self.init_app(app)
    
    def init_app(self, app: Flask):
        """
        Initialize cache monitoring with Flask application factory pattern.
        
        Args:
            app: Flask application instance
        """
        self.app = app
        
        # Initialize Prometheus metrics
        registry = getattr(app.config.get('MONITORING_METRICS'), '_registry', None)
        self.metrics = CachePerformanceMetrics(registry=registry)
        
        # Store cache monitoring in app config for access
        app.config['CACHE_MONITORING'] = self
        
        # Set cache configuration information
        cache_config = {
            'redis_enabled': app.config.get('REDIS_ENABLED', True),
            'redis_url': app.config.get('REDIS_URL', 'redis://localhost:6379'),
            'connection_pool_size': app.config.get('REDIS_MAX_CONNECTIONS', 50),
            'socket_timeout': app.config.get('REDIS_SOCKET_TIMEOUT', 30.0),
            'cache_default_ttl': app.config.get('CACHE_DEFAULT_TIMEOUT', 300),
            'monitoring_enabled': True
        }
        self.metrics.set_cache_configuration(cache_config)
        
        self._initialized = True
        
        self.logger.info(
            "Cache monitoring initialized",
            redis_enabled=cache_config['redis_enabled'],
            monitoring_enabled=True,
            timestamp=datetime.now(timezone.utc).isoformat()
        )
    
    def init_redis_monitoring(self, redis_client: redis.Redis):
        """
        Initialize Redis-specific monitoring with client instance.
        
        Args:
            redis_client: Redis client instance for health monitoring
        """
        if not self.metrics:
            raise RuntimeError("Cache monitoring not initialized. Call init_app() first.")
        
        self.health_monitor = CacheHealthMonitor(redis_client, self.metrics)
        
        self.logger.info(
            "Redis health monitoring initialized",
            health_check_timeout=self.health_monitor.health_check_timeout,
            failure_threshold=self.health_monitor.failure_threshold
        )
    
    @contextmanager
    def monitor_cache_operation(self, operation: str, cache_type: str = 'redis', 
                              key_pattern: Optional[str] = None):
        """
        Context manager for monitoring cache operations with automatic metrics collection.
        
        Args:
            operation: Cache operation type (get, set, delete, exists)
            cache_type: Cache type (redis, memory, session)
            key_pattern: Cache key pattern for categorization
            
        Yields:
            Context for cache operation execution
        """
        start_time = time.perf_counter()
        status = 'success'
        
        try:
            yield
        except redis.ConnectionError:
            status = 'connection_error'
            raise
        except redis.TimeoutError:
            status = 'timeout'
            raise
        except Exception:
            status = 'error'
            raise
        finally:
            duration = time.perf_counter() - start_time
            
            if self.metrics:
                self.metrics.record_cache_operation(
                    operation=operation,
                    cache_type=cache_type,
                    duration=duration,
                    status=status,
                    key_pattern=key_pattern
                )
    
    def record_cache_hit(self, cache_type: str = 'redis', key_pattern: Optional[str] = None):
        """
        Record cache hit with automatic metrics collection.
        
        Args:
            cache_type: Cache type (redis, memory, session)
            key_pattern: Cache key pattern for categorization
        """
        if self.metrics:
            self.metrics.record_cache_hit(cache_type, key_pattern)
    
    def record_cache_miss(self, cache_type: str = 'redis', key_pattern: Optional[str] = None):
        """
        Record cache miss with automatic metrics collection.
        
        Args:
            cache_type: Cache type (redis, memory, session)
            key_pattern: Cache key pattern for categorization
        """
        if self.metrics:
            self.metrics.record_cache_miss(cache_type, key_pattern)
    
    def update_redis_metrics(self, redis_client: redis.Redis, pool_name: str = 'default'):
        """
        Update Redis connection and memory metrics.
        
        Args:
            redis_client: Redis client instance
            pool_name: Connection pool identifier
        """
        if self.metrics:
            self.metrics.update_redis_connection_metrics(redis_client, pool_name)
            self.metrics.update_redis_memory_metrics(redis_client)
    
    def check_cache_health(self) -> Tuple[bool, Dict[str, Any]]:
        """
        Perform comprehensive cache health check.
        
        Returns:
            Tuple of (is_healthy, health_details)
        """
        if not self.health_monitor:
            return False, {
                'error': 'Health monitor not initialized',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        
        return self.health_monitor.check_redis_health()
    
    def get_monitoring_summary(self) -> Dict[str, Any]:
        """Get comprehensive monitoring summary for dashboard integration."""
        summary = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'monitoring_enabled': self._initialized,
            'metrics': {},
            'health': {},
            'errors': []
        }
        
        try:
            if self.metrics:
                summary['metrics'] = self.metrics.get_metrics_summary()
            
            if self.health_monitor:
                summary['health'] = self.health_monitor.get_health_summary()
        
        except Exception as e:
            summary['errors'].append(f'Failed to generate summary: {str(e)}')
            self.logger.error(
                "Failed to generate monitoring summary",
                error=str(e),
                traceback=traceback.format_exc()
            )
        
        return summary
    
    def is_cache_healthy(self) -> bool:
        """Quick cache health check for circuit breaker integration."""
        if not self.health_monitor:
            return False
        
        return not self.health_monitor.is_circuit_breaker_open()


# Cache monitoring decorators for automatic metrics collection
def monitor_cache_operation(operation: str, cache_type: str = 'redis', 
                          key_pattern: Optional[str] = None):
    """
    Decorator for automatic cache operation monitoring with performance tracking.
    
    Args:
        operation: Cache operation type (get, set, delete, exists)
        cache_type: Cache type (redis, memory, session)
        key_pattern: Cache key pattern for categorization
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            cache_monitoring = None
            
            # Get cache monitoring from Flask app config
            if hasattr(g, 'cache_monitoring'):
                cache_monitoring = g.cache_monitoring
            elif current_app:
                cache_monitoring = current_app.config.get('CACHE_MONITORING')
            
            if cache_monitoring:
                with cache_monitoring.monitor_cache_operation(operation, cache_type, key_pattern):
                    return func(*args, **kwargs)
            else:
                return func(*args, **kwargs)
        
        return wrapper
    return decorator


def track_cache_hit_miss(cache_type: str = 'redis', key_pattern: Optional[str] = None):
    """
    Decorator for automatic cache hit/miss tracking.
    
    Args:
        cache_type: Cache type (redis, memory, session)
        key_pattern: Cache key pattern for categorization
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            cache_monitoring = None
            
            # Get cache monitoring from Flask app config
            if hasattr(g, 'cache_monitoring'):
                cache_monitoring = g.cache_monitoring
            elif current_app:
                cache_monitoring = current_app.config.get('CACHE_MONITORING')
            
            result = func(*args, **kwargs)
            
            if cache_monitoring:
                # Determine hit or miss based on result
                if result is not None:
                    cache_monitoring.record_cache_hit(cache_type, key_pattern)
                else:
                    cache_monitoring.record_cache_miss(cache_type, key_pattern)
            
            return result
        
        return wrapper
    return decorator


def init_cache_monitoring(app: Flask, redis_client: Optional[redis.Redis] = None) -> CacheMonitoringManager:
    """
    Initialize comprehensive cache monitoring for Flask application.
    
    Args:
        app: Flask application instance
        redis_client: Optional Redis client for health monitoring
        
    Returns:
        CacheMonitoringManager instance
    """
    # Initialize cache monitoring manager
    cache_monitoring = CacheMonitoringManager(app)
    
    # Initialize Redis monitoring if client provided
    if redis_client:
        cache_monitoring.init_redis_monitoring(redis_client)
    
    # Set up periodic health checks (would typically use a background task)
    @app.before_request
    def before_request():
        """Set cache monitoring in request context."""
        g.cache_monitoring = cache_monitoring
    
    # Add cache health to application health checks
    if hasattr(app, 'health_manager'):
        health_manager = app.health_manager
        
        def cache_health_check() -> bool:
            """Cache health check for application health manager."""
            is_healthy, _ = cache_monitoring.check_cache_health()
            return is_healthy
        
        health_manager.register_dependency('cache', cache_health_check, timeout=10)
    
    # Log cache monitoring initialization
    cache_monitoring.logger.info(
        "Cache monitoring integration completed",
        redis_monitoring=redis_client is not None,
        health_checks_enabled=hasattr(app, 'health_manager'),
        timestamp=datetime.now(timezone.utc).isoformat()
    )
    
    return cache_monitoring


# Export cache monitoring components for application integration
__all__ = [
    'CachePerformanceMetrics',
    'CacheHealthMonitor', 
    'CacheMonitoringManager',
    'monitor_cache_operation',
    'track_cache_hit_miss',
    'init_cache_monitoring'
]