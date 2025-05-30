"""
Cache Performance Monitoring Module

This module provides comprehensive cache performance monitoring with Prometheus metrics
collection, Redis connection health monitoring, and cache operation latency measurement.
Implements enterprise-grade observability for cache performance optimization and
monitoring integration per Section 6.1.1 and Section 3.4.5.

Key Features:
- Cache hit/miss ratio tracking and effectiveness measurement
- Redis connection health monitoring with circuit breaker integration
- Cache operation latency measurement and performance variance tracking
- Redis memory usage tracking and alerting
- Enterprise monitoring integration with Prometheus and APM systems
- Health check endpoints for Kubernetes and load balancer integration

Performance Requirements:
- Ensure ≤10% variance from Node.js baseline per Section 0.1.1
- Support horizontal scaling across multiple Flask instances
- Provide real-time metrics for capacity planning and optimization
"""

import logging
import time
from typing import Dict, Optional, Any, Callable
from functools import wraps
from contextlib import contextmanager
import redis
import structlog
from prometheus_client import (
    Counter, Gauge, Histogram, Summary, CollectorRegistry, 
    CONTENT_TYPE_LATEST, generate_latest
)
from flask import current_app, request, Response


# Configure structured logging for enterprise integration
logger = structlog.get_logger(__name__)

# Prometheus metrics collection for cache performance monitoring
# Global registry for cache metrics collection
cache_metrics_registry = CollectorRegistry()

# Cache operation counters for hit/miss ratio tracking
cache_operations_total = Counter(
    'cache_operations_total',
    'Total number of cache operations by type and result',
    ['operation', 'result', 'cache_type'],
    registry=cache_metrics_registry
)

cache_hits_total = Counter(
    'cache_hits_total',
    'Total number of cache hits by cache type',
    ['cache_type', 'key_pattern'],
    registry=cache_metrics_registry
)

cache_misses_total = Counter(
    'cache_misses_total',
    'Total number of cache misses by cache type',
    ['cache_type', 'key_pattern'],
    registry=cache_metrics_registry
)

# Cache effectiveness measurement
cache_hit_ratio = Gauge(
    'cache_hit_ratio',
    'Current cache hit ratio percentage by cache type',
    ['cache_type'],
    registry=cache_metrics_registry
)

# Cache operation latency measurement
cache_operation_duration = Histogram(
    'cache_operation_duration_seconds',
    'Duration of cache operations in seconds',
    ['operation', 'cache_type'],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
    registry=cache_metrics_registry
)

cache_operation_latency = Summary(
    'cache_operation_latency_seconds',
    'Cache operation latency summary statistics',
    ['operation', 'cache_type'],
    registry=cache_metrics_registry
)

# Redis connection health monitoring
redis_connections_active = Gauge(
    'redis_connections_active',
    'Number of active Redis connections',
    ['pool_name'],
    registry=cache_metrics_registry
)

redis_connections_created_total = Counter(
    'redis_connections_created_total',
    'Total number of Redis connections created',
    ['pool_name'],
    registry=cache_metrics_registry
)

redis_connection_errors_total = Counter(
    'redis_connection_errors_total',
    'Total number of Redis connection errors',
    ['pool_name', 'error_type'],
    registry=cache_metrics_registry
)

# Redis memory usage tracking
redis_memory_usage_bytes = Gauge(
    'redis_memory_usage_bytes',
    'Redis memory usage in bytes',
    ['instance', 'memory_type'],
    registry=cache_metrics_registry
)

redis_memory_fragmentation_ratio = Gauge(
    'redis_memory_fragmentation_ratio',
    'Redis memory fragmentation ratio',
    ['instance'],
    registry=cache_metrics_registry
)

# Cache performance variance tracking for Node.js baseline comparison
cache_performance_variance = Gauge(
    'cache_performance_variance_percentage',
    'Cache performance variance from Node.js baseline',
    ['metric_type'],
    registry=cache_metrics_registry
)

# Enterprise monitoring integration metrics
cache_circuit_breaker_state = Gauge(
    'cache_circuit_breaker_state',
    'Circuit breaker state for cache operations (0=closed, 1=open, 2=half-open)',
    ['service_name'],
    registry=cache_metrics_registry
)


class CacheMonitor:
    """
    Comprehensive cache monitoring class providing performance metrics,
    health monitoring, and enterprise integration capabilities.
    
    Implements cache performance monitoring per Section 6.1.1 with
    prometheus-client 0.17+ integration and Section 3.4.5 cache
    performance management requirements.
    """
    
    def __init__(self, redis_client: Optional[redis.Redis] = None):
        """
        Initialize cache monitor with Redis client and metrics collection.
        
        Args:
            redis_client: Redis client instance for health monitoring
        """
        self.redis_client = redis_client
        self.logger = structlog.get_logger(__name__)
        
        # Cache statistics tracking for hit rate calculation
        self._cache_stats: Dict[str, Dict[str, int]] = {}
        
        # Performance baseline tracking for variance calculation
        self._baseline_metrics: Dict[str, float] = {
            'average_latency_ms': 0.0,
            'hit_ratio_percentage': 0.0,
            'throughput_ops_per_second': 0.0
        }
        
        # Circuit breaker state tracking
        self._circuit_breaker_states: Dict[str, str] = {}
        
        self.logger.info(
            "cache_monitor_initialized",
            has_redis_client=redis_client is not None,
            baseline_metrics=self._baseline_metrics
        )
    
    def configure_redis_client(self, redis_client: redis.Redis) -> None:
        """
        Configure Redis client for health monitoring.
        
        Args:
            redis_client: Redis client instance
        """
        self.redis_client = redis_client
        self.logger.info("redis_client_configured_for_monitoring")
    
    @contextmanager
    def measure_cache_operation(self, operation: str, cache_type: str = 'redis'):
        """
        Context manager for measuring cache operation latency and tracking performance.
        
        Args:
            operation: Type of cache operation (get, set, delete, etc.)
            cache_type: Type of cache (redis, memory, etc.)
            
        Usage:
            with cache_monitor.measure_cache_operation('get', 'redis'):
                result = redis_client.get(key)
        """
        start_time = time.time()
        operation_success = True
        error_type = None
        
        try:
            yield
        except Exception as e:
            operation_success = False
            error_type = type(e).__name__
            self.logger.error(
                "cache_operation_error",
                operation=operation,
                cache_type=cache_type,
                error_type=error_type,
                error_message=str(e)
            )
            raise
        finally:
            duration = time.time() - start_time
            
            # Record operation metrics
            cache_operation_duration.labels(
                operation=operation,
                cache_type=cache_type
            ).observe(duration)
            
            cache_operation_latency.labels(
                operation=operation,
                cache_type=cache_type
            ).observe(duration)
            
            # Track operation result
            result = 'success' if operation_success else 'error'
            cache_operations_total.labels(
                operation=operation,
                result=result,
                cache_type=cache_type
            ).inc()
            
            # Log performance metrics
            self.logger.info(
                "cache_operation_completed",
                operation=operation,
                cache_type=cache_type,
                duration_ms=duration * 1000,
                success=operation_success,
                error_type=error_type
            )
            
            # Update performance variance tracking
            self._update_performance_variance('latency', duration * 1000)
    
    def record_cache_hit(self, cache_type: str = 'redis', key_pattern: str = 'default') -> None:
        """
        Record a cache hit for hit rate tracking and effectiveness measurement.
        
        Args:
            cache_type: Type of cache that had the hit
            key_pattern: Pattern or category of the cache key
        """
        cache_hits_total.labels(
            cache_type=cache_type,
            key_pattern=key_pattern
        ).inc()
        
        self._update_cache_stats(cache_type, 'hits', 1)
        self._update_hit_ratio(cache_type)
        
        self.logger.debug(
            "cache_hit_recorded",
            cache_type=cache_type,
            key_pattern=key_pattern
        )
    
    def record_cache_miss(self, cache_type: str = 'redis', key_pattern: str = 'default') -> None:
        """
        Record a cache miss for hit rate tracking and effectiveness measurement.
        
        Args:
            cache_type: Type of cache that had the miss
            key_pattern: Pattern or category of the cache key
        """
        cache_misses_total.labels(
            cache_type=cache_type,
            key_pattern=key_pattern
        ).inc()
        
        self._update_cache_stats(cache_type, 'misses', 1)
        self._update_hit_ratio(cache_type)
        
        self.logger.debug(
            "cache_miss_recorded",
            cache_type=cache_type,
            key_pattern=key_pattern
        )
    
    def monitor_redis_health(self) -> Dict[str, Any]:
        """
        Monitor Redis connection health and collect memory usage metrics.
        
        Returns:
            Dictionary containing Redis health status and metrics
        """
        if not self.redis_client:
            self.logger.warning("redis_client_not_configured_for_health_monitoring")
            return {'status': 'unknown', 'reason': 'client_not_configured'}
        
        health_status = {
            'status': 'healthy',
            'connection_active': False,
            'memory_info': {},
            'connection_pool_info': {},
            'latency_ms': None
        }
        
        try:
            # Test Redis connectivity with latency measurement
            start_time = time.time()
            ping_result = self.redis_client.ping()
            latency = (time.time() - start_time) * 1000
            
            health_status['connection_active'] = ping_result
            health_status['latency_ms'] = latency
            
            if ping_result:
                # Collect Redis memory information
                memory_info = self.redis_client.info('memory')
                health_status['memory_info'] = memory_info
                
                # Update Prometheus metrics for memory usage
                self._update_redis_memory_metrics(memory_info)
                
                # Collect connection pool information
                if hasattr(self.redis_client, 'connection_pool'):
                    pool = self.redis_client.connection_pool
                    pool_info = {
                        'created_connections': getattr(pool, 'created_connections', 0),
                        'available_connections': len(getattr(pool, '_available_connections', [])),
                        'in_use_connections': len(getattr(pool, '_in_use_connections', {}))
                    }
                    health_status['connection_pool_info'] = pool_info
                    
                    # Update connection pool metrics
                    redis_connections_active.labels(
                        pool_name='default'
                    ).set(pool_info['in_use_connections'])
                
                self.logger.info(
                    "redis_health_check_successful",
                    latency_ms=latency,
                    memory_used_mb=memory_info.get('used_memory', 0) / (1024 * 1024),
                    memory_peak_mb=memory_info.get('used_memory_peak', 0) / (1024 * 1024)
                )
            else:
                health_status['status'] = 'unhealthy'
                health_status['reason'] = 'ping_failed'
                
        except redis.ConnectionError as e:
            health_status['status'] = 'unhealthy'
            health_status['reason'] = 'connection_error'
            health_status['error'] = str(e)
            
            redis_connection_errors_total.labels(
                pool_name='default',
                error_type='connection_error'
            ).inc()
            
            self.logger.error(
                "redis_connection_error",
                error_message=str(e),
                error_type='ConnectionError'
            )
            
        except redis.TimeoutError as e:
            health_status['status'] = 'degraded'
            health_status['reason'] = 'timeout'
            health_status['error'] = str(e)
            
            redis_connection_errors_total.labels(
                pool_name='default',
                error_type='timeout'
            ).inc()
            
            self.logger.warning(
                "redis_timeout_error",
                error_message=str(e),
                error_type='TimeoutError'
            )
            
        except Exception as e:
            health_status['status'] = 'unhealthy'
            health_status['reason'] = 'unexpected_error'
            health_status['error'] = str(e)
            
            redis_connection_errors_total.labels(
                pool_name='default',
                error_type='unexpected'
            ).inc()
            
            self.logger.error(
                "redis_unexpected_error",
                error_message=str(e),
                error_type=type(e).__name__
            )
        
        return health_status
    
    def update_circuit_breaker_state(self, service_name: str, state: str) -> None:
        """
        Update circuit breaker state for cache services.
        
        Args:
            service_name: Name of the cache service
            state: Circuit breaker state ('closed', 'open', 'half-open')
        """
        self._circuit_breaker_states[service_name] = state
        
        # Map state to numeric value for Prometheus
        state_mapping = {'closed': 0, 'open': 1, 'half-open': 2}
        numeric_state = state_mapping.get(state, -1)
        
        cache_circuit_breaker_state.labels(
            service_name=service_name
        ).set(numeric_state)
        
        self.logger.info(
            "circuit_breaker_state_updated",
            service_name=service_name,
            state=state,
            numeric_state=numeric_state
        )
    
    def get_cache_metrics_summary(self) -> Dict[str, Any]:
        """
        Get comprehensive cache metrics summary for enterprise monitoring.
        
        Returns:
            Dictionary containing cache performance metrics and health status
        """
        summary = {
            'cache_statistics': self._cache_stats.copy(),
            'circuit_breaker_states': self._circuit_breaker_states.copy(),
            'performance_baselines': self._baseline_metrics.copy(),
            'redis_health': self.monitor_redis_health() if self.redis_client else None
        }
        
        # Calculate overall cache effectiveness
        total_hits = sum(
            stats.get('hits', 0) for stats in self._cache_stats.values()
        )
        total_misses = sum(
            stats.get('misses', 0) for stats in self._cache_stats.values()
        )
        total_operations = total_hits + total_misses
        
        if total_operations > 0:
            overall_hit_ratio = (total_hits / total_operations) * 100
            summary['overall_hit_ratio_percentage'] = overall_hit_ratio
        else:
            summary['overall_hit_ratio_percentage'] = 0.0
        
        return summary
    
    def _update_cache_stats(self, cache_type: str, stat_type: str, value: int) -> None:
        """Update internal cache statistics for hit rate calculation."""
        if cache_type not in self._cache_stats:
            self._cache_stats[cache_type] = {'hits': 0, 'misses': 0}
        
        self._cache_stats[cache_type][stat_type] += value
    
    def _update_hit_ratio(self, cache_type: str) -> None:
        """Update cache hit ratio metrics for effectiveness measurement."""
        stats = self._cache_stats.get(cache_type, {'hits': 0, 'misses': 0})
        total_operations = stats['hits'] + stats['misses']
        
        if total_operations > 0:
            hit_ratio_percentage = (stats['hits'] / total_operations) * 100
            cache_hit_ratio.labels(cache_type=cache_type).set(hit_ratio_percentage)
            
            # Update performance variance for hit ratio
            self._update_performance_variance('hit_ratio', hit_ratio_percentage)
    
    def _update_redis_memory_metrics(self, memory_info: Dict[str, Any]) -> None:
        """Update Redis memory usage metrics."""
        # Core memory usage metrics
        redis_memory_usage_bytes.labels(
            instance='default',
            memory_type='used'
        ).set(memory_info.get('used_memory', 0))
        
        redis_memory_usage_bytes.labels(
            instance='default',
            memory_type='peak'
        ).set(memory_info.get('used_memory_peak', 0))
        
        redis_memory_usage_bytes.labels(
            instance='default',
            memory_type='rss'
        ).set(memory_info.get('used_memory_rss', 0))
        
        # Memory fragmentation ratio
        fragmentation_ratio = memory_info.get('mem_fragmentation_ratio', 1.0)
        redis_memory_fragmentation_ratio.labels(
            instance='default'
        ).set(fragmentation_ratio)
        
        # Log memory usage for alerting
        used_memory_mb = memory_info.get('used_memory', 0) / (1024 * 1024)
        if used_memory_mb > 512:  # Alert threshold for high memory usage
            self.logger.warning(
                "redis_high_memory_usage",
                used_memory_mb=used_memory_mb,
                fragmentation_ratio=fragmentation_ratio,
                threshold_mb=512
            )
    
    def _update_performance_variance(self, metric_type: str, current_value: float) -> None:
        """Update performance variance metrics against Node.js baseline."""
        baseline_value = self._baseline_metrics.get(f'average_{metric_type}_ms', 0.0)
        
        if baseline_value > 0:
            variance_percentage = ((current_value - baseline_value) / baseline_value) * 100
            cache_performance_variance.labels(
                metric_type=metric_type
            ).set(variance_percentage)
            
            # Alert if variance exceeds ±10% threshold
            if abs(variance_percentage) > 10.0:
                self.logger.warning(
                    "cache_performance_variance_exceeded",
                    metric_type=metric_type,
                    current_value=current_value,
                    baseline_value=baseline_value,
                    variance_percentage=variance_percentage,
                    threshold_percentage=10.0
                )


# Global cache monitor instance for Flask application integration
cache_monitor = CacheMonitor()


def monitor_cache_operation(operation: str, cache_type: str = 'redis'):
    """
    Decorator for monitoring cache operations with automatic metrics collection.
    
    Args:
        operation: Type of cache operation
        cache_type: Type of cache being monitored
        
    Usage:
        @monitor_cache_operation('get', 'redis')
        def get_cached_data(key):
            return redis_client.get(key)
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            with cache_monitor.measure_cache_operation(operation, cache_type):
                return func(*args, **kwargs)
        return wrapper
    return decorator


def create_cache_metrics_endpoint() -> Response:
    """
    Create Flask endpoint for exposing cache metrics to Prometheus.
    
    Returns:
        Flask Response with Prometheus metrics data
    """
    try:
        metrics_data = generate_latest(cache_metrics_registry)
        return Response(
            metrics_data,
            mimetype=CONTENT_TYPE_LATEST,
            headers={'Cache-Control': 'no-cache, no-store, must-revalidate'}
        )
    except Exception as e:
        logger.error(
            "cache_metrics_endpoint_error",
            error_message=str(e),
            error_type=type(e).__name__
        )
        return Response(
            "Error generating cache metrics",
            status=500,
            mimetype='text/plain'
        )


def create_cache_health_endpoint() -> Response:
    """
    Create Flask endpoint for cache health checks compatible with Kubernetes probes.
    
    Returns:
        Flask Response with cache health status
    """
    try:
        health_status = cache_monitor.monitor_redis_health()
        
        if health_status['status'] == 'healthy':
            return Response(
                '{"status": "healthy", "cache": "operational"}',
                status=200,
                mimetype='application/json'
            )
        elif health_status['status'] == 'degraded':
            return Response(
                '{"status": "degraded", "cache": "slow_response"}',
                status=200,  # Still available but degraded
                mimetype='application/json'
            )
        else:
            return Response(
                '{"status": "unhealthy", "cache": "unavailable"}',
                status=503,
                mimetype='application/json'
            )
            
    except Exception as e:
        logger.error(
            "cache_health_endpoint_error",
            error_message=str(e),
            error_type=type(e).__name__
        )
        return Response(
            '{"status": "error", "cache": "monitoring_failure"}',
            status=503,
            mimetype='application/json'
        )


def init_cache_monitoring(app, redis_client: Optional[redis.Redis] = None) -> None:
    """
    Initialize cache monitoring for Flask application factory pattern.
    
    Args:
        app: Flask application instance
        redis_client: Redis client for health monitoring
    """
    # Configure Redis client for monitoring
    if redis_client:
        cache_monitor.configure_redis_client(redis_client)
    
    # Register cache monitoring endpoints
    app.add_url_rule(
        '/metrics/cache',
        'cache_metrics',
        create_cache_metrics_endpoint,
        methods=['GET']
    )
    
    app.add_url_rule(
        '/health/cache',
        'cache_health',
        create_cache_health_endpoint,
        methods=['GET']
    )
    
    # Initialize performance baseline tracking
    with app.app_context():
        logger.info(
            "cache_monitoring_initialized",
            app_name=app.name,
            has_redis_client=redis_client is not None,
            endpoints_registered=['cache_metrics', 'cache_health']
        )


# Enterprise monitoring integration exports
__all__ = [
    'CacheMonitor',
    'cache_monitor',
    'monitor_cache_operation',
    'create_cache_metrics_endpoint',
    'create_cache_health_endpoint',
    'init_cache_monitoring',
    'cache_metrics_registry'
]