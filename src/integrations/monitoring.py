"""
External Service Integration Monitoring

This module implements comprehensive monitoring and observability for third-party API integrations
using prometheus-client metrics collection, performance tracking, circuit breaker state monitoring,
and external service health verification. Provides enterprise-grade monitoring capabilities to ensure
performance parity with the Node.js baseline implementation.

Key Features:
- Prometheus metrics collection for external service calls
- Response time and error rate tracking per Section 6.3.5
- Circuit breaker state monitoring with service-specific labels
- External service health check metrics per Section 6.3.3
- Retry attempt tracking and success rate metrics
- Comprehensive service dependency monitoring

Performance Requirements:
- Monitoring overhead <1ms per request per Section 6.5.1.1
- ≤10% variance from Node.js baseline per Section 0.3.2
- Real-time metrics collection per Section 6.5.1.1
- Enterprise APM integration compatibility
"""

import time
import logging
import threading
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Set, Callable
from functools import wraps
from contextlib import contextmanager
from enum import Enum
from collections import defaultdict, deque

# Prometheus client for enterprise monitoring integration
from prometheus_client import (
    Counter, Histogram, Gauge, Enum as PrometheusEnum,
    Info, Summary, generate_latest, CollectorRegistry,
    multiprocess, values
)

# Structured logging for enterprise integration
import structlog

# JSON logger for enterprise log aggregation
import json

logger = structlog.get_logger(__name__)


class ServiceType(Enum):
    """External service type classifications for monitoring segmentation."""
    AUTH = "auth"
    AWS = "aws"
    DATABASE = "database"
    CACHE = "cache"
    API = "api"
    WEBHOOK = "webhook"
    FILE_STORAGE = "file_storage"


class CircuitBreakerState(Enum):
    """Circuit breaker state enumeration for monitoring."""
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class HealthStatus(Enum):
    """Health status enumeration for service dependency monitoring."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class ExternalServiceMonitoring:
    """
    External service integration monitoring implementation with prometheus-client
    metrics collection, performance tracking, and enterprise observability.
    
    Implements comprehensive monitoring per Section 6.3.3 and 6.3.5 requirements:
    - Response time and error rate tracking
    - Circuit breaker state monitoring
    - External service health verification
    - Retry effectiveness metrics
    - Service dependency monitoring
    """
    
    def __init__(self, registry: Optional[CollectorRegistry] = None):
        """
        Initialize external service monitoring with prometheus metrics.
        
        Args:
            registry: Optional Prometheus registry for metrics collection
        """
        self.registry = registry or CollectorRegistry()
        self._service_health_cache: Dict[str, Dict[str, Any]] = {}
        self._health_cache_ttl: Dict[str, datetime] = {}
        self._lock = threading.RLock()
        
        # Initialize Prometheus metrics for external service monitoring
        self._initialize_metrics()
        
        # Service dependency tracking
        self._registered_services: Set[str] = set()
        self._service_metadata: Dict[str, Dict[str, Any]] = {}
        
        logger.info(
            "external_service_monitoring_initialized",
            component="integrations.monitoring",
            registry_type=type(self.registry).__name__
        )
    
    def _initialize_metrics(self):
        """Initialize comprehensive Prometheus metrics for external service monitoring."""
        
        # External service request metrics per Section 6.3.5
        self.external_service_requests_total = Counter(
            'external_service_requests_total',
            'Total number of external service requests',
            ['service_name', 'service_type', 'method', 'endpoint', 'status_code'],
            registry=self.registry
        )
        
        self.external_service_request_duration_seconds = Histogram(
            'external_service_request_duration_seconds',
            'External service request duration in seconds',
            ['service_name', 'service_type', 'method', 'endpoint'],
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
            registry=self.registry
        )
        
        # Error rate tracking per Section 6.3.5 performance characteristics
        self.external_service_errors_total = Counter(
            'external_service_errors_total',
            'Total number of external service errors',
            ['service_name', 'service_type', 'error_type', 'error_code'],
            registry=self.registry
        )
        
        self.external_service_error_rate = Gauge(
            'external_service_error_rate',
            'External service error rate percentage',
            ['service_name', 'service_type'],
            registry=self.registry
        )
        
        # Circuit breaker state monitoring per Section 6.3.5
        self.circuit_breaker_state = PrometheusEnum(
            'external_service_circuit_breaker_state',
            'Current circuit breaker state for external services',
            ['service_name', 'service_type'],
            states=[state.value for state in CircuitBreakerState],
            registry=self.registry
        )
        
        self.circuit_breaker_transitions_total = Counter(
            'external_service_circuit_breaker_transitions_total',
            'Total circuit breaker state transitions',
            ['service_name', 'service_type', 'from_state', 'to_state'],
            registry=self.registry
        )
        
        self.circuit_breaker_failures_total = Counter(
            'external_service_circuit_breaker_failures_total',
            'Total circuit breaker failures',
            ['service_name', 'service_type', 'failure_reason'],
            registry=self.registry
        )
        
        # Retry logic effectiveness tracking per Section 6.3.5
        self.retry_attempts_total = Counter(
            'external_service_retry_attempts_total',
            'Total retry attempts for external services',
            ['service_name', 'service_type', 'attempt_number'],
            registry=self.registry
        )
        
        self.retry_success_rate = Gauge(
            'external_service_retry_success_rate',
            'Retry success rate percentage',
            ['service_name', 'service_type'],
            registry=self.registry
        )
        
        self.retry_exhausted_total = Counter(
            'external_service_retry_exhausted_total',
            'Total retry attempts exhausted',
            ['service_name', 'service_type', 'final_error'],
            registry=self.registry
        )
        
        # Service health monitoring per Section 6.3.3
        self.service_health_status = PrometheusEnum(
            'external_service_health_status',
            'Current health status of external services',
            ['service_name', 'service_type'],
            states=[status.value for status in HealthStatus],
            registry=self.registry
        )
        
        self.service_health_check_duration_seconds = Histogram(
            'external_service_health_check_duration_seconds',
            'Health check duration in seconds',
            ['service_name', 'service_type'],
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
            registry=self.registry
        )
        
        self.service_health_checks_total = Counter(
            'external_service_health_checks_total',
            'Total health checks performed',
            ['service_name', 'service_type', 'status'],
            registry=self.registry
        )
        
        # Performance variance tracking for migration compliance per Section 0.3.2
        self.performance_variance_percentage = Gauge(
            'external_service_performance_variance_percentage',
            'Performance variance from Node.js baseline',
            ['service_name', 'service_type', 'metric_type'],
            registry=self.registry
        )
        
        # Connection pooling and resource utilization monitoring
        self.connection_pool_active = Gauge(
            'external_service_connection_pool_active',
            'Active connections in pool',
            ['service_name', 'service_type'],
            registry=self.registry
        )
        
        self.connection_pool_size = Gauge(
            'external_service_connection_pool_size',
            'Total connection pool size',
            ['service_name', 'service_type'],
            registry=self.registry
        )
        
        # Service dependency monitoring per Section 6.3.3
        self.service_dependency_health = Gauge(
            'external_service_dependency_health',
            'Service dependency health score (0-1)',
            ['service_name', 'dependency_name', 'dependency_type'],
            registry=self.registry
        )
        
        # Migration-specific metrics for continuous performance validation
        self.migration_performance_baseline = Info(
            'external_service_migration_performance_baseline',
            'Node.js baseline performance characteristics',
            ['service_name', 'service_type'],
            registry=self.registry
        )
        
        logger.info(
            "prometheus_metrics_initialized",
            component="integrations.monitoring",
            metrics_count=len([attr for attr in dir(self) if not attr.startswith('_')])
        )
    
    def register_service(
        self,
        service_name: str,
        service_type: ServiceType,
        endpoint_url: str,
        health_check_path: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Register an external service for monitoring.
        
        Args:
            service_name: Unique service identifier
            service_type: Service type classification
            endpoint_url: Service base URL
            health_check_path: Optional health check endpoint path
            metadata: Optional service metadata
        """
        with self._lock:
            self._registered_services.add(service_name)
            self._service_metadata[service_name] = {
                'service_type': service_type.value,
                'endpoint_url': endpoint_url,
                'health_check_path': health_check_path,
                'metadata': metadata or {},
                'registered_at': datetime.utcnow().isoformat()
            }
        
        # Initialize health status
        self.service_health_status.labels(
            service_name=service_name,
            service_type=service_type.value
        ).state(HealthStatus.UNKNOWN.value)
        
        logger.info(
            "external_service_registered",
            service_name=service_name,
            service_type=service_type.value,
            endpoint_url=endpoint_url,
            health_check_path=health_check_path
        )
    
    @contextmanager
    def track_request(
        self,
        service_name: str,
        service_type: ServiceType,
        method: str,
        endpoint: str
    ):
        """
        Context manager for tracking external service requests with comprehensive metrics.
        
        Args:
            service_name: Service identifier
            service_type: Service type classification
            method: HTTP method
            endpoint: Request endpoint
        
        Yields:
            Dictionary for tracking request context
        """
        start_time = time.time()
        request_context = {
            'service_name': service_name,
            'service_type': service_type.value,
            'method': method,
            'endpoint': endpoint,
            'start_time': start_time,
            'status_code': None,
            'error': None,
            'duration': None
        }
        
        try:
            yield request_context
            
        except Exception as e:
            request_context['error'] = str(e)
            request_context['status_code'] = getattr(e, 'status_code', 'unknown')
            
            # Track error metrics
            self.external_service_errors_total.labels(
                service_name=service_name,
                service_type=service_type.value,
                error_type=type(e).__name__,
                error_code=str(getattr(e, 'status_code', 'unknown'))
            ).inc()
            
            logger.error(
                "external_service_request_error",
                service_name=service_name,
                service_type=service_type.value,
                method=method,
                endpoint=endpoint,
                error=str(e),
                error_type=type(e).__name__
            )
            raise
            
        finally:
            end_time = time.time()
            duration = end_time - start_time
            request_context['duration'] = duration
            
            # Track request metrics
            status_code = request_context.get('status_code', 'success' if not request_context.get('error') else 'error')
            
            self.external_service_requests_total.labels(
                service_name=service_name,
                service_type=service_type.value,
                method=method,
                endpoint=endpoint,
                status_code=str(status_code)
            ).inc()
            
            self.external_service_request_duration_seconds.labels(
                service_name=service_name,
                service_type=service_type.value,
                method=method,
                endpoint=endpoint
            ).observe(duration)
            
            logger.info(
                "external_service_request_completed",
                service_name=service_name,
                service_type=service_type.value,
                method=method,
                endpoint=endpoint,
                duration_seconds=duration,
                status_code=str(status_code)
            )
    
    def record_circuit_breaker_state(
        self,
        service_name: str,
        service_type: ServiceType,
        state: CircuitBreakerState,
        previous_state: Optional[CircuitBreakerState] = None
    ) -> None:
        """
        Record circuit breaker state change with transition tracking.
        
        Args:
            service_name: Service identifier
            service_type: Service type classification
            state: Current circuit breaker state
            previous_state: Previous state for transition tracking
        """
        # Update current state
        self.circuit_breaker_state.labels(
            service_name=service_name,
            service_type=service_type.value
        ).state(state.value)
        
        # Track state transitions
        if previous_state and previous_state != state:
            self.circuit_breaker_transitions_total.labels(
                service_name=service_name,
                service_type=service_type.value,
                from_state=previous_state.value,
                to_state=state.value
            ).inc()
            
            logger.warning(
                "circuit_breaker_state_transition",
                service_name=service_name,
                service_type=service_type.value,
                from_state=previous_state.value,
                to_state=state.value
            )
    
    def record_circuit_breaker_failure(
        self,
        service_name: str,
        service_type: ServiceType,
        failure_reason: str
    ) -> None:
        """
        Record circuit breaker failure with detailed context.
        
        Args:
            service_name: Service identifier
            service_type: Service type classification
            failure_reason: Reason for circuit breaker failure
        """
        self.circuit_breaker_failures_total.labels(
            service_name=service_name,
            service_type=service_type.value,
            failure_reason=failure_reason
        ).inc()
        
        logger.error(
            "circuit_breaker_failure",
            service_name=service_name,
            service_type=service_type.value,
            failure_reason=failure_reason
        )
    
    def record_retry_attempt(
        self,
        service_name: str,
        service_type: ServiceType,
        attempt_number: int,
        success: bool = False
    ) -> None:
        """
        Record retry attempt with success tracking.
        
        Args:
            service_name: Service identifier
            service_type: Service type classification
            attempt_number: Current attempt number
            success: Whether the retry was successful
        """
        self.retry_attempts_total.labels(
            service_name=service_name,
            service_type=service_type.value,
            attempt_number=str(attempt_number)
        ).inc()
        
        logger.info(
            "retry_attempt_recorded",
            service_name=service_name,
            service_type=service_type.value,
            attempt_number=attempt_number,
            success=success
        )
    
    def record_retry_exhaustion(
        self,
        service_name: str,
        service_type: ServiceType,
        final_error: str
    ) -> None:
        """
        Record retry exhaustion with final error context.
        
        Args:
            service_name: Service identifier
            service_type: Service type classification
            final_error: Final error that caused retry exhaustion
        """
        self.retry_exhausted_total.labels(
            service_name=service_name,
            service_type=service_type.value,
            final_error=final_error
        ).inc()
        
        logger.error(
            "retry_attempts_exhausted",
            service_name=service_name,
            service_type=service_type.value,
            final_error=final_error
        )
    
    def update_retry_success_rate(
        self,
        service_name: str,
        service_type: ServiceType,
        success_rate: float
    ) -> None:
        """
        Update retry success rate percentage.
        
        Args:
            service_name: Service identifier
            service_type: Service type classification
            success_rate: Success rate as percentage (0-100)
        """
        self.retry_success_rate.labels(
            service_name=service_name,
            service_type=service_type.value
        ).set(success_rate)
    
    def update_error_rate(
        self,
        service_name: str,
        service_type: ServiceType,
        error_rate: float
    ) -> None:
        """
        Update service error rate percentage.
        
        Args:
            service_name: Service identifier
            service_type: Service type classification
            error_rate: Error rate as percentage (0-100)
        """
        self.external_service_error_rate.labels(
            service_name=service_name,
            service_type=service_type.value
        ).set(error_rate)
    
    def record_health_check(
        self,
        service_name: str,
        service_type: ServiceType,
        status: HealthStatus,
        duration: float,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Record service health check results with comprehensive metrics.
        
        Args:
            service_name: Service identifier
            service_type: Service type classification
            status: Health check status
            duration: Health check duration in seconds
            metadata: Optional health check metadata
        """
        # Update health status
        self.service_health_status.labels(
            service_name=service_name,
            service_type=service_type.value
        ).state(status.value)
        
        # Track health check duration
        self.service_health_check_duration_seconds.labels(
            service_name=service_name,
            service_type=service_type.value
        ).observe(duration)
        
        # Track health check counts
        self.service_health_checks_total.labels(
            service_name=service_name,
            service_type=service_type.value,
            status=status.value
        ).inc()
        
        # Cache health status with TTL
        with self._lock:
            self._service_health_cache[service_name] = {
                'status': status.value,
                'duration': duration,
                'metadata': metadata or {},
                'timestamp': datetime.utcnow().isoformat()
            }
            self._health_cache_ttl[service_name] = datetime.utcnow() + timedelta(minutes=5)
        
        logger.info(
            "health_check_recorded",
            service_name=service_name,
            service_type=service_type.value,
            status=status.value,
            duration_seconds=duration,
            metadata=metadata
        )
    
    def update_connection_pool_metrics(
        self,
        service_name: str,
        service_type: ServiceType,
        active_connections: int,
        pool_size: int
    ) -> None:
        """
        Update connection pool utilization metrics.
        
        Args:
            service_name: Service identifier
            service_type: Service type classification
            active_connections: Number of active connections
            pool_size: Total pool size
        """
        self.connection_pool_active.labels(
            service_name=service_name,
            service_type=service_type.value
        ).set(active_connections)
        
        self.connection_pool_size.labels(
            service_name=service_name,
            service_type=service_type.value
        ).set(pool_size)
    
    def record_performance_variance(
        self,
        service_name: str,
        service_type: ServiceType,
        metric_type: str,
        variance_percentage: float
    ) -> None:
        """
        Record performance variance from Node.js baseline for migration monitoring.
        
        Args:
            service_name: Service identifier
            service_type: Service type classification
            metric_type: Type of metric (response_time, throughput, etc.)
            variance_percentage: Variance percentage from baseline
        """
        self.performance_variance_percentage.labels(
            service_name=service_name,
            service_type=service_type.value,
            metric_type=metric_type
        ).set(variance_percentage)
        
        # Alert if variance exceeds ±10% threshold per Section 0.3.2
        if abs(variance_percentage) > 10.0:
            logger.warning(
                "performance_variance_threshold_exceeded",
                service_name=service_name,
                service_type=service_type.value,
                metric_type=metric_type,
                variance_percentage=variance_percentage,
                threshold_exceeded=True
            )
    
    def update_service_dependency_health(
        self,
        service_name: str,
        dependency_name: str,
        dependency_type: str,
        health_score: float
    ) -> None:
        """
        Update service dependency health score.
        
        Args:
            service_name: Service identifier
            dependency_name: Dependency service name
            dependency_type: Type of dependency
            health_score: Health score (0.0 to 1.0)
        """
        self.service_dependency_health.labels(
            service_name=service_name,
            dependency_name=dependency_name,
            dependency_type=dependency_type
        ).set(health_score)
    
    def set_migration_baseline(
        self,
        service_name: str,
        service_type: ServiceType,
        baseline_metrics: Dict[str, Any]
    ) -> None:
        """
        Set Node.js baseline performance metrics for comparison.
        
        Args:
            service_name: Service identifier
            service_type: Service type classification
            baseline_metrics: Baseline performance metrics
        """
        self.migration_performance_baseline.labels(
            service_name=service_name,
            service_type=service_type.value
        ).info(baseline_metrics)
        
        logger.info(
            "migration_baseline_established",
            service_name=service_name,
            service_type=service_type.value,
            baseline_metrics=baseline_metrics
        )
    
    def get_service_health_summary(self) -> Dict[str, Any]:
        """
        Get comprehensive service health summary for operations dashboard.
        
        Returns:
            Dictionary containing service health summary
        """
        with self._lock:
            # Clean expired cache entries
            current_time = datetime.utcnow()
            expired_services = [
                service for service, expiry in self._health_cache_ttl.items()
                if expiry < current_time
            ]
            
            for service in expired_services:
                self._service_health_cache.pop(service, None)
                self._health_cache_ttl.pop(service, None)
            
            summary = {
                'registered_services': list(self._registered_services),
                'health_cache': dict(self._service_health_cache),
                'service_metadata': dict(self._service_metadata),
                'cache_entries': len(self._service_health_cache),
                'last_updated': current_time.isoformat()
            }
        
        return summary
    
    def get_metrics_for_export(self) -> str:
        """
        Export Prometheus metrics in text format for scraping.
        
        Returns:
            Prometheus metrics in text format
        """
        return generate_latest(self.registry)
    
    def create_monitoring_decorator(
        self,
        service_name: str,
        service_type: ServiceType,
        endpoint: Optional[str] = None
    ) -> Callable:
        """
        Create a decorator for automatic external service monitoring.
        
        Args:
            service_name: Service identifier
            service_type: Service type classification
            endpoint: Optional endpoint override
        
        Returns:
            Decorator function for monitoring external service calls
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs):
                method = kwargs.get('method', 'GET')
                endpoint_path = endpoint or func.__name__
                
                with self.track_request(service_name, service_type, method, endpoint_path) as context:
                    try:
                        result = func(*args, **kwargs)
                        context['status_code'] = getattr(result, 'status_code', 200)
                        return result
                    except Exception as e:
                        context['error'] = str(e)
                        context['status_code'] = getattr(e, 'status_code', 'error')
                        raise
            
            return wrapper
        return decorator


# Global monitoring instance for external service integration
external_service_monitor = ExternalServiceMonitoring()


def track_external_service_call(
    service_name: str,
    service_type: ServiceType,
    endpoint: Optional[str] = None
) -> Callable:
    """
    Decorator for tracking external service calls with comprehensive monitoring.
    
    Args:
        service_name: Service identifier
        service_type: Service type classification
        endpoint: Optional endpoint override
    
    Returns:
        Decorator function
    """
    return external_service_monitor.create_monitoring_decorator(
        service_name, service_type, endpoint
    )


def record_circuit_breaker_event(
    service_name: str,
    service_type: ServiceType,
    event_type: str,
    **kwargs
) -> None:
    """
    Record circuit breaker events with context.
    
    Args:
        service_name: Service identifier
        service_type: Service type classification
        event_type: Type of circuit breaker event
        **kwargs: Additional event context
    """
    if event_type == "state_change":
        external_service_monitor.record_circuit_breaker_state(
            service_name, service_type, 
            kwargs.get('new_state'), kwargs.get('previous_state')
        )
    elif event_type == "failure":
        external_service_monitor.record_circuit_breaker_failure(
            service_name, service_type, kwargs.get('failure_reason', 'unknown')
        )


def update_service_health(
    service_name: str,
    service_type: ServiceType,
    status: HealthStatus,
    duration: float = 0.0,
    metadata: Optional[Dict[str, Any]] = None
) -> None:
    """
    Update external service health status.
    
    Args:
        service_name: Service identifier
        service_type: Service type classification
        status: Health status
        duration: Health check duration
        metadata: Optional metadata
    """
    external_service_monitor.record_health_check(
        service_name, service_type, status, duration, metadata
    )


def get_monitoring_summary() -> Dict[str, Any]:
    """
    Get comprehensive monitoring summary for operations dashboard.
    
    Returns:
        Dictionary containing monitoring summary
    """
    return external_service_monitor.get_service_health_summary()


def export_metrics() -> str:
    """
    Export Prometheus metrics for scraping endpoint.
    
    Returns:
        Prometheus metrics in text format
    """
    return external_service_monitor.get_metrics_for_export()


# Module-level logger configuration for enterprise integration
logger.info(
    "external_service_monitoring_module_loaded",
    component="integrations.monitoring",
    features=[
        "prometheus_metrics",
        "circuit_breaker_monitoring", 
        "health_check_tracking",
        "retry_effectiveness",
        "performance_variance",
        "service_dependency_monitoring"
    ]
)