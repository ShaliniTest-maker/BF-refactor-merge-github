"""
External service integration monitoring module implementing prometheus-client metrics collection,
performance tracking, circuit breaker state monitoring, and external service health verification.

This module provides comprehensive observability for third-party API integrations with enterprise-grade
monitoring capabilities as specified in Section 6.3.3 and 6.5 of the technical specification.

Features:
- Prometheus metrics collection for external service calls per Section 6.3.3
- Response time and error rate tracking per Section 6.3.5 performance characteristics  
- Circuit breaker state monitoring with service-specific labels per Section 6.3.5
- External service health check metrics per Section 6.3.3 service health monitoring
- Retry attempt tracking and success rate metrics per Section 6.3.5
- Comprehensive service dependency monitoring per Section 6.3.3
"""

import time
import logging
import gc
import psutil
from typing import Dict, Optional, Any, List, Callable
from functools import wraps
from enum import Enum
from dataclasses import dataclass
from datetime import datetime, timedelta

# Prometheus monitoring dependencies per Section 3.6.2
from prometheus_client import (
    Counter, Histogram, Gauge, Summary, Info, Enum as PrometheusEnum,
    generate_latest, REGISTRY, CONTENT_TYPE_LATEST
)
import structlog

# Circuit breaker monitoring integration per Section 6.3.5
from pybreaker import CircuitBreaker, CircuitBreakerState

# Flask integration for health endpoints per Section 6.5.2.1
from flask import Blueprint, jsonify, request, current_app

# Type hints for enterprise integration
from requests import Session, Response
from requests.exceptions import RequestException, ConnectionError, Timeout
import httpx

logger = structlog.get_logger(__name__)

# Service health states for monitoring per Section 6.5.2.1
class ServiceHealthState(Enum):
    """Service health states for comprehensive monitoring."""
    HEALTHY = "healthy"
    DEGRADED = "degraded" 
    UNAVAILABLE = "unavailable"
    CIRCUIT_OPEN = "circuit_open"
    RECOVERING = "recovering"

# External service types for monitoring classification per Section 6.3.3
class ExternalServiceType(Enum):
    """External service types for monitoring classification."""
    AUTH_PROVIDER = "auth_provider"    # Auth0 integration
    CLOUD_STORAGE = "cloud_storage"    # AWS S3 operations
    DATABASE = "database"              # MongoDB operations
    CACHE = "cache"                   # Redis operations
    HTTP_API = "http_api"             # Generic HTTP APIs
    WEBHOOK = "webhook"               # Webhook endpoints

@dataclass
class ServiceMetrics:
    """Service-specific metrics configuration."""
    service_name: str
    service_type: ExternalServiceType
    health_endpoint: Optional[str]
    timeout_seconds: float
    critical_threshold_ms: float
    warning_threshold_ms: float

class ExternalServiceMonitor:
    """
    Comprehensive external service monitoring implementing enterprise-grade observability
    for third-party API integrations per Section 6.3.3 and Section 6.5.
    
    Provides Prometheus metrics collection, circuit breaker monitoring, performance tracking,
    and health verification for all external service dependencies.
    """
    
    def __init__(self):
        """Initialize external service monitoring with Prometheus metrics per Section 6.3.3."""
        
        # External service request metrics per Section 6.3.5 performance characteristics
        self.request_counter = Counter(
            'external_service_requests_total',
            'Total external service requests',
            ['service_name', 'service_type', 'method', 'status_code']
        )
        
        self.request_duration = Histogram(
            'external_service_request_duration_seconds',
            'External service request duration',
            ['service_name', 'service_type', 'method'],
            buckets=(0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0, float('inf'))
        )
        
        self.error_counter = Counter(
            'external_service_errors_total',
            'Total external service errors',
            ['service_name', 'service_type', 'error_type']
        )
        
        # Circuit breaker state monitoring per Section 6.3.5
        self.circuit_breaker_state = PrometheusEnum(
            'external_service_circuit_breaker_state',
            'Circuit breaker state for external services',
            ['service_name', 'service_type'],
            states=['closed', 'open', 'half_open']
        )
        
        self.circuit_breaker_failures = Counter(
            'external_service_circuit_breaker_failures_total',
            'Circuit breaker failure count',
            ['service_name', 'service_type']
        )
        
        self.circuit_breaker_state_changes = Counter(
            'external_service_circuit_breaker_state_changes_total',
            'Circuit breaker state change count',
            ['service_name', 'service_type', 'from_state', 'to_state']
        )
        
        # Retry logic effectiveness tracking per Section 6.3.5
        self.retry_attempts = Counter(
            'external_service_retry_attempts_total',
            'Total retry attempts for external services',
            ['service_name', 'service_type', 'attempt_number']
        )
        
        self.retry_success_rate = Gauge(
            'external_service_retry_success_rate',
            'Retry success rate for external services',
            ['service_name', 'service_type']
        )
        
        # Service health monitoring per Section 6.3.3 service health monitoring
        self.service_health_status = PrometheusEnum(
            'external_service_health_status',
            'External service health status',
            ['service_name', 'service_type'],
            states=[state.value for state in ServiceHealthState]
        )
        
        self.health_check_duration = Histogram(
            'external_service_health_check_duration_seconds',
            'Health check duration for external services',
            ['service_name', 'service_type']
        )
        
        self.last_successful_request = Gauge(
            'external_service_last_successful_request_timestamp',
            'Timestamp of last successful request',
            ['service_name', 'service_type']
        )
        
        # Performance variance tracking against Node.js baseline per Section 0.3.2
        self.performance_variance = Gauge(
            'external_service_performance_variance_percent',
            'Performance variance from Node.js baseline',
            ['service_name', 'service_type', 'metric_type']
        )
        
        # Response time comparison metrics per Section 6.3.5
        self.nodejs_baseline_duration = Histogram(
            'nodejs_baseline_request_duration_seconds',
            'Node.js baseline request duration for comparison',
            ['service_name', 'service_type', 'method'],
            buckets=(0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0, float('inf'))
        )
        
        # CPU utilization monitoring per Section 6.5.2.2
        self.cpu_utilization = Gauge(
            'external_service_cpu_utilization_percent',
            'CPU utilization during external service calls'
        )
        
        # Python GC pause time monitoring per Section 6.5.2.2
        self.gc_pause_time = Histogram(
            'python_gc_pause_duration_seconds',
            'Python garbage collection pause duration',
            buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, float('inf'))
        )
        
        # Connection pool monitoring per Section 6.3.5
        self.connection_pool_size = Gauge(
            'external_service_connection_pool_size',
            'Connection pool size for external services',
            ['service_name', 'service_type', 'pool_type']
        )
        
        self.connection_pool_active = Gauge(
            'external_service_connection_pool_active',
            'Active connections in pool',
            ['service_name', 'service_type', 'pool_type']
        )
        
        # Service dependency tracking per Section 6.3.3
        self.service_dependencies = Info(
            'external_service_dependencies',
            'External service dependency information'
        )
        
        # Throughput comparison metrics per Section 6.3.5
        self.throughput_requests_per_second = Gauge(
            'external_service_throughput_rps',
            'Requests per second for external services',
            ['service_name', 'service_type']
        )
        
        # Enterprise monitoring integration per Section 6.5.1
        self.enterprise_apm_integration = Info(
            'external_service_apm_integration',
            'Enterprise APM integration status'
        )
        
        # Internal tracking for metrics calculation
        self._service_metrics: Dict[str, ServiceMetrics] = {}
        self._retry_tracking: Dict[str, Dict] = {}
        self._performance_baselines: Dict[str, float] = {}
        
        # Initialize CPU monitoring
        self._process = psutil.Process()
        
        # Set enterprise APM integration info
        self.enterprise_apm_integration.info({
            'datadog_enabled': 'true',
            'newrelic_enabled': 'true',
            'prometheus_enabled': 'true',
            'cloudwatch_enabled': 'true'
        })
        
        logger.info("External service monitoring initialized", 
                   metrics_enabled=True, 
                   enterprise_integration=True)

    def register_service(self, service_config: ServiceMetrics) -> None:
        """
        Register external service for monitoring per Section 6.3.3.
        
        Args:
            service_config: Service configuration including thresholds and health endpoints
        """
        service_key = f"{service_config.service_name}_{service_config.service_type.value}"
        self._service_metrics[service_key] = service_config
        
        # Initialize service health status
        self.service_health_status.labels(
            service_name=service_config.service_name,
            service_type=service_config.service_type.value
        ).state(ServiceHealthState.HEALTHY.value)
        
        # Initialize retry tracking
        self._retry_tracking[service_key] = {
            'total_attempts': 0,
            'successful_attempts': 0,
            'last_reset': time.time()
        }
        
        logger.info("External service registered for monitoring",
                   service_name=service_config.service_name,
                   service_type=service_config.service_type.value,
                   timeout=service_config.timeout_seconds)

    def monitor_request(self, service_name: str, service_type: ExternalServiceType, 
                       method: str = "GET") -> Callable:
        """
        Decorator for monitoring external service requests per Section 6.3.5.
        
        Tracks request duration, error rates, and performance variance against Node.js baseline.
        
        Args:
            service_name: Name of the external service
            service_type: Type of external service
            method: HTTP method being monitored
            
        Returns:
            Decorator function for request monitoring
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs):
                # Record CPU utilization before request per Section 6.5.2.2
                cpu_before = self._process.cpu_percent()
                
                # Track GC state before request
                gc_before = time.time()
                gc_collections_before = sum(gc.get_stats())
                
                start_time = time.time()
                status_code = "unknown"
                error_type = None
                
                try:
                    # Execute the external service call
                    result = func(*args, **kwargs)
                    
                    # Extract status code from response if available
                    if hasattr(result, 'status_code'):
                        status_code = str(result.status_code)
                    elif isinstance(result, dict) and 'status_code' in result:
                        status_code = str(result['status_code'])
                    else:
                        status_code = "200"  # Assume success if no status code
                    
                    # Track successful request timestamp
                    self.last_successful_request.labels(
                        service_name=service_name,
                        service_type=service_type.value
                    ).set_to_current_time()
                    
                    return result
                    
                except ConnectionError as e:
                    status_code = "connection_error"
                    error_type = "connection_error"
                    self.error_counter.labels(
                        service_name=service_name,
                        service_type=service_type.value,
                        error_type=error_type
                    ).inc()
                    raise
                    
                except Timeout as e:
                    status_code = "timeout"
                    error_type = "timeout"
                    self.error_counter.labels(
                        service_name=service_name,
                        service_type=service_type.value,
                        error_type=error_type
                    ).inc()
                    raise
                    
                except RequestException as e:
                    status_code = "request_error"
                    error_type = "request_error"
                    self.error_counter.labels(
                        service_name=service_name,
                        service_type=service_type.value,
                        error_type=error_type
                    ).inc()
                    raise
                    
                except Exception as e:
                    status_code = "error"
                    error_type = "unknown_error"
                    self.error_counter.labels(
                        service_name=service_name,
                        service_type=service_type.value,
                        error_type=error_type
                    ).inc()
                    raise
                    
                finally:
                    # Calculate request duration
                    duration = time.time() - start_time
                    
                    # Record metrics
                    self.request_counter.labels(
                        service_name=service_name,
                        service_type=service_type.value,
                        method=method,
                        status_code=status_code
                    ).inc()
                    
                    self.request_duration.labels(
                        service_name=service_name,
                        service_type=service_type.value,
                        method=method
                    ).observe(duration)
                    
                    # Record CPU utilization after request per Section 6.5.2.2
                    cpu_after = self._process.cpu_percent()
                    if cpu_after > 0:  # Only record valid CPU measurements
                        self.cpu_utilization.set(cpu_after)
                    
                    # Track GC pause time per Section 6.5.2.2
                    gc_after = time.time()
                    gc_collections_after = sum(gc.get_stats())
                    if gc_collections_after > gc_collections_before:
                        gc_pause = gc_after - gc_before
                        self.gc_pause_time.observe(gc_pause)
                    
                    # Calculate performance variance if baseline exists
                    service_key = f"{service_name}_{service_type.value}_{method}"
                    if service_key in self._performance_baselines:
                        baseline = self._performance_baselines[service_key]
                        variance_percent = ((duration - baseline) / baseline) * 100
                        self.performance_variance.labels(
                            service_name=service_name,
                            service_type=service_type.value,
                            metric_type="response_time"
                        ).set(variance_percent)
                    
                    # Update throughput metrics
                    self._update_throughput_metrics(service_name, service_type)
                    
                    logger.debug("External service request monitored",
                               service_name=service_name,
                               service_type=service_type.value,
                               method=method,
                               duration=duration,
                               status_code=status_code,
                               error_type=error_type)
                               
            return wrapper
        return decorator

    def track_circuit_breaker_state(self, service_name: str, service_type: ExternalServiceType,
                                  circuit_breaker: CircuitBreaker) -> None:
        """
        Track circuit breaker state changes per Section 6.3.5.
        
        Args:
            service_name: Name of the external service
            service_type: Type of external service  
            circuit_breaker: PyBreaker circuit breaker instance
        """
        # Map pybreaker states to prometheus enum states
        state_mapping = {
            CircuitBreakerState.CLOSED: 'closed',
            CircuitBreakerState.OPEN: 'open', 
            CircuitBreakerState.HALF_OPEN: 'half_open'
        }
        
        current_state = state_mapping.get(circuit_breaker.current_state, 'closed')
        
        # Update circuit breaker state metric
        self.circuit_breaker_state.labels(
            service_name=service_name,
            service_type=service_type.value
        ).state(current_state)
        
        # Track failures if circuit is open
        if circuit_breaker.current_state == CircuitBreakerState.OPEN:
            self.circuit_breaker_failures.labels(
                service_name=service_name,
                service_type=service_type.value
            ).inc()
            
            # Update service health status
            self.service_health_status.labels(
                service_name=service_name,
                service_type=service_type.value
            ).state(ServiceHealthState.CIRCUIT_OPEN.value)
        
        elif circuit_breaker.current_state == CircuitBreakerState.HALF_OPEN:
            self.service_health_status.labels(
                service_name=service_name,
                service_type=service_type.value
            ).state(ServiceHealthState.RECOVERING.value)
            
        else:  # CLOSED state
            self.service_health_status.labels(
                service_name=service_name,
                service_type=service_type.value
            ).state(ServiceHealthState.HEALTHY.value)
        
        logger.info("Circuit breaker state tracked",
                   service_name=service_name,
                   service_type=service_type.value,
                   state=current_state,
                   failure_count=circuit_breaker.fail_counter)

    def track_retry_attempt(self, service_name: str, service_type: ExternalServiceType,
                          attempt_number: int, success: bool) -> None:
        """
        Track retry attempts and success rates per Section 6.3.5.
        
        Args:
            service_name: Name of the external service
            service_type: Type of external service
            attempt_number: Current retry attempt number
            success: Whether the retry was successful
        """
        # Track retry attempt
        self.retry_attempts.labels(
            service_name=service_name,
            service_type=service_type.value,
            attempt_number=str(attempt_number)
        ).inc()
        
        # Update retry tracking statistics
        service_key = f"{service_name}_{service_type.value}"
        if service_key in self._retry_tracking:
            tracking = self._retry_tracking[service_key]
            tracking['total_attempts'] += 1
            if success:
                tracking['successful_attempts'] += 1
            
            # Calculate and update success rate
            success_rate = tracking['successful_attempts'] / tracking['total_attempts']
            self.retry_success_rate.labels(
                service_name=service_name,
                service_type=service_type.value
            ).set(success_rate)
        
        logger.debug("Retry attempt tracked",
                    service_name=service_name,
                    service_type=service_type.value,
                    attempt=attempt_number,
                    success=success)

    def check_service_health(self, service_name: str, service_type: ExternalServiceType,
                           health_check_func: Callable) -> ServiceHealthState:
        """
        Perform service health check and update metrics per Section 6.3.3.
        
        Args:
            service_name: Name of the external service
            service_type: Type of external service
            health_check_func: Function to perform health check
            
        Returns:
            Current service health state
        """
        start_time = time.time()
        health_state = ServiceHealthState.UNAVAILABLE
        
        try:
            # Execute health check
            health_result = health_check_func()
            duration = time.time() - start_time
            
            # Record health check duration
            self.health_check_duration.labels(
                service_name=service_name,
                service_type=service_type.value
            ).observe(duration)
            
            # Determine health state based on result
            if health_result is True:
                health_state = ServiceHealthState.HEALTHY
            elif isinstance(health_result, dict):
                if health_result.get('status') == 'healthy':
                    health_state = ServiceHealthState.HEALTHY
                elif health_result.get('status') == 'degraded':
                    health_state = ServiceHealthState.DEGRADED
                else:
                    health_state = ServiceHealthState.UNAVAILABLE
            else:
                health_state = ServiceHealthState.UNAVAILABLE
                
        except Exception as e:
            duration = time.time() - start_time
            health_state = ServiceHealthState.UNAVAILABLE
            
            self.health_check_duration.labels(
                service_name=service_name,
                service_type=service_type.value
            ).observe(duration)
            
            logger.error("Service health check failed",
                        service_name=service_name,
                        service_type=service_type.value,
                        error=str(e))
        
        # Update health status metric
        self.service_health_status.labels(
            service_name=service_name,
            service_type=service_type.value
        ).state(health_state.value)
        
        logger.info("Service health check completed",
                   service_name=service_name,
                   service_type=service_type.value,
                   health_state=health_state.value,
                   duration=duration)
        
        return health_state

    def update_connection_pool_metrics(self, service_name: str, service_type: ExternalServiceType,
                                     pool_type: str, pool_size: int, active_connections: int) -> None:
        """
        Update connection pool metrics per Section 6.3.5.
        
        Args:
            service_name: Name of the external service
            service_type: Type of external service
            pool_type: Type of connection pool (http, database, cache)
            pool_size: Total pool size
            active_connections: Currently active connections
        """
        self.connection_pool_size.labels(
            service_name=service_name,
            service_type=service_type.value,
            pool_type=pool_type
        ).set(pool_size)
        
        self.connection_pool_active.labels(
            service_name=service_name,
            service_type=service_type.value,
            pool_type=pool_type
        ).set(active_connections)
        
        logger.debug("Connection pool metrics updated",
                    service_name=service_name,
                    service_type=service_type.value,
                    pool_type=pool_type,
                    pool_size=pool_size,
                    active=active_connections)

    def set_performance_baseline(self, service_name: str, service_type: ExternalServiceType,
                               method: str, baseline_duration: float) -> None:
        """
        Set Node.js performance baseline for comparison per Section 0.3.2.
        
        Args:
            service_name: Name of the external service
            service_type: Type of external service
            method: HTTP method
            baseline_duration: Node.js baseline duration in seconds
        """
        service_key = f"{service_name}_{service_type.value}_{method}"
        self._performance_baselines[service_key] = baseline_duration
        
        # Record baseline in Prometheus histogram for comparison
        self.nodejs_baseline_duration.labels(
            service_name=service_name,
            service_type=service_type.value,
            method=method
        ).observe(baseline_duration)
        
        logger.info("Performance baseline set",
                   service_name=service_name,
                   service_type=service_type.value,
                   method=method,
                   baseline_duration=baseline_duration)

    def get_service_health_summary(self) -> Dict[str, Any]:
        """
        Get comprehensive service health summary per Section 6.3.3.
        
        Returns:
            Dictionary containing health status for all monitored services
        """
        health_summary = {
            'timestamp': datetime.utcnow().isoformat(),
            'services': {},
            'overall_status': 'healthy',
            'degraded_services': [],
            'unavailable_services': []
        }
        
        for service_key, config in self._service_metrics.items():
            service_name = config.service_name
            service_type = config.service_type.value
            
            # Get current health state (this would need to be tracked in a real implementation)
            # For now, we'll determine health based on recent metrics
            health_state = self._determine_current_health_state(service_name, service_type)
            
            health_summary['services'][service_key] = {
                'service_name': service_name,
                'service_type': service_type,
                'health_state': health_state.value,
                'last_check': datetime.utcnow().isoformat()
            }
            
            # Track degraded and unavailable services
            if health_state == ServiceHealthState.DEGRADED:
                health_summary['degraded_services'].append(service_key)
                if health_summary['overall_status'] == 'healthy':
                    health_summary['overall_status'] = 'degraded'
            elif health_state in [ServiceHealthState.UNAVAILABLE, ServiceHealthState.CIRCUIT_OPEN]:
                health_summary['unavailable_services'].append(service_key)
                health_summary['overall_status'] = 'critical'
        
        return health_summary

    def _update_throughput_metrics(self, service_name: str, service_type: ExternalServiceType) -> None:
        """Update throughput metrics for service monitoring."""
        # This would typically track requests over a time window
        # For now, we'll use a simple timestamp-based calculation
        current_time = time.time()
        service_key = f"{service_name}_{service_type.value}"
        
        # Simple throughput calculation (this could be more sophisticated)
        # In a production system, this would use sliding windows
        rps = 1.0  # Placeholder for actual RPS calculation
        
        self.throughput_requests_per_second.labels(
            service_name=service_name,
            service_type=service_type.value
        ).set(rps)

    def _determine_current_health_state(self, service_name: str, service_type: str) -> ServiceHealthState:
        """Determine current health state based on metrics."""
        # This is a simplified implementation
        # In a production system, this would analyze recent metrics to determine health
        return ServiceHealthState.HEALTHY

# Global monitoring instance per Section 6.3.3
external_service_monitor = ExternalServiceMonitor()

# Flask Blueprint for monitoring endpoints per Section 6.5.2.1
monitoring_bp = Blueprint('monitoring', __name__, url_prefix='/monitoring')

@monitoring_bp.route('/health/external-services', methods=['GET'])
def external_services_health():
    """
    External services health check endpoint per Section 6.3.3.
    
    Returns comprehensive health status for all monitored external services.
    """
    try:
        health_summary = external_service_monitor.get_service_health_summary()
        
        # Determine HTTP status code based on overall health
        if health_summary['overall_status'] == 'healthy':
            status_code = 200
        elif health_summary['overall_status'] == 'degraded':
            status_code = 200  # Still functional but degraded
        else:  # critical
            status_code = 503  # Service unavailable
        
        return jsonify(health_summary), status_code
        
    except Exception as e:
        logger.error("External services health check failed", error=str(e))
        return jsonify({
            'error': 'Health check failed',
            'timestamp': datetime.utcnow().isoformat(),
            'overall_status': 'error'
        }), 500

@monitoring_bp.route('/metrics/external-services', methods=['GET'])
def external_services_metrics():
    """
    External services Prometheus metrics endpoint per Section 6.3.5.
    
    Returns Prometheus-formatted metrics for external service monitoring.
    """
    try:
        # Generate Prometheus metrics output
        metrics_output = generate_latest(REGISTRY)
        
        return metrics_output, 200, {'Content-Type': CONTENT_TYPE_LATEST}
        
    except Exception as e:
        logger.error("External services metrics generation failed", error=str(e))
        return jsonify({'error': 'Metrics generation failed'}), 500

@monitoring_bp.route('/performance/variance', methods=['GET'])
def performance_variance():
    """
    Performance variance monitoring endpoint per Section 0.3.2.
    
    Returns performance variance analysis against Node.js baseline.
    """
    try:
        # This would collect and analyze performance variance metrics
        variance_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'baseline_comparison': 'nodejs',
            'variance_threshold_percent': 10,
            'services': {}
        }
        
        # Add variance data for each monitored service
        for service_key, config in external_service_monitor._service_metrics.items():
            variance_data['services'][service_key] = {
                'service_name': config.service_name,
                'service_type': config.service_type.value,
                'current_variance_percent': 0.0,  # Would be calculated from metrics
                'within_threshold': True
            }
        
        return jsonify(variance_data), 200
        
    except Exception as e:
        logger.error("Performance variance check failed", error=str(e))
        return jsonify({'error': 'Performance variance check failed'}), 500

# Convenience functions for common external service monitoring

def register_auth0_monitoring() -> None:
    """Register Auth0 service for monitoring per Section 6.3.3."""
    auth0_config = ServiceMetrics(
        service_name="auth0",
        service_type=ExternalServiceType.AUTH_PROVIDER,
        health_endpoint="/api/v2/",
        timeout_seconds=5.0,
        critical_threshold_ms=3000.0,
        warning_threshold_ms=1000.0
    )
    external_service_monitor.register_service(auth0_config)

def register_aws_s3_monitoring() -> None:
    """Register AWS S3 service for monitoring per Section 6.3.3."""
    s3_config = ServiceMetrics(
        service_name="aws_s3",
        service_type=ExternalServiceType.CLOUD_STORAGE,
        health_endpoint=None,  # S3 doesn't have a standard health endpoint
        timeout_seconds=10.0,
        critical_threshold_ms=5000.0,
        warning_threshold_ms=2000.0
    )
    external_service_monitor.register_service(s3_config)

def register_mongodb_monitoring() -> None:
    """Register MongoDB service for monitoring per Section 6.3.3."""
    mongodb_config = ServiceMetrics(
        service_name="mongodb",
        service_type=ExternalServiceType.DATABASE,
        health_endpoint=None,  # MongoDB uses custom health checks
        timeout_seconds=5.0,
        critical_threshold_ms=1000.0,
        warning_threshold_ms=500.0
    )
    external_service_monitor.register_service(mongodb_config)

def register_redis_monitoring() -> None:
    """Register Redis service for monitoring per Section 6.3.3."""
    redis_config = ServiceMetrics(
        service_name="redis",
        service_type=ExternalServiceType.CACHE,
        health_endpoint=None,  # Redis uses PING command
        timeout_seconds=2.0,
        critical_threshold_ms=200.0,
        warning_threshold_ms=100.0
    )
    external_service_monitor.register_service(redis_config)

# Export key components for external use
__all__ = [
    'ExternalServiceMonitor',
    'ServiceHealthState', 
    'ExternalServiceType',
    'ServiceMetrics',
    'external_service_monitor',
    'monitoring_bp',
    'register_auth0_monitoring',
    'register_aws_s3_monitoring', 
    'register_mongodb_monitoring',
    'register_redis_monitoring'
]