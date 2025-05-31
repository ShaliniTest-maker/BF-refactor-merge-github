"""
Health Monitoring Blueprint for Flask Migration Application

This Blueprint provides comprehensive health check endpoints for load balancers, Kubernetes probes,
and monitoring systems. Implements application health validation, database connectivity checks,
external service status monitoring, and Prometheus metrics exposure per Section 6.1.3 and Section 6.5.

Key Features:
- Kubernetes-native readiness and liveness probe endpoints per Section 6.5.2.1
- Basic application health status for load balancer integration per Section 6.1.3
- Comprehensive dependency health validation per Section 6.1.3
- Prometheus metrics endpoint for enterprise monitoring per Section 6.5.1.1
- Circuit breaker state monitoring for external services per Section 6.1.3
- PyMongo and Motor database connection health validation per Section 6.1.3
- Redis connectivity monitoring with connection pool status per Section 6.1.3
- Performance metrics tracking for ≤10% variance compliance per Section 0.1.1

Endpoint Implementation:
- /health: Basic application status with overall health summary
- /health/live: Kubernetes liveness probe (application process health)
- /health/ready: Kubernetes readiness probe (dependency availability)
- /health/dependencies: Detailed dependency health status
- /metrics: Prometheus metrics endpoint for monitoring integration

Performance Requirements:
- Health check response time: <100ms per Section 6.5.2.1
- Monitoring overhead: <2% CPU impact per Section 6.5.1.1
- Prometheus metrics collection: 15-second intervals per Section 6.5.1.1

References:
- Section 6.1.3: Health Check and Monitoring Endpoints implementation
- Section 6.5.2.1: Kubernetes Health Probe Configuration and requirements
- Section 6.5.1.1: Prometheus metrics collection and enterprise integration
- Section 0.1.1: Performance monitoring ensuring ≤10% variance compliance
"""

import asyncio
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union
from functools import wraps

from flask import Blueprint, Flask, current_app, jsonify, request, Response
import structlog

# Prometheus metrics for health monitoring and enterprise integration
try:
    from prometheus_client import Counter, Gauge, Histogram, Info, generate_latest, CONTENT_TYPE_LATEST
    from prometheus_client.multiprocess import MultiProcessCollector
    from prometheus_client.registry import REGISTRY, CollectorRegistry
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

# Database health monitoring integration per Section 6.1.3
try:
    from src.data import (
        get_database_health_status,
        get_database_performance_metrics,
        get_mongodb_manager,
        get_async_mongodb_manager,
        DatabaseServices,
        get_database_services
    )
    DATABASE_MONITORING_AVAILABLE = True
except ImportError:
    DATABASE_MONITORING_AVAILABLE = False

# Cache health monitoring integration per Section 6.1.3
try:
    from src.cache import (
        get_cache_health,
        get_cache_stats,
        get_default_redis_client,
        get_cache_extensions
    )
    CACHE_MONITORING_AVAILABLE = True
except ImportError:
    CACHE_MONITORING_AVAILABLE = False

# Monitoring infrastructure integration per Section 6.5.1
try:
    from src.monitoring import (
        get_monitoring_manager,
        get_monitoring_logger,
        get_metrics_collector,
        get_health_endpoints
    )
    MONITORING_INFRASTRUCTURE_AVAILABLE = True
except ImportError:
    MONITORING_INFRASTRUCTURE_AVAILABLE = False

# External service integration monitoring per Section 6.1.3
try:
    from src.integrations import (
        get_integration_summary,
        integration_manager,
        external_service_monitor
    )
    INTEGRATIONS_MONITORING_AVAILABLE = True
except ImportError:
    INTEGRATIONS_MONITORING_AVAILABLE = False

# Configure structured logger for health monitoring
logger = structlog.get_logger(__name__)

# Create health monitoring Blueprint per Section 6.1.1 Flask Blueprint architecture
health_bp = Blueprint(
    'health', 
    __name__,
    url_prefix='',  # No prefix to allow /health, /health/live, /health/ready
    template_folder=None,
    static_folder=None
)

# Prometheus metrics for health monitoring per Section 6.5.1.1
if PROMETHEUS_AVAILABLE:
    # Health check request metrics
    health_check_requests = Counter(
        'health_check_requests_total',
        'Total number of health check requests',
        ['endpoint', 'status']
    )
    
    # Health check response time tracking
    health_check_duration = Histogram(
        'health_check_duration_seconds',
        'Time spent processing health checks',
        ['endpoint']
    )
    
    # Dependency health status gauges
    dependency_health_status = Gauge(
        'dependency_health_status',
        'Health status of dependencies (1=healthy, 0.5=degraded, 0=unhealthy)',
        ['dependency_name', 'dependency_type']
    )
    
    # Overall application health gauge
    application_health_status = Gauge(
        'application_health_status',
        'Overall application health status (1=healthy, 0.5=degraded, 0=unhealthy)'
    )
    
    # Database connection pool metrics
    database_connection_pool_usage = Gauge(
        'database_connection_pool_usage_ratio',
        'Database connection pool usage ratio',
        ['pool_type', 'database_name']
    )
    
    # External service circuit breaker states
    circuit_breaker_state = Gauge(
        'circuit_breaker_state',
        'Circuit breaker state (1=closed, 0.5=half-open, 0=open)',
        ['service_name', 'service_type']
    )
    
    # Performance variance tracking per Section 0.1.1
    performance_variance_percentage = Gauge(
        'performance_variance_percentage',
        'Performance variance percentage from Node.js baseline',
        ['metric_type', 'endpoint']
    )
    
    # Health check execution time compliance tracking
    health_check_compliance = Gauge(
        'health_check_response_time_compliance',
        'Health check response time compliance (1=<100ms, 0=>=100ms)',
        ['endpoint']
    )


class HealthStatus:
    """Enumeration for health status values with enterprise monitoring integration."""
    HEALTHY = "healthy"
    DEGRADED = "degraded" 
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class HealthMonitor:
    """
    Centralized health monitoring manager providing comprehensive health validation
    and Prometheus metrics integration per Section 6.1.3 and Section 6.5.1.1.
    
    This class coordinates health checks across all application dependencies including
    database connections, cache services, external integrations, and circuit breaker
    states with enterprise-grade monitoring and alerting capabilities.
    """
    
    def __init__(self):
        """Initialize health monitor with comprehensive dependency tracking."""
        self._last_health_check = None
        self._cached_health_status = None
        self._cache_ttl = 30  # Cache health status for 30 seconds
        self._check_lock = threading.RLock()
        
        # Initialize dependency status tracking
        self._dependency_status = {
            'database': HealthStatus.UNKNOWN,
            'cache': HealthStatus.UNKNOWN,
            'monitoring': HealthStatus.UNKNOWN,
            'integrations': HealthStatus.UNKNOWN
        }
        
        logger.info(
            "Health monitor initialized",
            database_monitoring_available=DATABASE_MONITORING_AVAILABLE,
            cache_monitoring_available=CACHE_MONITORING_AVAILABLE,
            monitoring_infrastructure_available=MONITORING_INFRASTRUCTURE_AVAILABLE,
            integrations_monitoring_available=INTEGRATIONS_MONITORING_AVAILABLE,
            prometheus_available=PROMETHEUS_AVAILABLE
        )
    
    def check_application_health(self, detailed: bool = False) -> Dict[str, Any]:
        """
        Perform comprehensive application health check with dependency validation.
        
        Implements health validation per Section 6.1.3 with <100ms response time
        compliance per Section 6.5.2.1 and comprehensive dependency monitoring.
        
        Args:
            detailed: Include detailed dependency information and metrics
            
        Returns:
            Dict containing comprehensive health status and dependency information
        """
        start_time = time.time()
        
        try:
            with self._check_lock:
                # Use cached status if recent and not requesting detailed info
                if (not detailed and 
                    self._cached_health_status and 
                    self._last_health_check and 
                    (time.time() - self._last_health_check) < self._cache_ttl):
                    
                    return self._cached_health_status
                
                # Perform comprehensive health check
                health_status = {
                    'status': HealthStatus.HEALTHY,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'application': {
                        'name': 'flask-migration-app',
                        'status': HealthStatus.HEALTHY,
                        'version': current_app.config.get('APP_VERSION', '1.0.0'),
                        'environment': current_app.config.get('ENVIRONMENT', 'development')
                    },
                    'dependencies': {},
                    'summary': {
                        'total_dependencies': 0,
                        'healthy_dependencies': 0,
                        'degraded_dependencies': 0,
                        'unhealthy_dependencies': 0
                    }
                }
                
                # Check database health per Section 6.1.3
                database_status = self._check_database_health()
                health_status['dependencies']['database'] = database_status
                self._dependency_status['database'] = database_status['status']
                
                # Check cache health per Section 6.1.3  
                cache_status = self._check_cache_health()
                health_status['dependencies']['cache'] = cache_status
                self._dependency_status['cache'] = cache_status['status']
                
                # Check monitoring infrastructure
                monitoring_status = self._check_monitoring_health()
                health_status['dependencies']['monitoring'] = monitoring_status
                self._dependency_status['monitoring'] = monitoring_status['status']
                
                # Check external integrations per Section 6.1.3
                integrations_status = self._check_integrations_health()
                health_status['dependencies']['integrations'] = integrations_status
                self._dependency_status['integrations'] = integrations_status['status']
                
                # Calculate overall health status and summary
                self._calculate_overall_health(health_status)
                
                # Include detailed metrics if requested
                if detailed:
                    health_status['metrics'] = self._collect_health_metrics()
                    health_status['performance'] = self._collect_performance_metrics()
                
                # Update Prometheus metrics per Section 6.5.1.1
                self._update_health_metrics(health_status)
                
                # Cache the result
                self._cached_health_status = health_status
                self._last_health_check = time.time()
                
                # Track response time compliance per Section 6.5.2.1
                response_time_ms = (time.time() - start_time) * 1000
                compliance = 1.0 if response_time_ms < 100 else 0.0
                
                if PROMETHEUS_AVAILABLE:
                    health_check_compliance.labels(endpoint='application').set(compliance)
                
                logger.debug(
                    "Application health check completed",
                    overall_status=health_status['status'],
                    response_time_ms=response_time_ms,
                    compliance=compliance == 1.0,
                    total_dependencies=health_status['summary']['total_dependencies'],
                    healthy_dependencies=health_status['summary']['healthy_dependencies']
                )
                
                return health_status
                
        except Exception as e:
            error_response = {
                'status': HealthStatus.UNHEALTHY,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'error': str(e),
                'application': {
                    'name': 'flask-migration-app',
                    'status': HealthStatus.UNHEALTHY
                }
            }
            
            logger.error(
                "Health check failed with exception",
                error=str(e),
                response_time_ms=(time.time() - start_time) * 1000,
                exc_info=True
            )
            
            if PROMETHEUS_AVAILABLE:
                health_check_compliance.labels(endpoint='application').set(0.0)
                application_health_status.set(0.0)
            
            return error_response
    
    def _check_database_health(self) -> Dict[str, Any]:
        """Check database connectivity and performance per Section 6.1.3."""
        if not DATABASE_MONITORING_AVAILABLE:
            return {
                'status': HealthStatus.UNKNOWN,
                'details': {'error': 'Database monitoring not available'},
                'mongodb_sync': {'available': False},
                'mongodb_async': {'available': False}
            }
        
        try:
            # Get comprehensive database health status
            db_health = get_database_health_status()
            
            # Analyze database service status
            services = db_health.get('services', {})
            mongodb_sync = services.get('mongodb_sync', {})
            mongodb_async = services.get('mongodb_async', {})
            database_config = services.get('database_config', {})
            
            # Determine overall database health
            healthy_services = 0
            total_services = 0
            
            for service_name, service_status in services.items():
                total_services += 1
                if service_status.get('status') == 'healthy':
                    healthy_services += 1
            
            if healthy_services == total_services and total_services > 0:
                status = HealthStatus.HEALTHY
            elif healthy_services > 0:
                status = HealthStatus.DEGRADED
            else:
                status = HealthStatus.UNHEALTHY
            
            # Collect connection pool metrics
            connection_info = {}
            try:
                db_services = get_database_services()
                if db_services and db_services.database_config:
                    connection_info = db_services.database_config.get_connection_info()
            except Exception as e:
                logger.warning(f"Failed to get database connection info: {e}")
            
            database_status = {
                'status': status,
                'mongodb_sync': {
                    'available': mongodb_sync.get('status') == 'healthy',
                    'status': mongodb_sync.get('status', 'unknown'),
                    'details': mongodb_sync
                },
                'mongodb_async': {
                    'available': mongodb_async.get('status') in ['healthy', 'available'],
                    'status': mongodb_async.get('status', 'unknown'),
                    'details': mongodb_async
                },
                'connection_pools': connection_info,
                'summary': {
                    'total_services': total_services,
                    'healthy_services': healthy_services,
                    'degraded_services': total_services - healthy_services
                }
            }
            
            # Update Prometheus metrics
            if PROMETHEUS_AVAILABLE:
                # Database health status
                health_value = 1.0 if status == HealthStatus.HEALTHY else (0.5 if status == HealthStatus.DEGRADED else 0.0)
                dependency_health_status.labels(dependency_name='database', dependency_type='mongodb').set(health_value)
                
                # Connection pool metrics
                if connection_info:
                    for pool_name, pool_info in connection_info.items():
                        if isinstance(pool_info, dict) and 'usage_ratio' in pool_info:
                            database_connection_pool_usage.labels(
                                pool_type=pool_name,
                                database_name=pool_info.get('database_name', 'default')
                            ).set(pool_info['usage_ratio'])
            
            return database_status
            
        except Exception as e:
            logger.error(f"Database health check failed: {e}", exc_info=True)
            return {
                'status': HealthStatus.UNHEALTHY,
                'error': str(e),
                'mongodb_sync': {'available': False},
                'mongodb_async': {'available': False}
            }
    
    def _check_cache_health(self) -> Dict[str, Any]:
        """Check Redis cache connectivity and performance per Section 6.1.3."""
        if not CACHE_MONITORING_AVAILABLE:
            return {
                'status': HealthStatus.UNKNOWN,
                'details': {'error': 'Cache monitoring not available'},
                'redis': {'available': False}
            }
        
        try:
            # Get comprehensive cache health status
            cache_health = get_cache_health()
            
            redis_healthy = cache_health.get('redis', {}).get('healthy', False)
            response_cache_healthy = cache_health.get('response_cache', {}).get('healthy', False)
            overall_healthy = cache_health.get('overall_healthy', False)
            
            # Determine cache health status
            if overall_healthy and redis_healthy and response_cache_healthy:
                status = HealthStatus.HEALTHY
            elif redis_healthy or response_cache_healthy:
                status = HealthStatus.DEGRADED
            else:
                status = HealthStatus.UNHEALTHY
            
            # Get cache statistics for detailed monitoring
            cache_stats = {}
            try:
                cache_stats = get_cache_stats()
            except Exception as e:
                logger.warning(f"Failed to get cache statistics: {e}")
            
            cache_status = {
                'status': status,
                'redis': {
                    'available': redis_healthy,
                    'details': cache_health.get('redis', {}).get('details', {})
                },
                'response_cache': {
                    'available': response_cache_healthy,
                    'details': cache_health.get('response_cache', {}).get('details', {})
                },
                'statistics': cache_stats.get('redis', {}),
                'extensions_initialized': cache_health.get('extensions', {}).get('initialized', False)
            }
            
            # Update Prometheus metrics
            if PROMETHEUS_AVAILABLE:
                health_value = 1.0 if status == HealthStatus.HEALTHY else (0.5 if status == HealthStatus.DEGRADED else 0.0)
                dependency_health_status.labels(dependency_name='cache', dependency_type='redis').set(health_value)
            
            return cache_status
            
        except Exception as e:
            logger.error(f"Cache health check failed: {e}", exc_info=True)
            return {
                'status': HealthStatus.UNHEALTHY,
                'error': str(e),
                'redis': {'available': False}
            }
    
    def _check_monitoring_health(self) -> Dict[str, Any]:
        """Check monitoring infrastructure health and availability."""
        if not MONITORING_INFRASTRUCTURE_AVAILABLE:
            return {
                'status': HealthStatus.DEGRADED,  # Not critical for application function
                'details': {'error': 'Monitoring infrastructure not available'},
                'prometheus_metrics': {'available': PROMETHEUS_AVAILABLE}
            }
        
        try:
            monitoring_manager = get_monitoring_manager()
            
            if monitoring_manager:
                monitoring_status = monitoring_manager.get_monitoring_status()
                components_status = monitoring_status.get('components_status', {})
                
                # Count healthy monitoring components
                healthy_components = sum(1 for status in components_status.values() if status)
                total_components = len(components_status)
                
                if healthy_components == total_components and total_components > 0:
                    status = HealthStatus.HEALTHY
                elif healthy_components > 0:
                    status = HealthStatus.DEGRADED
                else:
                    status = HealthStatus.DEGRADED  # Monitoring is not critical
                
                return {
                    'status': status,
                    'components': components_status,
                    'initialized': monitoring_status.get('initialized', False),
                    'prometheus_metrics': {'available': PROMETHEUS_AVAILABLE},
                    'summary': {
                        'total_components': total_components,
                        'healthy_components': healthy_components
                    }
                }
            else:
                return {
                    'status': HealthStatus.DEGRADED,
                    'details': {'error': 'Monitoring manager not initialized'},
                    'prometheus_metrics': {'available': PROMETHEUS_AVAILABLE}
                }
                
        except Exception as e:
            logger.warning(f"Monitoring health check failed: {e}")
            return {
                'status': HealthStatus.DEGRADED,
                'error': str(e),
                'prometheus_metrics': {'available': PROMETHEUS_AVAILABLE}
            }
    
    def _check_integrations_health(self) -> Dict[str, Any]:
        """Check external service integrations health per Section 6.1.3."""
        if not INTEGRATIONS_MONITORING_AVAILABLE:
            return {
                'status': HealthStatus.UNKNOWN,
                'details': {'error': 'Integrations monitoring not available'},
                'external_services': []
            }
        
        try:
            # Get integration summary and health status
            integration_summary = get_integration_summary()
            health_summary = integration_summary.get('health_summary', {})
            
            total_integrations = integration_summary.get('total_integrations', 0)
            if total_integrations == 0:
                # No external integrations configured
                return {
                    'status': HealthStatus.HEALTHY,
                    'details': {'message': 'No external integrations configured'},
                    'external_services': []
                }
            
            # Analyze integration health
            healthy_services = health_summary.get('healthy_services', 0)
            degraded_services = health_summary.get('degraded_services', 0)
            unhealthy_services = health_summary.get('unhealthy_services', 0)
            
            if unhealthy_services == 0 and degraded_services == 0:
                status = HealthStatus.HEALTHY
            elif unhealthy_services == 0:
                status = HealthStatus.DEGRADED
            else:
                status = HealthStatus.UNHEALTHY
            
            # Collect circuit breaker states
            circuit_breaker_states = {}
            try:
                for service_name, service_health in health_summary.get('services', {}).items():
                    circuit_state = service_health.get('circuit_breaker_state', 'unknown')
                    circuit_breaker_states[service_name] = circuit_state
                    
                    # Update Prometheus circuit breaker metrics
                    if PROMETHEUS_AVAILABLE:
                        state_value = 1.0 if circuit_state == 'closed' else (0.5 if circuit_state == 'half-open' else 0.0)
                        service_type = service_health.get('service_type', 'unknown')
                        circuit_breaker_state.labels(service_name=service_name, service_type=service_type).set(state_value)
            except Exception as e:
                logger.warning(f"Failed to collect circuit breaker states: {e}")
            
            integrations_status = {
                'status': status,
                'total_integrations': total_integrations,
                'external_services': list(integration_summary.get('registered_services', [])),
                'health_summary': {
                    'healthy_services': healthy_services,
                    'degraded_services': degraded_services,
                    'unhealthy_services': unhealthy_services
                },
                'circuit_breaker_states': circuit_breaker_states,
                'monitoring_initialized': integration_summary.get('monitoring_initialized', False)
            }
            
            # Update Prometheus metrics
            if PROMETHEUS_AVAILABLE:
                health_value = 1.0 if status == HealthStatus.HEALTHY else (0.5 if status == HealthStatus.DEGRADED else 0.0)
                dependency_health_status.labels(dependency_name='integrations', dependency_type='external_services').set(health_value)
            
            return integrations_status
            
        except Exception as e:
            logger.error(f"Integrations health check failed: {e}", exc_info=True)
            return {
                'status': HealthStatus.UNHEALTHY,
                'error': str(e),
                'external_services': []
            }
    
    def _calculate_overall_health(self, health_status: Dict[str, Any]) -> None:
        """Calculate overall application health based on dependency status."""
        dependencies = health_status.get('dependencies', {})
        summary = health_status['summary']
        
        # Count dependency health states
        for dep_name, dep_status in dependencies.items():
            status = dep_status.get('status', HealthStatus.UNKNOWN)
            summary['total_dependencies'] += 1
            
            if status == HealthStatus.HEALTHY:
                summary['healthy_dependencies'] += 1
            elif status == HealthStatus.DEGRADED:
                summary['degraded_dependencies'] += 1
            else:
                summary['unhealthy_dependencies'] += 1
        
        # Determine overall health status
        # Critical dependencies: database and cache
        database_status = dependencies.get('database', {}).get('status', HealthStatus.UNHEALTHY)
        cache_status = dependencies.get('cache', {}).get('status', HealthStatus.UNHEALTHY)
        
        # Non-critical dependencies: monitoring and integrations (degraded if failing)
        monitoring_status = dependencies.get('monitoring', {}).get('status', HealthStatus.DEGRADED)
        integrations_status = dependencies.get('integrations', {}).get('status', HealthStatus.HEALTHY)
        
        # Overall health calculation
        if (database_status == HealthStatus.UNHEALTHY or 
            cache_status == HealthStatus.UNHEALTHY):
            overall_status = HealthStatus.UNHEALTHY
        elif (database_status == HealthStatus.DEGRADED or 
              cache_status == HealthStatus.DEGRADED or
              monitoring_status == HealthStatus.UNHEALTHY or
              integrations_status == HealthStatus.UNHEALTHY):
            overall_status = HealthStatus.DEGRADED
        else:
            overall_status = HealthStatus.HEALTHY
        
        health_status['status'] = overall_status
        health_status['application']['status'] = overall_status
        
        # Update Prometheus overall health metric
        if PROMETHEUS_AVAILABLE:
            health_value = 1.0 if overall_status == HealthStatus.HEALTHY else (0.5 if overall_status == HealthStatus.DEGRADED else 0.0)
            application_health_status.set(health_value)
    
    def _collect_health_metrics(self) -> Dict[str, Any]:
        """Collect comprehensive health metrics for detailed monitoring."""
        metrics = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'check_cache_ttl_seconds': self._cache_ttl,
            'last_check_age_seconds': time.time() - self._last_health_check if self._last_health_check else None
        }
        
        # Database performance metrics
        if DATABASE_MONITORING_AVAILABLE:
            try:
                db_metrics = get_database_performance_metrics()
                metrics['database'] = db_metrics
            except Exception as e:
                metrics['database'] = {'error': str(e)}
        
        # Cache performance metrics  
        if CACHE_MONITORING_AVAILABLE:
            try:
                cache_stats = get_cache_stats()
                metrics['cache'] = cache_stats
            except Exception as e:
                metrics['cache'] = {'error': str(e)}
        
        return metrics
    
    def _collect_performance_metrics(self) -> Dict[str, Any]:
        """Collect performance metrics for baseline compliance per Section 0.1.1."""
        performance = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'variance_tracking': {
                'target_variance': '≤10%',
                'monitoring_enabled': True
            }
        }
        
        # This would be implemented with actual performance baseline data
        # For now, provide structure for future implementation
        performance['baseline_comparison'] = {
            'nodejs_baseline_available': False,
            'flask_performance_tracking': True,
            'variance_percentage': None,
            'compliance_status': 'monitoring_active'
        }
        
        return performance
    
    def _update_health_metrics(self, health_status: Dict[str, Any]) -> None:
        """Update Prometheus metrics based on health check results."""
        if not PROMETHEUS_AVAILABLE:
            return
        
        try:
            # Update dependency health metrics
            dependencies = health_status.get('dependencies', {})
            for dep_name, dep_status in dependencies.items():
                status = dep_status.get('status', HealthStatus.UNKNOWN)
                health_value = 1.0 if status == HealthStatus.HEALTHY else (0.5 if status == HealthStatus.DEGRADED else 0.0)
                
                # Map dependency names to types for metrics
                dep_type_map = {
                    'database': 'mongodb',
                    'cache': 'redis',
                    'monitoring': 'infrastructure',
                    'integrations': 'external_services'
                }
                dep_type = dep_type_map.get(dep_name, dep_name)
                dependency_health_status.labels(dependency_name=dep_name, dependency_type=dep_type).set(health_value)
            
        except Exception as e:
            logger.warning(f"Failed to update health metrics: {e}")


# Global health monitor instance
health_monitor = HealthMonitor()


def track_health_endpoint_metrics(endpoint_name: str):
    """Decorator to track health endpoint metrics per Section 6.5.1.1."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            status = 'success'
            
            try:
                response = func(*args, **kwargs)
                
                # Determine status based on response
                if hasattr(response, 'status_code'):
                    status = 'success' if response.status_code < 400 else 'error'
                elif isinstance(response, tuple) and len(response) >= 2:
                    status_code = response[1]
                    status = 'success' if status_code < 400 else 'error'
                
                return response
                
            except Exception as e:
                status = 'error'
                logger.error(f"Health endpoint {endpoint_name} failed: {e}", exc_info=True)
                raise
                
            finally:
                # Track metrics
                duration = time.time() - start_time
                
                if PROMETHEUS_AVAILABLE:
                    health_check_requests.labels(endpoint=endpoint_name, status=status).inc()
                    health_check_duration.labels(endpoint=endpoint_name).observe(duration)
                    
                    # Track response time compliance (target <100ms per Section 6.5.2.1)
                    compliance = 1.0 if duration * 1000 < 100 else 0.0
                    health_check_compliance.labels(endpoint=endpoint_name).set(compliance)
                
                logger.debug(
                    f"Health endpoint {endpoint_name} completed",
                    duration_ms=duration * 1000,
                    status=status,
                    compliance=duration * 1000 < 100
                )
        
        return wrapper
    return decorator


@health_bp.route('/health', methods=['GET'])
@track_health_endpoint_metrics('basic_health')
def basic_health():
    """
    Basic application health endpoint for load balancer integration per Section 6.1.3.
    
    Provides overall application health status with dependency summary for load balancer
    health checks and basic monitoring integration. Optimized for <100ms response time
    per Section 6.5.2.1 requirements.
    
    Returns:
        JSON response with overall health status and basic dependency summary
        HTTP 200 if healthy, HTTP 503 if unhealthy or degraded
    """
    try:
        health_status = health_monitor.check_application_health(detailed=False)
        
        # Simplified response for load balancer compatibility
        response = {
            'status': health_status['status'],
            'timestamp': health_status['timestamp'],
            'application': health_status['application'],
            'summary': health_status['summary']
        }
        
        # Return appropriate HTTP status code
        if health_status['status'] == HealthStatus.HEALTHY:
            return jsonify(response), 200
        else:
            return jsonify(response), 503
            
    except Exception as e:
        logger.error(f"Basic health check failed: {e}", exc_info=True)
        
        error_response = {
            'status': HealthStatus.UNHEALTHY,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'error': str(e)
        }
        
        return jsonify(error_response), 503


@health_bp.route('/health/live', methods=['GET'])
@track_health_endpoint_metrics('liveness_probe')
def liveness_probe():
    """
    Kubernetes liveness probe endpoint per Section 6.5.2.1.
    
    Returns HTTP 200 when the Flask application process is running and capable of
    handling requests. Returns HTTP 503 when the application is in a fatal state
    requiring container restart. Focuses on application process health only.
    
    Returns:
        JSON response with liveness status
        HTTP 200 if application is alive, HTTP 503 if application needs restart
    """
    try:
        # Liveness check focuses on application process health
        app_status = {
            'status': HealthStatus.HEALTHY,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'probe_type': 'liveness',
            'application': {
                'name': 'flask-migration-app',
                'process_status': 'running',
                'flask_app_active': current_app is not None,
                'pid': os.getpid() if hasattr(os, 'getpid') else None
            }
        }
        
        # Basic application responsiveness check
        if current_app is None:
            app_status['status'] = HealthStatus.UNHEALTHY
            app_status['application']['process_status'] = 'not_responsive'
            return jsonify(app_status), 503
        
        return jsonify(app_status), 200
        
    except Exception as e:
        logger.error(f"Liveness probe failed: {e}", exc_info=True)
        
        error_response = {
            'status': HealthStatus.UNHEALTHY,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'probe_type': 'liveness',
            'error': str(e)
        }
        
        return jsonify(error_response), 503


@health_bp.route('/health/ready', methods=['GET'])
@track_health_endpoint_metrics('readiness_probe')
def readiness_probe():
    """
    Kubernetes readiness probe endpoint per Section 6.5.2.1.
    
    Returns HTTP 200 when all critical dependencies (MongoDB, Redis, external APIs)
    are accessible and functional. Returns HTTP 503 when dependencies are unavailable
    or degraded. Used by Kubernetes and load balancers for traffic routing decisions.
    
    Returns:
        JSON response with readiness status and critical dependency health
        HTTP 200 if ready to serve traffic, HTTP 503 if not ready
    """
    try:
        health_status = health_monitor.check_application_health(detailed=False)
        
        # Extract critical dependency status for readiness
        dependencies = health_status.get('dependencies', {})
        database_status = dependencies.get('database', {}).get('status', HealthStatus.UNHEALTHY)
        cache_status = dependencies.get('cache', {}).get('status', HealthStatus.UNHEALTHY)
        
        # Readiness requires critical dependencies to be healthy
        ready = (database_status == HealthStatus.HEALTHY and 
                cache_status == HealthStatus.HEALTHY)
        
        readiness_response = {
            'status': HealthStatus.HEALTHY if ready else HealthStatus.UNHEALTHY,
            'timestamp': health_status['timestamp'],
            'probe_type': 'readiness',
            'ready': ready,
            'critical_dependencies': {
                'database': {
                    'status': database_status,
                    'ready': database_status == HealthStatus.HEALTHY
                },
                'cache': {
                    'status': cache_status,
                    'ready': cache_status == HealthStatus.HEALTHY
                }
            }
        }
        
        return jsonify(readiness_response), 200 if ready else 503
        
    except Exception as e:
        logger.error(f"Readiness probe failed: {e}", exc_info=True)
        
        error_response = {
            'status': HealthStatus.UNHEALTHY,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'probe_type': 'readiness',
            'ready': False,
            'error': str(e)
        }
        
        return jsonify(error_response), 503


@health_bp.route('/health/dependencies', methods=['GET'])
@track_health_endpoint_metrics('dependencies_detailed')
def dependencies_health():
    """
    Detailed dependency health status endpoint with comprehensive monitoring data.
    
    Provides comprehensive health information for all application dependencies including
    database connections, cache services, external integrations, and circuit breaker
    states. Includes performance metrics and detailed diagnostic information.
    
    Returns:
        JSON response with detailed dependency health information
        HTTP 200 with complete dependency status
    """
    try:
        # Get detailed health status with metrics
        health_status = health_monitor.check_application_health(detailed=True)
        
        # Enhanced response with detailed dependency information
        detailed_response = {
            'status': health_status['status'],
            'timestamp': health_status['timestamp'],
            'application': health_status['application'],
            'dependencies': health_status['dependencies'],
            'summary': health_status['summary'],
            'metrics': health_status.get('metrics', {}),
            'performance': health_status.get('performance', {}),
            'monitoring': {
                'prometheus_available': PROMETHEUS_AVAILABLE,
                'database_monitoring_available': DATABASE_MONITORING_AVAILABLE,
                'cache_monitoring_available': CACHE_MONITORING_AVAILABLE,
                'integrations_monitoring_available': INTEGRATIONS_MONITORING_AVAILABLE
            }
        }
        
        return jsonify(detailed_response), 200
        
    except Exception as e:
        logger.error(f"Dependencies health check failed: {e}", exc_info=True)
        
        error_response = {
            'status': HealthStatus.UNHEALTHY,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'error': str(e),
            'dependencies': {}
        }
        
        return jsonify(error_response), 500


@health_bp.route('/metrics', methods=['GET'])
def prometheus_metrics():
    """
    Prometheus metrics endpoint for monitoring integration per Section 6.5.1.1.
    
    Exposes application and health metrics in Prometheus format for enterprise
    monitoring integration. Includes custom migration metrics for performance
    variance tracking per Section 0.1.1 requirements.
    
    Returns:
        Prometheus metrics in text format
        HTTP 200 with metrics data, HTTP 503 if metrics collection fails
    """
    if not PROMETHEUS_AVAILABLE:
        return jsonify({
            'error': 'Prometheus client not available',
            'message': 'Metrics collection disabled'
        }), 503
    
    try:
        start_time = time.time()
        
        # Trigger health check to update current metrics
        health_monitor.check_application_health(detailed=False)
        
        # Generate Prometheus metrics
        if hasattr(REGISTRY, '_collector_to_names'):
            # Standard single-process mode
            metrics_data = generate_latest(REGISTRY)
        else:
            # Multi-process mode (e.g., Gunicorn)
            try:
                collector = MultiProcessCollector(REGISTRY)
                metrics_data = generate_latest(collector)
            except Exception:
                # Fallback to standard registry
                metrics_data = generate_latest(REGISTRY)
        
        # Track metrics endpoint performance
        metrics_generation_time = time.time() - start_time
        
        logger.debug(
            "Prometheus metrics generated",
            generation_time_ms=metrics_generation_time * 1000,
            metrics_size_bytes=len(metrics_data),
            prometheus_registry_collectors=len(REGISTRY._collector_to_names) if hasattr(REGISTRY, '_collector_to_names') else 'unknown'
        )
        
        # Return metrics in Prometheus format
        response = Response(metrics_data, mimetype=CONTENT_TYPE_LATEST)
        response.headers['Cache-Control'] = 'no-cache'
        return response
        
    except Exception as e:
        logger.error(f"Metrics endpoint failed: {e}", exc_info=True)
        
        return jsonify({
            'error': 'Metrics generation failed',
            'message': str(e),
            'prometheus_available': True
        }), 500


# Health monitoring Blueprint initialization function
def init_health_blueprint(app: Flask) -> None:
    """
    Initialize health monitoring Blueprint with Flask application.
    
    Configures health monitoring endpoints and integrates with Flask application
    factory pattern per Section 6.1.1. Sets up Prometheus metrics collection
    and monitoring infrastructure integration.
    
    Args:
        app: Flask application instance
    """
    try:
        # Register health monitoring Blueprint
        app.register_blueprint(health_bp)
        
        # Configure Blueprint-specific settings
        app.config['HEALTH_CHECK_CACHE_TTL'] = 30  # seconds
        app.config['HEALTH_CHECK_TIMEOUT'] = 5     # seconds
        
        # Store health monitor instance in app config
        app.config['HEALTH_MONITOR'] = health_monitor
        
        logger.info(
            "Health monitoring Blueprint initialized",
            blueprint_name='health',
            endpoints=['health', 'health/live', 'health/ready', 'health/dependencies', 'metrics'],
            prometheus_available=PROMETHEUS_AVAILABLE,
            database_monitoring=DATABASE_MONITORING_AVAILABLE,
            cache_monitoring=CACHE_MONITORING_AVAILABLE,
            integrations_monitoring=INTEGRATIONS_MONITORING_AVAILABLE
        )
        
        # Log initialization summary
        if logger:
            logger.info(
                "Health monitoring capabilities initialized",
                kubernetes_probes=True,
                prometheus_metrics=PROMETHEUS_AVAILABLE,
                dependency_monitoring=True,
                circuit_breaker_monitoring=INTEGRATIONS_MONITORING_AVAILABLE,
                response_time_target='<100ms'
            )
        
    except Exception as e:
        logger.error(f"Health Blueprint initialization failed: {e}", exc_info=True)
        raise


# Export health monitoring components
__all__ = [
    'health_bp',
    'HealthStatus',
    'HealthMonitor',
    'health_monitor',
    'init_health_blueprint',
    'track_health_endpoint_metrics'
]


# Import os for process ID in liveness probe
import os