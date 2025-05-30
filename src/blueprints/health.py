"""
Health Monitoring Blueprint

Comprehensive health monitoring and system status Blueprint providing health check endpoints for
load balancers, Kubernetes probes, and monitoring systems. Implements application health validation,
database connectivity checks, external service status, and Prometheus metrics exposure per Section 6.1.3
and Section 6.5.2.1 requirements.

This Blueprint provides enterprise-grade health monitoring capabilities for the Flask application migration,
ensuring seamless integration with container orchestration, load balancer health checks, and monitoring
infrastructure while maintaining ≤10% performance variance from Node.js baseline per Section 0.1.1.

Key Features:
- Kubernetes-native liveness and readiness probe endpoints per Section 6.5.2.1
- Load balancer compatible health check endpoints per Section 6.1.3
- Comprehensive dependency health validation (MongoDB, Redis, external services)
- Prometheus metrics endpoint for monitoring integration per Section 6.5.1.1
- Circuit breaker state monitoring and reporting per Section 6.1.3
- Performance variance tracking against Node.js baseline per Section 0.3.2
- Flask application factory pattern integration per Section 6.1.1

Endpoints:
- GET /health - Basic application status and overall health summary
- GET /health/live - Kubernetes liveness probe (application process health)
- GET /health/ready - Kubernetes readiness probe (dependency health validation)
- GET /health/dependencies - Detailed dependency health status and metrics
- GET /metrics - Prometheus metrics endpoint for monitoring system integration

Health Check Components:
- Database connectivity validation (PyMongo synchronous and Motor async clients)
- Redis cache connectivity and circuit breaker state monitoring
- External service integration health validation and circuit breaker states
- Application performance metrics and variance tracking
- System resource utilization monitoring and capacity health

Integration Points:
- src.data: MongoDB health validation via DatabaseHealthChecker
- src.cache: Redis connectivity monitoring via CacheManager health checks
- src.monitoring: Comprehensive health state management via HealthChecker
- src.integrations: External service circuit breaker state monitoring

Compliance:
- Section 6.1.3: Health check endpoints for monitoring application status and connectivity
- Section 6.5.2.1: Kubernetes readiness and liveness probe support
- Section 6.5.1.1: Prometheus metrics endpoint for monitoring integration
- Section 6.1.1: Flask application factory pattern implementation
- Section 0.1.1: Performance monitoring ensuring ≤10% variance from Node.js baseline
"""

import time
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field

from flask import Blueprint, jsonify, request, current_app, g
from werkzeug.exceptions import ServiceUnavailable, InternalServerError

import structlog

# Import dependency health checking capabilities
from src.data import (
    get_database_manager,
    DatabaseManager,
    get_mongodb_client,
    get_motor_database
)

from src.cache import (
    get_cache_manager,
    CacheManager,
    is_cache_available
)

from src.monitoring import (
    get_health_status,
    get_circuit_breaker_states,
    HealthChecker,
    health_checker,
    HealthStatus,
    DependencyType,
    HealthCheckResult,
    SystemHealth,
    CircuitBreakerState,
    get_performance_summary,
    METRICS_REGISTRY,
    get_monitoring_stack
)

from src.integrations import (
    get_monitoring_summary,
    external_service_monitor
)

# Configure structured logger for health monitoring
logger = structlog.get_logger(__name__)

# Create health monitoring Blueprint
health_blueprint = Blueprint(
    'health',
    __name__,
    url_prefix='/health'
)


@dataclass
class HealthCheckConfiguration:
    """
    Configuration for health check endpoints and monitoring thresholds.
    
    Defines health check timeouts, dependency validation settings, and performance
    monitoring thresholds for comprehensive health state assessment.
    """
    
    # Health check timeout settings
    database_timeout_seconds: float = 5.0
    cache_timeout_seconds: float = 3.0
    external_service_timeout_seconds: float = 10.0
    overall_health_timeout_seconds: float = 15.0
    
    # Performance monitoring thresholds
    max_response_time_variance_percent: float = 10.0  # ≤10% variance requirement
    cpu_utilization_warning_threshold: float = 70.0
    cpu_utilization_critical_threshold: float = 90.0
    memory_usage_warning_threshold: float = 80.0
    memory_usage_critical_threshold: float = 95.0
    
    # Dependency health validation settings
    enable_database_health_checks: bool = True
    enable_cache_health_checks: bool = True
    enable_external_service_health_checks: bool = True
    enable_circuit_breaker_monitoring: bool = True
    
    # Kubernetes probe settings
    liveness_probe_enabled: bool = True
    readiness_probe_enabled: bool = True
    load_balancer_health_enabled: bool = True
    
    # Metrics and monitoring settings
    prometheus_metrics_enabled: bool = True
    performance_variance_tracking: bool = True
    detailed_dependency_reporting: bool = True
    
    def __post_init__(self):
        """Validate configuration parameters."""
        if self.database_timeout_seconds <= 0:
            raise ValueError("Database timeout must be positive")
        if self.cache_timeout_seconds <= 0:
            raise ValueError("Cache timeout must be positive")
        if not 0 < self.max_response_time_variance_percent <= 100:
            raise ValueError("Response time variance percent must be between 0 and 100")


@dataclass
class DependencyHealthStatus:
    """
    Health status container for individual system dependencies.
    
    Provides standardized health status representation for database, cache,
    external services, and monitoring components with detailed diagnostic information.
    """
    
    name: str
    status: str  # 'healthy', 'degraded', 'unhealthy', 'unknown'
    response_time_ms: Optional[float] = None
    error_message: Optional[str] = None
    last_check_timestamp: Optional[str] = None
    additional_info: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'name': self.name,
            'status': self.status,
            'response_time_ms': self.response_time_ms,
            'error_message': self.error_message,
            'last_check_timestamp': self.last_check_timestamp,
            'additional_info': self.additional_info
        }
    
    @property
    def is_healthy(self) -> bool:
        """Check if dependency is healthy."""
        return self.status == 'healthy'
    
    @property
    def is_operational(self) -> bool:
        """Check if dependency is operational (healthy or degraded)."""
        return self.status in ['healthy', 'degraded']


class HealthMonitor:
    """
    Central health monitoring coordinator providing comprehensive health state assessment.
    
    Coordinates health checks across all system dependencies including database connections,
    cache systems, external service integrations, and monitoring components while tracking
    performance metrics and circuit breaker states.
    """
    
    def __init__(self, config: Optional[HealthCheckConfiguration] = None):
        """
        Initialize health monitor with configuration.
        
        Args:
            config: Health check configuration (creates default if not provided)
        """
        self.config = config or HealthCheckConfiguration()
        self.last_full_health_check: Optional[datetime] = None
        self.cached_health_status: Optional[Dict[str, Any]] = None
        self.health_check_count = 0
        
        logger.info(
            "Health monitor initialized",
            database_timeout=self.config.database_timeout_seconds,
            cache_timeout=self.config.cache_timeout_seconds,
            external_service_timeout=self.config.external_service_timeout_seconds,
            performance_variance_threshold=self.config.max_response_time_variance_percent
        )
    
    def check_application_liveness(self) -> Tuple[Dict[str, Any], int]:
        """
        Check application liveness for Kubernetes liveness probe per Section 6.5.2.1.
        
        Validates that the Flask application process is running and capable of handling
        requests. Returns HTTP 200 for healthy state, HTTP 503 for fatal conditions
        requiring container restart.
        
        Returns:
            Tuple[Dict[str, Any], int]: Response data and HTTP status code
        """
        try:
            start_time = time.time()
            
            # Basic Flask application health check
            app_status = {
                'status': 'healthy',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'check_type': 'liveness',
                'application': {
                    'flask_app_name': current_app.name,
                    'debug_mode': current_app.debug,
                    'testing_mode': current_app.testing,
                    'process_responsive': True
                },
                'uptime_info': {
                    'check_duration_ms': round((time.time() - start_time) * 1000, 2)
                }
            }
            
            # Validate critical application components
            try:
                # Test basic Flask application responsiveness
                with current_app.app_context():
                    # Verify application context is accessible
                    config_available = bool(current_app.config)
                    extensions_available = hasattr(current_app, 'extensions')
                    
                    app_status['application'].update({
                        'config_accessible': config_available,
                        'extensions_loaded': extensions_available
                    })
                
                logger.debug(
                    "Application liveness check completed",
                    status="healthy",
                    duration_ms=app_status['uptime_info']['check_duration_ms']
                )
                
                return app_status, 200
                
            except Exception as app_error:
                logger.error(
                    "Application liveness check failed",
                    error=str(app_error),
                    error_type=type(app_error).__name__
                )
                
                app_status.update({
                    'status': 'unhealthy',
                    'error': 'Application context failure',
                    'error_details': str(app_error)
                })
                
                return app_status, 503
        
        except Exception as e:
            logger.error(
                "Liveness probe execution failed",
                error=str(e),
                error_type=type(e).__name__
            )
            
            return {
                'status': 'unhealthy',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'check_type': 'liveness',
                'error': 'Liveness probe execution failed',
                'error_details': str(e)
            }, 503
    
    def check_application_readiness(self) -> Tuple[Dict[str, Any], int]:
        """
        Check application readiness for Kubernetes readiness probe per Section 6.5.2.1.
        
        Validates that all critical dependencies (MongoDB, Redis, external services) are
        accessible and functional. Returns HTTP 200 when ready to serve traffic,
        HTTP 503 when dependencies are unavailable or degraded.
        
        Returns:
            Tuple[Dict[str, Any], int]: Response data and HTTP status code
        """
        try:
            start_time = time.time()
            dependency_statuses = []
            overall_ready = True
            
            readiness_status = {
                'status': 'ready',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'check_type': 'readiness',
                'dependencies': {},
                'summary': {
                    'total_dependencies': 0,
                    'healthy_dependencies': 0,
                    'degraded_dependencies': 0,
                    'unhealthy_dependencies': 0
                }
            }
            
            # Check database connectivity
            if self.config.enable_database_health_checks:
                db_status = self._check_database_health()
                dependency_statuses.append(db_status)
                readiness_status['dependencies']['database'] = db_status.to_dict()
                
                if not db_status.is_operational:
                    overall_ready = False
            
            # Check cache connectivity
            if self.config.enable_cache_health_checks:
                cache_status = self._check_cache_health()
                dependency_statuses.append(cache_status)
                readiness_status['dependencies']['cache'] = cache_status.to_dict()
                
                if not cache_status.is_operational:
                    overall_ready = False
            
            # Check external service health
            if self.config.enable_external_service_health_checks:
                external_status = self._check_external_services_health()
                readiness_status['dependencies']['external_services'] = external_status
                
                # Determine if external services are operational
                external_operational = True
                for service_name, service_data in external_status.items():
                    if service_data.get('status') not in ['healthy', 'degraded']:
                        external_operational = False
                        break
                
                if not external_operational:
                    overall_ready = False
            
            # Check monitoring system health
            monitoring_status = self._check_monitoring_health()
            readiness_status['dependencies']['monitoring'] = monitoring_status
            
            # Calculate dependency summary
            for dep_status in dependency_statuses:
                readiness_status['summary']['total_dependencies'] += 1
                if dep_status.status == 'healthy':
                    readiness_status['summary']['healthy_dependencies'] += 1
                elif dep_status.status == 'degraded':
                    readiness_status['summary']['degraded_dependencies'] += 1
                else:
                    readiness_status['summary']['unhealthy_dependencies'] += 1
            
            # Add external services to summary
            if self.config.enable_external_service_health_checks:
                for service_name, service_data in external_status.items():
                    readiness_status['summary']['total_dependencies'] += 1
                    service_status = service_data.get('status', 'unknown')
                    if service_status == 'healthy':
                        readiness_status['summary']['healthy_dependencies'] += 1
                    elif service_status == 'degraded':
                        readiness_status['summary']['degraded_dependencies'] += 1
                    else:
                        readiness_status['summary']['unhealthy_dependencies'] += 1
            
            # Add monitoring to summary
            readiness_status['summary']['total_dependencies'] += 1
            monitoring_status_value = monitoring_status.get('status', 'unknown')
            if monitoring_status_value == 'healthy':
                readiness_status['summary']['healthy_dependencies'] += 1
            elif monitoring_status_value == 'degraded':
                readiness_status['summary']['degraded_dependencies'] += 1
            else:
                readiness_status['summary']['unhealthy_dependencies'] += 1
                overall_ready = False
            
            # Finalize readiness status
            readiness_status['uptime_info'] = {
                'check_duration_ms': round((time.time() - start_time) * 1000, 2)
            }
            
            if overall_ready:
                readiness_status['status'] = 'ready'
                status_code = 200
                logger.info(
                    "Application readiness check passed",
                    total_dependencies=readiness_status['summary']['total_dependencies'],
                    healthy_count=readiness_status['summary']['healthy_dependencies'],
                    duration_ms=readiness_status['uptime_info']['check_duration_ms']
                )
            else:
                readiness_status['status'] = 'not_ready'
                status_code = 503
                logger.warning(
                    "Application readiness check failed",
                    total_dependencies=readiness_status['summary']['total_dependencies'],
                    unhealthy_count=readiness_status['summary']['unhealthy_dependencies'],
                    degraded_count=readiness_status['summary']['degraded_dependencies'],
                    duration_ms=readiness_status['uptime_info']['check_duration_ms']
                )
            
            return readiness_status, status_code
            
        except Exception as e:
            logger.error(
                "Readiness probe execution failed",
                error=str(e),
                error_type=type(e).__name__
            )
            
            return {
                'status': 'not_ready',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'check_type': 'readiness',
                'error': 'Readiness probe execution failed',
                'error_details': str(e)
            }, 503
    
    def check_comprehensive_health(self) -> Tuple[Dict[str, Any], int]:
        """
        Perform comprehensive health check including all dependencies and performance metrics.
        
        Provides detailed health status for all system components including database connections,
        cache systems, external services, monitoring systems, and performance variance tracking
        against Node.js baseline per Section 0.3.2.
        
        Returns:
            Tuple[Dict[str, Any], int]: Comprehensive health data and HTTP status code
        """
        try:
            start_time = time.time()
            self.health_check_count += 1
            
            health_data = {
                'status': 'healthy',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'check_type': 'comprehensive',
                'check_sequence': self.health_check_count,
                'system_info': {
                    'service_name': 'flask-migration-app',
                    'environment': current_app.config.get('FLASK_ENV', 'development'),
                    'version': current_app.config.get('APP_VERSION', '1.0.0')
                },
                'dependencies': {},
                'performance_metrics': {},
                'circuit_breakers': {},
                'summary': {
                    'overall_status': 'healthy',
                    'total_dependencies': 0,
                    'healthy_dependencies': 0,
                    'degraded_dependencies': 0,
                    'unhealthy_dependencies': 0,
                    'performance_variance_within_threshold': True
                }
            }
            
            overall_healthy = True
            dependency_statuses = []
            
            # Database health assessment
            if self.config.enable_database_health_checks:
                db_status = self._check_database_health()
                dependency_statuses.append(db_status)
                health_data['dependencies']['database'] = db_status.to_dict()
                
                if not db_status.is_healthy:
                    if db_status.status == 'degraded':
                        health_data['summary']['overall_status'] = 'degraded'
                    else:
                        overall_healthy = False
            
            # Cache system health assessment
            if self.config.enable_cache_health_checks:
                cache_status = self._check_cache_health()
                dependency_statuses.append(cache_status)
                health_data['dependencies']['cache'] = cache_status.to_dict()
                
                if not cache_status.is_healthy:
                    if cache_status.status == 'degraded':
                        if health_data['summary']['overall_status'] == 'healthy':
                            health_data['summary']['overall_status'] = 'degraded'
                    else:
                        overall_healthy = False
            
            # External services health assessment
            if self.config.enable_external_service_health_checks:
                external_services = self._check_external_services_health()
                health_data['dependencies']['external_services'] = external_services
                
                for service_name, service_data in external_services.items():
                    service_status = service_data.get('status', 'unknown')
                    if service_status not in ['healthy', 'degraded']:
                        overall_healthy = False
                    elif service_status == 'degraded':
                        if health_data['summary']['overall_status'] == 'healthy':
                            health_data['summary']['overall_status'] = 'degraded'
            
            # Monitoring system health assessment
            monitoring_health = self._check_monitoring_health()
            health_data['dependencies']['monitoring'] = monitoring_health
            
            # Performance metrics collection
            if self.config.performance_variance_tracking:
                performance_data = self._collect_performance_metrics()
                health_data['performance_metrics'] = performance_data
                
                # Check performance variance against threshold
                variance_percentage = performance_data.get('response_time_variance_percent', 0)
                if variance_percentage > self.config.max_response_time_variance_percent:
                    health_data['summary']['performance_variance_within_threshold'] = False
                    overall_healthy = False
                    logger.warning(
                        "Performance variance exceeds threshold",
                        variance_percent=variance_percentage,
                        threshold_percent=self.config.max_response_time_variance_percent
                    )
            
            # Circuit breaker state monitoring
            if self.config.enable_circuit_breaker_monitoring:
                circuit_breaker_states = self._check_circuit_breaker_states()
                health_data['circuit_breakers'] = circuit_breaker_states
            
            # Calculate dependency summary statistics
            for dep_status in dependency_statuses:
                health_data['summary']['total_dependencies'] += 1
                if dep_status.status == 'healthy':
                    health_data['summary']['healthy_dependencies'] += 1
                elif dep_status.status == 'degraded':
                    health_data['summary']['degraded_dependencies'] += 1
                else:
                    health_data['summary']['unhealthy_dependencies'] += 1
            
            # Add external services to summary
            if self.config.enable_external_service_health_checks:
                for service_name, service_data in external_services.items():
                    health_data['summary']['total_dependencies'] += 1
                    service_status = service_data.get('status', 'unknown')
                    if service_status == 'healthy':
                        health_data['summary']['healthy_dependencies'] += 1
                    elif service_status == 'degraded':
                        health_data['summary']['degraded_dependencies'] += 1
                    else:
                        health_data['summary']['unhealthy_dependencies'] += 1
            
            # Add monitoring to summary
            health_data['summary']['total_dependencies'] += 1
            monitoring_status_value = monitoring_health.get('status', 'unknown')
            if monitoring_status_value == 'healthy':
                health_data['summary']['healthy_dependencies'] += 1
            elif monitoring_status_value == 'degraded':
                health_data['summary']['degraded_dependencies'] += 1
            else:
                health_data['summary']['unhealthy_dependencies'] += 1
            
            # Finalize overall health status
            if overall_healthy:
                health_data['status'] = health_data['summary']['overall_status']  # 'healthy' or 'degraded'
                status_code = 200
            else:
                health_data['status'] = 'unhealthy'
                health_data['summary']['overall_status'] = 'unhealthy'
                status_code = 503
            
            # Add timing information
            health_data['uptime_info'] = {
                'check_duration_ms': round((time.time() - start_time) * 1000, 2),
                'last_full_check': self.last_full_health_check.isoformat() if self.last_full_health_check else None
            }
            
            # Cache the health status for performance optimization
            self.cached_health_status = health_data
            self.last_full_health_check = datetime.now(timezone.utc)
            
            logger.info(
                "Comprehensive health check completed",
                overall_status=health_data['status'],
                total_dependencies=health_data['summary']['total_dependencies'],
                healthy_count=health_data['summary']['healthy_dependencies'],
                degraded_count=health_data['summary']['degraded_dependencies'],
                unhealthy_count=health_data['summary']['unhealthy_dependencies'],
                performance_within_threshold=health_data['summary']['performance_variance_within_threshold'],
                duration_ms=health_data['uptime_info']['check_duration_ms']
            )
            
            return health_data, status_code
            
        except Exception as e:
            logger.error(
                "Comprehensive health check failed",
                error=str(e),
                error_type=type(e).__name__
            )
            
            return {
                'status': 'unhealthy',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'check_type': 'comprehensive',
                'error': 'Health check execution failed',
                'error_details': str(e)
            }, 503
    
    def _check_database_health(self) -> DependencyHealthStatus:
        """
        Check MongoDB database connectivity health via PyMongo and Motor clients.
        
        Returns:
            DependencyHealthStatus: Database health status with diagnostic information
        """
        start_time = time.time()
        
        try:
            # Get database manager from Flask application context
            db_manager = get_database_manager()
            
            if not db_manager:
                return DependencyHealthStatus(
                    name='database',
                    status='unhealthy',
                    error_message='Database manager not initialized',
                    last_check_timestamp=datetime.now(timezone.utc).isoformat()
                )
            
            # Get comprehensive database health status
            try:
                db_health = db_manager.get_health_status()
                response_time = round((time.time() - start_time) * 1000, 2)
                
                # Determine health status based on database response
                overall_status = db_health.get('overall_status', 'unknown')
                
                if overall_status == 'healthy':
                    status = 'healthy'
                elif overall_status in ['degraded', 'warning']:
                    status = 'degraded'
                else:
                    status = 'unhealthy'
                
                return DependencyHealthStatus(
                    name='database',
                    status=status,
                    response_time_ms=response_time,
                    last_check_timestamp=datetime.now(timezone.utc).isoformat(),
                    additional_info={
                        'mongodb_components': db_health.get('components', {}),
                        'connection_pool_status': 'active',
                        'motor_async_enabled': bool(db_manager.motor_database),
                        'pymongo_sync_enabled': bool(db_manager.mongodb_client)
                    }
                )
                
            except Exception as health_error:
                response_time = round((time.time() - start_time) * 1000, 2)
                
                return DependencyHealthStatus(
                    name='database',
                    status='unhealthy',
                    response_time_ms=response_time,
                    error_message=f'Database health check failed: {str(health_error)}',
                    last_check_timestamp=datetime.now(timezone.utc).isoformat()
                )
        
        except Exception as e:
            response_time = round((time.time() - start_time) * 1000, 2)
            
            return DependencyHealthStatus(
                name='database',
                status='unhealthy',
                response_time_ms=response_time,
                error_message=f'Database connectivity check failed: {str(e)}',
                last_check_timestamp=datetime.now(timezone.utc).isoformat()
            )
    
    def _check_cache_health(self) -> DependencyHealthStatus:
        """
        Check Redis cache connectivity health via CacheManager.
        
        Returns:
            DependencyHealthStatus: Cache health status with diagnostic information
        """
        start_time = time.time()
        
        try:
            # Check if cache system is available
            cache_available = is_cache_available()
            
            if not cache_available:
                return DependencyHealthStatus(
                    name='cache',
                    status='unhealthy',
                    response_time_ms=round((time.time() - start_time) * 1000, 2),
                    error_message='Cache system not available or not initialized',
                    last_check_timestamp=datetime.now(timezone.utc).isoformat()
                )
            
            # Get cache manager and health status
            try:
                cache_manager = get_cache_manager()
                cache_health = cache_manager.get_health_status()
                response_time = round((time.time() - start_time) * 1000, 2)
                
                # Determine health status based on cache response
                cache_status = cache_health.get('status', 'unknown')
                
                if cache_status == 'healthy':
                    status = 'healthy'
                elif cache_status == 'degraded':
                    status = 'degraded'
                else:
                    status = 'unhealthy'
                
                return DependencyHealthStatus(
                    name='cache',
                    status=status,
                    response_time_ms=response_time,
                    last_check_timestamp=datetime.now(timezone.utc).isoformat(),
                    additional_info={
                        'redis_components': cache_health.get('components', {}),
                        'connection_pool_status': 'active',
                        'cache_statistics': cache_health.get('cache_stats', {})
                    }
                )
                
            except Exception as cache_error:
                response_time = round((time.time() - start_time) * 1000, 2)
                
                return DependencyHealthStatus(
                    name='cache',
                    status='unhealthy',
                    response_time_ms=response_time,
                    error_message=f'Cache health check failed: {str(cache_error)}',
                    last_check_timestamp=datetime.now(timezone.utc).isoformat()
                )
        
        except Exception as e:
            response_time = round((time.time() - start_time) * 1000, 2)
            
            return DependencyHealthStatus(
                name='cache',
                status='unhealthy',
                response_time_ms=response_time,
                error_message=f'Cache connectivity check failed: {str(e)}',
                last_check_timestamp=datetime.now(timezone.utc).isoformat()
            )
    
    def _check_external_services_health(self) -> Dict[str, Any]:
        """
        Check external service integration health via monitoring summary.
        
        Returns:
            Dict[str, Any]: External services health status
        """
        try:
            # Get comprehensive external service monitoring summary
            monitoring_summary = get_monitoring_summary()
            
            external_services_health = {}
            
            # Process registered services
            registered_services = monitoring_summary.get('registered_services', [])
            health_cache = monitoring_summary.get('health_cache', {})
            service_metadata = monitoring_summary.get('service_metadata', {})
            
            for service_name in registered_services:
                service_health = health_cache.get(service_name, {})
                service_meta = service_metadata.get(service_name, {})
                
                external_services_health[service_name] = {
                    'status': service_health.get('status', 'unknown'),
                    'response_time_ms': service_health.get('duration', 0) * 1000 if service_health.get('duration') else None,
                    'last_check_timestamp': service_health.get('timestamp'),
                    'service_type': service_meta.get('service_type', 'unknown'),
                    'endpoint_url': service_meta.get('endpoint_url'),
                    'circuit_breaker_enabled': service_meta.get('metadata', {}).get('circuit_breaker_enabled', False)
                }
            
            # If no services are registered, add placeholder status
            if not external_services_health:
                external_services_health['integration_monitoring'] = {
                    'status': 'healthy',
                    'response_time_ms': 0,
                    'last_check_timestamp': datetime.now(timezone.utc).isoformat(),
                    'service_type': 'monitoring',
                    'message': 'No external services currently registered'
                }
            
            return external_services_health
            
        except Exception as e:
            logger.error(
                "External services health check failed",
                error=str(e),
                error_type=type(e).__name__
            )
            
            return {
                'external_services_monitor': {
                    'status': 'unhealthy',
                    'error_message': f'External services health check failed: {str(e)}',
                    'last_check_timestamp': datetime.now(timezone.utc).isoformat()
                }
            }
    
    def _check_monitoring_health(self) -> Dict[str, Any]:
        """
        Check monitoring system health via monitoring stack.
        
        Returns:
            Dict[str, Any]: Monitoring system health status
        """
        try:
            # Get monitoring stack status
            monitoring_stack = get_monitoring_stack()
            
            if not monitoring_stack:
                return {
                    'status': 'degraded',
                    'error_message': 'Monitoring stack not initialized',
                    'last_check_timestamp': datetime.now(timezone.utc).isoformat(),
                    'components': {
                        'logging': False,
                        'metrics': False,
                        'health_checks': False,
                        'apm': False
                    }
                }
            
            # Get comprehensive monitoring status
            monitoring_status = monitoring_stack.get_monitoring_status()
            
            # Determine overall monitoring health
            components = monitoring_status.get('components', {})
            is_healthy = all([
                components.get('logging', {}).get('initialized', False),
                components.get('metrics', {}).get('initialized', False),
                components.get('health_checks', {}).get('initialized', False)
            ])
            
            # APM is optional but good to have
            apm_initialized = components.get('apm', {}).get('initialized', False)
            
            if is_healthy:
                status = 'healthy' if apm_initialized else 'degraded'
            else:
                status = 'unhealthy'
            
            return {
                'status': status,
                'last_check_timestamp': datetime.now(timezone.utc).isoformat(),
                'service_name': monitoring_status.get('service_name'),
                'environment': monitoring_status.get('environment'),
                'uptime_seconds': monitoring_status.get('uptime_seconds'),
                'initialization_metrics': monitoring_status.get('initialization_metrics', {}),
                'components': {
                    'logging': components.get('logging', {}).get('initialized', False),
                    'metrics': components.get('metrics', {}).get('initialized', False),
                    'health_checks': components.get('health_checks', {}).get('initialized', False),
                    'apm': components.get('apm', {}).get('initialized', False)
                }
            }
            
        except Exception as e:
            logger.error(
                "Monitoring system health check failed",
                error=str(e),
                error_type=type(e).__name__
            )
            
            return {
                'status': 'unhealthy',
                'error_message': f'Monitoring health check failed: {str(e)}',
                'last_check_timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    def _collect_performance_metrics(self) -> Dict[str, Any]:
        """
        Collect performance metrics and variance tracking against Node.js baseline.
        
        Returns:
            Dict[str, Any]: Performance metrics and variance analysis
        """
        try:
            # Get performance summary from monitoring system
            performance_summary = get_performance_summary()
            
            performance_data = {
                'response_time_variance_percent': 0.0,
                'baseline_comparison': {
                    'nodejs_baseline_available': False,
                    'flask_performance_measured': False
                },
                'system_metrics': {
                    'cpu_utilization_percent': 0.0,
                    'memory_usage_percent': 0.0,
                    'gc_pause_time_ms': 0.0
                },
                'thresholds': {
                    'max_variance_percent': self.config.max_response_time_variance_percent,
                    'cpu_warning_threshold': self.config.cpu_utilization_warning_threshold,
                    'cpu_critical_threshold': self.config.cpu_utilization_critical_threshold,
                    'memory_warning_threshold': self.config.memory_usage_warning_threshold,
                    'memory_critical_threshold': self.config.memory_usage_critical_threshold
                },
                'last_updated': datetime.now(timezone.utc).isoformat()
            }
            
            # Extract performance metrics if available
            if performance_summary:
                # Response time variance
                variance_data = performance_summary.get('variance_tracking', {})
                performance_data['response_time_variance_percent'] = variance_data.get('current_variance_percent', 0.0)
                
                # Baseline comparison information
                baseline_info = performance_summary.get('baseline_comparison', {})
                performance_data['baseline_comparison'] = {
                    'nodejs_baseline_available': baseline_info.get('baselines_configured', False),
                    'flask_performance_measured': baseline_info.get('measurements_available', False),
                    'endpoints_tracked': baseline_info.get('tracked_endpoints', [])
                }
                
                # System resource metrics
                system_metrics = performance_summary.get('system_metrics', {})
                performance_data['system_metrics'] = {
                    'cpu_utilization_percent': system_metrics.get('cpu_percent', 0.0),
                    'memory_usage_percent': system_metrics.get('memory_percent', 0.0),
                    'gc_pause_time_ms': system_metrics.get('gc_pause_ms', 0.0)
                }
            
            return performance_data
            
        except Exception as e:
            logger.warning(
                "Performance metrics collection failed",
                error=str(e),
                error_type=type(e).__name__
            )
            
            return {
                'response_time_variance_percent': 0.0,
                'baseline_comparison': {
                    'nodejs_baseline_available': False,
                    'flask_performance_measured': False
                },
                'system_metrics': {
                    'cpu_utilization_percent': 0.0,
                    'memory_usage_percent': 0.0,
                    'gc_pause_time_ms': 0.0
                },
                'error': f'Performance metrics collection failed: {str(e)}',
                'last_updated': datetime.now(timezone.utc).isoformat()
            }
    
    def _check_circuit_breaker_states(self) -> Dict[str, Any]:
        """
        Check circuit breaker states for external service integrations.
        
        Returns:
            Dict[str, Any]: Circuit breaker states and statistics
        """
        try:
            # Get circuit breaker states from monitoring system
            circuit_breaker_states = get_circuit_breaker_states()
            
            circuit_breaker_summary = {
                'total_circuit_breakers': 0,
                'open_circuit_breakers': 0,
                'half_open_circuit_breakers': 0,
                'closed_circuit_breakers': 0,
                'circuit_breaker_details': {},
                'last_updated': datetime.now(timezone.utc).isoformat()
            }
            
            # Process circuit breaker states if available
            if circuit_breaker_states:
                for service_name, breaker_state in circuit_breaker_states.items():
                    circuit_breaker_summary['total_circuit_breakers'] += 1
                    
                    state = breaker_state.get('state', 'unknown')
                    if state == 'open':
                        circuit_breaker_summary['open_circuit_breakers'] += 1
                    elif state == 'half_open':
                        circuit_breaker_summary['half_open_circuit_breakers'] += 1
                    elif state == 'closed':
                        circuit_breaker_summary['closed_circuit_breakers'] += 1
                    
                    circuit_breaker_summary['circuit_breaker_details'][service_name] = {
                        'state': state,
                        'failure_count': breaker_state.get('failure_count', 0),
                        'last_failure_time': breaker_state.get('last_failure_time'),
                        'next_attempt_time': breaker_state.get('next_attempt_time')
                    }
            else:
                # Fallback to integration monitoring data
                monitoring_summary = get_monitoring_summary()
                registered_services = monitoring_summary.get('registered_services', [])
                
                for service_name in registered_services:
                    circuit_breaker_summary['total_circuit_breakers'] += 1
                    circuit_breaker_summary['closed_circuit_breakers'] += 1
                    
                    circuit_breaker_summary['circuit_breaker_details'][service_name] = {
                        'state': 'closed',
                        'failure_count': 0,
                        'status': 'monitoring_data_only'
                    }
            
            return circuit_breaker_summary
            
        except Exception as e:
            logger.warning(
                "Circuit breaker state check failed",
                error=str(e),
                error_type=type(e).__name__
            )
            
            return {
                'total_circuit_breakers': 0,
                'open_circuit_breakers': 0,
                'half_open_circuit_breakers': 0,
                'closed_circuit_breakers': 0,
                'circuit_breaker_details': {},
                'error': f'Circuit breaker state check failed: {str(e)}',
                'last_updated': datetime.now(timezone.utc).isoformat()
            }


# Initialize global health monitor instance
health_monitor = HealthMonitor()


@health_blueprint.route('', methods=['GET'])
def basic_health_check():
    """
    Basic application health check endpoint per Section 6.1.3.
    
    Provides comprehensive health status summary including all dependencies,
    performance metrics, and circuit breaker states. Used by load balancers
    and monitoring systems for overall application health assessment.
    
    Returns:
        JSON response with comprehensive health status
    """
    try:
        # Perform comprehensive health check
        health_data, status_code = health_monitor.check_comprehensive_health()
        
        # Log health check execution for monitoring
        logger.info(
            "Basic health check executed",
            status=health_data.get('status'),
            total_dependencies=health_data.get('summary', {}).get('total_dependencies', 0),
            response_code=status_code,
            check_duration_ms=health_data.get('uptime_info', {}).get('check_duration_ms', 0)
        )
        
        return jsonify(health_data), status_code
        
    except Exception as e:
        logger.error(
            "Basic health check endpoint failed",
            error=str(e),
            error_type=type(e).__name__
        )
        
        error_response = {
            'status': 'unhealthy',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'check_type': 'basic',
            'error': 'Health check endpoint execution failed',
            'error_details': str(e)
        }
        
        return jsonify(error_response), 503


@health_blueprint.route('/live', methods=['GET'])
def liveness_probe():
    """
    Kubernetes liveness probe endpoint per Section 6.5.2.1.
    
    Returns HTTP 200 when the Flask application process is running and capable
    of handling requests. Returns HTTP 503 when the application is in a fatal
    state requiring container restart.
    
    Returns:
        JSON response with liveness status
    """
    try:
        # Perform liveness check
        liveness_data, status_code = health_monitor.check_application_liveness()
        
        # Log liveness check for debugging (debug level to avoid log spam)
        logger.debug(
            "Liveness probe executed",
            status=liveness_data.get('status'),
            response_code=status_code,
            duration_ms=liveness_data.get('uptime_info', {}).get('check_duration_ms', 0)
        )
        
        return jsonify(liveness_data), status_code
        
    except Exception as e:
        logger.error(
            "Liveness probe endpoint failed",
            error=str(e),
            error_type=type(e).__name__
        )
        
        error_response = {
            'status': 'unhealthy',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'check_type': 'liveness',
            'error': 'Liveness probe execution failed',
            'error_details': str(e)
        }
        
        return jsonify(error_response), 503


@health_blueprint.route('/ready', methods=['GET'])
def readiness_probe():
    """
    Kubernetes readiness probe endpoint per Section 6.5.2.1.
    
    Returns HTTP 200 when all critical dependencies (MongoDB, Redis, external services)
    are accessible and functional. Returns HTTP 503 when dependencies are unavailable
    or degraded, indicating the application should not receive traffic.
    
    Returns:
        JSON response with readiness status
    """
    try:
        # Perform readiness check
        readiness_data, status_code = health_monitor.check_application_readiness()
        
        # Log readiness check for monitoring
        logger.info(
            "Readiness probe executed",
            status=readiness_data.get('status'),
            total_dependencies=readiness_data.get('summary', {}).get('total_dependencies', 0),
            healthy_count=readiness_data.get('summary', {}).get('healthy_dependencies', 0),
            response_code=status_code,
            duration_ms=readiness_data.get('uptime_info', {}).get('check_duration_ms', 0)
        )
        
        return jsonify(readiness_data), status_code
        
    except Exception as e:
        logger.error(
            "Readiness probe endpoint failed",
            error=str(e),
            error_type=type(e).__name__
        )
        
        error_response = {
            'status': 'not_ready',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'check_type': 'readiness',
            'error': 'Readiness probe execution failed',
            'error_details': str(e)
        }
        
        return jsonify(error_response), 503


@health_blueprint.route('/dependencies', methods=['GET'])
def dependencies_health_check():
    """
    Detailed dependency health check endpoint per Section 6.1.3.
    
    Provides comprehensive dependency health status including individual component
    health, response times, error details, and diagnostic information for each
    system dependency including database, cache, external services, and monitoring.
    
    Returns:
        JSON response with detailed dependency health status
    """
    try:
        # Get comprehensive health data
        health_data, _ = health_monitor.check_comprehensive_health()
        
        # Extract dependency-specific information
        dependencies_data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'check_type': 'dependencies',
            'dependencies': health_data.get('dependencies', {}),
            'summary': health_data.get('summary', {}),
            'circuit_breakers': health_data.get('circuit_breakers', {}),
            'performance_metrics': health_data.get('performance_metrics', {}),
            'uptime_info': health_data.get('uptime_info', {})
        }
        
        # Determine status code based on dependencies health
        unhealthy_count = dependencies_data.get('summary', {}).get('unhealthy_dependencies', 0)
        status_code = 503 if unhealthy_count > 0 else 200
        
        logger.info(
            "Dependencies health check executed",
            total_dependencies=dependencies_data.get('summary', {}).get('total_dependencies', 0),
            healthy_count=dependencies_data.get('summary', {}).get('healthy_dependencies', 0),
            unhealthy_count=unhealthy_count,
            response_code=status_code
        )
        
        return jsonify(dependencies_data), status_code
        
    except Exception as e:
        logger.error(
            "Dependencies health check endpoint failed",
            error=str(e),
            error_type=type(e).__name__
        )
        
        error_response = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'check_type': 'dependencies',
            'error': 'Dependencies health check execution failed',
            'error_details': str(e),
            'dependencies': {},
            'summary': {
                'total_dependencies': 0,
                'healthy_dependencies': 0,
                'degraded_dependencies': 0,
                'unhealthy_dependencies': 0
            }
        }
        
        return jsonify(error_response), 503


@health_blueprint.route('/metrics', methods=['GET'])
def prometheus_metrics():
    """
    Prometheus metrics endpoint per Section 6.5.1.1.
    
    Exposes comprehensive metrics in Prometheus format for monitoring system integration
    including application performance metrics, dependency health metrics, circuit breaker
    states, and performance variance tracking against Node.js baseline.
    
    Returns:
        Prometheus metrics in text/plain format
    """
    try:
        # Generate Prometheus metrics exposition
        from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
        
        # Get metrics registry from monitoring system
        metrics_data = generate_latest(METRICS_REGISTRY)
        
        logger.debug(
            "Prometheus metrics endpoint accessed",
            metrics_size_bytes=len(metrics_data),
            content_type=CONTENT_TYPE_LATEST
        )
        
        return metrics_data, 200, {'Content-Type': CONTENT_TYPE_LATEST}
        
    except Exception as e:
        logger.error(
            "Prometheus metrics endpoint failed",
            error=str(e),
            error_type=type(e).__name__
        )
        
        # Return error metrics in Prometheus format
        error_metrics = f"""# HELP health_blueprint_metrics_error Metrics endpoint error indicator
# TYPE health_blueprint_metrics_error gauge
health_blueprint_metrics_error{{error_type="{type(e).__name__}"}} 1
"""
        
        return error_metrics, 500, {'Content-Type': 'text/plain; charset=utf-8'}


@health_blueprint.errorhandler(Exception)
def handle_health_blueprint_error(error):
    """
    Global error handler for health blueprint endpoints.
    
    Provides consistent error response format and logging for all health
    blueprint endpoint errors while ensuring monitoring systems receive
    appropriate HTTP status codes.
    """
    logger.error(
        "Health blueprint error",
        error=str(error),
        error_type=type(error).__name__,
        endpoint=request.endpoint,
        method=request.method,
        url=request.url
    )
    
    error_response = {
        'status': 'error',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'error': 'Health check endpoint error',
        'error_details': str(error),
        'endpoint': request.endpoint,
        'method': request.method
    }
    
    # Determine appropriate HTTP status code
    if isinstance(error, ServiceUnavailable):
        status_code = 503
    elif isinstance(error, InternalServerError):
        status_code = 500
    else:
        status_code = 500
    
    return jsonify(error_response), status_code


def init_health_blueprint(app):
    """
    Initialize health blueprint with Flask application factory pattern per Section 6.1.1.
    
    Registers health monitoring blueprint with Flask application and configures
    health monitoring settings based on application configuration.
    
    Args:
        app: Flask application instance
    """
    try:
        # Configure health monitoring from Flask app config
        health_config = HealthCheckConfiguration(
            database_timeout_seconds=app.config.get('HEALTH_CHECK_DATABASE_TIMEOUT', 5.0),
            cache_timeout_seconds=app.config.get('HEALTH_CHECK_CACHE_TIMEOUT', 3.0),
            external_service_timeout_seconds=app.config.get('HEALTH_CHECK_EXTERNAL_TIMEOUT', 10.0),
            max_response_time_variance_percent=app.config.get('MAX_RESPONSE_TIME_VARIANCE_PERCENT', 10.0),
            enable_database_health_checks=app.config.get('ENABLE_DATABASE_HEALTH_CHECKS', True),
            enable_cache_health_checks=app.config.get('ENABLE_CACHE_HEALTH_CHECKS', True),
            enable_external_service_health_checks=app.config.get('ENABLE_EXTERNAL_SERVICE_HEALTH_CHECKS', True),
            prometheus_metrics_enabled=app.config.get('PROMETHEUS_METRICS_ENABLED', True),
            performance_variance_tracking=app.config.get('PERFORMANCE_VARIANCE_TRACKING', True)
        )
        
        # Update global health monitor configuration
        global health_monitor
        health_monitor.config = health_config
        
        # Register health blueprint
        app.register_blueprint(health_blueprint)
        
        # Store health monitor reference in app extensions
        if not hasattr(app, 'extensions'):
            app.extensions = {}
        app.extensions['health_monitor'] = health_monitor
        
        logger.info(
            "Health blueprint initialized",
            blueprint_name=health_blueprint.name,
            url_prefix=health_blueprint.url_prefix,
            endpoints=[
                '/health',
                '/health/live',
                '/health/ready',
                '/health/dependencies',
                '/health/metrics'
            ],
            database_health_checks=health_config.enable_database_health_checks,
            cache_health_checks=health_config.enable_cache_health_checks,
            external_service_checks=health_config.enable_external_service_health_checks,
            performance_variance_threshold=health_config.max_response_time_variance_percent
        )
        
    except Exception as e:
        logger.error(
            "Health blueprint initialization failed",
            error=str(e),
            error_type=type(e).__name__
        )
        raise


# Export health monitoring components for external use
__all__ = [
    'health_blueprint',
    'init_health_blueprint',
    'HealthMonitor',
    'HealthCheckConfiguration',
    'DependencyHealthStatus',
    'health_monitor'
]