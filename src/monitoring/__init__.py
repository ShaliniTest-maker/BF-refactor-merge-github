"""
Monitoring Module Initialization

Central entry point for comprehensive Flask application monitoring providing enterprise-grade
observability through structured logging, Prometheus metrics collection, health check endpoints,
and APM integration. Implements Flask application factory pattern for seamless integration.

This module serves as the unified interface for:
- Structured logging with enterprise SIEM integration (structlog 23.1+)
- Prometheus metrics collection and WSGI server instrumentation
- Kubernetes-native health check endpoints (/health/live, /health/ready)
- Enterprise APM integration (Datadog ddtrace 2.1+, New Relic 9.2+)
- Performance monitoring for ≤10% variance compliance with Node.js baseline
- Circuit breaker patterns and dependency health validation

Key Features:
- Flask application factory pattern integration per Section 6.1.1
- Comprehensive observability stack per Section 6.5.1
- Enterprise APM compatibility per Section 3.6.1  
- Kubernetes health probe endpoints per Section 6.5.2.1
- Centralized monitoring configuration and initialization
- Performance variance tracking for migration quality assurance

Usage:
    from src.monitoring import init_monitoring
    
    app = Flask(__name__)
    monitoring = init_monitoring(app)

Compliance:
- Section 6.1.1: Flask application factory pattern implementation
- Section 6.5.1: Comprehensive observability capabilities
- Section 3.6.1: Enterprise APM integration requirements
- Section 6.5.2.1: Health check endpoints for container orchestration
- Section 6.5.4: Monitoring architecture overview and component integration
"""

import os
import time
import logging
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass

from flask import Flask
import structlog

# Import all monitoring components
from .logging import (
    init_logging,
    configure_structlog,
    get_logger,
    RequestLoggingMiddleware,
    set_correlation_id,
    set_user_context,
    set_request_id,
    clear_request_context,
    log_security_event,
    log_performance_metric,
    log_business_event,
    log_integration_event
)

from .metrics import (
    init_metrics,
    start_metrics_server,
    FlaskMetricsCollector,
    metrics_collector,
    track_business_operation,
    track_external_service_call,
    track_database_operation,
    update_cache_metrics,
    update_auth_metrics,
    set_nodejs_baseline,
    get_performance_summary,
    METRICS_REGISTRY
)

from .health import (
    init_health_monitoring,
    get_health_status,
    get_circuit_breaker_states,
    HealthChecker,
    health_checker,
    HealthStatus,
    DependencyType,
    HealthCheckResult,
    SystemHealth,
    CircuitBreakerState,
    circuit_breaker
)

from .apm import (
    create_apm_integration,
    init_apm_with_app,
    APMIntegration,
    APMConfiguration,
    APMProvider
)


# Initialize module-level logger
logger = structlog.get_logger(__name__)


@dataclass
class MonitoringConfiguration:
    """
    Comprehensive monitoring configuration for enterprise observability stack.
    
    Consolidates configuration for logging, metrics, health checks, and APM
    with environment-specific settings and performance optimization.
    """
    # Core monitoring settings
    enable_logging: bool = True
    enable_metrics: bool = True
    enable_health_checks: bool = True
    enable_apm: bool = True
    
    # Environment and service identification
    environment: str = "development"
    service_name: str = "flask-migration-app"
    service_version: str = "1.0.0"
    instance_id: str = None
    
    # Logging configuration
    log_level: str = "INFO"
    log_format: str = "json"
    enable_correlation_id: bool = True
    enable_security_audit: bool = True
    
    # Metrics configuration
    metrics_port: int = 8000
    enable_multiprocess_metrics: bool = True
    nodejs_baseline_enabled: bool = True
    performance_variance_threshold: float = 0.10  # 10% variance threshold
    
    # Health check configuration
    health_check_timeout: float = 10.0
    enable_dependency_checks: bool = True
    enable_circuit_breakers: bool = True
    
    # APM configuration
    apm_provider: str = "datadog"
    apm_sample_rate: Optional[float] = None
    enable_distributed_tracing: bool = True
    enable_performance_correlation: bool = True
    
    # Enterprise integration settings
    enable_prometheus_multiproc: bool = True
    enable_kubernetes_probes: bool = True
    enable_load_balancer_health: bool = True
    
    def __post_init__(self):
        """Initialize derived configuration values."""
        if self.instance_id is None:
            self.instance_id = os.environ.get('HOSTNAME', f'flask-{os.getpid()}')
        
        # Set environment-specific defaults
        if self.environment == "production":
            self.apm_sample_rate = self.apm_sample_rate or 0.1
            self.log_level = "WARNING"
        elif self.environment == "staging":
            self.apm_sample_rate = self.apm_sample_rate or 0.5
            self.log_level = "INFO"
        else:  # development
            self.apm_sample_rate = self.apm_sample_rate or 1.0
            self.log_level = "DEBUG"


class MonitoringStack:
    """
    Comprehensive monitoring stack manager providing unified initialization and management
    of all observability components for Flask applications.
    
    Implements enterprise-grade monitoring patterns with Flask application factory
    integration, comprehensive observability capabilities, and performance tracking.
    """
    
    def __init__(self, config: Optional[MonitoringConfiguration] = None):
        """
        Initialize monitoring stack with comprehensive configuration.
        
        Args:
            config: Monitoring configuration (auto-generated if not provided)
        """
        self.config = config or self._create_default_config()
        self.app: Optional[Flask] = None
        self.is_initialized = False
        
        # Component instances
        self.logging_middleware: Optional[RequestLoggingMiddleware] = None
        self.metrics_collector: Optional[FlaskMetricsCollector] = None
        self.health_checker: Optional[HealthChecker] = None
        self.apm_integration: Optional[APMIntegration] = None
        
        # Performance tracking
        self.start_time = time.time()
        self.initialization_metrics = {
            "logging_initialized": False,
            "metrics_initialized": False,
            "health_initialized": False,
            "apm_initialized": False,
            "total_init_time": 0.0
        }
        
        logger.info(
            "Monitoring stack created",
            service_name=self.config.service_name,
            environment=self.config.environment,
            instance_id=self.config.instance_id
        )
    
    def _create_default_config(self) -> MonitoringConfiguration:
        """Create default monitoring configuration from environment variables."""
        return MonitoringConfiguration(
            environment=os.getenv("FLASK_ENV", "development"),
            service_name=os.getenv("SERVICE_NAME", "flask-migration-app"),
            service_version=os.getenv("APP_VERSION", "1.0.0"),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            log_format=os.getenv("LOG_FORMAT", "json"),
            apm_provider=os.getenv("APM_PROVIDER", "datadog"),
            enable_correlation_id=os.getenv("ENABLE_CORRELATION_ID", "true").lower() == "true",
            enable_security_audit=os.getenv("ENABLE_SECURITY_AUDIT", "true").lower() == "true",
            enable_distributed_tracing=os.getenv("ENABLE_DISTRIBUTED_TRACING", "true").lower() == "true"
        )
    
    def init_app(self, app: Flask) -> 'MonitoringStack':
        """
        Initialize comprehensive monitoring for Flask application using factory pattern.
        
        Implements Section 6.1.1 Flask application factory pattern with centralized
        monitoring initialization, Section 6.5.1 comprehensive observability capabilities,
        and Section 6.5.4 monitoring architecture integration.
        
        Args:
            app: Flask application instance for monitoring integration
            
        Returns:
            MonitoringStack: Self-reference for method chaining
        """
        if self.is_initialized:
            logger.warning("Monitoring stack already initialized")
            return self
        
        self.app = app
        init_start_time = time.time()
        
        try:
            # Store monitoring configuration in Flask app config
            app.config.update({
                'MONITORING_ENABLED': True,
                'MONITORING_SERVICE_NAME': self.config.service_name,
                'MONITORING_ENVIRONMENT': self.config.environment,
                'MONITORING_INSTANCE_ID': self.config.instance_id
            })
            
            # Initialize logging subsystem
            if self.config.enable_logging:
                self._init_logging(app)
            
            # Initialize metrics collection
            if self.config.enable_metrics:
                self._init_metrics(app)
            
            # Initialize health monitoring
            if self.config.enable_health_checks:
                self._init_health_monitoring(app)
            
            # Initialize APM integration
            if self.config.enable_apm:
                self._init_apm(app)
            
            # Store monitoring stack reference in Flask app extensions
            app.extensions = getattr(app, 'extensions', {})
            app.extensions['monitoring'] = self
            
            # Record initialization completion
            self.initialization_metrics['total_init_time'] = time.time() - init_start_time
            self.is_initialized = True
            
            # Log comprehensive initialization summary
            logger.info(
                "Monitoring stack initialized successfully",
                service_name=self.config.service_name,
                environment=self.config.environment,
                instance_id=self.config.instance_id,
                initialization_time_ms=round(self.initialization_metrics['total_init_time'] * 1000, 2),
                components_initialized={
                    'logging': self.initialization_metrics['logging_initialized'],
                    'metrics': self.initialization_metrics['metrics_initialized'],
                    'health': self.initialization_metrics['health_initialized'],
                    'apm': self.initialization_metrics['apm_initialized']
                },
                endpoints_registered=[
                    '/health/live',
                    '/health/ready', 
                    '/health',
                    '/health/dependencies',
                    '/metrics'
                ]
            )
            
            return self
            
        except Exception as e:
            logger.error(
                "Failed to initialize monitoring stack",
                error=str(e),
                service_name=self.config.service_name,
                environment=self.config.environment,
                initialization_time_ms=round((time.time() - init_start_time) * 1000, 2)
            )
            raise
    
    def _init_logging(self, app: Flask) -> None:
        """
        Initialize structured logging with enterprise integration.
        
        Implements comprehensive structured logging per Section 6.5.1.2 with
        JSON formatting, correlation ID tracking, and enterprise SIEM compatibility.
        """
        try:
            # Configure Flask app logging settings
            app.config.update({
                'LOG_LEVEL': self.config.log_level,
                'LOG_FORMAT': self.config.log_format,
                'ENABLE_CORRELATION_ID': self.config.enable_correlation_id,
                'ENABLE_SECURITY_AUDIT': self.config.enable_security_audit
            })
            
            # Initialize comprehensive logging system
            init_logging(app)
            
            # Store logging middleware reference
            self.logging_middleware = app.request_logging_middleware
            
            self.initialization_metrics['logging_initialized'] = True
            
            logger.info(
                "Structured logging initialized",
                log_level=self.config.log_level,
                log_format=self.config.log_format,
                correlation_id_enabled=self.config.enable_correlation_id,
                security_audit_enabled=self.config.enable_security_audit
            )
            
        except Exception as e:
            logger.error("Failed to initialize logging", error=str(e))
            raise
    
    def _init_metrics(self, app: Flask) -> None:
        """
        Initialize Prometheus metrics collection with WSGI server instrumentation.
        
        Implements Section 6.5.1.1 metrics collection and Section 6.5.4.1 WSGI server
        instrumentation for comprehensive performance monitoring.
        """
        try:
            # Initialize metrics collector with Flask application
            self.metrics_collector = init_metrics(app)
            
            # Configure Node.js baseline tracking if enabled
            if self.config.nodejs_baseline_enabled:
                self._setup_nodejs_baseline_tracking()
            
            # Start standalone metrics server if configured
            if self.config.metrics_port and self.config.metrics_port != 0:
                try:
                    start_metrics_server(self.config.metrics_port)
                except Exception as e:
                    logger.warning(
                        "Failed to start standalone metrics server",
                        error=str(e),
                        port=self.config.metrics_port
                    )
            
            self.initialization_metrics['metrics_initialized'] = True
            
            logger.info(
                "Prometheus metrics collection initialized",
                multiprocess_enabled=self.config.enable_multiprocess_metrics,
                nodejs_baseline_enabled=self.config.nodejs_baseline_enabled,
                variance_threshold_percent=round(self.config.performance_variance_threshold * 100, 1),
                metrics_port=self.config.metrics_port
            )
            
        except Exception as e:
            logger.error("Failed to initialize metrics collection", error=str(e))
            raise
    
    def _init_health_monitoring(self, app: Flask) -> None:
        """
        Initialize comprehensive health check endpoints.
        
        Implements Section 6.5.2.1 Kubernetes probe endpoints and load balancer
        integration with dependency health validation and circuit breaker monitoring.
        """
        try:
            # Initialize health checker with Flask application
            self.health_checker = init_health_monitoring(app)
            
            self.initialization_metrics['health_initialized'] = True
            
            logger.info(
                "Health monitoring initialized",
                kubernetes_probes_enabled=self.config.enable_kubernetes_probes,
                dependency_checks_enabled=self.config.enable_dependency_checks,
                circuit_breakers_enabled=self.config.enable_circuit_breakers,
                health_check_timeout=self.config.health_check_timeout
            )
            
        except Exception as e:
            logger.error("Failed to initialize health monitoring", error=str(e))
            raise
    
    def _init_apm(self, app: Flask) -> None:
        """
        Initialize enterprise APM integration.
        
        Implements Section 3.6.1 enterprise APM integration with distributed tracing,
        performance correlation analysis, and environment-specific sampling.
        """
        try:
            # Create APM integration with environment-specific configuration
            self.apm_integration = init_apm_with_app(
                app,
                provider=self.config.apm_provider,
                environment=self.config.environment,
                service_name=self.config.service_name,
                sample_rates={
                    "production": 0.1,
                    "staging": 0.5,
                    "development": 1.0,
                    "testing": 0.0
                },
                distributed_tracing=self.config.enable_distributed_tracing,
                enable_performance_correlation=self.config.enable_performance_correlation,
                baseline_variance_threshold=self.config.performance_variance_threshold
            )
            
            self.initialization_metrics['apm_initialized'] = True
            
            logger.info(
                "APM integration initialized",
                provider=self.config.apm_provider,
                sample_rate=self.config.apm_sample_rate,
                distributed_tracing=self.config.enable_distributed_tracing,
                performance_correlation=self.config.enable_performance_correlation
            )
            
        except Exception as e:
            logger.warning(
                "APM integration failed - continuing without APM",
                error=str(e),
                provider=self.config.apm_provider
            )
            # APM failure is not critical - continue without it
            self.initialization_metrics['apm_initialized'] = False
    
    def _setup_nodejs_baseline_tracking(self) -> None:
        """
        Set up Node.js baseline performance tracking for migration compliance.
        
        Loads Node.js baseline metrics and configures variance tracking for
        ≤10% performance compliance monitoring.
        """
        try:
            # Load Node.js baseline metrics from configuration or external source
            # This would typically be loaded from a configuration file or metrics store
            nodejs_baselines = self._load_nodejs_baselines()
            
            if nodejs_baselines:
                for endpoint, baseline_ms in nodejs_baselines.items():
                    baseline_seconds = baseline_ms / 1000.0
                    set_nodejs_baseline(endpoint, baseline_seconds)
                
                logger.info(
                    "Node.js baseline tracking configured",
                    baselines_loaded=len(nodejs_baselines),
                    variance_threshold_percent=round(self.config.performance_variance_threshold * 100, 1)
                )
            else:
                logger.warning("No Node.js baseline metrics available for tracking")
                
        except Exception as e:
            logger.error("Failed to setup Node.js baseline tracking", error=str(e))
    
    def _load_nodejs_baselines(self) -> Dict[str, float]:
        """
        Load Node.js baseline performance metrics.
        
        Returns:
            Dict[str, float]: Mapping of endpoint names to baseline duration in milliseconds
        """
        # Placeholder implementation - would load from configuration or external source
        # In production, this would load from a configuration file, environment variables,
        # or a metrics store containing the Node.js baseline measurements
        
        baselines_env = os.getenv('NODEJS_BASELINES')
        if baselines_env:
            try:
                import json
                return json.loads(baselines_env)
            except (json.JSONDecodeError, TypeError):
                logger.warning("Invalid NODEJS_BASELINES environment variable format")
        
        # Default baseline values for common endpoints (example data)
        return {
            "api.auth.login": 250.0,
            "api.users.list": 150.0,
            "api.users.create": 300.0,
            "api.users.update": 200.0,
            "api.data.query": 500.0
        }
    
    def get_monitoring_status(self) -> Dict[str, Any]:
        """
        Get comprehensive monitoring system status.
        
        Returns:
            Dict[str, Any]: Complete monitoring status including all components
        """
        status = {
            "service_name": self.config.service_name,
            "environment": self.config.environment,
            "instance_id": self.config.instance_id,
            "uptime_seconds": time.time() - self.start_time,
            "is_initialized": self.is_initialized,
            "initialization_metrics": self.initialization_metrics.copy(),
            "components": {
                "logging": {
                    "enabled": self.config.enable_logging,
                    "initialized": self.initialization_metrics['logging_initialized'],
                    "log_level": self.config.log_level,
                    "log_format": self.config.log_format
                },
                "metrics": {
                    "enabled": self.config.enable_metrics,
                    "initialized": self.initialization_metrics['metrics_initialized'],
                    "multiprocess": self.config.enable_multiprocess_metrics,
                    "nodejs_baseline": self.config.nodejs_baseline_enabled
                },
                "health_checks": {
                    "enabled": self.config.enable_health_checks,
                    "initialized": self.initialization_metrics['health_initialized'],
                    "dependency_checks": self.config.enable_dependency_checks,
                    "circuit_breakers": self.config.enable_circuit_breakers
                },
                "apm": {
                    "enabled": self.config.enable_apm,
                    "initialized": self.initialization_metrics['apm_initialized'],
                    "provider": self.config.apm_provider,
                    "sample_rate": self.config.apm_sample_rate,
                    "distributed_tracing": self.config.enable_distributed_tracing
                }
            }
        }
        
        # Add component-specific status if available
        if self.metrics_collector:
            try:
                performance_summary = get_performance_summary()
                status["performance_summary"] = performance_summary
            except Exception:
                pass
        
        if self.health_checker:
            try:
                health_status = get_health_status()
                status["health_status"] = health_status
            except Exception:
                pass
        
        if self.apm_integration:
            try:
                apm_summary = self.apm_integration.get_performance_summary()
                status["apm_summary"] = apm_summary
            except Exception:
                pass
        
        return status
    
    def configure_nodejs_baseline(self, endpoint: str, baseline_ms: float) -> None:
        """
        Configure Node.js baseline for specific endpoint.
        
        Args:
            endpoint: API endpoint name
            baseline_ms: Baseline response time in milliseconds
        """
        if self.metrics_collector:
            baseline_seconds = baseline_ms / 1000.0
            set_nodejs_baseline(endpoint, baseline_seconds)
            
            logger.info(
                "Node.js baseline configured",
                endpoint=endpoint,
                baseline_ms=baseline_ms,
                variance_threshold_percent=round(self.config.performance_variance_threshold * 100, 1)
            )
        else:
            logger.warning("Cannot configure baseline - metrics collector not initialized")
    
    def track_migration_event(self, event_type: str, details: Dict[str, Any] = None) -> None:
        """
        Track migration-specific events for quality assurance monitoring.
        
        Args:
            event_type: Migration event type
            details: Additional event details
        """
        event_data = {
            "migration_event": True,
            "event_type": event_type,
            "service_name": self.config.service_name,
            "environment": self.config.environment,
            "instance_id": self.config.instance_id
        }
        
        if details:
            event_data.update(details)
        
        log_business_event(f"migration_{event_type}", event_data)


# Global monitoring stack instance
_monitoring_stack: Optional[MonitoringStack] = None


def init_monitoring(
    app: Flask,
    config: Optional[MonitoringConfiguration] = None,
    **kwargs
) -> MonitoringStack:
    """
    Initialize comprehensive monitoring for Flask application using factory pattern.
    
    Primary entry point for monitoring system initialization implementing Section 6.1.1
    Flask application factory pattern, Section 6.5.1 comprehensive observability capabilities,
    and Section 6.5.4 monitoring architecture integration.
    
    Args:
        app: Flask application instance for monitoring integration
        config: Optional monitoring configuration (auto-generated if not provided)
        **kwargs: Additional configuration overrides
        
    Returns:
        MonitoringStack: Initialized monitoring stack for the application
        
    Example:
        app = Flask(__name__)
        monitoring = init_monitoring(app)
        
        # Configure Node.js baselines for performance tracking
        monitoring.configure_nodejs_baseline("api.users.list", 150.0)
        
        # Track migration events
        monitoring.track_migration_event("performance_baseline_set")
    """
    global _monitoring_stack
    
    # Create configuration with overrides
    if config is None:
        config = MonitoringConfiguration(**kwargs)
    else:
        # Apply kwargs overrides to provided config
        for key, value in kwargs.items():
            if hasattr(config, key):
                setattr(config, key, value)
    
    # Create and initialize monitoring stack
    _monitoring_stack = MonitoringStack(config)
    _monitoring_stack.init_app(app)
    
    return _monitoring_stack


def get_monitoring_stack() -> Optional[MonitoringStack]:
    """
    Get the global monitoring stack instance.
    
    Returns:
        Optional[MonitoringStack]: Global monitoring stack if initialized
    """
    return _monitoring_stack


def get_monitoring_status() -> Dict[str, Any]:
    """
    Get comprehensive monitoring system status.
    
    Returns:
        Dict[str, Any]: Monitoring status or error information
    """
    if _monitoring_stack:
        return _monitoring_stack.get_monitoring_status()
    else:
        return {
            "status": "not_initialized",
            "message": "Monitoring stack has not been initialized",
            "timestamp": time.time()
        }


# Re-export key interfaces for convenient access
from .logging import logger as monitoring_logger


# Export comprehensive public interface
__all__ = [
    # Core initialization
    'init_monitoring',
    'MonitoringConfiguration',
    'MonitoringStack',
    'get_monitoring_stack',
    'get_monitoring_status',
    
    # Logging components
    'init_logging',
    'configure_structlog',
    'get_logger',
    'RequestLoggingMiddleware',
    'set_correlation_id',
    'set_user_context',
    'set_request_id',
    'clear_request_context',
    'log_security_event',
    'log_performance_metric',
    'log_business_event',
    'log_integration_event',
    'monitoring_logger',
    
    # Metrics components
    'init_metrics',
    'start_metrics_server',
    'FlaskMetricsCollector',
    'metrics_collector',
    'track_business_operation',
    'track_external_service_call',
    'track_database_operation',
    'update_cache_metrics',
    'update_auth_metrics',
    'set_nodejs_baseline',
    'get_performance_summary',
    'METRICS_REGISTRY',
    
    # Health monitoring components
    'init_health_monitoring',
    'get_health_status',
    'get_circuit_breaker_states',
    'HealthChecker',
    'health_checker',
    'HealthStatus',
    'DependencyType',
    'HealthCheckResult',
    'SystemHealth',
    'CircuitBreakerState',
    'circuit_breaker',
    
    # APM components
    'create_apm_integration',
    'init_apm_with_app',
    'APMIntegration',
    'APMConfiguration',
    'APMProvider'
]