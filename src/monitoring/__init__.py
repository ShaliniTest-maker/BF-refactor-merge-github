"""
Monitoring Module Initialization for Flask Migration Application

This module provides comprehensive monitoring initialization and Flask application factory integration
for enterprise-grade observability. Implements centralized monitoring setup including structured logging,
Prometheus metrics collection, health check endpoints, and APM integration for complete system visibility.

Key Features:
- Flask application factory pattern integration per Section 6.1.1
- Comprehensive observability stack: logging, metrics, health checks, APM per Section 6.5.1
- Enterprise APM integration (Datadog/New Relic) per Section 3.6.1
- Kubernetes-native health endpoints per Section 6.5.2.1
- Performance monitoring with ≤10% variance tracking per Section 0.1.1
- Centralized monitoring configuration and error handling
- Blueprint registration and Flask extension initialization
- Graceful degradation and monitoring system fault tolerance

Architecture Integration:
- Flask application factory initialization with monitoring extensions
- Blueprint registration for health check endpoints (/health/live, /health/ready)
- WSGI server instrumentation for Gunicorn/uWSGI deployment
- Enterprise monitoring integration (Splunk, ELK Stack, Prometheus)
- APM distributed tracing with correlation ID propagation
- Circuit breaker integration for external service monitoring
- Container orchestration health probe compatibility

Performance Requirements:
- Monitoring overhead: <2% CPU impact per Section 6.5.1.1
- Health check response time: <100ms per Section 6.5.2.1
- APM instrumentation latency: <1ms per request per Section 6.5.4.3
- Metrics collection efficiency: 15-second intervals per Section 6.5.1.1
- Log processing throughput: >15MB/min per Section 6.5.1.2

References:
- Section 6.1.1: Flask application factory pattern implementation
- Section 6.5.1: Comprehensive monitoring infrastructure requirements
- Section 3.6.1: Enterprise APM integration and logging systems
- Section 6.5.2.1: Kubernetes health probe endpoint specifications
- Section 6.5.4: Monitoring architecture overview and integration patterns
"""

import os
import logging
import traceback
import threading
from typing import Dict, Any, Optional, Callable, List
from functools import wraps

from flask import Flask, current_app, g, has_app_context
import structlog

# Monitoring component imports with graceful fallback handling
try:
    from .logging import (
        setup_structured_logging,
        create_flask_logging_middleware,
        get_logger,
        LoggingConfig,
        CorrelationManager,
        RequestContextManager,
        SecurityAuditLogger,
        PerformanceLogger
    )
    LOGGING_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Logging module import failed: {e}")
    LOGGING_AVAILABLE = False

try:
    from .metrics import (
        setup_metrics_collection,
        PrometheusMetricsCollector,
        MetricsMiddleware,
        create_metrics_endpoint,
        monitor_performance,
        monitor_database_operation,
        monitor_external_service,
        monitor_cache_operation
    )
    METRICS_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Metrics module import failed: {e}")
    METRICS_AVAILABLE = False

try:
    from .health import (
        init_health_monitoring,
        health_blueprint,
        HealthCheckEndpoints,
        DependencyHealthValidator,
        HealthState,
        HealthCheckResult,
        health_metrics
    )
    HEALTH_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Health module import failed: {e}")
    HEALTH_AVAILABLE = False

try:
    from .apm import (
        init_apm,
        APMIntegrationManager,
        APMConfig,
        CorrelationIDManager as APMCorrelationManager,
        trace_business_operation,
        trace_database_operation,
        trace_external_service
    )
    APM_AVAILABLE = True
except ImportError as e:
    print(f"Warning: APM module import failed: {e}")
    APM_AVAILABLE = False

# Optional configuration imports
try:
    from src.config.monitoring import MonitoringConfig
    CONFIG_AVAILABLE = True
except ImportError:
    # Fallback configuration class
    class MonitoringConfig:
        def __init__(self):
            self.MONITORING_ENABLED = os.getenv('MONITORING_ENABLED', 'true').lower() == 'true'
            self.STRUCTURED_LOGGING_ENABLED = os.getenv('STRUCTURED_LOGGING_ENABLED', 'true').lower() == 'true'
            self.PROMETHEUS_METRICS_ENABLED = os.getenv('PROMETHEUS_METRICS_ENABLED', 'true').lower() == 'true'
            self.HEALTH_CHECKS_ENABLED = os.getenv('HEALTH_CHECKS_ENABLED', 'true').lower() == 'true'
            self.APM_ENABLED = os.getenv('APM_ENABLED', 'false').lower() == 'true'
    CONFIG_AVAILABLE = False


class MonitoringInitializationError(Exception):
    """Custom exception for monitoring initialization failures."""
    pass


class MonitoringSystemManager:
    """
    Central monitoring system manager coordinating all monitoring components.
    
    Provides centralized initialization, configuration, and lifecycle management
    for the complete observability stack including logging, metrics, health checks,
    and APM integration with enterprise-grade fault tolerance.
    """
    
    def __init__(self, config: Optional[MonitoringConfig] = None):
        """
        Initialize monitoring system manager.
        
        Args:
            config: Monitoring configuration instance (optional)
        """
        self.config = config or MonitoringConfig()
        self.logger = None
        self.metrics_collector = None
        self.health_endpoints = None
        self.apm_manager = None
        self.correlation_manager = None
        self.request_context_manager = None
        
        # Component status tracking
        self.component_status = {
            'logging': False,
            'metrics': False,
            'health': False,
            'apm': False
        }
        
        # Initialization lock for thread safety
        self._init_lock = threading.Lock()
        self._initialized = False
        
        # Error tracking for graceful degradation
        self._initialization_errors = {}
    
    def initialize_monitoring_stack(self, app: Flask) -> Dict[str, Any]:
        """
        Initialize complete monitoring stack with Flask application integration.
        
        Args:
            app: Flask application instance
            
        Returns:
            Dictionary containing initialization status and component references
        """
        with self._init_lock:
            if self._initialized:
                return self._get_status_summary()
            
            initialization_summary = {
                'monitoring_enabled': self.config.MONITORING_ENABLED,
                'components_initialized': {},
                'initialization_errors': {},
                'flask_integration_status': 'pending'
            }
            
            if not self.config.MONITORING_ENABLED:
                initialization_summary['flask_integration_status'] = 'disabled'
                self._initialized = True
                return initialization_summary
            
            # Initialize structured logging first (foundation for other components)
            logging_status = self._initialize_structured_logging(app)
            initialization_summary['components_initialized']['logging'] = logging_status
            
            # Initialize metrics collection
            metrics_status = self._initialize_metrics_collection(app)
            initialization_summary['components_initialized']['metrics'] = metrics_status
            
            # Initialize health monitoring
            health_status = self._initialize_health_monitoring(app)
            initialization_summary['components_initialized']['health'] = health_status
            
            # Initialize APM integration
            apm_status = self._initialize_apm_integration(app)
            initialization_summary['components_initialized']['apm'] = apm_status
            
            # Setup Flask application integration
            flask_integration_status = self._setup_flask_integration(app)
            initialization_summary['flask_integration_status'] = flask_integration_status
            
            # Store initialization errors
            initialization_summary['initialization_errors'] = self._initialization_errors.copy()
            
            # Log initialization summary
            if self.logger:
                self.logger.info(
                    "Monitoring stack initialization completed",
                    monitoring_enabled=self.config.MONITORING_ENABLED,
                    logging_enabled=logging_status['enabled'],
                    metrics_enabled=metrics_status['enabled'],
                    health_enabled=health_status['enabled'],
                    apm_enabled=apm_status['enabled'],
                    flask_integration=flask_integration_status,
                    errors=list(self._initialization_errors.keys())
                )
            
            self._initialized = True
            return initialization_summary
    
    def _initialize_structured_logging(self, app: Flask) -> Dict[str, Any]:
        """Initialize structured logging with enterprise integration."""
        status = {
            'enabled': False,
            'component': 'logging',
            'details': {},
            'error': None
        }
        
        try:
            if not LOGGING_AVAILABLE:
                raise MonitoringInitializationError("Logging module not available")
            
            if not self.config.STRUCTURED_LOGGING_ENABLED:
                status['details']['reason'] = 'disabled_by_configuration'
                return status
            
            # Setup structured logging
            self.logger = setup_structured_logging(app)
            
            # Initialize correlation and context managers
            self.correlation_manager = CorrelationManager()
            self.request_context_manager = RequestContextManager()
            
            # Setup Flask logging middleware
            logging_middleware = create_flask_logging_middleware(self.logger)
            logging_middleware(app)
            
            # Store logger in app config for access by other components
            app.config['MONITORING_LOGGER'] = self.logger
            
            self.component_status['logging'] = True
            status['enabled'] = True
            status['details'] = {
                'structured_logging': True,
                'correlation_tracking': True,
                'flask_middleware': True,
                'enterprise_integration': LoggingConfig.ENTERPRISE_LOGGING_ENABLED
            }
            
            # Log successful initialization
            self.logger.info(
                "Structured logging initialized successfully",
                log_level=LoggingConfig.LOG_LEVEL,
                log_format=LoggingConfig.LOG_FORMAT,
                enterprise_logging=LoggingConfig.ENTERPRISE_LOGGING_ENABLED,
                correlation_tracking=LoggingConfig.CORRELATION_ID_ENABLED
            )
            
        except Exception as e:
            error_message = f"Structured logging initialization failed: {str(e)}"
            status['error'] = error_message
            self._initialization_errors['logging'] = error_message
            
            # Fallback to basic logging
            logging.basicConfig(level=logging.INFO)
            print(f"Warning: {error_message}")
            print(f"Traceback: {traceback.format_exc()}")
        
        return status
    
    def _initialize_metrics_collection(self, app: Flask) -> Dict[str, Any]:
        """Initialize Prometheus metrics collection with WSGI instrumentation."""
        status = {
            'enabled': False,
            'component': 'metrics',
            'details': {},
            'error': None
        }
        
        try:
            if not METRICS_AVAILABLE:
                raise MonitoringInitializationError("Metrics module not available")
            
            if not self.config.PROMETHEUS_METRICS_ENABLED:
                status['details']['reason'] = 'disabled_by_configuration'
                return status
            
            # Initialize Prometheus metrics collector
            self.metrics_collector = setup_metrics_collection(app, self.config)
            
            # Store metrics collector in app config
            app.config['MONITORING_METRICS'] = self.metrics_collector
            
            self.component_status['metrics'] = True
            status['enabled'] = True
            status['details'] = {
                'prometheus_integration': True,
                'wsgi_instrumentation': True,
                'custom_migration_metrics': True,
                'performance_tracking': True
            }
            
            if self.logger:
                self.logger.info(
                    "Prometheus metrics collection initialized",
                    metrics_endpoint='/metrics',
                    wsgi_instrumentation=True,
                    performance_tracking=True
                )
            
        except Exception as e:
            error_message = f"Metrics collection initialization failed: {str(e)}"
            status['error'] = error_message
            self._initialization_errors['metrics'] = error_message
            
            if self.logger:
                self.logger.error("Metrics initialization failed", error=str(e), exc_info=True)
            else:
                print(f"Warning: {error_message}")
                print(f"Traceback: {traceback.format_exc()}")
        
        return status
    
    def _initialize_health_monitoring(self, app: Flask) -> Dict[str, Any]:
        """Initialize health check endpoints with Kubernetes probe support."""
        status = {
            'enabled': False,
            'component': 'health',
            'details': {},
            'error': None
        }
        
        try:
            if not HEALTH_AVAILABLE:
                raise MonitoringInitializationError("Health module not available")
            
            if not self.config.HEALTH_CHECKS_ENABLED:
                status['details']['reason'] = 'disabled_by_configuration'
                return status
            
            # Initialize health monitoring
            init_health_monitoring(app)
            
            # Initialize health endpoints for programmatic access
            self.health_endpoints = HealthCheckEndpoints()
            
            # Store health endpoints in app config
            app.config['MONITORING_HEALTH'] = self.health_endpoints
            
            self.component_status['health'] = True
            status['enabled'] = True
            status['details'] = {
                'kubernetes_probes': True,
                'dependency_validation': True,
                'circuit_breaker_integration': True,
                'load_balancer_compatibility': True,
                'endpoints': ['/health/live', '/health/ready', '/health', '/health/dependencies']
            }
            
            if self.logger:
                self.logger.info(
                    "Health monitoring initialized",
                    kubernetes_probes=True,
                    endpoints=status['details']['endpoints'],
                    dependency_validation=True
                )
            
        except Exception as e:
            error_message = f"Health monitoring initialization failed: {str(e)}"
            status['error'] = error_message
            self._initialization_errors['health'] = error_message
            
            if self.logger:
                self.logger.error("Health monitoring initialization failed", error=str(e), exc_info=True)
            else:
                print(f"Warning: {error_message}")
                print(f"Traceback: {traceback.format_exc()}")
        
        return status
    
    def _initialize_apm_integration(self, app: Flask) -> Dict[str, Any]:
        """Initialize APM integration with enterprise monitoring systems."""
        status = {
            'enabled': False,
            'component': 'apm',
            'details': {},
            'error': None
        }
        
        try:
            if not APM_AVAILABLE:
                raise MonitoringInitializationError("APM module not available")
            
            if not self.config.APM_ENABLED:
                status['details']['reason'] = 'disabled_by_configuration'
                return status
            
            # Initialize APM integration
            self.apm_manager = init_apm(app, self.config)
            
            # Store APM manager in app config
            app.config['MONITORING_APM'] = self.apm_manager
            
            self.component_status['apm'] = True
            status['enabled'] = True
            status['details'] = {
                'distributed_tracing': True,
                'custom_attributes': self.apm_manager.apm_config.custom_attributes_enabled,
                'performance_tracking': self.apm_manager.apm_config.track_performance_variance,
                'datadog_enabled': self.apm_manager.apm_config.datadog_enabled,
                'newrelic_enabled': self.apm_manager.apm_config.newrelic_enabled,
                'correlation_id_propagation': True
            }
            
            if self.logger:
                self.logger.info(
                    "APM integration initialized",
                    service_name=self.apm_manager.apm_config.service_name,
                    environment=self.apm_manager.apm_config.environment,
                    datadog_enabled=self.apm_manager.apm_config.datadog_enabled,
                    newrelic_enabled=self.apm_manager.apm_config.newrelic_enabled,
                    distributed_tracing=True
                )
            
        except Exception as e:
            error_message = f"APM integration initialization failed: {str(e)}"
            status['error'] = error_message
            self._initialization_errors['apm'] = error_message
            
            if self.logger:
                self.logger.warning("APM integration failed, continuing without APM", error=str(e))
            else:
                print(f"Warning: {error_message}")
                print(f"Note: Application will continue without APM integration")
        
        return status
    
    def _setup_flask_integration(self, app: Flask) -> str:
        """Setup Flask application integration and configuration."""
        try:
            # Store monitoring manager in app config
            app.config['MONITORING_MANAGER'] = self
            app.config['MONITORING_CONFIG'] = self.config
            
            # Setup monitoring context processors
            self._setup_context_processors(app)
            
            # Setup error handlers for monitoring
            self._setup_error_handlers(app)
            
            # Add monitoring utility functions to app
            self._setup_utility_functions(app)
            
            if self.logger:
                self.logger.info(
                    "Flask monitoring integration completed",
                    components_enabled=list(k for k, v in self.component_status.items() if v),
                    monitoring_overhead_target="<2% CPU",
                    performance_variance_tracking="≤10% threshold"
                )
            
            return 'success'
            
        except Exception as e:
            error_message = f"Flask integration setup failed: {str(e)}"
            self._initialization_errors['flask_integration'] = error_message
            
            if self.logger:
                self.logger.error("Flask integration failed", error=str(e), exc_info=True)
            else:
                print(f"Error: {error_message}")
                print(f"Traceback: {traceback.format_exc()}")
            
            return 'failed'
    
    def _setup_context_processors(self, app: Flask):
        """Setup Flask context processors for monitoring integration."""
        @app.context_processor
        def inject_monitoring_context():
            """Inject monitoring context into Flask templates."""
            context = {}
            
            # Add correlation ID if available
            if self.correlation_manager and has_app_context():
                try:
                    correlation_id = self.correlation_manager.get_correlation_id()
                    if correlation_id:
                        context['correlation_id'] = correlation_id
                except Exception:
                    pass
            
            # Add monitoring status
            context['monitoring_enabled'] = self.config.MONITORING_ENABLED
            context['monitoring_components'] = {
                k: v for k, v in self.component_status.items() if v
            }
            
            return context
    
    def _setup_error_handlers(self, app: Flask):
        """Setup error handlers with monitoring integration."""
        @app.errorhandler(Exception)
        def handle_monitoring_exception(error):
            """Handle exceptions with monitoring context."""
            try:
                # Log error with monitoring context
                if self.logger:
                    correlation_id = None
                    if self.correlation_manager:
                        correlation_id = self.correlation_manager.get_correlation_id()
                    
                    self.logger.error(
                        "Application exception occurred",
                        exception_type=type(error).__name__,
                        exception_message=str(error),
                        correlation_id=correlation_id,
                        endpoint=getattr(g, 'endpoint', 'unknown'),
                        method=getattr(g, 'method', 'unknown'),
                        exc_info=True
                    )
                
                # Record exception in APM if available
                if self.apm_manager:
                    self.apm_manager.add_custom_attributes({
                        'error.type': type(error).__name__,
                        'error.message': str(error),
                        'error.handled': True
                    })
                
                # Record exception metrics if available
                if self.metrics_collector:
                    # This would be implemented in the metrics collector
                    pass
            
            except Exception as monitoring_error:
                # Don't let monitoring errors break the application
                print(f"Monitoring error handling failed: {monitoring_error}")
            
            # Re-raise the original exception for normal Flask error handling
            raise error
    
    def _setup_utility_functions(self, app: Flask):
        """Setup utility functions for easy monitoring access."""
        # Add monitoring utility functions to app
        app.get_monitoring_logger = lambda: self.logger
        app.get_metrics_collector = lambda: self.metrics_collector
        app.get_health_endpoints = lambda: self.health_endpoints
        app.get_apm_manager = lambda: self.apm_manager
        
        # Add convenience methods for adding monitoring context
        def add_user_context(user_id: str, user_role: str = None, **kwargs):
            """Add user context to monitoring systems."""
            if self.apm_manager:
                self.apm_manager.add_user_context(user_id, user_role, kwargs)
        
        def add_business_context(operation: str, entity_type: str = None, **kwargs):
            """Add business context to monitoring systems."""
            if self.apm_manager:
                self.apm_manager.add_business_context(operation, entity_type, additional_context=kwargs)
        
        def set_performance_baseline(endpoint: str, baseline_time: float):
            """Set Node.js performance baseline for comparison."""
            if self.apm_manager:
                self.apm_manager.set_performance_baseline(endpoint, baseline_time)
        
        app.add_user_context = add_user_context
        app.add_business_context = add_business_context
        app.set_performance_baseline = set_performance_baseline
    
    def _get_status_summary(self) -> Dict[str, Any]:
        """Get current monitoring system status summary."""
        return {
            'monitoring_enabled': self.config.MONITORING_ENABLED,
            'initialized': self._initialized,
            'components_status': self.component_status.copy(),
            'initialization_errors': self._initialization_errors.copy(),
            'available_modules': {
                'logging': LOGGING_AVAILABLE,
                'metrics': METRICS_AVAILABLE,
                'health': HEALTH_AVAILABLE,
                'apm': APM_AVAILABLE
            }
        }
    
    def get_monitoring_status(self) -> Dict[str, Any]:
        """
        Get comprehensive monitoring system status.
        
        Returns:
            Dictionary containing detailed monitoring status
        """
        status = self._get_status_summary()
        
        # Add runtime status information
        if self._initialized:
            status['runtime_status'] = {
                'logging_active': bool(self.logger),
                'metrics_collecting': bool(self.metrics_collector),
                'health_checks_active': bool(self.health_endpoints),
                'apm_tracing': bool(self.apm_manager),
                'correlation_tracking': bool(self.correlation_manager)
            }
        
        return status


# Global monitoring manager instance for Flask application factory integration
_monitoring_manager: Optional[MonitoringSystemManager] = None
_monitoring_lock = threading.Lock()


def init_monitoring(app: Flask, config: Optional[MonitoringConfig] = None) -> MonitoringSystemManager:
    """
    Initialize comprehensive monitoring stack for Flask application.
    
    This function provides the main entry point for monitoring system initialization,
    implementing enterprise-grade observability with graceful degradation and
    comprehensive error handling.
    
    Args:
        app: Flask application instance
        config: Monitoring configuration (optional)
        
    Returns:
        MonitoringSystemManager: Initialized monitoring system manager
        
    Example:
        ```python
        from src.monitoring import init_monitoring
        
        def create_app():
            app = Flask(__name__)
            
            # Initialize monitoring stack
            monitoring_manager = init_monitoring(app)
            
            # Check initialization status
            status = monitoring_manager.get_monitoring_status()
            app.logger.info(f"Monitoring status: {status}")
            
            return app
        ```
    """
    global _monitoring_manager
    
    with _monitoring_lock:
        if _monitoring_manager is None:
            _monitoring_manager = MonitoringSystemManager(config)
        
        # Initialize monitoring stack with Flask application
        initialization_result = _monitoring_manager.initialize_monitoring_stack(app)
        
        # Print initialization summary (before logger might be available)
        print("=" * 80)
        print("MONITORING STACK INITIALIZATION SUMMARY")
        print("=" * 80)
        print(f"Monitoring Enabled: {initialization_result['monitoring_enabled']}")
        print(f"Flask Integration: {initialization_result['flask_integration_status']}")
        print()
        
        for component, status in initialization_result['components_initialized'].items():
            enabled = "✓" if status['enabled'] else "✗"
            print(f"{component.upper():12} {enabled} {'Enabled' if status['enabled'] else 'Disabled'}")
            if status.get('error'):
                print(f"             ⚠ Error: {status['error']}")
        
        if initialization_result['initialization_errors']:
            print("\nInitialization Errors:")
            for component, error in initialization_result['initialization_errors'].items():
                print(f"  {component}: {error}")
        
        print("=" * 80)
        
        return _monitoring_manager


def get_monitoring_manager() -> Optional[MonitoringSystemManager]:
    """
    Get the global monitoring manager instance.
    
    Returns:
        MonitoringSystemManager or None if not initialized
    """
    return _monitoring_manager


# Convenience functions for direct access to monitoring components
def get_monitoring_logger() -> Optional[structlog.stdlib.BoundLogger]:
    """Get the structured monitoring logger."""
    if _monitoring_manager and _monitoring_manager.logger:
        return _monitoring_manager.logger
    return None


def get_metrics_collector() -> Optional[PrometheusMetricsCollector]:
    """Get the Prometheus metrics collector."""
    if _monitoring_manager and _monitoring_manager.metrics_collector:
        return _monitoring_manager.metrics_collector
    return None


def get_health_endpoints() -> Optional[HealthCheckEndpoints]:
    """Get the health check endpoints manager."""
    if _monitoring_manager and _monitoring_manager.health_endpoints:
        return _monitoring_manager.health_endpoints
    return None


def get_apm_manager() -> Optional[APMIntegrationManager]:
    """Get the APM integration manager."""
    if _monitoring_manager and _monitoring_manager.apm_manager:
        return _monitoring_manager.apm_manager
    return None


# Re-export key monitoring components for convenient access
__all__ = [
    # Core initialization
    'init_monitoring',
    'MonitoringSystemManager',
    'MonitoringInitializationError',
    
    # Access functions
    'get_monitoring_manager',
    'get_monitoring_logger',
    'get_metrics_collector',
    'get_health_endpoints',
    'get_apm_manager',
    
    # Logging components (if available)
    *(
        [
            'setup_structured_logging',
            'create_flask_logging_middleware',
            'get_logger',
            'LoggingConfig',
            'CorrelationManager',
            'RequestContextManager',
            'SecurityAuditLogger',
            'PerformanceLogger'
        ] if LOGGING_AVAILABLE else []
    ),
    
    # Metrics components (if available)
    *(
        [
            'setup_metrics_collection',
            'PrometheusMetricsCollector',
            'MetricsMiddleware',
            'create_metrics_endpoint',
            'monitor_performance',
            'monitor_database_operation',
            'monitor_external_service',
            'monitor_cache_operation'
        ] if METRICS_AVAILABLE else []
    ),
    
    # Health check components (if available)
    *(
        [
            'init_health_monitoring',
            'health_blueprint',
            'HealthCheckEndpoints',
            'DependencyHealthValidator',
            'HealthState',
            'HealthCheckResult',
            'health_metrics'
        ] if HEALTH_AVAILABLE else []
    ),
    
    # APM components (if available)
    *(
        [
            'init_apm',
            'APMIntegrationManager',
            'APMConfig',
            'trace_business_operation',
            'trace_database_operation',
            'trace_external_service'
        ] if APM_AVAILABLE else []
    ),
    
    # Module availability flags
    'LOGGING_AVAILABLE',
    'METRICS_AVAILABLE', 
    'HEALTH_AVAILABLE',
    'APM_AVAILABLE',
    'CONFIG_AVAILABLE'
]


# Module-level initialization logging
if __name__ != '__main__':
    # Print module loading status
    available_components = []
    if LOGGING_AVAILABLE:
        available_components.append('logging')
    if METRICS_AVAILABLE:
        available_components.append('metrics')
    if HEALTH_AVAILABLE:
        available_components.append('health')
    if APM_AVAILABLE:
        available_components.append('apm')
    
    print(f"Monitoring module loaded with components: {', '.join(available_components)}")
    if not available_components:
        print("Warning: No monitoring components available - check dependencies")