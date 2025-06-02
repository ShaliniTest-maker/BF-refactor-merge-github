"""
Monitoring and Observability Configuration

This module provides comprehensive monitoring and observability configuration implementing:
- structlog 23.1+ for structured logging equivalent to Node.js logging patterns
- prometheus-client 0.17+ for metrics collection and enterprise integration
- APM integration configuration for enterprise tools (Datadog, New Relic)
- Performance monitoring configuration to ensure ≤10% variance compliance
- Health check endpoints configuration for Kubernetes and load balancer integration
- Enterprise logging systems integration (ELK Stack, Splunk) configuration

Author: Blitzy Development Team
Version: 1.0.0
Date: 2024
"""

import os
import logging
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, field
from datetime import timedelta


@dataclass
class StructuredLoggingConfig:
    """
    Structured logging configuration using structlog 23.1+ equivalent to Node.js logging patterns.
    
    Provides JSON-formatted enterprise logging compatible with centralized log aggregation
    systems including ELK Stack and Splunk integration.
    """
    
    # Log level configuration
    default_level: str = "INFO"
    debug_level: str = "DEBUG"
    production_level: str = "WARNING"
    
    # JSON formatting configuration for enterprise log aggregation
    enable_json_formatting: bool = True
    enable_structured_output: bool = True
    include_timestamp: bool = True
    timestamp_format: str = "iso"
    
    # Correlation ID tracking for distributed tracing
    enable_correlation_id: bool = True
    correlation_id_header: str = "X-Correlation-ID"
    auto_generate_correlation_id: bool = True
    
    # Enterprise integration settings
    enable_enterprise_integration: bool = True
    elk_stack_compatible: bool = True
    splunk_compatible: bool = True
    
    # Log filtering and sampling
    enable_sampling: bool = False
    sampling_rate: float = 1.0  # 100% by default, can be reduced for high-volume environments
    
    # Security audit logging
    enable_security_audit: bool = True
    audit_events: List[str] = field(default_factory=lambda: [
        "authentication_success",
        "authentication_failure", 
        "authorization_denied",
        "token_validation_error",
        "suspicious_activity"
    ])
    
    # Performance logging
    enable_performance_logging: bool = True
    log_slow_requests: bool = True
    slow_request_threshold_ms: int = 1000  # 1 second
    
    # Log rotation and retention
    enable_log_rotation: bool = True
    max_file_size_mb: int = 100
    backup_count: int = 5
    
    def get_log_level(self, environment: str) -> str:
        """Get appropriate log level based on environment."""
        if environment.lower() == "production":
            return self.production_level
        elif environment.lower() == "debug":
            return self.debug_level
        return self.default_level


@dataclass 
class PrometheusMetricsConfig:
    """
    Prometheus metrics collection configuration using prometheus-client 0.17+.
    
    Implements comprehensive application performance monitoring, WSGI server
    instrumentation, and custom migration metrics for ≤10% variance compliance.
    """
    
    # Basic Prometheus configuration
    enable_metrics: bool = True
    metrics_endpoint: str = "/metrics"
    metrics_port: Optional[int] = None  # Use main app port by default
    
    # WSGI server instrumentation configuration
    enable_wsgi_instrumentation: bool = True
    prometheus_multiproc_dir: str = "/tmp/prometheus_multiproc"
    enable_gunicorn_metrics: bool = True
    
    # Flask application metrics
    enable_request_metrics: bool = True
    enable_response_time_histogram: bool = True
    histogram_buckets: List[float] = field(default_factory=lambda: [
        0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0
    ])
    
    # Custom migration performance metrics
    enable_migration_metrics: bool = True
    enable_baseline_comparison: bool = True
    performance_variance_threshold: float = 0.10  # 10% variance threshold
    
    # Business logic metrics
    enable_business_logic_metrics: bool = True
    enable_endpoint_specific_metrics: bool = True
    
    # Database and external service metrics
    enable_database_metrics: bool = True
    enable_external_service_metrics: bool = True
    enable_circuit_breaker_metrics: bool = True
    
    # Memory and resource metrics
    enable_memory_metrics: bool = True
    enable_cpu_metrics: bool = True
    enable_gc_metrics: bool = True
    
    # Metric naming conventions
    metric_prefix: str = "flask_migration_app"
    namespace: str = "flask_app"
    
    # Performance alert thresholds
    response_time_warning_threshold: float = 0.05  # 5% variance warning
    response_time_critical_threshold: float = 0.10  # 10% variance critical
    error_rate_warning_threshold: float = 0.01  # 1% error rate warning
    error_rate_critical_threshold: float = 0.05  # 5% error rate critical
    
    def get_metric_name(self, metric: str) -> str:
        """Generate standardized metric name with prefix."""
        return f"{self.metric_prefix}_{metric}"


@dataclass
class APMIntegrationConfig:
    """
    Application Performance Monitoring integration configuration.
    
    Supports enterprise APM tools including Datadog ddtrace 2.1+ and New Relic
    newrelic 9.2+ with environment-specific sampling and cost optimization.
    """
    
    # APM provider selection
    enable_apm: bool = True
    primary_provider: str = "datadog"  # Options: "datadog", "newrelic", "disabled"
    fallback_provider: Optional[str] = "newrelic"
    
    # Datadog APM configuration
    datadog_enabled: bool = True
    datadog_service_name: str = "flask-migration-app"
    datadog_version: Optional[str] = None  # Will be set from app config
    datadog_env: Optional[str] = None  # Will be set from environment
    
    # Environment-specific sampling rates for cost optimization
    sampling_rates: Dict[str, float] = field(default_factory=lambda: {
        "production": 0.1,   # 10% sampling in production for cost optimization
        "staging": 0.5,      # 50% sampling in staging
        "development": 1.0   # 100% sampling in development
    })
    
    # New Relic APM configuration  
    newrelic_enabled: bool = False
    newrelic_license_key: Optional[str] = None
    newrelic_app_name: str = "Flask Migration App"
    
    # Distributed tracing configuration
    enable_distributed_tracing: bool = True
    enable_correlation_propagation: bool = True
    trace_correlation_header: str = "X-Trace-ID"
    
    # Custom attribute collection
    enable_custom_attributes: bool = True
    collect_user_context: bool = True
    collect_endpoint_tags: bool = True
    collect_business_metrics: bool = True
    
    # Performance impact configuration
    max_trace_overhead_ms: float = 2.0  # Maximum acceptable tracing overhead
    enable_performance_monitoring: bool = True
    
    def get_sampling_rate(self, environment: str) -> float:
        """Get sampling rate for specific environment."""
        return self.sampling_rates.get(environment.lower(), 0.1)


@dataclass
class HealthCheckConfig:
    """
    Health check endpoints configuration for Kubernetes probes and load balancer integration.
    
    Implements liveness and readiness probes with dependency health validation
    and comprehensive diagnostic information.
    """
    
    # Health check endpoints
    enable_health_checks: bool = True
    liveness_endpoint: str = "/health/live"
    readiness_endpoint: str = "/health/ready"
    general_health_endpoint: str = "/health"
    
    # Kubernetes probe configuration
    enable_kubernetes_probes: bool = True
    liveness_check_interval: int = 30  # seconds
    readiness_check_interval: int = 15  # seconds
    probe_timeout: int = 10  # seconds
    
    # Load balancer integration
    enable_load_balancer_health: bool = True
    load_balancer_endpoint: str = "/health/ready"
    load_balancer_check_interval: int = 10  # seconds
    
    # Dependency health validation
    enable_dependency_checks: bool = True
    check_database: bool = True
    check_redis: bool = True
    check_external_services: bool = True
    
    # Dependencies configuration
    dependencies: Dict[str, Dict[str, Any]] = field(default_factory=lambda: {
        "mongodb": {
            "enabled": True,
            "timeout": 5.0,
            "critical": True
        },
        "redis": {
            "enabled": True, 
            "timeout": 3.0,
            "critical": False  # Non-critical, can degrade gracefully
        },
        "auth0": {
            "enabled": True,
            "timeout": 5.0,
            "critical": True
        }
    })
    
    # Health state management
    enable_circuit_breaker_monitoring: bool = True
    enable_graceful_degradation: bool = True
    
    # Response format configuration
    enable_json_response: bool = True
    include_diagnostic_info: bool = True
    include_dependency_status: bool = True
    include_performance_metrics: bool = True


@dataclass
class PerformanceMonitoringConfig:
    """
    Performance monitoring configuration to ensure ≤10% variance compliance.
    
    Implements comprehensive performance tracking including CPU utilization,
    memory profiling, garbage collection analysis, and Node.js baseline comparison.
    """
    
    # Performance variance tracking
    enable_performance_monitoring: bool = True
    enable_baseline_comparison: bool = True
    performance_variance_threshold: float = 0.10  # 10% variance threshold
    variance_warning_threshold: float = 0.05  # 5% variance warning
    
    # CPU utilization monitoring
    enable_cpu_monitoring: bool = True
    cpu_warning_threshold: float = 0.70  # 70% CPU utilization warning
    cpu_critical_threshold: float = 0.90  # 90% CPU utilization critical
    cpu_monitoring_interval: int = 15  # seconds
    
    # Memory monitoring configuration
    enable_memory_monitoring: bool = True
    memory_warning_threshold: float = 0.80  # 80% memory usage warning
    memory_critical_threshold: float = 0.95  # 95% memory usage critical
    
    # Python garbage collection monitoring
    enable_gc_monitoring: bool = True
    gc_pause_warning_threshold: float = 0.010  # 10ms GC pause warning
    gc_pause_critical_threshold: float = 0.020  # 20ms GC pause critical
    
    # Container resource monitoring
    enable_container_monitoring: bool = True
    container_cpu_limit_threshold: float = 0.75  # 75% of container CPU limit
    container_memory_limit_threshold: float = 0.80  # 80% of container memory limit
    
    # Network I/O monitoring
    enable_network_monitoring: bool = True
    network_latency_threshold: float = 0.100  # 100ms network latency threshold
    
    # Disk I/O monitoring
    enable_disk_monitoring: bool = True
    disk_io_latency_threshold: float = 0.050  # 50ms disk I/O latency threshold
    
    # Worker and thread monitoring
    enable_worker_monitoring: bool = True
    worker_utilization_threshold: float = 0.80  # 80% worker utilization threshold
    max_queue_depth: int = 10  # Maximum request queue depth
    
    # Performance baseline tracking
    baseline_collection_period: int = 300  # 5 minutes baseline collection
    enable_baseline_drift_detection: bool = True
    
    # Alert configuration
    enable_performance_alerts: bool = True
    alert_cooldown_period: int = 300  # 5 minutes between similar alerts


@dataclass
class EnterpriseIntegrationConfig:
    """
    Enterprise systems integration configuration.
    
    Manages integration with enterprise logging, monitoring, and alerting systems
    including ELK Stack, Splunk, PagerDuty, and enterprise SIEM platforms.
    """
    
    # Enterprise logging integration
    enable_enterprise_logging: bool = True
    elk_stack_integration: bool = True
    splunk_integration: bool = True
    
    # ELK Stack configuration
    elasticsearch_hosts: List[str] = field(default_factory=list)
    logstash_host: Optional[str] = None
    kibana_dashboard_url: Optional[str] = None
    
    # Splunk integration
    splunk_host: Optional[str] = None
    splunk_port: Optional[int] = 8088
    splunk_token: Optional[str] = None
    splunk_index: str = "flask_migration_app"
    
    # Enterprise alerting
    enable_enterprise_alerting: bool = True
    pagerduty_integration: bool = False
    pagerduty_service_key: Optional[str] = None
    
    # Slack integration
    slack_integration: bool = True
    slack_webhook_url: Optional[str] = None
    slack_channel: str = "#flask-migration-alerts"
    
    # SIEM integration
    enable_siem_integration: bool = True
    siem_format: str = "CEF"  # Common Event Format
    
    # Enterprise monitoring tools
    grafana_dashboard_url: Optional[str] = None
    enterprise_apm_url: Optional[str] = None
    
    # Cost optimization
    enable_cost_optimization: bool = True
    log_retention_days: int = 30
    metrics_retention_days: int = 90
    
    # Security and compliance
    enable_audit_logging: bool = True
    encrypt_sensitive_logs: bool = True
    pii_data_masking: bool = True


class MonitoringConfiguration:
    """
    Centralized monitoring configuration manager.
    
    Provides unified access to all monitoring configuration components and
    environment-specific settings for comprehensive observability.
    """
    
    def __init__(self, environment: str = "development"):
        """
        Initialize monitoring configuration for specific environment.
        
        Args:
            environment: Deployment environment (development, staging, production)
        """
        self.environment = environment.lower()
        
        # Initialize configuration components
        self.logging = StructuredLoggingConfig()
        self.metrics = PrometheusMetricsConfig() 
        self.apm = APMIntegrationConfig()
        self.health = HealthCheckConfig()
        self.performance = PerformanceMonitoringConfig()
        self.enterprise = EnterpriseIntegrationConfig()
        
        # Apply environment-specific configurations
        self._apply_environment_config()
        
        # Validate configuration
        self._validate_configuration()
    
    def _apply_environment_config(self) -> None:
        """Apply environment-specific configuration overrides."""
        
        if self.environment == "production":
            # Production optimizations
            self.logging.default_level = "WARNING"
            self.logging.enable_sampling = True
            self.logging.sampling_rate = 0.8  # 80% sampling in production
            
            # APM sampling optimization
            self.apm.sampling_rates["production"] = 0.05  # Reduce to 5% for cost optimization
            
            # Reduced health check frequency
            self.health.liveness_check_interval = 60
            self.health.readiness_check_interval = 30
            
            # Enterprise integration enabled
            self.enterprise.enable_enterprise_logging = True
            self.enterprise.enable_enterprise_alerting = True
            
        elif self.environment == "staging":
            # Staging configuration
            self.logging.default_level = "INFO" 
            self.apm.sampling_rates["staging"] = 0.3  # 30% sampling in staging
            
        elif self.environment == "development":
            # Development configuration - full observability
            self.logging.default_level = "DEBUG"
            self.apm.sampling_rates["development"] = 1.0  # 100% sampling in development
            
            # Disable enterprise integration in development
            self.enterprise.enable_enterprise_logging = False
            self.enterprise.enable_enterprise_alerting = False
    
    def _validate_configuration(self) -> None:
        """Validate configuration consistency and requirements."""
        
        # Validate performance thresholds
        if self.performance.variance_warning_threshold >= self.performance.performance_variance_threshold:
            raise ValueError("Warning threshold must be less than critical threshold")
        
        # Validate APM configuration
        if self.apm.enable_apm and not self.apm.primary_provider:
            raise ValueError("APM provider must be specified when APM is enabled")
        
        # Validate health check dependencies
        for dep_name, dep_config in self.health.dependencies.items():
            if dep_config.get("timeout", 0) <= 0:
                raise ValueError(f"Invalid timeout for dependency {dep_name}")
    
    def get_flask_config(self) -> Dict[str, Any]:
        """
        Generate Flask application configuration dictionary.
        
        Returns:
            Dictionary of configuration values for Flask application
        """
        return {
            # Logging configuration
            "LOGGING_LEVEL": self.logging.get_log_level(self.environment),
            "ENABLE_JSON_LOGGING": self.logging.enable_json_formatting,
            "ENABLE_CORRELATION_ID": self.logging.enable_correlation_id,
            
            # Metrics configuration
            "ENABLE_METRICS": self.metrics.enable_metrics,
            "METRICS_ENDPOINT": self.metrics.metrics_endpoint,
            "PROMETHEUS_MULTIPROC_DIR": self.metrics.prometheus_multiproc_dir,
            
            # APM configuration
            "ENABLE_APM": self.apm.enable_apm,
            "APM_SERVICE_NAME": self.apm.datadog_service_name,
            "APM_SAMPLING_RATE": self.apm.get_sampling_rate(self.environment),
            
            # Health check configuration
            "ENABLE_HEALTH_CHECKS": self.health.enable_health_checks,
            "LIVENESS_ENDPOINT": self.health.liveness_endpoint,
            "READINESS_ENDPOINT": self.health.readiness_endpoint,
            
            # Performance monitoring
            "ENABLE_PERFORMANCE_MONITORING": self.performance.enable_performance_monitoring,
            "PERFORMANCE_VARIANCE_THRESHOLD": self.performance.performance_variance_threshold,
            "CPU_WARNING_THRESHOLD": self.performance.cpu_warning_threshold,
            
            # Environment identifier
            "MONITORING_ENVIRONMENT": self.environment
        }
    
    def get_structlog_config(self) -> Dict[str, Any]:
        """
        Generate structlog configuration dictionary.
        
        Returns:
            Configuration for structlog setup
        """
        return {
            "enable_json": self.logging.enable_json_formatting,
            "enable_correlation_id": self.logging.enable_correlation_id,
            "log_level": self.logging.get_log_level(self.environment),
            "timestamp_format": self.logging.timestamp_format,
            "enable_enterprise_integration": self.logging.enable_enterprise_integration
        }
    
    def get_prometheus_config(self) -> Dict[str, Any]:
        """
        Generate Prometheus metrics configuration.
        
        Returns:
            Configuration for Prometheus metrics collection
        """
        return {
            "enable_metrics": self.metrics.enable_metrics,
            "metrics_endpoint": self.metrics.metrics_endpoint,
            "multiproc_dir": self.metrics.prometheus_multiproc_dir,
            "histogram_buckets": self.metrics.histogram_buckets,
            "metric_prefix": self.metrics.metric_prefix,
            "enable_migration_metrics": self.metrics.enable_migration_metrics,
            "performance_variance_threshold": self.metrics.performance_variance_threshold
        }
    
    def get_apm_config(self) -> Dict[str, Any]:
        """
        Generate APM integration configuration.
        
        Returns:
            Configuration for APM provider setup
        """
        return {
            "enable_apm": self.apm.enable_apm,
            "provider": self.apm.primary_provider,
            "service_name": self.apm.datadog_service_name,
            "sampling_rate": self.apm.get_sampling_rate(self.environment),
            "enable_distributed_tracing": self.apm.enable_distributed_tracing,
            "enable_custom_attributes": self.apm.enable_custom_attributes
        }
    
    def get_health_config(self) -> Dict[str, Any]:
        """
        Generate health check configuration.
        
        Returns:
            Configuration for health check endpoints
        """
        return {
            "enable_health_checks": self.health.enable_health_checks,
            "liveness_endpoint": self.health.liveness_endpoint,
            "readiness_endpoint": self.health.readiness_endpoint,
            "dependencies": self.health.dependencies,
            "enable_dependency_checks": self.health.enable_dependency_checks,
            "include_diagnostic_info": self.health.include_diagnostic_info
        }
    
    def is_enterprise_environment(self) -> bool:
        """Check if running in enterprise environment."""
        return self.environment in ["production", "staging"]
    
    def should_enable_cost_optimization(self) -> bool:
        """Check if cost optimization should be enabled."""
        return self.environment == "production" and self.enterprise.enable_cost_optimization


# Environment-specific configuration factories
def get_development_config() -> MonitoringConfiguration:
    """Get monitoring configuration for development environment."""
    return MonitoringConfiguration("development")


def get_staging_config() -> MonitoringConfiguration:
    """Get monitoring configuration for staging environment."""
    return MonitoringConfiguration("staging")


def get_production_config() -> MonitoringConfiguration:
    """Get monitoring configuration for production environment."""
    return MonitoringConfiguration("production")


def get_monitoring_config(environment: Optional[str] = None) -> MonitoringConfiguration:
    """
    Get monitoring configuration for specified environment.
    
    Args:
        environment: Target environment, defaults to environment variable
        
    Returns:
        MonitoringConfiguration instance for the environment
    """
    if environment is None:
        environment = os.getenv("FLASK_ENV", "development")
    
    environment = environment.lower()
    
    if environment == "production":
        return get_production_config()
    elif environment == "staging":
        return get_staging_config()
    else:
        return get_development_config()


# Export main configuration classes and functions
__all__ = [
    "MonitoringConfiguration",
    "StructuredLoggingConfig", 
    "PrometheusMetricsConfig",
    "APMIntegrationConfig",
    "HealthCheckConfig",
    "PerformanceMonitoringConfig",
    "EnterpriseIntegrationConfig",
    "get_monitoring_config",
    "get_development_config",
    "get_staging_config", 
    "get_production_config"
]