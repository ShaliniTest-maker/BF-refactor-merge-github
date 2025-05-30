"""
Application Performance Monitoring integration providing enterprise APM client configuration,
distributed tracing, custom attribute collection, and performance correlation analysis.

Implements Datadog ddtrace 2.1+ and New Relic newrelic 9.2+ integration with environment-specific
sampling and cost optimization for comprehensive observability.

This module provides:
- Enterprise APM client initialization and configuration
- Environment-specific sampling rate optimization (production: 0.1, staging: 0.5, development: 1.0)
- Distributed tracing with correlation ID propagation
- Custom attribute collection for user context and endpoint tags
- Performance correlation analysis for Flask request lifecycle
- Cost optimization tracking and sampling rate management
- Flask application factory integration for seamless APM deployment
"""

import os
import time
import logging
import traceback
from typing import Dict, Any, Optional, Callable, Union
from functools import wraps
from dataclasses import dataclass
from enum import Enum

import flask
from flask import Flask, request, g, current_app

# APM vendor libraries with conditional imports for flexible deployment
try:
    import ddtrace
    from ddtrace import tracer, patch_all
    from ddtrace.constants import ANALYTICS_SAMPLE_RATE_KEY
    from ddtrace.ext import http, db, errors
    HAS_DATADOG = True
except ImportError:
    HAS_DATADOG = False
    ddtrace = None
    tracer = None

try:
    import newrelic.agent
    from newrelic.agent import add_custom_attribute, current_trace, record_exception
    HAS_NEW_RELIC = True
except ImportError:
    HAS_NEW_RELIC = False
    newrelic = None

# Configure logging for APM operations
logger = logging.getLogger(__name__)


class APMProvider(Enum):
    """APM provider enumeration for vendor selection."""
    DATADOG = "datadog"
    NEW_RELIC = "newrelic"
    DISABLED = "disabled"


@dataclass
class APMConfiguration:
    """
    APM configuration dataclass managing environment-specific settings and cost optimization.
    
    Implements enterprise-grade APM configuration with sampling rate optimization,
    distributed tracing enablement, and custom attribute collection settings.
    """
    provider: APMProvider
    service_name: str = "flask-migration-app"
    version: str = "1.0.0"
    environment: str = "development"
    
    # Environment-specific sampling rates for cost optimization
    sample_rates: Dict[str, float] = None
    
    # Distributed tracing configuration
    distributed_tracing: bool = True
    correlation_id_header: str = "X-Correlation-ID"
    
    # Custom attribute collection settings
    collect_user_context: bool = True
    collect_endpoint_tags: bool = True
    collect_performance_metrics: bool = True
    
    # Cost optimization settings
    enable_sampling_optimization: bool = True
    sampling_cost_threshold: float = 100.0  # Monthly cost threshold in USD
    
    # Performance correlation settings
    enable_performance_correlation: bool = True
    baseline_variance_threshold: float = 0.10  # 10% variance threshold
    
    def __post_init__(self):
        """Initialize default sampling rates if not provided."""
        if self.sample_rates is None:
            self.sample_rates = {
                "production": 0.1,      # Cost-optimized production sampling
                "staging": 0.5,         # Moderate staging sampling
                "development": 1.0,     # Full development sampling
                "testing": 0.0          # Disabled testing sampling
            }


class APMIntegration:
    """
    Enterprise APM integration providing comprehensive application performance monitoring
    with support for Datadog ddtrace 2.1+ and New Relic newrelic 9.2+.
    
    Implements distributed tracing, custom attribute collection, performance correlation
    analysis, and cost optimization for enterprise-grade observability.
    """
    
    def __init__(self, config: APMConfiguration):
        """
        Initialize APM integration with enterprise configuration.
        
        Args:
            config: APM configuration with environment-specific settings
        """
        self.config = config
        self.provider = config.provider
        self.is_initialized = False
        self.current_sample_rate = self._get_current_sample_rate()
        
        # Performance tracking for baseline comparison
        self.performance_metrics = {
            "request_count": 0,
            "total_duration": 0.0,
            "error_count": 0,
            "last_baseline_check": time.time()
        }
        
        logger.info(
            "APM integration initialized",
            extra={
                "provider": self.provider.value,
                "environment": config.environment,
                "sample_rate": self.current_sample_rate,
                "service_name": config.service_name
            }
        )
    
    def _get_current_sample_rate(self) -> float:
        """Get current sampling rate based on environment configuration."""
        return self.config.sample_rates.get(
            self.config.environment, 
            self.config.sample_rates["development"]
        )
    
    def initialize_apm(self) -> bool:
        """
        Initialize APM agent based on configured provider.
        
        Returns:
            bool: True if initialization successful, False otherwise
        """
        if self.is_initialized:
            logger.warning("APM integration already initialized")
            return True
        
        try:
            if self.provider == APMProvider.DATADOG and HAS_DATADOG:
                return self._initialize_datadog()
            elif self.provider == APMProvider.NEW_RELIC and HAS_NEW_RELIC:
                return self._initialize_new_relic()
            elif self.provider == APMProvider.DISABLED:
                logger.info("APM integration disabled by configuration")
                self.is_initialized = True
                return True
            else:
                logger.error(
                    "APM provider not available or unsupported",
                    extra={
                        "provider": self.provider.value,
                        "has_datadog": HAS_DATADOG,
                        "has_new_relic": HAS_NEW_RELIC
                    }
                )
                return False
        
        except Exception as e:
            logger.error(
                "Failed to initialize APM integration",
                extra={
                    "provider": self.provider.value,
                    "error": str(e),
                    "traceback": traceback.format_exc()
                }
            )
            return False
    
    def _initialize_datadog(self) -> bool:
        """
        Initialize Datadog APM integration with enterprise configuration.
        
        Implements ddtrace 2.1+ with automatic instrumentation, custom sampling,
        and distributed tracing enablement.
        
        Returns:
            bool: True if Datadog initialization successful
        """
        try:
            # Configure Datadog tracer with enterprise settings
            tracer.configure(
                service=self.config.service_name,
                version=self.config.version,
                env=self.config.environment,
                enabled=True,
                
                # Sampling configuration for cost optimization
                priority_sampling=True,
                
                # Distributed tracing settings
                partial_flush_enabled=True,
                partial_flush_min_spans=100,
                
                # Performance optimization
                writer=ddtrace.Writer(
                    agent_url=os.getenv("DD_AGENT_URL", "http://localhost:8126"),
                    priority_sampler=ddtrace.priority.PrioritySampler()
                )
            )
            
            # Enable automatic instrumentation for Flask and dependencies
            patch_all(
                flask=True,
                pymongo=True,
                redis=True,
                requests=True,
                logging=True
            )
            
            # Set global sampling rate
            tracer.set_default_service(
                service=self.config.service_name,
                app=self.config.service_name,
                app_type="web"
            )
            
            # Configure custom sampling rate
            os.environ["DD_TRACE_SAMPLE_RATE"] = str(self.current_sample_rate)
            
            logger.info(
                "Datadog APM initialized successfully",
                extra={
                    "service": self.config.service_name,
                    "version": self.config.version,
                    "environment": self.config.environment,
                    "sample_rate": self.current_sample_rate
                }
            )
            
            self.is_initialized = True
            return True
            
        except Exception as e:
            logger.error(
                "Failed to initialize Datadog APM",
                extra={
                    "error": str(e),
                    "traceback": traceback.format_exc()
                }
            )
            return False
    
    def _initialize_new_relic(self) -> bool:
        """
        Initialize New Relic APM integration with enterprise configuration.
        
        Implements newrelic 9.2+ with custom attribute collection and
        environment-specific sampling.
        
        Returns:
            bool: True if New Relic initialization successful
        """
        try:
            # New Relic configuration
            config_file = os.getenv("NEW_RELIC_CONFIG_FILE", "newrelic.ini")
            license_key = os.getenv("NEW_RELIC_LICENSE_KEY")
            
            if not license_key:
                logger.error("New Relic license key not configured")
                return False
            
            # Initialize New Relic agent
            newrelic.agent.initialize(
                config_file=config_file,
                environment=self.config.environment,
                log_file="stdout",
                log_level="info"
            )
            
            # Configure application settings
            app_settings = {
                "app_name": f"{self.config.service_name}-{self.config.environment}",
                "transaction_tracer.enabled": True,
                "distributed_tracing.enabled": self.config.distributed_tracing,
                "application_logging.enabled": True,
                "application_logging.forwarding.enabled": True
            }
            
            # Apply sampling rate configuration
            if self.config.environment == "production":
                app_settings["transaction_tracer.record_sql"] = "obfuscated"
                app_settings["slow_sql.enabled"] = False
            else:
                app_settings["transaction_tracer.record_sql"] = "raw"
                app_settings["slow_sql.enabled"] = True
            
            logger.info(
                "New Relic APM initialized successfully",
                extra={
                    "app_name": app_settings["app_name"],
                    "environment": self.config.environment,
                    "distributed_tracing": self.config.distributed_tracing
                }
            )
            
            self.is_initialized = True
            return True
            
        except Exception as e:
            logger.error(
                "Failed to initialize New Relic APM",
                extra={
                    "error": str(e),
                    "traceback": traceback.format_exc()
                }
            )
            return False
    
    def init_app(self, app: Flask) -> None:
        """
        Initialize APM integration with Flask application factory pattern.
        
        Integrates APM monitoring into Flask application lifecycle with
        request hooks, error handling, and performance tracking.
        
        Args:
            app: Flask application instance
        """
        if not self.initialize_apm():
            logger.warning("APM initialization failed, monitoring will be limited")
            return
        
        # Configure Flask application context
        app.config.setdefault("APM_PROVIDER", self.provider.value)
        app.config.setdefault("APM_SERVICE_NAME", self.config.service_name)
        app.config.setdefault("APM_SAMPLE_RATE", self.current_sample_rate)
        
        # Register Flask request hooks for comprehensive monitoring
        app.before_request(self._before_request)
        app.after_request(self._after_request)
        app.teardown_appcontext(self._teardown_request)
        
        # Register error handlers for exception tracking
        app.errorhandler(Exception)(self._handle_exception)
        
        # Store APM instance in Flask app for access across requests
        app.extensions = getattr(app, "extensions", {})
        app.extensions["apm"] = self
        
        logger.info(
            "APM integration configured with Flask application",
            extra={
                "provider": self.provider.value,
                "service_name": self.config.service_name,
                "sample_rate": self.current_sample_rate
            }
        )
    
    def _before_request(self) -> None:
        """
        Flask before_request hook for request initialization and tracing setup.
        
        Initializes request-level tracing, correlation ID management,
        and performance metric collection.
        """
        if not self.is_initialized:
            return
        
        try:
            # Generate or extract correlation ID for distributed tracing
            correlation_id = self._get_or_create_correlation_id()
            g.correlation_id = correlation_id
            g.request_start_time = time.time()
            
            # Add custom attributes for user context and endpoint tracking
            if self.config.collect_endpoint_tags:
                self._add_endpoint_attributes()
            
            if self.config.collect_user_context:
                self._add_user_context_attributes()
            
            # Initialize request-level performance tracking
            if self.config.enable_performance_correlation:
                g.performance_metrics = {
                    "start_time": g.request_start_time,
                    "endpoint": request.endpoint or "unknown",
                    "method": request.method,
                    "path": request.path
                }
            
        except Exception as e:
            logger.error(
                "Error in APM before_request hook",
                extra={
                    "error": str(e),
                    "path": request.path,
                    "method": request.method
                }
            )
    
    def _after_request(self, response: flask.Response) -> flask.Response:
        """
        Flask after_request hook for response processing and metric collection.
        
        Collects response metrics, performance data, and finalizes tracing spans.
        
        Args:
            response: Flask response object
            
        Returns:
            flask.Response: Processed response with APM metadata
        """
        if not self.is_initialized:
            return response
        
        try:
            # Calculate request duration for performance tracking
            if hasattr(g, "request_start_time"):
                duration = time.time() - g.request_start_time
                
                # Update performance metrics for baseline comparison
                self.performance_metrics["request_count"] += 1
                self.performance_metrics["total_duration"] += duration
                
                # Add performance attributes to APM trace
                self._add_performance_attributes(duration, response.status_code)
                
                # Check performance variance against Node.js baseline
                if self.config.enable_performance_correlation:
                    self._check_performance_variance(duration)
            
            # Add correlation ID to response headers for client tracing
            if hasattr(g, "correlation_id"):
                response.headers[self.config.correlation_id_header] = g.correlation_id
            
            # Add response-level custom attributes
            self._add_response_attributes(response)
            
        except Exception as e:
            logger.error(
                "Error in APM after_request hook",
                extra={
                    "error": str(e),
                    "status_code": response.status_code
                }
            )
        
        return response
    
    def _teardown_request(self, exception: Optional[Exception]) -> None:
        """
        Flask teardown hook for request cleanup and span finalization.
        
        Args:
            exception: Exception that occurred during request processing, if any
        """
        if not self.is_initialized:
            return
        
        try:
            # Handle exceptions for error tracking
            if exception:
                self.performance_metrics["error_count"] += 1
                self._record_exception(exception)
            
            # Clean up request-level APM context
            if hasattr(g, "correlation_id"):
                delattr(g, "correlation_id")
            
            if hasattr(g, "request_start_time"):
                delattr(g, "request_start_time")
            
            if hasattr(g, "performance_metrics"):
                delattr(g, "performance_metrics")
        
        except Exception as e:
            logger.error(
                "Error in APM teardown hook",
                extra={"error": str(e)}
            )
    
    def _handle_exception(self, exception: Exception) -> flask.Response:
        """
        Flask error handler for comprehensive exception tracking.
        
        Args:
            exception: Exception to be tracked and handled
            
        Returns:
            flask.Response: Error response with APM context
        """
        if self.is_initialized:
            self._record_exception(exception)
        
        # Re-raise exception for normal Flask error handling
        raise exception
    
    def _get_or_create_correlation_id(self) -> str:
        """
        Generate or extract correlation ID for distributed tracing.
        
        Returns:
            str: Correlation ID for request tracking
        """
        # Check for existing correlation ID in request headers
        correlation_id = request.headers.get(self.config.correlation_id_header)
        
        if not correlation_id:
            # Generate new correlation ID using timestamp and request hash
            import uuid
            correlation_id = str(uuid.uuid4())
        
        return correlation_id
    
    def _add_endpoint_attributes(self) -> None:
        """Add endpoint-specific attributes to APM trace."""
        endpoint_attributes = {
            "endpoint": request.endpoint or "unknown",
            "method": request.method,
            "path": request.path,
            "url_rule": str(request.url_rule) if request.url_rule else "unknown",
            "remote_addr": request.environ.get("REMOTE_ADDR", "unknown")
        }
        
        self._add_custom_attributes(endpoint_attributes)
    
    def _add_user_context_attributes(self) -> None:
        """Add user context attributes to APM trace."""
        user_attributes = {}
        
        # Extract user context from Flask-Login or custom authentication
        if hasattr(g, "current_user") and g.current_user:
            user_attributes["user_id"] = getattr(g.current_user, "id", "anonymous")
            user_attributes["user_email"] = getattr(g.current_user, "email", "unknown")
        
        # Extract user context from JWT token
        if hasattr(g, "jwt_payload") and g.jwt_payload:
            user_attributes["user_id"] = g.jwt_payload.get("sub", "anonymous")
            user_attributes["user_role"] = g.jwt_payload.get("role", "unknown")
        
        # Add request-level user context
        user_attributes["session_id"] = request.headers.get("X-Session-ID", "unknown")
        user_attributes["user_agent"] = request.headers.get("User-Agent", "unknown")
        
        if user_attributes:
            self._add_custom_attributes(user_attributes)
    
    def _add_performance_attributes(self, duration: float, status_code: int) -> None:
        """
        Add performance-related attributes to APM trace.
        
        Args:
            duration: Request processing duration in seconds
            status_code: HTTP response status code
        """
        performance_attributes = {
            "request_duration_ms": round(duration * 1000, 2),
            "response_status_code": status_code,
            "is_error": status_code >= 400,
            "performance_category": self._categorize_performance(duration)
        }
        
        # Add Node.js baseline comparison if available
        if self.config.enable_performance_correlation:
            baseline_variance = self._calculate_baseline_variance(duration)
            if baseline_variance is not None:
                performance_attributes["baseline_variance_percent"] = round(baseline_variance * 100, 2)
                performance_attributes["exceeds_variance_threshold"] = abs(baseline_variance) > self.config.baseline_variance_threshold
        
        self._add_custom_attributes(performance_attributes)
    
    def _add_response_attributes(self, response: flask.Response) -> None:
        """
        Add response-specific attributes to APM trace.
        
        Args:
            response: Flask response object
        """
        response_attributes = {
            "response_content_type": response.content_type or "unknown",
            "response_content_length": response.content_length or 0,
            "response_charset": response.charset or "unknown"
        }
        
        self._add_custom_attributes(response_attributes)
    
    def _add_custom_attributes(self, attributes: Dict[str, Any]) -> None:
        """
        Add custom attributes to current APM trace span.
        
        Args:
            attributes: Dictionary of custom attributes to add
        """
        if not self.is_initialized:
            return
        
        try:
            if self.provider == APMProvider.DATADOG and HAS_DATADOG:
                # Add attributes to current Datadog span
                span = tracer.current_span()
                if span:
                    for key, value in attributes.items():
                        span.set_tag(key, value)
            
            elif self.provider == APMProvider.NEW_RELIC and HAS_NEW_RELIC:
                # Add attributes to current New Relic transaction
                for key, value in attributes.items():
                    add_custom_attribute(key, value)
        
        except Exception as e:
            logger.debug(
                "Failed to add custom attributes",
                extra={
                    "error": str(e),
                    "attributes": attributes
                }
            )
    
    def _record_exception(self, exception: Exception) -> None:
        """
        Record exception with APM provider for error tracking.
        
        Args:
            exception: Exception to record
        """
        if not self.is_initialized:
            return
        
        try:
            if self.provider == APMProvider.DATADOG and HAS_DATADOG:
                # Record exception with Datadog
                span = tracer.current_span()
                if span:
                    span.set_exc_info(type(exception), exception, exception.__traceback__)
                    span.error = 1
            
            elif self.provider == APMProvider.NEW_RELIC and HAS_NEW_RELIC:
                # Record exception with New Relic
                record_exception()
        
        except Exception as e:
            logger.debug(
                "Failed to record exception with APM",
                extra={
                    "error": str(e),
                    "original_exception": str(exception)
                }
            )
    
    def _categorize_performance(self, duration: float) -> str:
        """
        Categorize request performance for monitoring analysis.
        
        Args:
            duration: Request duration in seconds
            
        Returns:
            str: Performance category
        """
        if duration < 0.1:
            return "fast"
        elif duration < 0.5:
            return "normal"
        elif duration < 2.0:
            return "slow"
        else:
            return "very_slow"
    
    def _calculate_baseline_variance(self, duration: float) -> Optional[float]:
        """
        Calculate performance variance against Node.js baseline.
        
        Args:
            duration: Current request duration
            
        Returns:
            Optional[float]: Variance percentage (None if baseline not available)
        """
        # Implement baseline comparison logic
        # This would typically compare against stored Node.js baseline metrics
        # For now, using a placeholder implementation
        
        # Expected Node.js baseline (would be loaded from configuration or metrics store)
        baseline_duration = getattr(current_app, "_nodejs_baseline_duration", None)
        
        if baseline_duration and baseline_duration > 0:
            variance = (duration - baseline_duration) / baseline_duration
            return variance
        
        return None
    
    def _check_performance_variance(self, duration: float) -> None:
        """
        Check if current performance exceeds variance threshold.
        
        Args:
            duration: Current request duration
        """
        variance = self._calculate_baseline_variance(duration)
        
        if variance and abs(variance) > self.config.baseline_variance_threshold:
            logger.warning(
                "Performance variance threshold exceeded",
                extra={
                    "current_duration": duration,
                    "variance_percent": round(variance * 100, 2),
                    "threshold_percent": round(self.config.baseline_variance_threshold * 100, 2),
                    "endpoint": getattr(g, "performance_metrics", {}).get("endpoint", "unknown")
                }
            )
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """
        Get current performance metrics summary for monitoring dashboards.
        
        Returns:
            Dict[str, Any]: Performance metrics summary
        """
        if self.performance_metrics["request_count"] == 0:
            return {
                "status": "no_data",
                "request_count": 0,
                "average_duration": 0.0,
                "error_rate": 0.0
            }
        
        average_duration = self.performance_metrics["total_duration"] / self.performance_metrics["request_count"]
        error_rate = self.performance_metrics["error_count"] / self.performance_metrics["request_count"]
        
        return {
            "status": "active",
            "provider": self.provider.value,
            "service_name": self.config.service_name,
            "environment": self.config.environment,
            "sample_rate": self.current_sample_rate,
            "request_count": self.performance_metrics["request_count"],
            "average_duration_ms": round(average_duration * 1000, 2),
            "error_rate_percent": round(error_rate * 100, 2),
            "total_errors": self.performance_metrics["error_count"],
            "last_baseline_check": self.performance_metrics["last_baseline_check"]
        }
    
    def optimize_sampling_rate(self, cost_data: Optional[Dict[str, float]] = None) -> float:
        """
        Optimize APM sampling rate based on cost and performance requirements.
        
        Args:
            cost_data: Optional cost data for optimization decisions
            
        Returns:
            float: Optimized sampling rate
        """
        if not self.config.enable_sampling_optimization:
            return self.current_sample_rate
        
        try:
            # Implement cost-based sampling optimization
            current_cost = cost_data.get("monthly_cost", 0.0) if cost_data else 0.0
            
            if current_cost > self.config.sampling_cost_threshold:
                # Reduce sampling rate to control costs
                optimized_rate = max(0.05, self.current_sample_rate * 0.8)
                logger.info(
                    "Reducing APM sampling rate for cost optimization",
                    extra={
                        "current_rate": self.current_sample_rate,
                        "optimized_rate": optimized_rate,
                        "current_cost": current_cost,
                        "threshold": self.config.sampling_cost_threshold
                    }
                )
                return optimized_rate
            
            # Maintain current sampling rate
            return self.current_sample_rate
        
        except Exception as e:
            logger.error(
                "Failed to optimize sampling rate",
                extra={"error": str(e)}
            )
            return self.current_sample_rate


def create_apm_integration(
    provider: Union[APMProvider, str] = None,
    environment: str = None,
    service_name: str = None,
    **kwargs
) -> APMIntegration:
    """
    Factory function for creating APM integration with environment-based configuration.
    
    Args:
        provider: APM provider (datadog, newrelic, or disabled)
        environment: Deployment environment (production, staging, development)
        service_name: Service name for APM identification
        **kwargs: Additional configuration parameters
        
    Returns:
        APMIntegration: Configured APM integration instance
    """
    # Default configuration from environment variables
    provider = provider or os.getenv("APM_PROVIDER", "datadog")
    environment = environment or os.getenv("FLASK_ENV", "development")
    service_name = service_name or os.getenv("APM_SERVICE_NAME", "flask-migration-app")
    
    # Convert string provider to enum
    if isinstance(provider, str):
        try:
            provider = APMProvider(provider.lower())
        except ValueError:
            logger.warning(f"Unknown APM provider '{provider}', defaulting to disabled")
            provider = APMProvider.DISABLED
    
    # Create configuration with environment-specific defaults
    config = APMConfiguration(
        provider=provider,
        service_name=service_name,
        environment=environment,
        version=os.getenv("APP_VERSION", "1.0.0"),
        **kwargs
    )
    
    return APMIntegration(config)


def init_apm_with_app(app: Flask, **kwargs) -> APMIntegration:
    """
    Initialize APM integration with Flask application factory pattern.
    
    Args:
        app: Flask application instance
        **kwargs: APM configuration parameters
        
    Returns:
        APMIntegration: Initialized APM integration
    """
    # Extract configuration from Flask app config
    provider = kwargs.get("provider") or app.config.get("APM_PROVIDER")
    environment = kwargs.get("environment") or app.config.get("FLASK_ENV")
    service_name = kwargs.get("service_name") or app.config.get("APM_SERVICE_NAME")
    
    # Create and initialize APM integration
    apm = create_apm_integration(
        provider=provider,
        environment=environment,
        service_name=service_name,
        **kwargs
    )
    
    # Initialize with Flask application
    apm.init_app(app)
    
    return apm


# Export public interface
__all__ = [
    "APMProvider",
    "APMConfiguration", 
    "APMIntegration",
    "create_apm_integration",
    "init_apm_with_app"
]