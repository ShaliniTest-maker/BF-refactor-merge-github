"""
Application Performance Monitoring (APM) Integration Module

Comprehensive APM integration providing enterprise APM client configuration, distributed tracing,
custom attribute collection, and performance correlation analysis for Flask migration application.

This module implements dual APM provider support with Datadog ddtrace 2.1+ and New Relic newrelic 9.2+
integration, featuring environment-specific sampling configuration, cost optimization strategies,
and comprehensive performance monitoring to ensure compliance with ≤10% variance requirement.

Key Features:
- Datadog APM integration with automatic Flask instrumentation
- New Relic APM alternative with comprehensive monitoring capabilities
- Environment-specific sampling rates for cost optimization
- Distributed tracing with correlation ID propagation
- Custom attribute collection for user context and endpoint tags
- APM agent initialization within Flask application factory
- Performance baseline comparison and variance tracking
- Circuit breaker integration with APM event correlation
- Business logic performance tracing with custom spans

Enterprise Integration:
- Multi-provider APM support for vendor flexibility and redundancy
- Cost optimization through intelligent sampling rate management
- Enterprise security compliance with PII filtering and data governance
- Integration with existing monitoring infrastructure (Prometheus, structlog)
- Kubernetes-native deployment support with container-aware tracing

Performance Requirements:
- Response time variance monitoring: ≤10% from Node.js baseline
- APM instrumentation overhead: <1ms per request average
- Sampling rate optimization: Production (0.1), Staging (0.5), Development (1.0)
- Distributed trace propagation with <0.5ms overhead
- Custom attribute collection with minimal performance impact

References:
- Section 6.5.1.1: Python APM client configuration and enterprise integration
- Section 6.5.4.3: APM agent initialization and custom attribute collection
- Section 4.5.1: Distributed tracing and correlation ID propagation
- Section 6.5.3.5: APM sampling rate optimization tracking
- Section 0.1.1: ≤10% performance variance requirement compliance
"""

import os
import time
import uuid
import logging
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Callable, Union, List
from functools import wraps
from contextlib import contextmanager

from flask import Flask, request, g, has_request_context
import structlog

from ..config.monitoring import MonitoringConfig
from ..monitoring.logging import get_logger, set_correlation_id, log_performance_metric

# APM Provider Imports with Graceful Fallback
try:
    import ddtrace
    from ddtrace import tracer as dd_tracer
    from ddtrace.contrib.flask import patch as ddtrace_patch_flask
    from ddtrace.contrib.pymongo import patch as ddtrace_patch_pymongo
    from ddtrace.contrib.redis import patch as ddtrace_patch_redis
    from ddtrace.contrib.requests import patch as ddtrace_patch_requests
    from ddtrace.contrib.httpx import patch as ddtrace_patch_httpx
    from ddtrace.filters import TraceFilter
    from ddtrace import config as dd_config
    DATADOG_AVAILABLE = True
except ImportError:
    DATADOG_AVAILABLE = False
    ddtrace = None
    dd_tracer = None

try:
    import newrelic.agent
    from newrelic.api.application import application_instance
    from newrelic.api.transaction import current_transaction, add_custom_attribute
    from newrelic.api.function_trace import function_trace
    from newrelic.api.external_trace import external_trace
    from newrelic.api.database_trace import database_trace
    NEWRELIC_AVAILABLE = True
except ImportError:
    NEWRELIC_AVAILABLE = False
    newrelic = None


class APMConfig:
    """
    Comprehensive APM configuration for enterprise monitoring integration.
    
    Provides centralized configuration management for multiple APM providers
    with environment-specific settings, sampling optimization, and cost control.
    """
    
    def __init__(self):
        """Initialize APM configuration from environment and monitoring config."""
        # Base APM Configuration
        self.enabled = os.getenv('APM_ENABLED', 'true').lower() == 'true'
        self.service_name = os.getenv('APM_SERVICE_NAME', 'flask-migration-app')
        self.environment = os.getenv('APM_ENVIRONMENT', 'production')
        self.version = os.getenv('APM_VERSION', '1.0.0')
        
        # Datadog APM Configuration
        self.datadog_enabled = (
            os.getenv('DATADOG_APM_ENABLED', 'false').lower() == 'true' and 
            DATADOG_AVAILABLE
        )
        self.datadog_agent_host = os.getenv('DD_AGENT_HOST', 'localhost')
        self.datadog_trace_agent_port = int(os.getenv('DD_TRACE_AGENT_PORT', '8126'))
        self.datadog_sample_rate = self._get_environment_sample_rate('DATADOG_SAMPLE_RATE')
        self.datadog_priority_sampling = os.getenv('DD_PRIORITY_SAMPLING', 'true').lower() == 'true'
        self.datadog_distributed_tracing = os.getenv('DD_DISTRIBUTED_TRACING', 'true').lower() == 'true'
        
        # New Relic APM Configuration
        self.newrelic_enabled = (
            os.getenv('NEWRELIC_APM_ENABLED', 'false').lower() == 'true' and 
            NEWRELIC_AVAILABLE
        )
        self.newrelic_license_key = os.getenv('NEWRELIC_LICENSE_KEY', None)
        self.newrelic_app_name = os.getenv('NEWRELIC_APP_NAME', self.service_name)
        self.newrelic_sample_rate = self._get_environment_sample_rate('NEWRELIC_SAMPLE_RATE')
        self.newrelic_distributed_tracing = os.getenv('NEWRELIC_DISTRIBUTED_TRACING', 'true').lower() == 'true'
        
        # Performance Monitoring Configuration
        self.track_performance_variance = os.getenv('APM_TRACK_PERFORMANCE_VARIANCE', 'true').lower() == 'true'
        self.baseline_comparison_enabled = os.getenv('APM_BASELINE_COMPARISON', 'true').lower() == 'true'
        self.custom_attributes_enabled = os.getenv('APM_CUSTOM_ATTRIBUTES', 'true').lower() == 'true'
        
        # Cost Optimization Configuration
        self.cost_optimization_enabled = os.getenv('APM_COST_OPTIMIZATION', 'true').lower() == 'true'
        self.adaptive_sampling = os.getenv('APM_ADAPTIVE_SAMPLING', 'false').lower() == 'true'
        self.high_volume_endpoints = self._parse_list(os.getenv('APM_HIGH_VOLUME_ENDPOINTS', ''))
        
        # Security and Compliance Configuration
        self.pii_filtering_enabled = os.getenv('APM_PII_FILTERING', 'true').lower() == 'true'
        self.trace_sanitization = os.getenv('APM_TRACE_SANITIZATION', 'true').lower() == 'true'
        self.sensitive_headers = self._parse_list(os.getenv('APM_SENSITIVE_HEADERS', 
                                                           'authorization,cookie,x-api-key'))
        
    def _get_environment_sample_rate(self, env_var: str) -> float:
        """Get environment-specific sample rate with intelligent defaults."""
        sample_rate = float(os.getenv(env_var, '0.0'))
        
        if sample_rate == 0.0:
            # Environment-specific defaults for cost optimization
            if self.environment in ['production', 'prod']:
                return 0.1  # 10% sampling for production cost optimization
            elif self.environment in ['staging', 'stage']:
                return 0.5  # 50% sampling for staging validation
            elif self.environment in ['development', 'dev', 'local']:
                return 1.0  # 100% sampling for development debugging
            else:
                return 0.1  # Conservative default for unknown environments
        
        return sample_rate
    
    def _parse_list(self, value: str) -> List[str]:
        """Parse comma-separated list from environment variable."""
        if not value:
            return []
        return [item.strip() for item in value.split(',') if item.strip()]
    
    def get_effective_sample_rate(self, endpoint: str = None) -> float:
        """Get effective sample rate considering endpoint-specific optimization."""
        base_rate = self.datadog_sample_rate if self.datadog_enabled else self.newrelic_sample_rate
        
        if not self.cost_optimization_enabled:
            return base_rate
        
        # Reduce sampling for high-volume endpoints if configured
        if endpoint and self.high_volume_endpoints:
            for pattern in self.high_volume_endpoints:
                if pattern in endpoint:
                    return base_rate * 0.5  # Reduce sampling by 50% for high-volume endpoints
        
        return base_rate


class CorrelationIDManager:
    """
    Manages correlation ID propagation across APM providers and request lifecycle.
    
    Ensures consistent correlation ID tracking across distributed tracing,
    structured logging, and APM systems for comprehensive request visibility.
    """
    
    def __init__(self):
        """Initialize correlation ID manager."""
        self.logger = get_logger(__name__)
    
    def generate_correlation_id(self) -> str:
        """Generate new correlation ID with enterprise format."""
        timestamp = int(time.time() * 1000)
        random_part = str(uuid.uuid4()).replace('-', '')[:12]
        return f"cor-{timestamp}-{random_part}"
    
    def extract_correlation_id(self, headers: Dict[str, str]) -> Optional[str]:
        """Extract correlation ID from HTTP headers."""
        # Standard correlation ID headers
        correlation_headers = [
            'X-Correlation-ID',
            'X-Request-ID', 
            'X-Trace-ID',
            'Correlation-ID',
            'Request-ID'
        ]
        
        for header in correlation_headers:
            if header in headers:
                return headers[header]
        
        return None
    
    def set_correlation_context(self, correlation_id: str, apm_config: APMConfig):
        """Set correlation ID across all APM providers and logging systems."""
        # Set in structured logging
        set_correlation_id(correlation_id)
        
        # Set in Flask request context
        if has_request_context():
            g.correlation_id = correlation_id
        
        # Set in Datadog tracing
        if apm_config.datadog_enabled and dd_tracer:
            span = dd_tracer.current_span()
            if span:
                span.set_tag('correlation_id', correlation_id)
                span.set_tag('request_id', correlation_id)
        
        # Set in New Relic tracing
        if apm_config.newrelic_enabled and newrelic:
            try:
                add_custom_attribute('correlation_id', correlation_id)
                add_custom_attribute('request_id', correlation_id)
            except Exception:
                pass
    
    def propagate_to_external_request(self, headers: Dict[str, str], correlation_id: str) -> Dict[str, str]:
        """Add correlation ID to external request headers."""
        propagated_headers = headers.copy()
        propagated_headers['X-Correlation-ID'] = correlation_id
        propagated_headers['X-Request-ID'] = correlation_id
        
        return propagated_headers


class CustomAttributeCollector:
    """
    Collects and manages custom attributes for APM tracing enhancement.
    
    Provides comprehensive attribute collection for user context, endpoint tags,
    business logic context, and performance metrics with PII filtering compliance.
    """
    
    def __init__(self, apm_config: APMConfig):
        """Initialize custom attribute collector."""
        self.config = apm_config
        self.logger = get_logger(__name__)
        self.sensitive_keys = {
            'password', 'token', 'secret', 'key', 'auth', 'credential',
            'ssn', 'social_security', 'credit_card', 'card_number',
            'email', 'phone', 'address', 'ip_address'
        }
    
    def collect_request_attributes(self) -> Dict[str, Any]:
        """Collect HTTP request attributes for tracing enhancement."""
        if not has_request_context():
            return {}
        
        attributes = {
            'http.method': request.method,
            'http.url': self._sanitize_url(request.url),
            'http.endpoint': request.endpoint or 'unknown',
            'http.remote_addr': self._sanitize_ip(request.remote_addr),
            'http.user_agent': self._sanitize_user_agent(request.headers.get('User-Agent', '')),
            'http.content_length': request.content_length or 0,
            'http.scheme': request.scheme,
            'http.host': request.host,
        }
        
        # Add query parameters (filtered)
        if request.args:
            filtered_params = self._filter_sensitive_data(dict(request.args))
            attributes['http.query_params'] = str(filtered_params)
        
        return attributes
    
    def collect_user_context(self, user_id: str = None, user_role: str = None, 
                           additional_context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Collect user context attributes for security and audit tracking."""
        attributes = {}
        
        if user_id:
            attributes['user.id'] = user_id
        
        if user_role:
            attributes['user.role'] = user_role
        
        # Add authentication context from Flask g object
        if has_request_context():
            if hasattr(g, 'current_user_id'):
                attributes['user.authenticated_id'] = g.current_user_id
            
            if hasattr(g, 'jwt_claims'):
                jwt_claims = g.jwt_claims
                if isinstance(jwt_claims, dict):
                    attributes['auth.subject'] = jwt_claims.get('sub', '')
                    attributes['auth.issuer'] = jwt_claims.get('iss', '')
                    attributes['auth.audience'] = jwt_claims.get('aud', '')
                    if 'exp' in jwt_claims:
                        attributes['auth.expires_at'] = jwt_claims['exp']
        
        if additional_context:
            # Filter and add additional context
            filtered_context = self._filter_sensitive_data(additional_context)
            for key, value in filtered_context.items():
                attributes[f'user.{key}'] = value
        
        return attributes
    
    def collect_business_context(self, operation: str, entity_type: str = None,
                               entity_id: str = None, additional_context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Collect business logic context for operational tracking."""
        attributes = {
            'business.operation': operation,
            'business.timestamp': datetime.now(timezone.utc).isoformat(),
        }
        
        if entity_type:
            attributes['business.entity_type'] = entity_type
        
        if entity_id:
            attributes['business.entity_id'] = entity_id
        
        if additional_context:
            filtered_context = self._filter_sensitive_data(additional_context)
            for key, value in filtered_context.items():
                attributes[f'business.{key}'] = value
        
        return attributes
    
    def collect_performance_context(self, baseline_time: float = None, 
                                  current_time: float = None) -> Dict[str, Any]:
        """Collect performance metrics for baseline comparison."""
        attributes = {
            'performance.measurement_timestamp': datetime.now(timezone.utc).isoformat(),
        }
        
        if current_time is not None:
            attributes['performance.response_time_ms'] = current_time * 1000
        
        if baseline_time is not None:
            attributes['performance.baseline_time_ms'] = baseline_time * 1000
            
            if current_time is not None:
                variance_percent = ((current_time - baseline_time) / baseline_time) * 100
                attributes['performance.variance_percent'] = round(variance_percent, 2)
                attributes['performance.within_threshold'] = abs(variance_percent) <= 10.0
                attributes['performance.baseline_comparison'] = 'enabled'
        
        return attributes
    
    def collect_infrastructure_context(self) -> Dict[str, Any]:
        """Collect infrastructure and deployment context."""
        return {
            'deployment.environment': self.config.environment,
            'deployment.version': self.config.version,
            'deployment.service': self.config.service_name,
            'infrastructure.hostname': os.getenv('HOSTNAME', 'unknown'),
            'infrastructure.container_id': os.getenv('CONTAINER_ID', ''),
            'infrastructure.pod_name': os.getenv('POD_NAME', ''),
            'infrastructure.namespace': os.getenv('NAMESPACE', ''),
            'infrastructure.node_name': os.getenv('NODE_NAME', ''),
        }
    
    def _filter_sensitive_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Filter sensitive data from attributes based on PII compliance."""
        if not self.config.pii_filtering_enabled:
            return data
        
        filtered = {}
        for key, value in data.items():
            key_lower = key.lower()
            
            # Check if key contains sensitive information
            if any(sensitive in key_lower for sensitive in self.sensitive_keys):
                filtered[key] = '[REDACTED]'
            elif isinstance(value, str) and len(value) > 50:
                # Truncate very long strings that might contain sensitive data
                filtered[key] = value[:50] + '...'
            else:
                filtered[key] = value
        
        return filtered
    
    def _sanitize_url(self, url: str) -> str:
        """Sanitize URL by removing sensitive query parameters."""
        if not self.config.trace_sanitization:
            return url
        
        # Remove common sensitive parameters
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        if parsed.query:
            query_params = urllib.parse.parse_qs(parsed.query)
            sanitized_params = {}
            
            for key, values in query_params.items():
                if any(sensitive in key.lower() for sensitive in self.sensitive_keys):
                    sanitized_params[key] = ['[REDACTED]']
                else:
                    sanitized_params[key] = values
            
            sanitized_query = urllib.parse.urlencode(sanitized_params, doseq=True)
            return urllib.parse.urlunparse(parsed._replace(query=sanitized_query))
        
        return url
    
    def _sanitize_ip(self, ip_address: str) -> str:
        """Sanitize IP address for privacy compliance."""
        if not self.config.trace_sanitization or not ip_address:
            return ip_address
        
        # Mask last octet of IPv4 addresses
        if '.' in ip_address:
            parts = ip_address.split('.')
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{parts[2]}.xxx"
        
        return ip_address
    
    def _sanitize_user_agent(self, user_agent: str) -> str:
        """Sanitize user agent for privacy compliance."""
        if not self.config.trace_sanitization:
            return user_agent
        
        # Truncate very long user agent strings
        if len(user_agent) > 200:
            return user_agent[:200] + '...'
        
        return user_agent


class DatadogAPMProvider:
    """
    Datadog APM provider implementation with comprehensive Flask instrumentation.
    
    Provides enterprise-grade Datadog APM integration with automatic instrumentation,
    custom attribute collection, and performance optimization features.
    """
    
    def __init__(self, apm_config: APMConfig):
        """Initialize Datadog APM provider."""
        self.config = apm_config
        self.logger = get_logger(__name__)
        self.tracer = None
        self.initialized = False
        
        if DATADOG_AVAILABLE and self.config.datadog_enabled:
            self._initialize_datadog()
    
    def _initialize_datadog(self):
        """Initialize Datadog tracer with enterprise configuration."""
        try:
            # Configure Datadog tracer
            ddtrace.config.service = self.config.service_name
            ddtrace.config.env = self.config.environment
            ddtrace.config.version = self.config.version
            
            # Configure Flask integration
            dd_config.flask.service_name = self.config.service_name
            dd_config.flask.distributed_tracing = self.config.datadog_distributed_tracing
            dd_config.flask.trace_query_string = True
            dd_config.flask.analytics_enabled = True
            dd_config.flask.analytics_sample_rate = self.config.datadog_sample_rate
            
            # Configure database integrations
            dd_config.pymongo.service = f"{self.config.service_name}-mongodb"
            dd_config.redis.service = f"{self.config.service_name}-redis"
            
            # Configure external service integrations
            dd_config.requests.service = f"{self.config.service_name}-http"
            dd_config.httpx.service = f"{self.config.service_name}-httpx"
            
            # Configure tracer settings
            dd_tracer.configure(
                settings={
                    'PRIORITY_SAMPLING': self.config.datadog_priority_sampling,
                    'ANALYTICS_ENABLED': True,
                    'ANALYTICS_SAMPLE_RATE': self.config.datadog_sample_rate,
                    'DISTRIBUTED_TRACING': self.config.datadog_distributed_tracing,
                }
            )
            
            # Enable automatic instrumentation
            ddtrace.patch(
                flask=True,
                pymongo=True,
                redis=True,
                requests=True,
                httpx=True,
                logging=True
            )
            
            self.tracer = dd_tracer
            self.initialized = True
            
            self.logger.info("Datadog APM initialized successfully",
                           service=self.config.service_name,
                           environment=self.config.environment,
                           sample_rate=self.config.datadog_sample_rate,
                           distributed_tracing=self.config.datadog_distributed_tracing)
            
        except Exception as e:
            self.logger.error("Failed to initialize Datadog APM",
                            error=str(e),
                            error_type=type(e).__name__)
            self.initialized = False
    
    def patch_flask_app(self, app: Flask):
        """Apply Datadog instrumentation to Flask application."""
        if self.initialized:
            try:
                ddtrace_patch_flask(app)
                self.logger.info("Datadog Flask instrumentation applied")
            except Exception as e:
                self.logger.error("Failed to patch Flask app with Datadog",
                                error=str(e))
    
    def add_custom_attributes(self, attributes: Dict[str, Any]):
        """Add custom attributes to current Datadog span."""
        if not self.initialized or not self.tracer:
            return
        
        try:
            span = self.tracer.current_span()
            if span:
                for key, value in attributes.items():
                    span.set_tag(key, value)
        except Exception as e:
            self.logger.debug("Failed to add Datadog custom attributes",
                            error=str(e))
    
    def start_span(self, operation_name: str, service: str = None, 
                   resource: str = None) -> Any:
        """Start a new Datadog span for custom tracing."""
        if not self.initialized or not self.tracer:
            return None
        
        try:
            return self.tracer.trace(
                operation_name,
                service=service or self.config.service_name,
                resource=resource or operation_name
            )
        except Exception as e:
            self.logger.debug("Failed to start Datadog span",
                            operation=operation_name,
                            error=str(e))
            return None
    
    def record_exception(self, exception: Exception):
        """Record exception in current Datadog span."""
        if not self.initialized or not self.tracer:
            return
        
        try:
            span = self.tracer.current_span()
            if span:
                span.set_exc_info(type(exception), exception, exception.__traceback__)
                span.set_tag('error', True)
                span.set_tag('error.message', str(exception))
                span.set_tag('error.type', type(exception).__name__)
        except Exception as e:
            self.logger.debug("Failed to record exception in Datadog",
                            error=str(e))


class NewRelicAPMProvider:
    """
    New Relic APM provider implementation with comprehensive monitoring capabilities.
    
    Provides enterprise-grade New Relic APM integration with custom instrumentation,
    attribute collection, and performance tracking features.
    """
    
    def __init__(self, apm_config: APMConfig):
        """Initialize New Relic APM provider."""
        self.config = apm_config
        self.logger = get_logger(__name__)
        self.initialized = False
        
        if NEWRELIC_AVAILABLE and self.config.newrelic_enabled:
            self._initialize_newrelic()
    
    def _initialize_newrelic(self):
        """Initialize New Relic agent with enterprise configuration."""
        try:
            if not self.config.newrelic_license_key:
                self.logger.warning("New Relic license key not provided")
                return
            
            # Initialize New Relic agent
            newrelic.agent.initialize(
                config_file=None,
                environment=self.config.environment,
                log_file='/var/log/newrelic/python-agent.log',
                log_level='info'
            )
            
            self.initialized = True
            
            self.logger.info("New Relic APM initialized successfully",
                           app_name=self.config.newrelic_app_name,
                           environment=self.config.environment,
                           sample_rate=self.config.newrelic_sample_rate,
                           distributed_tracing=self.config.newrelic_distributed_tracing)
            
        except Exception as e:
            self.logger.error("Failed to initialize New Relic APM",
                            error=str(e),
                            error_type=type(e).__name__)
            self.initialized = False
    
    def patch_flask_app(self, app: Flask):
        """Apply New Relic instrumentation to Flask application."""
        if self.initialized:
            try:
                app.wsgi_app = newrelic.agent.WSGIApplicationWrapper(app.wsgi_app)
                self.logger.info("New Relic Flask instrumentation applied")
            except Exception as e:
                self.logger.error("Failed to patch Flask app with New Relic",
                                error=str(e))
    
    def add_custom_attributes(self, attributes: Dict[str, Any]):
        """Add custom attributes to current New Relic transaction."""
        if not self.initialized:
            return
        
        try:
            for key, value in attributes.items():
                add_custom_attribute(key, value)
        except Exception as e:
            self.logger.debug("Failed to add New Relic custom attributes",
                            error=str(e))
    
    def record_exception(self, exception: Exception):
        """Record exception in current New Relic transaction."""
        if not self.initialized:
            return
        
        try:
            newrelic.agent.record_exception()
        except Exception as e:
            self.logger.debug("Failed to record exception in New Relic",
                            error=str(e))


class PerformanceTracker:
    """
    Performance tracking and baseline comparison for APM integration.
    
    Provides comprehensive performance monitoring with Node.js baseline comparison,
    variance tracking, and performance optimization insights.
    """
    
    def __init__(self, apm_config: APMConfig):
        """Initialize performance tracker."""
        self.config = apm_config
        self.logger = get_logger(__name__)
        self.baseline_data = {}
        self.performance_data = {}
        self._lock = threading.Lock()
    
    def set_baseline(self, endpoint: str, baseline_time: float):
        """Set Node.js baseline performance for endpoint."""
        with self._lock:
            self.baseline_data[endpoint] = {
                'response_time': baseline_time,
                'timestamp': datetime.now(timezone.utc),
                'source': 'nodejs_baseline'
            }
    
    def record_performance(self, endpoint: str, response_time: float, 
                         additional_metrics: Dict[str, Any] = None) -> Dict[str, Any]:
        """Record Flask performance and calculate variance against baseline."""
        with self._lock:
            # Get baseline data
            baseline = self.baseline_data.get(endpoint)
            performance_data = {
                'endpoint': endpoint,
                'response_time': response_time,
                'timestamp': datetime.now(timezone.utc),
                'source': 'flask_migration'
            }
            
            if additional_metrics:
                performance_data.update(additional_metrics)
            
            # Calculate variance if baseline exists
            if baseline:
                baseline_time = baseline['response_time']
                variance_percent = ((response_time - baseline_time) / baseline_time) * 100
                
                performance_data.update({
                    'baseline_response_time': baseline_time,
                    'variance_percent': round(variance_percent, 2),
                    'within_threshold': abs(variance_percent) <= 10.0,
                    'variance_status': self._get_variance_status(variance_percent)
                })
                
                # Log performance variance
                log_performance_metric(
                    f"variance_{endpoint}",
                    variance_percent,
                    'percent',
                    {
                        'endpoint': endpoint,
                        'baseline_time': baseline_time,
                        'current_time': response_time,
                        'within_threshold': abs(variance_percent) <= 10.0
                    }
                )
            
            # Store performance data
            if endpoint not in self.performance_data:
                self.performance_data[endpoint] = []
            self.performance_data[endpoint].append(performance_data)
            
            # Limit stored data to last 100 measurements per endpoint
            if len(self.performance_data[endpoint]) > 100:
                self.performance_data[endpoint] = self.performance_data[endpoint][-100:]
            
            return performance_data
    
    def get_performance_summary(self, endpoint: str = None) -> Dict[str, Any]:
        """Get performance summary for endpoint or all endpoints."""
        with self._lock:
            if endpoint:
                return self._get_endpoint_summary(endpoint)
            else:
                return {ep: self._get_endpoint_summary(ep) 
                       for ep in self.performance_data.keys()}
    
    def _get_endpoint_summary(self, endpoint: str) -> Dict[str, Any]:
        """Get performance summary for specific endpoint."""
        if endpoint not in self.performance_data:
            return {}
        
        measurements = self.performance_data[endpoint]
        if not measurements:
            return {}
        
        # Calculate statistics
        response_times = [m['response_time'] for m in measurements]
        variances = [m.get('variance_percent', 0) for m in measurements if 'variance_percent' in m]
        
        summary = {
            'endpoint': endpoint,
            'measurement_count': len(measurements),
            'avg_response_time': sum(response_times) / len(response_times),
            'min_response_time': min(response_times),
            'max_response_time': max(response_times),
            'last_measurement': measurements[-1]['timestamp'].isoformat(),
        }
        
        # Add baseline comparison if available
        if variances:
            summary.update({
                'avg_variance_percent': sum(variances) / len(variances),
                'min_variance_percent': min(variances),
                'max_variance_percent': max(variances),
                'within_threshold_count': len([v for v in variances if abs(v) <= 10.0]),
                'within_threshold_percentage': (len([v for v in variances if abs(v) <= 10.0]) / len(variances)) * 100
            })
        
        if endpoint in self.baseline_data:
            summary['baseline_response_time'] = self.baseline_data[endpoint]['response_time']
        
        return summary
    
    def _get_variance_status(self, variance_percent: float) -> str:
        """Get variance status based on percentage."""
        abs_variance = abs(variance_percent)
        
        if abs_variance <= 5.0:
            return 'excellent'
        elif abs_variance <= 10.0:
            return 'acceptable'
        elif abs_variance <= 20.0:
            return 'warning'
        else:
            return 'critical'


class APMIntegrationManager:
    """
    Central APM integration manager coordinating multiple APM providers.
    
    Provides unified APM integration managing Datadog and New Relic providers,
    correlation ID propagation, custom attribute collection, and performance tracking.
    """
    
    def __init__(self, monitoring_config: MonitoringConfig = None):
        """Initialize APM integration manager."""
        self.apm_config = APMConfig()
        self.logger = get_logger(__name__)
        
        # Initialize components
        self.correlation_manager = CorrelationIDManager()
        self.attribute_collector = CustomAttributeCollector(self.apm_config)
        self.performance_tracker = PerformanceTracker(self.apm_config)
        
        # Initialize APM providers
        self.datadog_provider = None
        self.newrelic_provider = None
        
        if self.apm_config.enabled:
            self._initialize_providers()
    
    def _initialize_providers(self):
        """Initialize APM providers based on configuration."""
        if self.apm_config.datadog_enabled:
            self.datadog_provider = DatadogAPMProvider(self.apm_config)
        
        if self.apm_config.newrelic_enabled:
            self.newrelic_provider = NewRelicAPMProvider(self.apm_config)
        
        self.logger.info("APM providers initialized",
                        datadog_enabled=bool(self.datadog_provider and self.datadog_provider.initialized),
                        newrelic_enabled=bool(self.newrelic_provider and self.newrelic_provider.initialized))
    
    def patch_flask_application(self, app: Flask):
        """Apply APM instrumentation to Flask application."""
        if not self.apm_config.enabled:
            return
        
        # Patch providers
        if self.datadog_provider:
            self.datadog_provider.patch_flask_app(app)
        
        if self.newrelic_provider:
            self.newrelic_provider.patch_flask_app(app)
        
        # Setup request hooks
        app.before_request(self._before_request_handler)
        app.after_request(self._after_request_handler)
        app.teardown_request(self._teardown_request_handler)
        
        self.logger.info("Flask application patched with APM instrumentation")
    
    def _before_request_handler(self):
        """Handle request start for APM tracking."""
        # Extract or generate correlation ID
        correlation_id = self.correlation_manager.extract_correlation_id(dict(request.headers))
        if not correlation_id:
            correlation_id = self.correlation_manager.generate_correlation_id()
        
        # Set correlation context
        self.correlation_manager.set_correlation_context(correlation_id, self.apm_config)
        
        # Collect and add request attributes
        if self.apm_config.custom_attributes_enabled:
            request_attributes = self.attribute_collector.collect_request_attributes()
            infrastructure_attributes = self.attribute_collector.collect_infrastructure_context()
            
            all_attributes = {**request_attributes, **infrastructure_attributes}
            self.add_custom_attributes(all_attributes)
        
        # Store request start time for performance tracking
        g.apm_request_start = time.perf_counter()
        g.apm_correlation_id = correlation_id
    
    def _after_request_handler(self, response):
        """Handle request completion for APM tracking."""
        if hasattr(g, 'apm_request_start'):
            # Calculate response time
            response_time = time.perf_counter() - g.apm_request_start
            
            # Add response attributes
            response_attributes = {
                'http.status_code': response.status_code,
                'http.response_size': response.content_length or 0,
                'response.time_ms': response_time * 1000
            }
            
            self.add_custom_attributes(response_attributes)
            
            # Track performance if enabled
            if self.apm_config.track_performance_variance:
                endpoint = request.endpoint or 'unknown'
                performance_data = self.performance_tracker.record_performance(
                    endpoint, response_time, {
                        'status_code': response.status_code,
                        'method': request.method
                    }
                )
                
                # Add performance context attributes
                if self.apm_config.baseline_comparison_enabled:
                    perf_attributes = self.attribute_collector.collect_performance_context(
                        performance_data.get('baseline_response_time'),
                        response_time
                    )
                    self.add_custom_attributes(perf_attributes)
        
        return response
    
    def _teardown_request_handler(self, exception):
        """Handle request teardown for APM tracking."""
        if exception:
            # Record exception in APM providers
            if self.datadog_provider:
                self.datadog_provider.record_exception(exception)
            
            if self.newrelic_provider:
                self.newrelic_provider.record_exception(exception)
            
            # Add exception attributes
            exception_attributes = {
                'error': True,
                'error.type': type(exception).__name__,
                'error.message': str(exception),
                'error.timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            self.add_custom_attributes(exception_attributes)
    
    def add_custom_attributes(self, attributes: Dict[str, Any]):
        """Add custom attributes to all APM providers."""
        if not self.apm_config.custom_attributes_enabled:
            return
        
        if self.datadog_provider:
            self.datadog_provider.add_custom_attributes(attributes)
        
        if self.newrelic_provider:
            self.newrelic_provider.add_custom_attributes(attributes)
    
    def add_user_context(self, user_id: str, user_role: str = None, 
                        additional_context: Dict[str, Any] = None):
        """Add user context to APM tracing."""
        user_attributes = self.attribute_collector.collect_user_context(
            user_id, user_role, additional_context
        )
        self.add_custom_attributes(user_attributes)
    
    def add_business_context(self, operation: str, entity_type: str = None,
                           entity_id: str = None, additional_context: Dict[str, Any] = None):
        """Add business logic context to APM tracing."""
        business_attributes = self.attribute_collector.collect_business_context(
            operation, entity_type, entity_id, additional_context
        )
        self.add_custom_attributes(business_attributes)
    
    def set_performance_baseline(self, endpoint: str, baseline_time: float):
        """Set Node.js performance baseline for endpoint comparison."""
        self.performance_tracker.set_baseline(endpoint, baseline_time)
    
    def get_performance_summary(self, endpoint: str = None) -> Dict[str, Any]:
        """Get performance tracking summary."""
        return self.performance_tracker.get_performance_summary(endpoint)
    
    @contextmanager
    def trace_operation(self, operation_name: str, service: str = None,
                       resource: str = None, attributes: Dict[str, Any] = None):
        """Context manager for tracing custom operations."""
        # Start spans in both providers
        dd_span = None
        if self.datadog_provider:
            dd_span = self.datadog_provider.start_span(operation_name, service, resource)
        
        # Add custom attributes
        if attributes:
            self.add_custom_attributes(attributes)
        
        try:
            yield
        except Exception as e:
            # Record exception
            if self.datadog_provider:
                self.datadog_provider.record_exception(e)
            if self.newrelic_provider:
                self.newrelic_provider.record_exception(e)
            raise
        finally:
            # Close Datadog span
            if dd_span:
                dd_span.finish()


# Convenience decorators for APM tracing
def trace_business_operation(operation_name: str, entity_type: str = None):
    """Decorator for tracing business logic operations."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get APM manager from Flask app config
            apm_manager = None
            if has_request_context():
                from flask import current_app
                apm_manager = current_app.config.get('APM_MANAGER')
            
            if apm_manager:
                with apm_manager.trace_operation(
                    f"business.{operation_name}",
                    attributes={
                        'operation.name': operation_name,
                        'operation.type': 'business_logic',
                        'operation.entity_type': entity_type or 'unknown'
                    }
                ):
                    return func(*args, **kwargs)
            else:
                return func(*args, **kwargs)
        return wrapper
    return decorator


def trace_database_operation(operation: str, collection: str):
    """Decorator for tracing database operations."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get APM manager from Flask app config
            apm_manager = None
            if has_request_context():
                from flask import current_app
                apm_manager = current_app.config.get('APM_MANAGER')
            
            if apm_manager:
                with apm_manager.trace_operation(
                    f"database.{operation}",
                    service="mongodb",
                    resource=collection,
                    attributes={
                        'db.operation': operation,
                        'db.collection': collection,
                        'db.type': 'mongodb'
                    }
                ):
                    return func(*args, **kwargs)
            else:
                return func(*args, **kwargs)
        return wrapper
    return decorator


def trace_external_service(service_name: str, operation: str):
    """Decorator for tracing external service calls."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get APM manager from Flask app config
            apm_manager = None
            if has_request_context():
                from flask import current_app
                apm_manager = current_app.config.get('APM_MANAGER')
            
            if apm_manager:
                with apm_manager.trace_operation(
                    f"external.{service_name}.{operation}",
                    service=service_name,
                    resource=operation,
                    attributes={
                        'external.service': service_name,
                        'external.operation': operation,
                        'external.type': 'http'
                    }
                ):
                    return func(*args, **kwargs)
            else:
                return func(*args, **kwargs)
        return wrapper
    return decorator


def init_apm(app: Flask, monitoring_config: MonitoringConfig = None) -> APMIntegrationManager:
    """
    Initialize comprehensive APM integration for Flask application.
    
    Sets up enterprise-grade APM monitoring with Datadog and New Relic integration,
    distributed tracing, custom attribute collection, and performance tracking.
    
    Args:
        app: Flask application instance
        monitoring_config: Monitoring configuration (optional)
    
    Returns:
        APMIntegrationManager: Configured APM integration manager
    """
    # Initialize APM manager
    apm_manager = APMIntegrationManager(monitoring_config)
    
    # Patch Flask application
    apm_manager.patch_flask_application(app)
    
    # Store APM manager in app config
    app.config['APM_MANAGER'] = apm_manager
    app.config['APM_CONFIG'] = apm_manager.apm_config
    
    # Log initialization
    logger = get_logger(__name__)
    logger.info("APM integration initialized",
               service_name=apm_manager.apm_config.service_name,
               environment=apm_manager.apm_config.environment,
               datadog_enabled=apm_manager.apm_config.datadog_enabled,
               newrelic_enabled=apm_manager.apm_config.newrelic_enabled,
               custom_attributes_enabled=apm_manager.apm_config.custom_attributes_enabled,
               performance_tracking_enabled=apm_manager.apm_config.track_performance_variance)
    
    return apm_manager


# Export main interfaces
__all__ = [
    'APMConfig',
    'APMIntegrationManager',
    'CorrelationIDManager',
    'CustomAttributeCollector',
    'DatadogAPMProvider',
    'NewRelicAPMProvider',
    'PerformanceTracker',
    'trace_business_operation',
    'trace_database_operation',
    'trace_external_service',
    'init_apm'
]