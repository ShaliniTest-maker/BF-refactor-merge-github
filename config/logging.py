"""
Structured Logging Configuration Module

This module implements comprehensive structured logging using structlog 23.1+ with
JSON formatting, enterprise log aggregation, security audit trails, and monitoring
integration. This replaces Node.js winston/morgan logging patterns while providing
enhanced enterprise-grade logging capabilities for Flask applications.

Key Features:
- structlog 23.1+ for structured logging equivalent to Node.js patterns (Section 3.6.1)
- python-json-logger 2.0+ for JSON log formatting and enterprise aggregation (Section 3.6.1)
- Comprehensive security audit logging for enterprise compliance (Section 6.4.2)
- Enterprise logging system integration for Splunk/ELK Stack (Section 3.6.1)
- Performance monitoring and error tracking integration (Section 3.6.1)
- Circuit breaker and health check event logging (Section 4.5.2)
- OpenTelemetry tracing integration for distributed logging (Section 4.5.1)
- Prometheus metrics correlation and monitoring (Section 3.6.2)

Dependencies:
- structlog 23.1+ for structured logging framework
- python-json-logger 2.0+ for JSON log formatting
- pythonjsonlogger for enterprise log formatting
- opentelemetry-api 1.20+ for distributed tracing correlation
- config.settings for centralized configuration management

Author: Flask Migration Team
Version: 1.0.0
Migration Phase: Node.js to Python/Flask Migration (Section 0.1.1)
"""

import logging
import logging.config
import sys
import os
import json
import traceback
import threading
from pathlib import Path
from typing import Dict, Any, Optional, List, Union, Callable
from datetime import datetime, timezone
from contextlib import contextmanager
from functools import wraps

import structlog
from pythonjsonlogger import jsonlogger
from structlog.types import EventDict, WrappedLogger
from structlog._config import BoundLoggerLazyProxy

# Optional OpenTelemetry integration for distributed tracing
try:
    from opentelemetry import trace
    from opentelemetry.trace import get_current_span
    OPENTELEMETRY_AVAILABLE = True
except ImportError:
    OPENTELEMETRY_AVAILABLE = False
    trace = None
    get_current_span = None

# Optional Prometheus integration for metrics correlation
try:
    from prometheus_client import Counter, Histogram, Gauge
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    Counter = Histogram = Gauge = None

from config.settings import get_config


class LoggingConfigurationError(Exception):
    """Custom exception for logging configuration validation errors."""
    pass


class SecurityAuditLogger:
    """
    Comprehensive security audit logging implementation for Flask applications
    with structured event logging, threat detection, and compliance reporting.
    
    This class provides enterprise-grade security event logging capabilities
    with integration to SIEM systems and security monitoring platforms as
    specified in Section 6.4.2.
    """
    
    def __init__(self, logger_name: str = "security.audit"):
        """
        Initialize security audit logger with structured logging configuration.
        
        Args:
            logger_name: Logger name for security events
        """
        self.logger = structlog.get_logger(logger_name)
        self.metrics = SecurityMetrics() if PROMETHEUS_AVAILABLE else None
    
    def log_authentication_event(
        self,
        event_type: str,
        user_id: Optional[str] = None,
        result: str = "unknown",
        source_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        additional_context: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log authentication events with comprehensive security context.
        
        Args:
            event_type: Type of authentication event (login, logout, token_refresh)
            user_id: User identifier (masked for privacy)
            result: Authentication result (success, failure, blocked)
            source_ip: Client IP address
            user_agent: User agent string
            additional_context: Additional security context
        """
        log_data = {
            "event_category": "authentication",
            "event_type": event_type,
            "result": result,
            "user_id": self._mask_user_id(user_id) if user_id else None,
            "source_ip": source_ip,
            "user_agent": user_agent,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": "high" if result == "failure" else "info"
        }
        
        if additional_context:
            log_data.update(additional_context)
        
        # Add distributed tracing context if available
        if OPENTELEMETRY_AVAILABLE and get_current_span():
            span = get_current_span()
            span_context = span.get_span_context()
            log_data.update({
                "trace_id": format(span_context.trace_id, "032x"),
                "span_id": format(span_context.span_id, "016x")
            })
        
        if result == "failure":
            self.logger.warning("Authentication failed", **log_data)
            if self.metrics:
                self.metrics.auth_failures.inc()
        else:
            self.logger.info("Authentication event", **log_data)
            if self.metrics:
                self.metrics.auth_success.inc()
    
    def log_authorization_event(
        self,
        event_type: str,
        user_id: Optional[str] = None,
        resource: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        result: str = "unknown",
        endpoint: Optional[str] = None,
        additional_context: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log authorization events with resource and permission context.
        
        Args:
            event_type: Type of authorization event (permission_check, access_grant, access_deny)
            user_id: User identifier (masked for privacy)
            resource: Resource being accessed
            permissions: Required permissions
            result: Authorization result (granted, denied, error)
            endpoint: API endpoint accessed
            additional_context: Additional authorization context
        """
        log_data = {
            "event_category": "authorization",
            "event_type": event_type,
            "result": result,
            "user_id": self._mask_user_id(user_id) if user_id else None,
            "resource": resource,
            "permissions": permissions or [],
            "endpoint": endpoint,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": "warning" if result == "denied" else "info"
        }
        
        if additional_context:
            log_data.update(additional_context)
        
        # Add distributed tracing context if available
        if OPENTELEMETRY_AVAILABLE and get_current_span():
            span = get_current_span()
            span_context = span.get_span_context()
            log_data.update({
                "trace_id": format(span_context.trace_id, "032x"),
                "span_id": format(span_context.span_id, "016x")
            })
        
        if result == "denied":
            self.logger.warning("Authorization denied", **log_data)
            if self.metrics:
                self.metrics.authz_denials.inc()
        else:
            self.logger.info("Authorization event", **log_data)
            if self.metrics:
                self.metrics.authz_grants.inc()
    
    def log_security_violation(
        self,
        violation_type: str,
        severity: str = "high",
        user_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log security violations for threat detection and incident response.
        
        Args:
            violation_type: Type of security violation (rate_limit, injection_attempt, etc.)
            severity: Violation severity (low, medium, high, critical)
            user_id: User identifier (masked for privacy)
            source_ip: Source IP address
            details: Additional violation details
        """
        log_data = {
            "event_category": "security_violation",
            "violation_type": violation_type,
            "severity": severity,
            "user_id": self._mask_user_id(user_id) if user_id else None,
            "source_ip": source_ip,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "requires_investigation": severity in ["high", "critical"]
        }
        
        if details:
            log_data.update(details)
        
        # Add distributed tracing context if available
        if OPENTELEMETRY_AVAILABLE and get_current_span():
            span = get_current_span()
            span_context = span.get_span_context()
            log_data.update({
                "trace_id": format(span_context.trace_id, "032x"),
                "span_id": format(span_context.span_id, "016x")
            })
        
        if severity == "critical":
            self.logger.critical("Critical security violation detected", **log_data)
        elif severity == "high":
            self.logger.error("Security violation detected", **log_data)
        else:
            self.logger.warning("Security event detected", **log_data)
        
        if self.metrics:
            self.metrics.security_violations.labels(
                violation_type=violation_type,
                severity=severity
            ).inc()
    
    def log_data_access_event(
        self,
        operation: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        user_id: Optional[str] = None,
        result: str = "success",
        additional_context: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log data access events for compliance and audit requirements.
        
        Args:
            operation: Data operation (read, write, delete, export)
            resource_type: Type of resource accessed
            resource_id: Resource identifier (masked for privacy)
            user_id: User performing the operation
            result: Operation result (success, failure, partial)
            additional_context: Additional audit context
        """
        log_data = {
            "event_category": "data_access",
            "operation": operation,
            "resource_type": resource_type,
            "resource_id": self._mask_resource_id(resource_id) if resource_id else None,
            "user_id": self._mask_user_id(user_id) if user_id else None,
            "result": result,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "compliance_event": True
        }
        
        if additional_context:
            log_data.update(additional_context)
        
        # Add distributed tracing context if available
        if OPENTELEMETRY_AVAILABLE and get_current_span():
            span = get_current_span()
            span_context = span.get_span_context()
            log_data.update({
                "trace_id": format(span_context.trace_id, "032x"),
                "span_id": format(span_context.span_id, "016x")
            })
        
        self.logger.info("Data access event", **log_data)
        
        if self.metrics:
            self.metrics.data_access_events.labels(
                operation=operation,
                resource_type=resource_type,
                result=result
            ).inc()
    
    def _mask_user_id(self, user_id: str) -> str:
        """
        Mask user ID for privacy protection while maintaining audit capability.
        
        Args:
            user_id: Original user identifier
            
        Returns:
            Masked user identifier
        """
        if not user_id or len(user_id) < 4:
            return "****"
        return f"{user_id[:2]}***{user_id[-2:]}"
    
    def _mask_resource_id(self, resource_id: str) -> str:
        """
        Mask resource ID for privacy protection while maintaining audit capability.
        
        Args:
            resource_id: Original resource identifier
            
        Returns:
            Masked resource identifier
        """
        if not resource_id or len(resource_id) < 4:
            return "****"
        return f"{resource_id[:3]}***{resource_id[-3:]}"


class PerformanceLogger:
    """
    Performance monitoring logger for tracking system performance metrics,
    database operations, external service calls, and compliance with the
    ≤10% variance requirement from Node.js baseline.
    """
    
    def __init__(self, logger_name: str = "performance.monitoring"):
        """
        Initialize performance logger with metrics collection.
        
        Args:
            logger_name: Logger name for performance events
        """
        self.logger = structlog.get_logger(logger_name)
        self.metrics = PerformanceMetrics() if PROMETHEUS_AVAILABLE else None
    
    def log_request_performance(
        self,
        endpoint: str,
        method: str,
        duration_ms: float,
        status_code: int,
        user_id: Optional[str] = None,
        additional_context: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log HTTP request performance metrics.
        
        Args:
            endpoint: API endpoint accessed
            method: HTTP method
            duration_ms: Request duration in milliseconds
            status_code: HTTP response status code
            user_id: User making the request
            additional_context: Additional performance context
        """
        log_data = {
            "event_category": "performance",
            "event_type": "http_request",
            "endpoint": endpoint,
            "method": method,
            "duration_ms": duration_ms,
            "status_code": status_code,
            "user_id": user_id,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        if additional_context:
            log_data.update(additional_context)
        
        # Add distributed tracing context if available
        if OPENTELEMETRY_AVAILABLE and get_current_span():
            span = get_current_span()
            span_context = span.get_span_context()
            log_data.update({
                "trace_id": format(span_context.trace_id, "032x"),
                "span_id": format(span_context.span_id, "016x")
            })
        
        # Log at different levels based on performance
        if duration_ms > 5000:  # > 5 seconds
            self.logger.warning("Slow request detected", **log_data)
        elif duration_ms > 1000:  # > 1 second
            self.logger.info("Request completed", **log_data)
        else:
            self.logger.debug("Request completed", **log_data)
        
        if self.metrics:
            self.metrics.request_duration.labels(
                endpoint=endpoint,
                method=method,
                status=str(status_code)
            ).observe(duration_ms / 1000)  # Convert to seconds for Prometheus
    
    def log_database_operation(
        self,
        operation: str,
        collection: str,
        duration_ms: float,
        result: str = "success",
        record_count: Optional[int] = None,
        additional_context: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log database operation performance metrics.
        
        Args:
            operation: Database operation type (find, insert, update, delete)
            collection: Database collection name
            duration_ms: Operation duration in milliseconds
            result: Operation result (success, failure, timeout)
            record_count: Number of records affected
            additional_context: Additional database context
        """
        log_data = {
            "event_category": "performance",
            "event_type": "database_operation",
            "operation": operation,
            "collection": collection,
            "duration_ms": duration_ms,
            "result": result,
            "record_count": record_count,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        if additional_context:
            log_data.update(additional_context)
        
        # Add distributed tracing context if available
        if OPENTELEMETRY_AVAILABLE and get_current_span():
            span = get_current_span()
            span_context = span.get_span_context()
            log_data.update({
                "trace_id": format(span_context.trace_id, "032x"),
                "span_id": format(span_context.span_id, "016x")
            })
        
        # Log at different levels based on performance and result
        if result != "success":
            self.logger.error("Database operation failed", **log_data)
        elif duration_ms > 1000:  # > 1 second
            self.logger.warning("Slow database operation", **log_data)
        else:
            self.logger.debug("Database operation completed", **log_data)
        
        if self.metrics:
            self.metrics.db_operation_duration.labels(
                operation=operation,
                collection=collection,
                result=result
            ).observe(duration_ms / 1000)  # Convert to seconds for Prometheus
    
    def log_external_service_call(
        self,
        service_name: str,
        endpoint: str,
        duration_ms: float,
        status_code: Optional[int] = None,
        result: str = "success",
        additional_context: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log external service call performance metrics.
        
        Args:
            service_name: Name of external service
            endpoint: Service endpoint called
            duration_ms: Call duration in milliseconds
            status_code: HTTP status code if applicable
            result: Call result (success, failure, timeout, circuit_open)
            additional_context: Additional service context
        """
        log_data = {
            "event_category": "performance",
            "event_type": "external_service_call",
            "service_name": service_name,
            "endpoint": endpoint,
            "duration_ms": duration_ms,
            "status_code": status_code,
            "result": result,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        if additional_context:
            log_data.update(additional_context)
        
        # Add distributed tracing context if available
        if OPENTELEMETRY_AVAILABLE and get_current_span():
            span = get_current_span()
            span_context = span.get_span_context()
            log_data.update({
                "trace_id": format(span_context.trace_id, "032x"),
                "span_id": format(span_context.span_id, "016x")
            })
        
        # Log at different levels based on result and performance
        if result in ["failure", "timeout"]:
            self.logger.error("External service call failed", **log_data)
        elif result == "circuit_open":
            self.logger.warning("Circuit breaker open", **log_data)
        elif duration_ms > 5000:  # > 5 seconds
            self.logger.warning("Slow external service call", **log_data)
        else:
            self.logger.debug("External service call completed", **log_data)
        
        if self.metrics:
            self.metrics.external_service_duration.labels(
                service=service_name,
                result=result
            ).observe(duration_ms / 1000)  # Convert to seconds for Prometheus


class CircuitBreakerLogger:
    """
    Circuit breaker event logger for tracking service resilience patterns
    and system health monitoring as specified in Section 4.5.2.
    """
    
    def __init__(self, logger_name: str = "circuit_breaker"):
        """
        Initialize circuit breaker logger.
        
        Args:
            logger_name: Logger name for circuit breaker events
        """
        self.logger = structlog.get_logger(logger_name)
        self.metrics = CircuitBreakerMetrics() if PROMETHEUS_AVAILABLE else None
    
    def log_state_change(
        self,
        service_name: str,
        previous_state: str,
        new_state: str,
        failure_count: int,
        additional_context: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log circuit breaker state changes.
        
        Args:
            service_name: Name of the service
            previous_state: Previous circuit breaker state
            new_state: New circuit breaker state
            failure_count: Current failure count
            additional_context: Additional context
        """
        log_data = {
            "event_category": "circuit_breaker",
            "event_type": "state_change",
            "service_name": service_name,
            "previous_state": previous_state,
            "new_state": new_state,
            "failure_count": failure_count,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": "high" if new_state == "open" else "info"
        }
        
        if additional_context:
            log_data.update(additional_context)
        
        # Add distributed tracing context if available
        if OPENTELEMETRY_AVAILABLE and get_current_span():
            span = get_current_span()
            span_context = span.get_span_context()
            log_data.update({
                "trace_id": format(span_context.trace_id, "032x"),
                "span_id": format(span_context.span_id, "016x")
            })
        
        if new_state == "open":
            self.logger.error("Circuit breaker opened", **log_data)
        elif new_state == "closed" and previous_state == "open":
            self.logger.info("Circuit breaker recovered", **log_data)
        else:
            self.logger.info("Circuit breaker state change", **log_data)
        
        if self.metrics:
            self.metrics.state_changes.labels(
                service=service_name,
                new_state=new_state
            ).inc()


# Prometheus metrics classes (if prometheus_client is available)
if PROMETHEUS_AVAILABLE:
    class SecurityMetrics:
        """Prometheus metrics for security events."""
        
        def __init__(self):
            self.auth_success = Counter(
                'security_auth_success_total',
                'Total successful authentications'
            )
            self.auth_failures = Counter(
                'security_auth_failures_total',
                'Total authentication failures'
            )
            self.authz_grants = Counter(
                'security_authz_grants_total',
                'Total authorization grants'
            )
            self.authz_denials = Counter(
                'security_authz_denials_total',
                'Total authorization denials'
            )
            self.security_violations = Counter(
                'security_violations_total',
                'Total security violations',
                ['violation_type', 'severity']
            )
            self.data_access_events = Counter(
                'security_data_access_total',
                'Total data access events',
                ['operation', 'resource_type', 'result']
            )
    
    class PerformanceMetrics:
        """Prometheus metrics for performance monitoring."""
        
        def __init__(self):
            self.request_duration = Histogram(
                'http_request_duration_seconds',
                'HTTP request duration',
                ['endpoint', 'method', 'status']
            )
            self.db_operation_duration = Histogram(
                'database_operation_duration_seconds',
                'Database operation duration',
                ['operation', 'collection', 'result']
            )
            self.external_service_duration = Histogram(
                'external_service_duration_seconds',
                'External service call duration',
                ['service', 'result']
            )
    
    class CircuitBreakerMetrics:
        """Prometheus metrics for circuit breaker events."""
        
        def __init__(self):
            self.state_changes = Counter(
                'circuit_breaker_state_changes_total',
                'Circuit breaker state changes',
                ['service', 'new_state']
            )
else:
    # Stub classes when Prometheus is not available
    class SecurityMetrics:
        def __init__(self):
            pass
    
    class PerformanceMetrics:
        def __init__(self):
            pass
    
    class CircuitBreakerMetrics:
        def __init__(self):
            pass


class EnterpriseJSONFormatter(jsonlogger.JsonFormatter):
    """
    Enhanced JSON log formatter for enterprise log aggregation systems
    with SIEM integration support and compliance features.
    """
    
    def __init__(self, *args, **kwargs):
        """Initialize enterprise JSON formatter with enhanced fields."""
        # Define consistent field names for enterprise log aggregation
        format_string = ' '.join([
            '%(asctime)s',
            '%(name)s',
            '%(levelname)s',
            '%(message)s',
            '%(pathname)s',
            '%(lineno)d',
            '%(funcName)s',
            '%(process)d',
            '%(thread)d'
        ])
        super().__init__(format_string, *args, **kwargs)
    
    def add_fields(self, log_record: Dict[str, Any], record: logging.LogRecord, message_dict: Dict[str, Any]) -> None:
        """
        Add enterprise-specific fields to log records.
        
        Args:
            log_record: Dictionary to be logged
            record: Python logging record
            message_dict: Message dictionary from structlog
        """
        super().add_fields(log_record, record, message_dict)
        
        # Add enterprise-specific fields
        log_record['service'] = 'flask-application'
        log_record['environment'] = os.getenv('FLASK_ENV', 'production')
        log_record['application'] = 'flask-migration-app'
        log_record['version'] = os.getenv('APP_VERSION', '1.0.0')
        
        # Add process and thread information for debugging
        log_record['process_id'] = os.getpid()
        log_record['thread_id'] = threading.get_ident()
        
        # Add hostname for distributed system identification
        import socket
        log_record['hostname'] = socket.gethostname()
        
        # Ensure timestamp is in ISO format for SIEM systems
        if not log_record.get('timestamp'):
            log_record['timestamp'] = datetime.now(timezone.utc).isoformat()
        
        # Add log schema version for compatibility
        log_record['log_schema_version'] = '1.0'


def add_trace_context(logger: WrappedLogger, method_name: str, event_dict: EventDict) -> EventDict:
    """
    Add OpenTelemetry trace context to log entries for distributed tracing correlation.
    
    Args:
        logger: Wrapped logger instance
        method_name: Logging method name
        event_dict: Event dictionary to enhance
        
    Returns:
        Enhanced event dictionary with trace context
    """
    if OPENTELEMETRY_AVAILABLE and get_current_span():
        span = get_current_span()
        span_context = span.get_span_context()
        if span_context.is_valid:
            event_dict['trace_id'] = format(span_context.trace_id, "032x")
            event_dict['span_id'] = format(span_context.span_id, "016x")
            event_dict['trace_flags'] = format(span_context.trace_flags, "02x")
    
    return event_dict


def add_request_context(logger: WrappedLogger, method_name: str, event_dict: EventDict) -> EventDict:
    """
    Add Flask request context to log entries when available.
    
    Args:
        logger: Wrapped logger instance
        method_name: Logging method name
        event_dict: Event dictionary to enhance
        
    Returns:
        Enhanced event dictionary with request context
    """
    try:
        from flask import request, g
        if request:
            event_dict['request_id'] = getattr(g, 'request_id', None)
            event_dict['remote_addr'] = request.remote_addr
            event_dict['method'] = request.method
            event_dict['path'] = request.path
            event_dict['user_agent'] = request.headers.get('User-Agent')
            
            # Add user context if available
            if hasattr(g, 'current_user') and g.current_user:
                event_dict['user_id'] = getattr(g.current_user, 'id', None)
    except (RuntimeError, ImportError):
        # Outside of Flask request context or Flask not available
        pass
    
    return event_dict


def add_exception_context(logger: WrappedLogger, method_name: str, event_dict: EventDict) -> EventDict:
    """
    Add exception context to log entries for error tracking.
    
    Args:
        logger: Wrapped logger instance
        method_name: Logging method name
        event_dict: Event dictionary to enhance
        
    Returns:
        Enhanced event dictionary with exception context
    """
    if 'exc_info' in event_dict and event_dict['exc_info']:
        # Extract exception information
        exc_type, exc_value, exc_traceback = event_dict['exc_info']
        event_dict['exception_type'] = exc_type.__name__ if exc_type else None
        event_dict['exception_message'] = str(exc_value) if exc_value else None
        
        # Add stack trace for error analysis
        if exc_traceback:
            event_dict['stack_trace'] = ''.join(traceback.format_tb(exc_traceback))
    
    return event_dict


def filter_sensitive_data(logger: WrappedLogger, method_name: str, event_dict: EventDict) -> EventDict:
    """
    Filter sensitive data from log entries for security compliance.
    
    Args:
        logger: Wrapped logger instance
        method_name: Logging method name
        event_dict: Event dictionary to filter
        
    Returns:
        Filtered event dictionary with sensitive data masked
    """
    sensitive_fields = [
        'password', 'secret', 'token', 'key', 'auth', 'credential',
        'ssn', 'social_security', 'credit_card', 'cc_number'
    ]
    
    def mask_sensitive_value(value: Any) -> Any:
        """Mask sensitive values while preserving type."""
        if isinstance(value, str) and len(value) > 4:
            return f"{value[:2]}***{value[-2:]}"
        elif isinstance(value, str):
            return "***"
        return "***"
    
    def filter_dict(data: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively filter dictionary for sensitive data."""
        filtered = {}
        for key, value in data.items():
            key_lower = key.lower()
            if any(sensitive in key_lower for sensitive in sensitive_fields):
                filtered[key] = mask_sensitive_value(value)
            elif isinstance(value, dict):
                filtered[key] = filter_dict(value)
            elif isinstance(value, list):
                filtered[key] = [
                    filter_dict(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                filtered[key] = value
        return filtered
    
    return filter_dict(event_dict)


class LoggingConfiguration:
    """
    Comprehensive logging configuration manager for Flask applications
    implementing enterprise-grade structured logging with security audit
    capabilities and monitoring integration.
    """
    
    def __init__(self, config: Optional[Any] = None):
        """
        Initialize logging configuration with Flask application settings.
        
        Args:
            config: Flask configuration object or None to load from settings
        """
        self.config = config or get_config()
        self.is_configured = False
        self._validate_configuration()
    
    def _validate_configuration(self) -> None:
        """
        Validate logging configuration requirements.
        
        Raises:
            LoggingConfigurationError: When configuration is invalid
        """
        required_attrs = ['LOG_LEVEL', 'LOG_FORMAT']
        missing_attrs = [attr for attr in required_attrs if not hasattr(self.config, attr)]
        
        if missing_attrs:
            raise LoggingConfigurationError(
                f"Missing required logging configuration: {', '.join(missing_attrs)}"
            )
    
    def configure_structured_logging(self) -> None:
        """
        Configure structlog with enterprise-grade processors and formatters.
        
        This method implements comprehensive structured logging configuration
        as specified in Section 3.6.1 with JSON formatting for enterprise
        log aggregation systems.
        """
        # Configure standard library logging first
        self._configure_stdlib_logging()
        
        # Define structlog processors pipeline
        processors = [
            # Add trace context for distributed logging
            add_trace_context,
            # Add Flask request context when available
            add_request_context,
            # Add exception context for error tracking
            add_exception_context,
            # Filter sensitive data for security compliance
            filter_sensitive_data,
            # Standard structlog processors
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
        ]
        
        # Add JSON formatting for enterprise log aggregation
        if self.config.LOG_FORMAT.lower() == 'json':
            processors.append(structlog.processors.JSONRenderer())
        else:
            processors.append(structlog.dev.ConsoleRenderer())
        
        # Configure structlog
        structlog.configure(
            processors=processors,
            wrapper_class=structlog.stdlib.LoggerFactory(),
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            cache_logger_on_first_use=True,
        )
        
        self.is_configured = True
    
    def _configure_stdlib_logging(self) -> None:
        """
        Configure Python standard library logging with enterprise formatters.
        """
        # Create log directory if specified
        log_file = getattr(self.config, 'LOG_FILE', None)
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Configure logging handlers
        handlers = self._create_log_handlers()
        
        # Configure root logger
        logging.basicConfig(
            level=getattr(logging, self.config.LOG_LEVEL.upper()),
            handlers=handlers,
            force=True  # Override any existing configuration
        )
        
        # Configure specific loggers for different components
        self._configure_component_loggers()
    
    def _create_log_handlers(self) -> List[logging.Handler]:
        """
        Create logging handlers for different output destinations.
        
        Returns:
            List of configured logging handlers
        """
        handlers = []
        
        # Console handler for development and container environments
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(self._create_formatter())
        handlers.append(console_handler)
        
        # File handler if log file is specified
        log_file = getattr(self.config, 'LOG_FILE', None)
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(self._create_formatter())
            handlers.append(file_handler)
        
        # Rotating file handler for production environments
        if hasattr(self.config, 'LOG_ROTATION_ENABLED') and self.config.LOG_ROTATION_ENABLED:
            from logging.handlers import RotatingFileHandler
            rotation_handler = RotatingFileHandler(
                log_file or 'logs/app.log',
                maxBytes=getattr(self.config, 'LOG_MAX_BYTES', 10 * 1024 * 1024),  # 10MB
                backupCount=getattr(self.config, 'LOG_BACKUP_COUNT', 5)
            )
            rotation_handler.setFormatter(self._create_formatter())
            handlers.append(rotation_handler)
        
        return handlers
    
    def _create_formatter(self) -> logging.Formatter:
        """
        Create appropriate log formatter based on configuration.
        
        Returns:
            Configured log formatter
        """
        if self.config.LOG_FORMAT.lower() == 'json':
            return EnterpriseJSONFormatter()
        else:
            return logging.Formatter(
                fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
    
    def _configure_component_loggers(self) -> None:
        """
        Configure specific loggers for different application components.
        """
        # Security logger configuration
        security_logger = logging.getLogger('security')
        security_logger.setLevel(logging.INFO)
        
        # Performance logger configuration
        performance_logger = logging.getLogger('performance')
        performance_logger.setLevel(
            logging.DEBUG if self.config.DEBUG else logging.INFO
        )
        
        # Circuit breaker logger configuration
        circuit_breaker_logger = logging.getLogger('circuit_breaker')
        circuit_breaker_logger.setLevel(logging.INFO)
        
        # Database logger configuration
        db_logger = logging.getLogger('database')
        db_logger.setLevel(
            logging.DEBUG if self.config.DEBUG else logging.WARNING
        )
        
        # External service logger configuration
        external_logger = logging.getLogger('external_services')
        external_logger.setLevel(logging.INFO)
        
        # Suppress verbose third-party library logging
        self._suppress_verbose_loggers()
    
    def _suppress_verbose_loggers(self) -> None:
        """
        Suppress verbose logging from third-party libraries.
        """
        verbose_loggers = [
            'urllib3.connectionpool',
            'requests.packages.urllib3',
            'boto3.session',
            'botocore.client',
            'werkzeug'
        ]
        
        for logger_name in verbose_loggers:
            logger = logging.getLogger(logger_name)
            logger.setLevel(logging.WARNING)
    
    def get_security_logger(self) -> SecurityAuditLogger:
        """
        Get configured security audit logger instance.
        
        Returns:
            Configured SecurityAuditLogger instance
        """
        if not self.is_configured:
            self.configure_structured_logging()
        
        return SecurityAuditLogger()
    
    def get_performance_logger(self) -> PerformanceLogger:
        """
        Get configured performance logger instance.
        
        Returns:
            Configured PerformanceLogger instance
        """
        if not self.is_configured:
            self.configure_structured_logging()
        
        return PerformanceLogger()
    
    def get_circuit_breaker_logger(self) -> CircuitBreakerLogger:
        """
        Get configured circuit breaker logger instance.
        
        Returns:
            Configured CircuitBreakerLogger instance
        """
        if not self.is_configured:
            self.configure_structured_logging()
        
        return CircuitBreakerLogger()


# Decorator for logging function performance
def log_performance(
    operation_name: Optional[str] = None,
    include_args: bool = False,
    include_result: bool = False
) -> Callable:
    """
    Decorator for automatic performance logging of function execution.
    
    Args:
        operation_name: Custom operation name for logging
        include_args: Whether to include function arguments in logs
        include_result: Whether to include function result in logs
        
    Returns:
        Decorated function with performance logging
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = datetime.now(timezone.utc)
            logger = structlog.get_logger(f"performance.{func.__module__}")
            op_name = operation_name or f"{func.__module__}.{func.__name__}"
            
            log_data = {
                "operation": op_name,
                "start_time": start_time.isoformat()
            }
            
            if include_args:
                log_data["args"] = str(args)
                log_data["kwargs"] = kwargs
            
            try:
                result = func(*args, **kwargs)
                end_time = datetime.now(timezone.utc)
                duration_ms = (end_time - start_time).total_seconds() * 1000
                
                log_data.update({
                    "duration_ms": duration_ms,
                    "result": "success",
                    "end_time": end_time.isoformat()
                })
                
                if include_result:
                    log_data["return_value"] = str(result)
                
                logger.info("Operation completed", **log_data)
                return result
                
            except Exception as e:
                end_time = datetime.now(timezone.utc)
                duration_ms = (end_time - start_time).total_seconds() * 1000
                
                log_data.update({
                    "duration_ms": duration_ms,
                    "result": "error",
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "end_time": end_time.isoformat()
                })
                
                logger.error("Operation failed", **log_data, exc_info=True)
                raise
        
        return wrapper
    return decorator


@contextmanager
def log_context(**context_data):
    """
    Context manager for adding context data to all log entries within the context.
    
    Args:
        **context_data: Context data to add to log entries
        
    Yields:
        Context manager with logging context
    """
    structlog.contextvars.clear_contextvars()
    for key, value in context_data.items():
        structlog.contextvars.bind_contextvars(**{key: value})
    
    try:
        yield
    finally:
        structlog.contextvars.clear_contextvars()


# Global logging configuration instance
_logging_config: Optional[LoggingConfiguration] = None


def configure_application_logging(app_config: Optional[Any] = None) -> LoggingConfiguration:
    """
    Configure application logging for Flask applications.
    
    This function should be called during Flask application initialization
    to set up comprehensive structured logging with enterprise features.
    
    Args:
        app_config: Flask application configuration
        
    Returns:
        Configured LoggingConfiguration instance
    """
    global _logging_config
    
    if _logging_config is None:
        _logging_config = LoggingConfiguration(app_config)
        _logging_config.configure_structured_logging()
    
    return _logging_config


def get_logger(name: str) -> BoundLoggerLazyProxy:
    """
    Get a configured structlog logger instance.
    
    Args:
        name: Logger name
        
    Returns:
        Configured structlog logger
    """
    if _logging_config is None:
        configure_application_logging()
    
    return structlog.get_logger(name)


def get_security_logger() -> SecurityAuditLogger:
    """
    Get the configured security audit logger.
    
    Returns:
        Configured SecurityAuditLogger instance
    """
    if _logging_config is None:
        configure_application_logging()
    
    return _logging_config.get_security_logger()


def get_performance_logger() -> PerformanceLogger:
    """
    Get the configured performance logger.
    
    Returns:
        Configured PerformanceLogger instance
    """
    if _logging_config is None:
        configure_application_logging()
    
    return _logging_config.get_performance_logger()


def get_circuit_breaker_logger() -> CircuitBreakerLogger:
    """
    Get the configured circuit breaker logger.
    
    Returns:
        Configured CircuitBreakerLogger instance
    """
    if _logging_config is None:
        configure_application_logging()
    
    return _logging_config.get_circuit_breaker_logger()


# Export public interface
__all__ = [
    'LoggingConfiguration',
    'SecurityAuditLogger',
    'PerformanceLogger',
    'CircuitBreakerLogger',
    'EnterpriseJSONFormatter',
    'configure_application_logging',
    'get_logger',
    'get_security_logger',
    'get_performance_logger',
    'get_circuit_breaker_logger',
    'log_performance',
    'log_context',
    'LoggingConfigurationError'
]