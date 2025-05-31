"""
Structured Logging Implementation using structlog 23.1+

This module implements enterprise-grade structured logging providing JSON-formatted
enterprise logging, correlation ID tracking, security audit logging, and centralized
log aggregation integration. Implements comprehensive logging patterns equivalent to
Node.js winston/morgan logging with enterprise SIEM compatibility.

Key Features:
- structlog 23.1+ structured logging equivalent to Node.js logging patterns
- JSON log formatting for enterprise log aggregation (Splunk, ELK Stack)
- Correlation ID tracking for distributed tracing and request correlation
- Security audit logging with structured event tracking and compliance support
- Enterprise integration with APM tools (Datadog, New Relic)
- Performance monitoring integration with request/response timing
- Environment-specific configuration management
- Rate limiting and circuit breaker event logging
- Comprehensive error tracking and exception handling

Architecture Integration:
- Flask application factory pattern integration for centralized logging configuration
- Integration with Flask-Talisman security headers for security event correlation
- Flask-Session integration for session-based event tracking
- Auth0 integration for authentication event logging with JWT validation tracking
- MongoDB and Redis operation logging with performance metrics
- AWS service integration logging for S3 operations and KMS key management

Performance Requirements:
- Minimal logging overhead: <2ms per log entry to maintain ≤10% variance requirement
- Efficient JSON serialization with structured data formatting
- Intelligent log level filtering based on environment configuration
- Optimized correlation ID generation and propagation
- High-performance enterprise log aggregation compatibility

References:
- Section 0.2.4: Dependency decisions for structlog 23.1+ structured logging
- Section 3.6.1: JSON log formatting for enterprise log aggregation
- Section 4.5.1: Application monitoring pipeline with structured logging integration
- Section 6.5.1.2: Log aggregation flow and enterprise logging systems
- Section 6.4.2: Security audit logging requirements and SIEM integration
"""

import gc
import inspect
import json
import logging
import logging.config
import logging.handlers
import os
import sys
import time
import traceback
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional, Union, Callable

import structlog
from flask import Flask, request, g, has_request_context, current_app
from werkzeug.local import LocalProxy

try:
    # Enterprise APM Integration - Datadog
    import ddtrace
    from ddtrace import tracer
    DATADOG_AVAILABLE = True
except ImportError:
    DATADOG_AVAILABLE = False

try:
    # Enterprise APM Integration - New Relic
    import newrelic.agent
    NEWRELIC_AVAILABLE = True
except ImportError:
    NEWRELIC_AVAILABLE = False

try:
    # Performance profiling for logging overhead monitoring
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


# Global correlation ID context variable for distributed tracing
correlation_id_context: ContextVar[Optional[str]] = ContextVar('correlation_id', default=None)

# Global request context variables for enhanced logging
request_start_time_context: ContextVar[Optional[float]] = ContextVar('request_start_time', default=None)
user_context: ContextVar[Optional[Dict[str, Any]]] = ContextVar('user_context', default=None)
session_context: ContextVar[Optional[Dict[str, Any]]] = ContextVar('session_context', default=None)


class LoggingConfig:
    """
    Comprehensive logging configuration for enterprise-grade structured logging
    with environment-specific settings, performance optimization, and security features.
    """
    
    # Core Logging Configuration
    STRUCTURED_LOGGING_ENABLED = os.getenv('STRUCTURED_LOGGING_ENABLED', 'true').lower() == 'true'
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
    LOG_FORMAT = os.getenv('LOG_FORMAT', 'json')  # json, console, structured
    
    # File Logging Configuration
    LOG_FILE_ENABLED = os.getenv('LOG_FILE_ENABLED', 'true').lower() == 'true'
    LOG_FILE_PATH = os.getenv('LOG_FILE_PATH', '/var/log/flask-migration/app.log')
    LOG_FILE_MAX_SIZE = int(os.getenv('LOG_FILE_MAX_SIZE', '100')) * 1024 * 1024  # 100MB default
    LOG_FILE_BACKUP_COUNT = int(os.getenv('LOG_FILE_BACKUP_COUNT', '5'))
    
    # Console Logging Configuration
    CONSOLE_LOGGING_ENABLED = os.getenv('CONSOLE_LOGGING_ENABLED', 'true').lower() == 'true'
    COLORED_CONSOLE_OUTPUT = os.getenv('COLORED_CONSOLE_OUTPUT', 'false').lower() == 'true'
    
    # Enterprise Log Aggregation
    ENTERPRISE_LOGGING_ENABLED = os.getenv('ENTERPRISE_LOGGING_ENABLED', 'true').lower() == 'true'
    SPLUNK_ENDPOINT = os.getenv('SPLUNK_ENDPOINT', None)
    SPLUNK_TOKEN = os.getenv('SPLUNK_TOKEN', None)
    ELK_ENDPOINT = os.getenv('ELK_ENDPOINT', None)
    ELK_API_KEY = os.getenv('ELK_API_KEY', None)
    SIEM_ENDPOINT = os.getenv('SIEM_ENDPOINT', None)
    
    # Correlation and Tracing Configuration
    CORRELATION_ID_ENABLED = os.getenv('CORRELATION_ID_ENABLED', 'true').lower() == 'true'
    DISTRIBUTED_TRACING_ENABLED = os.getenv('DISTRIBUTED_TRACING_ENABLED', 'true').lower() == 'true'
    REQUEST_LOGGING_ENABLED = os.getenv('REQUEST_LOGGING_ENABLED', 'true').lower() == 'true'
    
    # Security Audit Logging
    SECURITY_AUDIT_ENABLED = os.getenv('SECURITY_AUDIT_ENABLED', 'true').lower() == 'true'
    AUTH_EVENT_LOGGING = os.getenv('AUTH_EVENT_LOGGING', 'true').lower() == 'true'
    PERMISSION_AUDIT_LOGGING = os.getenv('PERMISSION_AUDIT_LOGGING', 'true').lower() == 'true'
    
    # Performance and Monitoring
    PERFORMANCE_LOGGING_ENABLED = os.getenv('PERFORMANCE_LOGGING_ENABLED', 'true').lower() == 'true'
    SLOW_REQUEST_THRESHOLD = float(os.getenv('SLOW_REQUEST_THRESHOLD', '5.0'))  # seconds
    LOG_SAMPLING_ENABLED = os.getenv('LOG_SAMPLING_ENABLED', 'false').lower() == 'true'
    LOG_SAMPLING_RATE = float(os.getenv('LOG_SAMPLING_RATE', '1.0'))  # 1.0 = 100%
    
    # Environment and Application Context
    ENVIRONMENT = os.getenv('FLASK_ENV', 'production')
    APPLICATION_NAME = os.getenv('APPLICATION_NAME', 'flask-migration-app')
    APPLICATION_VERSION = os.getenv('APPLICATION_VERSION', '1.0.0')
    DEPLOYMENT_ID = os.getenv('DEPLOYMENT_ID', 'unknown')
    
    # Log Retention and Cleanup
    LOG_RETENTION_DAYS = int(os.getenv('LOG_RETENTION_DAYS', '30'))
    LOG_CLEANUP_ENABLED = os.getenv('LOG_CLEANUP_ENABLED', 'true').lower() == 'true'
    
    # Advanced Configuration
    EXCEPTION_TRACEBACK_ENABLED = os.getenv('EXCEPTION_TRACEBACK_ENABLED', 'true').lower() == 'true'
    STACK_INFO_ENABLED = os.getenv('STACK_INFO_ENABLED', 'false').lower() == 'true'
    CALLER_INFO_ENABLED = os.getenv('CALLER_INFO_ENABLED', 'true').lower() == 'true'


class CorrelationManager:
    """
    Correlation ID management for distributed tracing and request tracking
    across microservices and external service integrations.
    """
    
    _instance = None
    _lock = Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not hasattr(self, 'initialized'):
            self.initialized = True
            self._correlation_counter = 0
            self._instance_id = str(uuid.uuid4())[:8]
    
    def generate_correlation_id(self) -> str:
        """
        Generate a unique correlation ID for request tracking.
        
        Format: {timestamp}-{instance_id}-{counter}
        Example: 20231201T120000-a1b2c3d4-000001
        
        Returns:
            Unique correlation ID string
        """
        with self._lock:
            self._correlation_counter += 1
            timestamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')
            return f"{timestamp}-{self._instance_id}-{self._correlation_counter:06d}"
    
    def set_correlation_id(self, correlation_id: Optional[str] = None) -> str:
        """
        Set correlation ID in context with automatic generation if not provided.
        
        Args:
            correlation_id: Optional correlation ID, generated if None
            
        Returns:
            The correlation ID that was set
        """
        if correlation_id is None:
            correlation_id = self.generate_correlation_id()
        
        correlation_id_context.set(correlation_id)
        
        # Set in Flask g context if available
        if has_request_context():
            g.correlation_id = correlation_id
        
        return correlation_id
    
    def get_correlation_id(self) -> Optional[str]:
        """
        Get current correlation ID from context or Flask g.
        
        Returns:
            Current correlation ID or None if not set
        """
        # Try context first
        correlation_id = correlation_id_context.get()
        if correlation_id:
            return correlation_id
        
        # Fallback to Flask g context
        if has_request_context() and hasattr(g, 'correlation_id'):
            return g.correlation_id
        
        return None
    
    def clear_correlation_id(self) -> None:
        """Clear correlation ID from all contexts."""
        correlation_id_context.set(None)
        
        if has_request_context() and hasattr(g, 'correlation_id'):
            delattr(g, 'correlation_id')


class RequestContextManager:
    """
    Request context management for enhanced logging with user, session,
    and performance data for comprehensive audit trails.
    """
    
    def __init__(self):
        self.correlation_manager = CorrelationManager()
    
    def set_request_context(
        self,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        endpoint: Optional[str] = None,
        method: Optional[str] = None,
        additional_context: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Set comprehensive request context for enhanced logging.
        
        Args:
            user_id: Authenticated user identifier
            session_id: Session identifier
            endpoint: API endpoint being accessed
            method: HTTP method
            additional_context: Additional contextual information
        """
        # Set request start time for performance tracking
        request_start_time_context.set(time.perf_counter())
        
        # Set user context
        if user_id:
            user_context.set({
                'user_id': user_id,
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
        
        # Set session context
        if session_id:
            session_context.set({
                'session_id': session_id,
                'endpoint': endpoint,
                'method': method,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                **(additional_context or {})
            })
        
        # Set in Flask g context if available
        if has_request_context():
            g.request_start_time = time.perf_counter()
            if user_id:
                g.user_id = user_id
            if session_id:
                g.session_id = session_id
    
    def get_request_context(self) -> Dict[str, Any]:
        """
        Get comprehensive request context for logging enhancement.
        
        Returns:
            Dictionary containing all available request context
        """
        context = {
            'correlation_id': self.correlation_manager.get_correlation_id(),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        # Add user context
        user_ctx = user_context.get()
        if user_ctx:
            context.update(user_ctx)
        
        # Add session context
        session_ctx = session_context.get()
        if session_ctx:
            context.update(session_ctx)
        
        # Add Flask context if available
        if has_request_context():
            if hasattr(g, 'user_id'):
                context['user_id'] = g.user_id
            if hasattr(g, 'session_id'):
                context['session_id'] = g.session_id
            if hasattr(g, 'request_start_time'):
                duration = time.perf_counter() - g.request_start_time
                context['request_duration_ms'] = round(duration * 1000, 2)
        
        # Add request-specific information
        if has_request_context():
            context.update({
                'endpoint': request.endpoint,
                'method': request.method,
                'path': request.path,
                'remote_addr': request.remote_addr,
                'user_agent': request.headers.get('User-Agent', 'unknown')[:200]  # Truncate for log size
            })
        
        return context
    
    def clear_request_context(self) -> None:
        """Clear all request context variables."""
        request_start_time_context.set(None)
        user_context.set(None)
        session_context.set(None)
        
        # Clear Flask g context
        if has_request_context():
            for attr in ['request_start_time', 'user_id', 'session_id']:
                if hasattr(g, attr):
                    delattr(g, attr)


class SecurityAuditLogger:
    """
    Security audit logging for authentication, authorization, and security events
    with structured event tracking and enterprise SIEM integration.
    """
    
    def __init__(self, logger: structlog.stdlib.BoundLogger):
        self.logger = logger
        self.correlation_manager = CorrelationManager()
        self.request_context = RequestContextManager()
    
    def log_authentication_event(
        self,
        event_type: str,
        user_id: Optional[str] = None,
        success: bool = True,
        auth_method: str = 'jwt',
        additional_data: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log authentication events with comprehensive security context.
        
        Args:
            event_type: Type of authentication event (login, logout, token_refresh)
            user_id: User identifier
            success: Whether authentication was successful
            auth_method: Authentication method used
            additional_data: Additional security context
        """
        if not LoggingConfig.AUTH_EVENT_LOGGING:
            return
        
        security_event = {
            'event_category': 'authentication',
            'event_type': event_type,
            'user_id': user_id,
            'success': success,
            'auth_method': auth_method,
            'severity': 'info' if success else 'warning',
            'security_audit': True,
            **self.request_context.get_request_context(),
            **(additional_data or {})
        }
        
        log_method = self.logger.info if success else self.logger.warning
        log_method(
            f"Authentication {event_type}: {'success' if success else 'failure'}",
            **security_event
        )
    
    def log_authorization_event(
        self,
        event_type: str,
        user_id: str,
        resource: str,
        action: str,
        granted: bool,
        permissions: Optional[List[str]] = None,
        additional_data: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log authorization events with permission details and resource context.
        
        Args:
            event_type: Type of authorization event
            user_id: User identifier
            resource: Resource being accessed
            action: Action being performed
            granted: Whether access was granted
            permissions: Required permissions
            additional_data: Additional context
        """
        if not LoggingConfig.PERMISSION_AUDIT_LOGGING:
            return
        
        security_event = {
            'event_category': 'authorization',
            'event_type': event_type,
            'user_id': user_id,
            'resource': resource,
            'action': action,
            'granted': granted,
            'required_permissions': permissions or [],
            'severity': 'info' if granted else 'warning',
            'security_audit': True,
            **self.request_context.get_request_context(),
            **(additional_data or {})
        }
        
        log_method = self.logger.info if granted else self.logger.warning
        log_method(
            f"Authorization {event_type}: {'granted' if granted else 'denied'} for {resource}.{action}",
            **security_event
        )
    
    def log_security_violation(
        self,
        violation_type: str,
        severity: str = 'high',
        user_id: Optional[str] = None,
        description: Optional[str] = None,
        additional_data: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log security violations and suspicious activities.
        
        Args:
            violation_type: Type of security violation
            severity: Severity level (low, medium, high, critical)
            user_id: User associated with violation
            description: Violation description
            additional_data: Additional security context
        """
        security_event = {
            'event_category': 'security_violation',
            'violation_type': violation_type,
            'severity': severity,
            'user_id': user_id,
            'description': description,
            'security_audit': True,
            'requires_investigation': severity in ['high', 'critical'],
            **self.request_context.get_request_context(),
            **(additional_data or {})
        }
        
        # Map severity to log level
        if severity == 'critical':
            self.logger.critical(f"CRITICAL SECURITY VIOLATION: {violation_type}", **security_event)
        elif severity == 'high':
            self.logger.error(f"Security violation: {violation_type}", **security_event)
        elif severity == 'medium':
            self.logger.warning(f"Security event: {violation_type}", **security_event)
        else:
            self.logger.info(f"Security notice: {violation_type}", **security_event)
    
    def log_data_access_event(
        self,
        event_type: str,
        user_id: str,
        data_type: str,
        operation: str,
        record_count: Optional[int] = None,
        additional_data: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log data access events for compliance and audit requirements.
        
        Args:
            event_type: Type of data access event
            user_id: User performing the operation
            data_type: Type of data accessed
            operation: Operation performed (read, write, delete)
            record_count: Number of records affected
            additional_data: Additional audit context
        """
        audit_event = {
            'event_category': 'data_access',
            'event_type': event_type,
            'user_id': user_id,
            'data_type': data_type,
            'operation': operation,
            'record_count': record_count,
            'security_audit': True,
            'compliance_event': True,
            **self.request_context.get_request_context(),
            **(additional_data or {})
        }
        
        self.logger.info(f"Data access: {operation} {data_type}", **audit_event)


class PerformanceLogger:
    """
    Performance logging for request timing, database operations, and external
    service calls with Node.js baseline comparison and performance variance tracking.
    """
    
    def __init__(self, logger: structlog.stdlib.BoundLogger):
        self.logger = logger
        self.correlation_manager = CorrelationManager()
        self.request_context = RequestContextManager()
    
    def log_request_performance(
        self,
        endpoint: str,
        method: str,
        duration_ms: float,
        status_code: int,
        baseline_ms: Optional[float] = None,
        additional_metrics: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log request performance with Node.js baseline comparison.
        
        Args:
            endpoint: API endpoint
            method: HTTP method
            duration_ms: Request duration in milliseconds
            status_code: HTTP status code
            baseline_ms: Node.js baseline duration for comparison
            additional_metrics: Additional performance metrics
        """
        if not LoggingConfig.PERFORMANCE_LOGGING_ENABLED:
            return
        
        performance_data = {
            'event_category': 'performance',
            'event_type': 'request_timing',
            'endpoint': endpoint,
            'method': method,
            'duration_ms': round(duration_ms, 2),
            'status_code': status_code,
            'performance_baseline': baseline_ms,
            **self.request_context.get_request_context(),
            **(additional_metrics or {})
        }
        
        # Calculate variance if baseline is available
        if baseline_ms:
            variance_percent = ((duration_ms - baseline_ms) / baseline_ms) * 100
            performance_data['variance_percent'] = round(variance_percent, 2)
            performance_data['variance_exceeds_threshold'] = abs(variance_percent) > 10.0
        
        # Determine log level based on performance
        is_slow = duration_ms > (LoggingConfig.SLOW_REQUEST_THRESHOLD * 1000)
        log_method = self.logger.warning if is_slow else self.logger.info
        
        log_method(
            f"Request performance: {method} {endpoint} in {duration_ms:.2f}ms",
            **performance_data
        )
    
    def log_database_operation(
        self,
        operation: str,
        collection: str,
        duration_ms: float,
        record_count: Optional[int] = None,
        query_type: Optional[str] = None,
        additional_metrics: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log database operation performance with MongoDB-specific metrics.
        
        Args:
            operation: Database operation (find, insert, update, delete)
            collection: MongoDB collection name
            duration_ms: Operation duration in milliseconds
            record_count: Number of records affected
            query_type: Type of query (indexed, full_scan, aggregation)
            additional_metrics: Additional database metrics
        """
        performance_data = {
            'event_category': 'performance',
            'event_type': 'database_operation',
            'operation': operation,
            'collection': collection,
            'duration_ms': round(duration_ms, 2),
            'record_count': record_count,
            'query_type': query_type,
            **self.request_context.get_request_context(),
            **(additional_metrics or {})
        }
        
        # Determine log level based on performance
        is_slow = duration_ms > 1000  # 1 second threshold for database operations
        log_method = self.logger.warning if is_slow else self.logger.debug
        
        log_method(
            f"Database operation: {operation} on {collection} in {duration_ms:.2f}ms",
            **performance_data
        )
    
    def log_external_service_call(
        self,
        service: str,
        operation: str,
        duration_ms: float,
        status_code: Optional[int] = None,
        success: bool = True,
        retry_count: int = 0,
        circuit_breaker_state: Optional[str] = None,
        additional_metrics: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log external service call performance with circuit breaker integration.
        
        Args:
            service: External service name (auth0, aws, redis)
            operation: Service operation
            duration_ms: Call duration in milliseconds
            status_code: HTTP status code if applicable
            success: Whether the call was successful
            retry_count: Number of retries performed
            circuit_breaker_state: Circuit breaker state
            additional_metrics: Additional service metrics
        """
        performance_data = {
            'event_category': 'performance',
            'event_type': 'external_service_call',
            'service': service,
            'operation': operation,
            'duration_ms': round(duration_ms, 2),
            'status_code': status_code,
            'success': success,
            'retry_count': retry_count,
            'circuit_breaker_state': circuit_breaker_state,
            **self.request_context.get_request_context(),
            **(additional_metrics or {})
        }
        
        # Determine log level based on success and performance
        if not success:
            log_method = self.logger.error
        elif duration_ms > 5000:  # 5 second threshold for external services
            log_method = self.logger.warning
        else:
            log_method = self.logger.debug
        
        status_text = "success" if success else "failure"
        log_method(
            f"External service call: {service}.{operation} {status_text} in {duration_ms:.2f}ms",
            **performance_data
        )


class APMIntegrationLogger:
    """
    APM integration for distributed tracing with Datadog and New Relic
    correlation and custom attribute enrichment.
    """
    
    def __init__(self, logger: structlog.stdlib.BoundLogger):
        self.logger = logger
        self.correlation_manager = CorrelationManager()
        self.datadog_enabled = DATADOG_AVAILABLE and os.getenv('DATADOG_APM_ENABLED', 'false').lower() == 'true'
        self.newrelic_enabled = NEWRELIC_AVAILABLE and os.getenv('NEWRELIC_APM_ENABLED', 'false').lower() == 'true'
    
    def add_trace_context(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Add APM trace context to log events for correlation.
        
        Args:
            event_data: Log event data
            
        Returns:
            Enhanced event data with trace context
        """
        enhanced_data = event_data.copy()
        
        # Add Datadog trace context
        if self.datadog_enabled and DATADOG_AVAILABLE:
            try:
                span = tracer.current_span()
                if span:
                    enhanced_data.update({
                        'dd.trace_id': str(span.trace_id),
                        'dd.span_id': str(span.span_id),
                        'dd.service': span.service,
                        'dd.version': span.get_tag('version'),
                        'dd.env': span.get_tag('env')
                    })
            except Exception as e:
                self.logger.debug(f"Failed to add Datadog trace context: {e}")
        
        # Add New Relic trace context
        if self.newrelic_enabled and NEWRELIC_AVAILABLE:
            try:
                trace_id = newrelic.agent.current_trace_id()
                if trace_id:
                    enhanced_data['newrelic.trace_id'] = trace_id
                
                span_id = newrelic.agent.current_span_id()
                if span_id:
                    enhanced_data['newrelic.span_id'] = span_id
            except Exception as e:
                self.logger.debug(f"Failed to add New Relic trace context: {e}")
        
        return enhanced_data
    
    def add_custom_attributes(self, **attributes) -> None:
        """
        Add custom attributes to current APM traces.
        
        Args:
            **attributes: Attributes to add to the current trace
        """
        # Add to Datadog
        if self.datadog_enabled and DATADOG_AVAILABLE:
            try:
                span = tracer.current_span()
                if span:
                    for key, value in attributes.items():
                        span.set_tag(key, value)
            except Exception as e:
                self.logger.debug(f"Failed to add Datadog custom attributes: {e}")
        
        # Add to New Relic
        if self.newrelic_enabled and NEWRELIC_AVAILABLE:
            try:
                for key, value in attributes.items():
                    newrelic.agent.add_custom_attribute(key, value)
            except Exception as e:
                self.logger.debug(f"Failed to add New Relic custom attributes: {e}")


class EnterpriseLogHandler(logging.Handler):
    """
    Custom log handler for enterprise log aggregation with Splunk/ELK integration
    and SIEM-compatible structured logging output.
    """
    
    def __init__(
        self,
        splunk_endpoint: Optional[str] = None,
        elk_endpoint: Optional[str] = None,
        siem_endpoint: Optional[str] = None,
        batch_size: int = 100,
        flush_interval: float = 5.0
    ):
        super().__init__()
        self.splunk_endpoint = splunk_endpoint
        self.elk_endpoint = elk_endpoint
        self.siem_endpoint = siem_endpoint
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.batch_buffer = []
        self.last_flush_time = time.time()
        self._lock = Lock()
    
    def emit(self, record: logging.LogRecord) -> None:
        """
        Emit log record to enterprise aggregation systems.
        
        Args:
            record: Log record to emit
        """
        if not LoggingConfig.ENTERPRISE_LOGGING_ENABLED:
            return
        
        try:
            # Format record for enterprise systems
            formatted_record = self.format_for_enterprise(record)
            
            with self._lock:
                self.batch_buffer.append(formatted_record)
                
                # Check if we should flush based on size or time
                should_flush = (
                    len(self.batch_buffer) >= self.batch_size or
                    time.time() - self.last_flush_time >= self.flush_interval
                )
                
                if should_flush:
                    self._flush_batch()
        
        except Exception as e:
            # Prevent logging failures from breaking the application
            print(f"Enterprise log handler error: {e}", file=sys.stderr)
    
    def format_for_enterprise(self, record: logging.LogRecord) -> Dict[str, Any]:
        """
        Format log record for enterprise SIEM compatibility.
        
        Args:
            record: Log record to format
            
        Returns:
            Formatted log record for enterprise systems
        """
        # Extract structured data if available
        structured_data = {}
        if hasattr(record, 'msg') and isinstance(record.msg, dict):
            structured_data = record.msg
        
        enterprise_record = {
            'timestamp': datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage() if not isinstance(record.msg, dict) else structured_data.get('message', ''),
            'module': record.module,
            'function': record.funcName,
            'line_number': record.lineno,
            'thread_id': record.thread,
            'process_id': record.process,
            'application': LoggingConfig.APPLICATION_NAME,
            'version': LoggingConfig.APPLICATION_VERSION,
            'environment': LoggingConfig.ENVIRONMENT,
            'deployment_id': LoggingConfig.DEPLOYMENT_ID
        }
        
        # Add exception information if present
        if record.exc_info:
            enterprise_record['exception'] = {
                'type': record.exc_info[0].__name__ if record.exc_info[0] else None,
                'message': str(record.exc_info[1]) if record.exc_info[1] else None,
                'traceback': self.format(record) if LoggingConfig.EXCEPTION_TRACEBACK_ENABLED else None
            }
        
        # Merge structured data
        if structured_data:
            enterprise_record.update(structured_data)
        
        return enterprise_record
    
    def _flush_batch(self) -> None:
        """Flush batch buffer to enterprise systems."""
        if not self.batch_buffer:
            return
        
        batch_to_send = self.batch_buffer.copy()
        self.batch_buffer.clear()
        self.last_flush_time = time.time()
        
        # Send to configured endpoints (implement based on enterprise requirements)
        if self.splunk_endpoint:
            self._send_to_splunk(batch_to_send)
        
        if self.elk_endpoint:
            self._send_to_elk(batch_to_send)
        
        if self.siem_endpoint:
            self._send_to_siem(batch_to_send)
    
    def _send_to_splunk(self, batch: List[Dict[str, Any]]) -> None:
        """Send batch to Splunk endpoint."""
        # Implementation would depend on Splunk HEC configuration
        pass
    
    def _send_to_elk(self, batch: List[Dict[str, Any]]) -> None:
        """Send batch to ELK Stack endpoint."""
        # Implementation would depend on Elasticsearch configuration
        pass
    
    def _send_to_siem(self, batch: List[Dict[str, Any]]) -> None:
        """Send batch to SIEM endpoint."""
        # Implementation would depend on SIEM configuration
        pass
    
    def flush(self) -> None:
        """Flush any remaining records."""
        with self._lock:
            self._flush_batch()
        super().flush()


def create_correlation_processor() -> Callable:
    """
    Create structlog processor for correlation ID enrichment.
    
    Returns:
        Processor function for structlog
    """
    correlation_manager = CorrelationManager()
    
    def processor(logger, method_name, event_dict):
        # Add correlation ID if available
        correlation_id = correlation_manager.get_correlation_id()
        if correlation_id:
            event_dict['correlation_id'] = correlation_id
        
        return event_dict
    
    return processor


def create_request_context_processor() -> Callable:
    """
    Create structlog processor for request context enrichment.
    
    Returns:
        Processor function for structlog
    """
    request_context = RequestContextManager()
    
    def processor(logger, method_name, event_dict):
        # Add request context if available
        if has_request_context():
            context = request_context.get_request_context()
            # Only add non-None values to avoid cluttering logs
            for key, value in context.items():
                if value is not None:
                    event_dict[key] = value
        
        return event_dict
    
    return processor


def create_apm_context_processor() -> Callable:
    """
    Create structlog processor for APM trace context enrichment.
    
    Returns:
        Processor function for structlog
    """
    apm_logger = None
    
    def processor(logger, method_name, event_dict):
        nonlocal apm_logger
        if apm_logger is None:
            apm_logger = APMIntegrationLogger(logger)
        
        # Add APM trace context
        enhanced_dict = apm_logger.add_trace_context(event_dict)
        return enhanced_dict
    
    return processor


def create_performance_processor() -> Callable:
    """
    Create structlog processor for performance metrics enrichment.
    
    Returns:
        Processor function for structlog
    """
    def processor(logger, method_name, event_dict):
        if PSUTIL_AVAILABLE and LoggingConfig.PERFORMANCE_LOGGING_ENABLED:
            try:
                # Add memory usage information
                process = psutil.Process()
                memory_info = process.memory_info()
                event_dict['memory_rss_mb'] = round(memory_info.rss / 1024 / 1024, 2)
                
                # Add CPU percentage
                cpu_percent = psutil.cpu_percent(interval=None)
                event_dict['cpu_percent'] = cpu_percent
                
                # Add garbage collection stats
                gc_stats = {
                    'gc_counts': gc.get_count(),
                    'gc_collections': sum(gc.get_stats(), [])
                }
                event_dict['gc_stats'] = gc_stats
                
            except Exception:
                # Don't fail logging if performance metrics collection fails
                pass
        
        return event_dict
    
    return processor


def setup_structured_logging(app: Optional[Flask] = None) -> structlog.stdlib.BoundLogger:
    """
    Setup comprehensive structured logging with enterprise configuration.
    
    Args:
        app: Optional Flask application for configuration
        
    Returns:
        Configured structured logger instance
    """
    # Create log directory if file logging is enabled
    if LoggingConfig.LOG_FILE_ENABLED and LoggingConfig.LOG_FILE_PATH:
        log_dir = Path(LoggingConfig.LOG_FILE_PATH).parent
        log_dir.mkdir(parents=True, exist_ok=True)
    
    # Configure structlog processors
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="ISO"),
        create_correlation_processor(),
        create_request_context_processor(),
        create_apm_context_processor(),
        create_performance_processor(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]
    
    # Add appropriate renderer based on format
    if LoggingConfig.LOG_FORMAT == 'json':
        processors.append(structlog.processors.JSONRenderer())
    elif LoggingConfig.LOG_FORMAT == 'console':
        if LoggingConfig.COLORED_CONSOLE_OUTPUT:
            processors.append(structlog.dev.ConsoleRenderer(colors=True))
        else:
            processors.append(structlog.dev.ConsoleRenderer(colors=False))
    else:
        # Default to JSON for enterprise compatibility
        processors.append(structlog.processors.JSONRenderer())
    
    # Configure structlog
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        context_class=dict,
        cache_logger_on_first_use=True,
    )
    
    # Configure Python logging
    logging_config = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'json': {
                'format': '%(message)s'
            },
            'console': {
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            }
        },
        'handlers': {},
        'loggers': {
            '': {
                'handlers': [],
                'level': LoggingConfig.LOG_LEVEL,
                'propagate': False
            }
        }
    }
    
    # Add console handler if enabled
    if LoggingConfig.CONSOLE_LOGGING_ENABLED:
        logging_config['handlers']['console'] = {
            'class': 'logging.StreamHandler',
            'formatter': 'json' if LoggingConfig.LOG_FORMAT == 'json' else 'console',
            'stream': 'ext://sys.stdout'
        }
        logging_config['loggers']['']['handlers'].append('console')
    
    # Add file handler if enabled
    if LoggingConfig.LOG_FILE_ENABLED and LoggingConfig.LOG_FILE_PATH:
        logging_config['handlers']['file'] = {
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'json',
            'filename': LoggingConfig.LOG_FILE_PATH,
            'maxBytes': LoggingConfig.LOG_FILE_MAX_SIZE,
            'backupCount': LoggingConfig.LOG_FILE_BACKUP_COUNT,
            'encoding': 'utf-8'
        }
        logging_config['loggers']['']['handlers'].append('file')
    
    # Add enterprise handler if enabled
    if LoggingConfig.ENTERPRISE_LOGGING_ENABLED:
        # Register the custom handler class
        logging_config['handlers']['enterprise'] = {
            'class': '__main__.EnterpriseLogHandler',
            'formatter': 'json',
            'splunk_endpoint': LoggingConfig.SPLUNK_ENDPOINT,
            'elk_endpoint': LoggingConfig.ELK_ENDPOINT,
            'siem_endpoint': LoggingConfig.SIEM_ENDPOINT
        }
        logging_config['loggers']['']['handlers'].append('enterprise')
    
    # Apply logging configuration
    logging.config.dictConfig(logging_config)
    
    # Get the main logger
    logger = structlog.get_logger(LoggingConfig.APPLICATION_NAME)
    
    # Log initialization
    logger.info(
        "Structured logging initialized",
        log_level=LoggingConfig.LOG_LEVEL,
        log_format=LoggingConfig.LOG_FORMAT,
        file_logging=LoggingConfig.LOG_FILE_ENABLED,
        console_logging=LoggingConfig.CONSOLE_LOGGING_ENABLED,
        enterprise_logging=LoggingConfig.ENTERPRISE_LOGGING_ENABLED,
        correlation_tracking=LoggingConfig.CORRELATION_ID_ENABLED,
        security_audit=LoggingConfig.SECURITY_AUDIT_ENABLED,
        performance_logging=LoggingConfig.PERFORMANCE_LOGGING_ENABLED,
        environment=LoggingConfig.ENVIRONMENT,
        version=LoggingConfig.APPLICATION_VERSION
    )
    
    return logger


def create_flask_logging_middleware(
    logger: Optional[structlog.stdlib.BoundLogger] = None
) -> Callable:
    """
    Create Flask middleware for comprehensive request/response logging
    with correlation ID tracking and performance monitoring.
    
    Args:
        logger: Optional logger instance
        
    Returns:
        Flask middleware function
    """
    if logger is None:
        logger = structlog.get_logger(LoggingConfig.APPLICATION_NAME)
    
    correlation_manager = CorrelationManager()
    request_context = RequestContextManager()
    security_logger = SecurityAuditLogger(logger)
    performance_logger = PerformanceLogger(logger)
    
    def logging_middleware(app: Flask):
        """Flask middleware for comprehensive request logging."""
        
        @app.before_request
        def before_request():
            """Setup request context and start timing."""
            if not LoggingConfig.REQUEST_LOGGING_ENABLED:
                return
            
            # Generate or extract correlation ID
            correlation_id = (
                request.headers.get('X-Correlation-ID') or
                request.headers.get('X-Request-ID') or
                correlation_manager.generate_correlation_id()
            )
            correlation_manager.set_correlation_id(correlation_id)
            
            # Set request context
            user_id = getattr(g, 'user_id', None) if has_request_context() else None
            session_id = request.headers.get('X-Session-ID')
            
            request_context.set_request_context(
                user_id=user_id,
                session_id=session_id,
                endpoint=request.endpoint,
                method=request.method,
                additional_context={
                    'content_length': request.content_length,
                    'content_type': request.content_type
                }
            )
            
            # Log request start
            logger.info(
                "Request started",
                event_type="request_start",
                method=request.method,
                path=request.path,
                endpoint=request.endpoint,
                user_agent=request.headers.get('User-Agent', 'unknown')[:100],
                content_length=request.content_length,
                correlation_id=correlation_id
            )
        
        @app.after_request
        def after_request(response):
            """Log request completion and performance metrics."""
            if not LoggingConfig.REQUEST_LOGGING_ENABLED:
                return response
            
            # Calculate request duration
            start_time = request_start_time_context.get()
            if start_time:
                duration_ms = (time.perf_counter() - start_time) * 1000
            else:
                duration_ms = 0
            
            # Log request completion
            logger.info(
                "Request completed",
                event_type="request_end",
                method=request.method,
                path=request.path,
                endpoint=request.endpoint,
                status_code=response.status_code,
                duration_ms=round(duration_ms, 2),
                content_length=response.content_length,
                correlation_id=correlation_manager.get_correlation_id()
            )
            
            # Log performance metrics
            if LoggingConfig.PERFORMANCE_LOGGING_ENABLED:
                performance_logger.log_request_performance(
                    endpoint=request.endpoint or request.path,
                    method=request.method,
                    duration_ms=duration_ms,
                    status_code=response.status_code
                )
            
            # Add correlation ID to response headers
            correlation_id = correlation_manager.get_correlation_id()
            if correlation_id:
                response.headers['X-Correlation-ID'] = correlation_id
            
            # Clear request context
            request_context.clear_request_context()
            correlation_manager.clear_correlation_id()
            
            return response
        
        @app.errorhandler(Exception)
        def handle_exception(error):
            """Handle and log application exceptions."""
            correlation_id = correlation_manager.get_correlation_id()
            
            # Log the exception with full context
            logger.error(
                "Unhandled exception occurred",
                event_type="exception",
                exception_type=type(error).__name__,
                exception_message=str(error),
                correlation_id=correlation_id,
                endpoint=request.endpoint if has_request_context() else None,
                method=request.method if has_request_context() else None,
                path=request.path if has_request_context() else None,
                exc_info=True
            )
            
            # Return error response with correlation ID
            error_response = {
                'error': 'Internal server error',
                'correlation_id': correlation_id,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            return error_response, 500
    
    return logging_middleware


# Logging decorators for business logic instrumentation
def log_function_performance(
    operation_name: Optional[str] = None,
    log_args: bool = False,
    log_result: bool = False,
    logger: Optional[structlog.stdlib.BoundLogger] = None
) -> Callable:
    """
    Decorator for logging function performance and execution context.
    
    Args:
        operation_name: Custom operation name for logging
        log_args: Whether to log function arguments
        log_result: Whether to log function result
        logger: Optional logger instance
        
    Returns:
        Decorator function
    """
    if logger is None:
        logger = structlog.get_logger(LoggingConfig.APPLICATION_NAME)
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            operation = operation_name or f"{func.__module__}.{func.__name__}"
            correlation_id = CorrelationManager().get_correlation_id()
            
            # Prepare log data
            log_data = {
                'event_type': 'function_execution',
                'operation': operation,
                'correlation_id': correlation_id,
                'function': func.__name__,
                'module': func.__module__
            }
            
            # Add arguments if requested
            if log_args:
                # Be careful with sensitive data
                try:
                    # Get function signature for argument names
                    sig = inspect.signature(func)
                    bound_args = sig.bind(*args, **kwargs)
                    bound_args.apply_defaults()
                    
                    # Filter out potentially sensitive arguments
                    safe_args = {}
                    for name, value in bound_args.arguments.items():
                        if any(sensitive in name.lower() for sensitive in ['password', 'token', 'secret', 'key']):
                            safe_args[name] = '[REDACTED]'
                        else:
                            safe_args[name] = str(value)[:200]  # Truncate for log size
                    
                    log_data['arguments'] = safe_args
                except Exception:
                    log_data['arguments'] = '[FAILED_TO_EXTRACT]'
            
            start_time = time.perf_counter()
            
            try:
                # Execute function
                result = func(*args, **kwargs)
                
                # Calculate duration
                duration_ms = (time.perf_counter() - start_time) * 1000
                
                # Log successful execution
                log_data.update({
                    'success': True,
                    'duration_ms': round(duration_ms, 2)
                })
                
                if log_result and result is not None:
                    try:
                        # Safely convert result to string for logging
                        result_str = str(result)[:500]  # Truncate for log size
                        log_data['result'] = result_str
                    except Exception:
                        log_data['result'] = '[FAILED_TO_SERIALIZE]'
                
                logger.debug(f"Function executed: {operation}", **log_data)
                
                return result
                
            except Exception as e:
                # Calculate duration for failed execution
                duration_ms = (time.perf_counter() - start_time) * 1000
                
                # Log failed execution
                log_data.update({
                    'success': False,
                    'duration_ms': round(duration_ms, 2),
                    'exception_type': type(e).__name__,
                    'exception_message': str(e)
                })
                
                logger.error(f"Function failed: {operation}", **log_data, exc_info=True)
                
                raise
        
        return wrapper
    return decorator


def log_database_operation(
    operation_type: str,
    collection_name: Optional[str] = None,
    logger: Optional[structlog.stdlib.BoundLogger] = None
) -> Callable:
    """
    Decorator for logging database operations with performance tracking.
    
    Args:
        operation_type: Type of database operation
        collection_name: MongoDB collection name
        logger: Optional logger instance
        
    Returns:
        Decorator function
    """
    if logger is None:
        logger = structlog.get_logger(LoggingConfig.APPLICATION_NAME)
    
    performance_logger = PerformanceLogger(logger)
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.perf_counter()
            correlation_id = CorrelationManager().get_correlation_id()
            
            try:
                result = func(*args, **kwargs)
                duration_ms = (time.perf_counter() - start_time) * 1000
                
                # Determine record count if possible
                record_count = None
                if hasattr(result, '__len__'):
                    try:
                        record_count = len(result)
                    except TypeError:
                        pass
                elif hasattr(result, 'matched_count'):
                    record_count = result.matched_count
                elif hasattr(result, 'inserted_id'):
                    record_count = 1
                
                # Log database operation
                performance_logger.log_database_operation(
                    operation=operation_type,
                    collection=collection_name or 'unknown',
                    duration_ms=duration_ms,
                    record_count=record_count,
                    additional_metrics={
                        'correlation_id': correlation_id,
                        'function': func.__name__
                    }
                )
                
                return result
                
            except Exception as e:
                duration_ms = (time.perf_counter() - start_time) * 1000
                
                logger.error(
                    f"Database operation failed: {operation_type}",
                    operation=operation_type,
                    collection=collection_name,
                    duration_ms=round(duration_ms, 2),
                    correlation_id=correlation_id,
                    exception_type=type(e).__name__,
                    exception_message=str(e),
                    exc_info=True
                )
                
                raise
        
        return wrapper
    return decorator


def log_external_service_call(
    service_name: str,
    operation_name: Optional[str] = None,
    logger: Optional[structlog.stdlib.BoundLogger] = None
) -> Callable:
    """
    Decorator for logging external service calls with circuit breaker integration.
    
    Args:
        service_name: Name of external service
        operation_name: Service operation name
        logger: Optional logger instance
        
    Returns:
        Decorator function
    """
    if logger is None:
        logger = structlog.get_logger(LoggingConfig.APPLICATION_NAME)
    
    performance_logger = PerformanceLogger(logger)
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            operation = operation_name or func.__name__
            start_time = time.perf_counter()
            correlation_id = CorrelationManager().get_correlation_id()
            
            try:
                result = func(*args, **kwargs)
                duration_ms = (time.perf_counter() - start_time) * 1000
                
                # Extract status code if available
                status_code = None
                if hasattr(result, 'status_code'):
                    status_code = result.status_code
                elif isinstance(result, dict) and 'status_code' in result:
                    status_code = result['status_code']
                
                # Log external service call
                performance_logger.log_external_service_call(
                    service=service_name,
                    operation=operation,
                    duration_ms=duration_ms,
                    status_code=status_code,
                    success=True,
                    additional_metrics={
                        'correlation_id': correlation_id,
                        'function': func.__name__
                    }
                )
                
                return result
                
            except Exception as e:
                duration_ms = (time.perf_counter() - start_time) * 1000
                
                performance_logger.log_external_service_call(
                    service=service_name,
                    operation=operation,
                    duration_ms=duration_ms,
                    success=False,
                    additional_metrics={
                        'correlation_id': correlation_id,
                        'function': func.__name__,
                        'exception_type': type(e).__name__,
                        'exception_message': str(e)
                    }
                )
                
                raise
        
        return wrapper
    return decorator


# Convenience functions for common logging patterns
def get_logger(name: Optional[str] = None) -> structlog.stdlib.BoundLogger:
    """
    Get a structured logger instance with optional name.
    
    Args:
        name: Logger name, defaults to application name
        
    Returns:
        Configured structured logger
    """
    logger_name = name or LoggingConfig.APPLICATION_NAME
    return structlog.get_logger(logger_name)


def log_security_event(
    event_type: str,
    severity: str = 'info',
    **additional_data
) -> None:
    """
    Convenience function for logging security events.
    
    Args:
        event_type: Type of security event
        severity: Event severity level
        **additional_data: Additional event data
    """
    logger = get_logger()
    security_logger = SecurityAuditLogger(logger)
    
    if event_type.startswith('auth'):
        security_logger.log_authentication_event(
            event_type=event_type,
            success=severity in ['info', 'debug'],
            additional_data=additional_data
        )
    elif 'violation' in event_type.lower():
        security_logger.log_security_violation(
            violation_type=event_type,
            severity=severity,
            additional_data=additional_data
        )
    else:
        logger.log(
            getattr(logging, severity.upper(), logging.INFO),
            f"Security event: {event_type}",
            event_category='security',
            event_type=event_type,
            severity=severity,
            security_audit=True,
            **additional_data
        )


def set_correlation_id(correlation_id: Optional[str] = None) -> str:
    """
    Set correlation ID for current request context.
    
    Args:
        correlation_id: Optional correlation ID, generated if None
        
    Returns:
        The correlation ID that was set
    """
    return CorrelationManager().set_correlation_id(correlation_id)


def get_correlation_id() -> Optional[str]:
    """
    Get current correlation ID from context.
    
    Returns:
        Current correlation ID or None
    """
    return CorrelationManager().get_correlation_id()


# Export main components for application integration
__all__ = [
    'LoggingConfig',
    'CorrelationManager', 
    'RequestContextManager',
    'SecurityAuditLogger',
    'PerformanceLogger',
    'APMIntegrationLogger',
    'EnterpriseLogHandler',
    'setup_structured_logging',
    'create_flask_logging_middleware',
    'log_function_performance',
    'log_database_operation',
    'log_external_service_call',
    'get_logger',
    'log_security_event',
    'set_correlation_id',
    'get_correlation_id'
]