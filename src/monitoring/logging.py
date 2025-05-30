"""
Structured logging implementation using structlog 23.1+ providing JSON-formatted enterprise logging,
correlation ID tracking, security audit logging, and centralized log aggregation integration.

This module implements comprehensive logging patterns equivalent to Node.js winston/morgan logging
with enterprise SIEM compatibility and distributed tracing support.

Key Features:
- Structured logging with JSON output for enterprise log aggregation
- Correlation ID tracking for distributed request tracing
- Security audit logging with structured event tracking
- Integration with ELK Stack, Splunk, and enterprise APM systems
- Environment-specific configuration and log level management
- Performance-optimized logging with minimal application overhead
"""

import os
import sys
import time
import uuid
import logging
import logging.config
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union, List
from contextvars import ContextVar
from flask import Flask, request, g, has_request_context
import structlog
from structlog.contextvars import bind_contextvars, clear_contextvars
from pythonjsonlogger import jsonlogger


# Context variables for correlation tracking
correlation_id_var: ContextVar[Optional[str]] = ContextVar('correlation_id', default=None)
user_id_var: ContextVar[Optional[str]] = ContextVar('user_id', default=None)
request_id_var: ContextVar[Optional[str]] = ContextVar('request_id', default=None)


class CorrelationIDProcessor:
    """
    Processor to add correlation ID and request context to log records.
    
    Automatically injects correlation IDs, request IDs, user context, and
    request metadata into all log records for distributed tracing support.
    """
    
    def __call__(self, logger: Any, method_name: str, event_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Add correlation and request context to log event."""
        # Add correlation ID from context variable
        correlation_id = correlation_id_var.get()
        if correlation_id:
            event_dict['correlation_id'] = correlation_id
        
        # Add request ID from context variable
        request_id = request_id_var.get()
        if request_id:
            event_dict['request_id'] = request_id
        
        # Add user ID from context variable
        user_id = user_id_var.get()
        if user_id:
            event_dict['user_id'] = user_id
        
        # Add Flask request context if available
        if has_request_context():
            try:
                event_dict['request_method'] = request.method
                event_dict['request_url'] = request.url
                event_dict['request_endpoint'] = request.endpoint
                event_dict['request_remote_addr'] = request.remote_addr
                event_dict['request_user_agent'] = request.headers.get('User-Agent', '')
                
                # Add request timing if available
                if hasattr(g, 'request_start_time'):
                    event_dict['request_duration_ms'] = int((time.time() - g.request_start_time) * 1000)
                
                # Add authentication context if available
                if hasattr(g, 'current_user_id'):
                    event_dict['authenticated_user_id'] = g.current_user_id
                
                if hasattr(g, 'jwt_claims'):
                    event_dict['jwt_subject'] = g.jwt_claims.get('sub')
                    event_dict['jwt_issuer'] = g.jwt_claims.get('iss')
            
            except Exception:
                # Silently fail if request context is not fully available
                pass
        
        return event_dict


class SecurityAuditProcessor:
    """
    Processor for security audit logging with structured event tracking.
    
    Automatically identifies and enhances security-related log events with
    additional context and standardized event classification.
    """
    
    SECURITY_EVENTS = {
        'auth_success': 'authentication_success',
        'auth_failure': 'authentication_failure',
        'auth_token_invalid': 'invalid_token',
        'auth_unauthorized': 'unauthorized_access',
        'auth_forbidden': 'forbidden_access',
        'security_violation': 'security_violation',
        'suspicious_activity': 'suspicious_activity',
        'data_access': 'data_access',
        'admin_action': 'administrative_action',
        'privilege_escalation': 'privilege_escalation'
    }
    
    def __call__(self, logger: Any, method_name: str, event_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance security events with audit context."""
        event_type = event_dict.get('event_type')
        
        if event_type in self.SECURITY_EVENTS:
            event_dict['security_event'] = True
            event_dict['security_category'] = self.SECURITY_EVENTS[event_type]
            event_dict['audit_timestamp'] = datetime.now(timezone.utc).isoformat()
            
            # Add security-specific context
            if has_request_context():
                try:
                    event_dict['source_ip'] = request.remote_addr
                    event_dict['session_id'] = request.headers.get('X-Session-ID', '')
                    event_dict['csrf_token'] = request.headers.get('X-CSRF-Token', '')
                    
                    # Add geolocation headers if present
                    event_dict['client_country'] = request.headers.get('CF-IPCountry', '')
                    event_dict['client_region'] = request.headers.get('CF-Region', '')
                
                except Exception:
                    pass
            
            # Mark as high priority for SIEM systems
            event_dict['log_priority'] = 'high'
            event_dict['siem_alert'] = True
        
        return event_dict


class PerformanceProcessor:
    """
    Processor for performance monitoring and optimization tracking.
    
    Adds performance metrics and timing information to log records
    for monitoring compliance with ≤10% variance requirement.
    """
    
    def __call__(self, logger: Any, method_name: str, event_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Add performance context to log events."""
        # Add performance markers
        if 'performance' in event_dict:
            event_dict['performance_tracking'] = True
            event_dict['baseline_comparison'] = True
            
            # Add Node.js baseline context if available
            if hasattr(g, 'nodejs_baseline_time'):
                event_dict['nodejs_baseline_ms'] = g.nodejs_baseline_time
                
                if 'duration_ms' in event_dict:
                    variance = ((event_dict['duration_ms'] - g.nodejs_baseline_time) / g.nodejs_baseline_time) * 100
                    event_dict['performance_variance_percent'] = round(variance, 2)
                    event_dict['within_threshold'] = abs(variance) <= 10.0
        
        return event_dict


class EnterpriseJSONFormatter(jsonlogger.JsonFormatter):
    """
    Enterprise-grade JSON formatter with enhanced field standardization.
    
    Provides consistent JSON log formatting for enterprise log aggregation
    systems including ELK Stack, Splunk, and enterprise SIEM platforms.
    """
    
    def __init__(self, *args, **kwargs):
        # Define standard field mapping for enterprise systems
        self.enterprise_fields = {
            'timestamp': '@timestamp',
            'level': 'log_level',
            'logger': 'logger_name',
            'message': 'message',
            'module': 'source_module',
            'function': 'source_function',
            'line': 'source_line'
        }
        
        super().__init__(*args, **kwargs)
    
    def add_fields(self, log_record: Dict[str, Any], record: logging.LogRecord, message_dict: Dict[str, Any]) -> None:
        """Add enterprise-standard fields to log record."""
        super().add_fields(log_record, record, message_dict)
        
        # Add enterprise-standard timestamp
        if '@timestamp' not in log_record:
            log_record['@timestamp'] = datetime.now(timezone.utc).isoformat()
        
        # Add service identification
        log_record['service_name'] = 'flask-migration-app'
        log_record['service_version'] = os.getenv('APP_VERSION', '1.0.0')
        log_record['environment'] = os.getenv('FLASK_ENV', 'production')
        log_record['deployment_id'] = os.getenv('DEPLOYMENT_ID', '')
        
        # Add host and container information
        log_record['hostname'] = os.getenv('HOSTNAME', 'unknown')
        log_record['container_id'] = os.getenv('CONTAINER_ID', '')
        log_record['pod_name'] = os.getenv('POD_NAME', '')
        log_record['namespace'] = os.getenv('NAMESPACE', '')
        
        # Add log classification
        log_record['log_source'] = 'application'
        log_record['log_type'] = 'structured'
        log_record['log_format_version'] = '1.0'
        
        # Add enterprise correlation fields
        if 'correlation_id' not in log_record and correlation_id_var.get():
            log_record['correlation_id'] = correlation_id_var.get()
        
        if 'trace_id' not in log_record:
            log_record['trace_id'] = log_record.get('correlation_id', '')


def configure_structlog(app: Flask) -> None:
    """
    Configure structlog for enterprise structured logging.
    
    Sets up comprehensive structured logging with JSON formatting,
    correlation ID tracking, security audit capabilities, and
    enterprise system integration.
    
    Args:
        app: Flask application instance for configuration
    """
    # Get configuration from Flask app or environment
    log_level = app.config.get('LOG_LEVEL', os.getenv('LOG_LEVEL', 'INFO')).upper()
    log_format = app.config.get('LOG_FORMAT', os.getenv('LOG_FORMAT', 'json'))
    enable_correlation = app.config.get('ENABLE_CORRELATION_ID', 
                                       os.getenv('ENABLE_CORRELATION_ID', 'true').lower() == 'true')
    enable_security_audit = app.config.get('ENABLE_SECURITY_AUDIT',
                                          os.getenv('ENABLE_SECURITY_AUDIT', 'true').lower() == 'true')
    
    # Configure processors chain
    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="ISO", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]
    
    # Add enterprise processors
    if enable_correlation:
        processors.append(CorrelationIDProcessor())
    
    if enable_security_audit:
        processors.append(SecurityAuditProcessor())
    
    processors.append(PerformanceProcessor())
    
    # Add final formatting processor
    if log_format.lower() == 'json':
        processors.append(structlog.stdlib.ProcessorFormatter.wrap_for_formatter)
    else:
        processors.append(structlog.dev.ConsoleRenderer())
    
    # Configure structlog
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        context_class=dict,
        cache_logger_on_first_use=True,
    )
    
    # Configure standard library logging
    logging_config = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'json': {
                '()': EnterpriseJSONFormatter,
                'format': '%(asctime)s %(name)s %(levelname)s %(message)s'
            },
            'console': {
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            }
        },
        'handlers': {
            'console': {
                'class': 'logging.StreamHandler',
                'formatter': 'json' if log_format.lower() == 'json' else 'console',
                'stream': sys.stdout
            }
        },
        'loggers': {
            '': {
                'level': log_level,
                'handlers': ['console'],
                'propagate': False
            },
            'flask-migration-app': {
                'level': log_level,
                'handlers': ['console'],
                'propagate': False
            },
            'structlog': {
                'level': log_level,
                'handlers': ['console'],
                'propagate': False
            }
        }
    }
    
    # Apply logging configuration
    logging.config.dictConfig(logging_config)
    
    # Store logger configuration in app context
    app.logger_config = {
        'level': log_level,
        'format': log_format,
        'correlation_enabled': enable_correlation,
        'security_audit_enabled': enable_security_audit
    }


def get_logger(name: str = None) -> structlog.BoundLogger:
    """
    Get a configured structlog logger instance.
    
    Returns a structured logger with enterprise formatting and
    correlation ID support for application logging.
    
    Args:
        name: Logger name (defaults to calling module)
    
    Returns:
        Configured structlog BoundLogger instance
    """
    if name is None:
        import inspect
        frame = inspect.currentframe().f_back
        name = frame.f_globals.get('__name__', 'unknown')
    
    return structlog.get_logger(name)


def set_correlation_id(correlation_id: str = None) -> str:
    """
    Set correlation ID for distributed tracing.
    
    Sets the correlation ID in context variables for automatic
    inclusion in all log records within the current request context.
    
    Args:
        correlation_id: Correlation ID (auto-generated if not provided)
    
    Returns:
        The correlation ID that was set
    """
    if correlation_id is None:
        correlation_id = str(uuid.uuid4())
    
    correlation_id_var.set(correlation_id)
    bind_contextvars(correlation_id=correlation_id)
    
    return correlation_id


def set_user_context(user_id: str, additional_context: Dict[str, Any] = None) -> None:
    """
    Set user context for audit logging.
    
    Sets user identification and additional context in context variables
    for automatic inclusion in log records and security audit trails.
    
    Args:
        user_id: User identifier for audit tracking
        additional_context: Additional user context data
    """
    user_id_var.set(user_id)
    
    context_data = {'user_id': user_id}
    if additional_context:
        context_data.update(additional_context)
    
    bind_contextvars(**context_data)


def set_request_id(request_id: str = None) -> str:
    """
    Set request ID for request tracking.
    
    Sets the request ID in context variables for automatic
    inclusion in all log records within the current request.
    
    Args:
        request_id: Request ID (auto-generated if not provided)
    
    Returns:
        The request ID that was set
    """
    if request_id is None:
        request_id = str(uuid.uuid4())
    
    request_id_var.set(request_id)
    bind_contextvars(request_id=request_id)
    
    return request_id


def clear_request_context() -> None:
    """
    Clear request context variables.
    
    Clears all context variables at the end of request processing
    to prevent context leakage between requests.
    """
    correlation_id_var.set(None)
    user_id_var.set(None)
    request_id_var.set(None)
    clear_contextvars()


def log_security_event(event_type: str, details: Dict[str, Any] = None, 
                      logger: structlog.BoundLogger = None) -> None:
    """
    Log security audit event with structured tracking.
    
    Creates structured security audit log entries for SIEM integration
    and compliance reporting with standardized event classification.
    
    Args:
        event_type: Security event type (from SecurityAuditProcessor.SECURITY_EVENTS)
        details: Additional event details and context
        logger: Logger instance (created if not provided)
    """
    if logger is None:
        logger = get_logger('security_audit')
    
    log_data = {
        'event_type': event_type,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'severity': 'high' if event_type in ['auth_failure', 'security_violation', 
                                            'suspicious_activity', 'privilege_escalation'] else 'medium'
    }
    
    if details:
        log_data.update(details)
    
    logger.warning("Security event detected", **log_data)


def log_performance_metric(metric_name: str, value: Union[int, float], 
                          unit: str = 'ms', details: Dict[str, Any] = None,
                          logger: structlog.BoundLogger = None) -> None:
    """
    Log performance metric for baseline comparison.
    
    Creates structured performance log entries for monitoring
    compliance with ≤10% variance requirement and optimization tracking.
    
    Args:
        metric_name: Performance metric identifier
        value: Metric value
        unit: Metric unit (ms, seconds, etc.)
        details: Additional metric context
        logger: Logger instance (created if not provided)
    """
    if logger is None:
        logger = get_logger('performance')
    
    log_data = {
        'metric_name': metric_name,
        'metric_value': value,
        'metric_unit': unit,
        'performance': True,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }
    
    if details:
        log_data.update(details)
    
    logger.info("Performance metric recorded", **log_data)


def log_business_event(event_name: str, event_data: Dict[str, Any] = None,
                      logger: structlog.BoundLogger = None) -> None:
    """
    Log business logic event for operational tracking.
    
    Creates structured business event log entries for operational
    monitoring, analytics, and business intelligence integration.
    
    Args:
        event_name: Business event identifier
        event_data: Business event data and context
        logger: Logger instance (created if not provided)
    """
    if logger is None:
        logger = get_logger('business')
    
    log_data = {
        'event_name': event_name,
        'event_category': 'business_logic',
        'timestamp': datetime.now(timezone.utc).isoformat()
    }
    
    if event_data:
        log_data.update(event_data)
    
    logger.info("Business event tracked", **log_data)


def log_integration_event(service_name: str, operation: str, 
                         status: str, details: Dict[str, Any] = None,
                         logger: structlog.BoundLogger = None) -> None:
    """
    Log external service integration event.
    
    Creates structured integration log entries for monitoring
    external service interactions, circuit breaker events,
    and service dependency health.
    
    Args:
        service_name: External service identifier
        operation: Operation being performed
        status: Operation status (success, failure, timeout, etc.)
        details: Additional integration context
        logger: Logger instance (created if not provided)
    """
    if logger is None:
        logger = get_logger('integration')
    
    log_data = {
        'service_name': service_name,
        'operation': operation,
        'status': status,
        'integration_event': True,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }
    
    if details:
        log_data.update(details)
    
    level = 'error' if status in ['failure', 'timeout', 'error'] else 'info'
    getattr(logger, level)("External service integration event", **log_data)


class RequestLoggingMiddleware:
    """
    Flask middleware for automatic request/response logging.
    
    Provides comprehensive request lifecycle logging equivalent to
    Node.js morgan middleware with enhanced context and performance tracking.
    """
    
    def __init__(self, app: Flask = None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app: Flask) -> None:
        """Initialize middleware with Flask application."""
        app.before_request(self.before_request)
        app.after_request(self.after_request)
        app.teardown_request(self.teardown_request)
    
    def before_request(self) -> None:
        """Log request start and set up context."""
        # Set request timing
        g.request_start_time = time.time()
        
        # Generate and set correlation ID
        correlation_id = request.headers.get('X-Correlation-ID') or set_correlation_id()
        
        # Generate and set request ID
        request_id = request.headers.get('X-Request-ID') or set_request_id()
        
        # Log request start
        logger = get_logger('request')
        logger.info("Request started",
                   method=request.method,
                   url=request.url,
                   endpoint=request.endpoint,
                   remote_addr=request.remote_addr,
                   user_agent=request.headers.get('User-Agent', ''),
                   content_length=request.content_length or 0,
                   correlation_id=correlation_id,
                   request_id=request_id)
    
    def after_request(self, response) -> Any:
        """Log request completion with response details."""
        if hasattr(g, 'request_start_time'):
            duration_ms = int((time.time() - g.request_start_time) * 1000)
            
            logger = get_logger('request')
            logger.info("Request completed",
                       method=request.method,
                       url=request.url,
                       endpoint=request.endpoint,
                       status_code=response.status_code,
                       content_length=response.content_length or 0,
                       duration_ms=duration_ms,
                       response_size_bytes=len(response.get_data()) if hasattr(response, 'get_data') else 0)
            
            # Log performance metric for monitoring
            log_performance_metric(f"request_{request.endpoint or 'unknown'}", 
                                 duration_ms, 'ms',
                                 {'method': request.method, 'status_code': response.status_code})
        
        return response
    
    def teardown_request(self, exception=None) -> None:
        """Clean up request context."""
        if exception:
            logger = get_logger('error')
            logger.error("Request failed with exception",
                        method=request.method,
                        url=request.url,
                        endpoint=request.endpoint,
                        exception_type=type(exception).__name__,
                        exception_message=str(exception),
                        exc_info=True)
        
        # Clear request context
        clear_request_context()


# Module-level logger for direct use
logger = get_logger(__name__)


def init_logging(app: Flask) -> None:
    """
    Initialize comprehensive logging for Flask application.
    
    Sets up structured logging, request middleware, and enterprise
    integration for complete observability and audit compliance.
    
    Args:
        app: Flask application instance
    """
    # Configure structlog
    configure_structlog(app)
    
    # Initialize request logging middleware
    request_middleware = RequestLoggingMiddleware(app)
    
    # Store middleware reference in app
    app.request_logging_middleware = request_middleware
    
    # Log initialization
    init_logger = get_logger('initialization')
    init_logger.info("Logging system initialized",
                    log_level=app.logger_config['level'],
                    log_format=app.logger_config['format'],
                    correlation_enabled=app.logger_config['correlation_enabled'],
                    security_audit_enabled=app.logger_config['security_audit_enabled'],
                    service_name='flask-migration-app',
                    environment=os.getenv('FLASK_ENV', 'production'))


# Export main interfaces
__all__ = [
    'configure_structlog',
    'get_logger',
    'set_correlation_id',
    'set_user_context',
    'set_request_id',
    'clear_request_context',
    'log_security_event',
    'log_performance_metric',
    'log_business_event',
    'log_integration_event',
    'RequestLoggingMiddleware',
    'init_logging',
    'logger'
]