"""
Structured logging configuration module implementing structlog 23.1+ for JSON-formatted 
logging, enterprise log aggregation, security audit trails, and monitoring integration.

This module replaces Node.js winston/morgan logging patterns with Python-based structured
logging, providing comprehensive security audit capabilities, enterprise SIEM integration,
and performance monitoring support per Section 3.6.1 and 6.4.2 requirements.

Key Features:
- structlog 23.1+ for structured logging equivalent to Node.js patterns
- python-json-logger 2.0+ for JSON log formatting
- Security audit logging for authentication and authorization events
- Enterprise log aggregation with Splunk/ELK Stack integration
- Performance monitoring and error tracking integration
- Flask application monitoring with request/response tracking
- Rate limiting violation and circuit breaker event logging
- JWT validation and permission cache event monitoring

Dependencies:
- structlog 23.1+ for structured logging framework
- python-json-logger 2.0+ for JSON formatting
- prometheus-client 0.17+ for metrics collection
- config.settings for application configuration
"""

import structlog
import logging
import logging.config
import sys
import os
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Union
from pathlib import Path
from prometheus_client import Counter, Histogram, Gauge
import traceback
from functools import wraps

# Import configuration settings
try:
    from config.settings import get_config
except ImportError:
    # Fallback for cases where settings might not be available during initialization
    def get_config():
        return type('Config', (), {
            'LOG_LEVEL': os.getenv('LOG_LEVEL', 'INFO'),
            'LOG_FORMAT': os.getenv('LOG_FORMAT', 'json'),
            'ENVIRONMENT': os.getenv('FLASK_ENV', 'production'),
            'ENABLE_SECURITY_AUDIT': os.getenv('ENABLE_SECURITY_AUDIT', 'true').lower() == 'true',
            'SIEM_INTEGRATION_ENABLED': os.getenv('SIEM_INTEGRATION_ENABLED', 'true').lower() == 'true',
            'LOG_FILE_PATH': os.getenv('LOG_FILE_PATH', '/var/log/flask-app'),
            'MAX_LOG_FILE_SIZE': int(os.getenv('MAX_LOG_FILE_SIZE', '104857600')),  # 100MB
            'LOG_BACKUP_COUNT': int(os.getenv('LOG_BACKUP_COUNT', '5')),
        })()


class SecurityAuditLogger:
    """
    Comprehensive security audit logging for authentication, authorization, and security events
    with structured JSON formatting and enterprise compliance support per Section 6.4.2.
    
    This class provides specialized logging methods for security events, threat detection,
    compliance reporting, and integration with Security Information and Event Management (SIEM)
    systems for enterprise-grade security monitoring.
    """
    
    def __init__(self):
        """Initialize security audit logger with structured logging configuration."""
        self.logger = structlog.get_logger("security.audit")
        self.metrics = SecurityMetrics()
    
    def log_authentication_event(
        self,
        event_type: str,
        user_id: Optional[str],
        result: str,
        source_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        auth_method: str = "jwt",
        additional_context: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log comprehensive authentication events with security context and metrics tracking.
        
        Args:
            event_type: Type of authentication event (login, logout, token_refresh, etc.)
            user_id: User identifier (None for failed attempts)
            result: Authentication result (success, failure, expired, invalid)
            source_ip: Client IP address for geolocation and threat analysis
            user_agent: User agent string for device fingerprinting
            auth_method: Authentication method used (jwt, oauth, mfa)
            additional_context: Additional security context information
        """
        log_data = {
            'event_category': 'authentication',
            'event_type': event_type,
            'user_id': user_id,
            'result': result,
            'auth_method': auth_method,
            'source_ip': source_ip,
            'user_agent': user_agent,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'severity': 'HIGH' if result == 'failure' else 'INFO',
            'compliance_tags': ['SOC2', 'ISO27001', 'GDPR'],
        }
        
        # Add additional context if provided
        if additional_context:
            log_data.update(additional_context)
        
        # Update security metrics
        self.metrics.record_authentication_event(result)
        
        # Log with appropriate severity level
        if result == 'success':
            self.logger.info("Authentication successful", **log_data)
        else:
            self.logger.warning("Authentication failed", **log_data)
    
    def log_authorization_event(
        self,
        event_type: str,
        user_id: str,
        resource: str,
        action: str,
        result: str,
        permissions: Optional[List[str]] = None,
        resource_id: Optional[str] = None,
        endpoint: Optional[str] = None,
        additional_context: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log authorization decisions with comprehensive security context and RBAC details.
        
        Args:
            event_type: Type of authorization event (permission_check, resource_access, etc.)
            user_id: User identifier making the request
            resource: Resource being accessed
            action: Action being attempted (read, write, delete, etc.)
            result: Authorization result (granted, denied, escalated)
            permissions: List of permissions checked
            resource_id: Specific resource identifier
            endpoint: API endpoint being accessed
            additional_context: Additional authorization context
        """
        log_data = {
            'event_category': 'authorization',
            'event_type': event_type,
            'user_id': user_id,
            'resource': resource,
            'resource_id': resource_id,
            'action': action,
            'result': result,
            'permissions': permissions or [],
            'endpoint': endpoint,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'severity': 'MEDIUM' if result == 'denied' else 'INFO',
            'compliance_tags': ['SOX', 'HIPAA', 'PCI_DSS'],
        }
        
        # Add additional context if provided
        if additional_context:
            log_data.update(additional_context)
        
        # Update security metrics
        self.metrics.record_authorization_event(result)
        
        # Log with appropriate severity level
        if result == 'granted':
            self.logger.info("Authorization granted", **log_data)
        else:
            self.logger.warning("Authorization denied", **log_data)
    
    def log_security_violation(
        self,
        violation_type: str,
        user_id: Optional[str],
        details: str,
        severity: str = "HIGH",
        source_ip: Optional[str] = None,
        endpoint: Optional[str] = None,
        additional_context: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log security violations and potential threats with comprehensive incident context.
        
        Args:
            violation_type: Type of security violation (rate_limit, injection, xss, etc.)
            user_id: User identifier (if known)
            details: Detailed description of the violation
            severity: Violation severity (LOW, MEDIUM, HIGH, CRITICAL)
            source_ip: Source IP address for threat intelligence
            endpoint: Affected endpoint
            additional_context: Additional security context
        """
        log_data = {
            'event_category': 'security_violation',
            'violation_type': violation_type,
            'user_id': user_id,
            'details': details,
            'severity': severity,
            'source_ip': source_ip,
            'endpoint': endpoint,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'requires_investigation': severity in ['HIGH', 'CRITICAL'],
            'compliance_tags': ['SECURITY_INCIDENT', 'SOC_ALERT'],
        }
        
        # Add additional context if provided
        if additional_context:
            log_data.update(additional_context)
        
        # Update security metrics
        self.metrics.record_security_violation(violation_type, severity)
        
        # Log as error for high severity violations
        if severity in ['HIGH', 'CRITICAL']:
            self.logger.error("Security violation detected", **log_data)
        else:
            self.logger.warning("Security violation detected", **log_data)
    
    def log_rate_limit_violation(
        self,
        user_id: Optional[str],
        endpoint: str,
        limit_type: str,
        current_rate: int,
        limit_threshold: int,
        source_ip: Optional[str] = None,
        additional_context: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log rate limiting violations with detailed rate analysis for threat detection.
        
        Args:
            user_id: User identifier (if authenticated)
            endpoint: Endpoint being rate limited
            limit_type: Type of rate limit (per_minute, per_hour, burst)
            current_rate: Current request rate
            limit_threshold: Rate limit threshold
            source_ip: Source IP address
            additional_context: Additional rate limiting context
        """
        log_data = {
            'event_category': 'rate_limiting',
            'event_type': 'rate_limit_violation',
            'user_id': user_id,
            'endpoint': endpoint,
            'limit_type': limit_type,
            'current_rate': current_rate,
            'limit_threshold': limit_threshold,
            'source_ip': source_ip,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'severity': 'MEDIUM',
            'potential_attack': current_rate > (limit_threshold * 2),
        }
        
        # Add additional context if provided
        if additional_context:
            log_data.update(additional_context)
        
        # Update security metrics
        self.metrics.record_rate_limit_violation(endpoint)
        
        self.logger.warning("Rate limit violation", **log_data)
    
    def log_circuit_breaker_event(
        self,
        service: str,
        event: str,
        failure_count: int,
        circuit_state: str,
        additional_info: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log circuit breaker events for service resilience monitoring and alerting.
        
        Args:
            service: Service name (auth0, database, external_api)
            event: Circuit breaker event (opened, closed, half_open, failure)
            failure_count: Current failure count
            circuit_state: Current circuit breaker state
            additional_info: Additional circuit breaker context
        """
        log_data = {
            'event_category': 'circuit_breaker',
            'service': service,
            'circuit_event': event,
            'failure_count': failure_count,
            'circuit_state': circuit_state,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'severity': 'HIGH' if event == 'opened' else 'INFO',
            'monitoring_tags': ['SERVICE_HEALTH', 'AVAILABILITY'],
        }
        
        # Add additional context if provided
        if additional_info:
            log_data.update(additional_info)
        
        # Update circuit breaker metrics
        self.metrics.record_circuit_breaker_event(service, event)
        
        if event == 'opened':
            self.logger.error("Circuit breaker opened", **log_data)
        else:
            self.logger.info("Circuit breaker event", **log_data)


class PerformanceLogger:
    """
    Performance monitoring logger for Flask application metrics, request tracking,
    and baseline compliance monitoring per Section 3.6.1 requirements.
    
    This class provides specialized logging for performance metrics, request timing,
    database query performance, and external service integration performance to
    ensure ≤10% variance compliance with Node.js baseline performance.
    """
    
    def __init__(self):
        """Initialize performance logger with metrics collection."""
        self.logger = structlog.get_logger("performance.monitoring")
        self.metrics = PerformanceMetrics()
    
    def log_request_performance(
        self,
        method: str,
        endpoint: str,
        status_code: int,
        response_time: float,
        user_id: Optional[str] = None,
        request_size: Optional[int] = None,
        response_size: Optional[int] = None,
        additional_context: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log detailed request performance metrics for baseline compliance monitoring.
        
        Args:
            method: HTTP method
            endpoint: API endpoint
            status_code: HTTP status code
            response_time: Request response time in seconds
            user_id: User identifier (if authenticated)
            request_size: Request payload size in bytes
            response_size: Response payload size in bytes
            additional_context: Additional performance context
        """
        log_data = {
            'event_category': 'performance',
            'event_type': 'request_performance',
            'method': method,
            'endpoint': endpoint,
            'status_code': status_code,
            'response_time_ms': round(response_time * 1000, 2),
            'user_id': user_id,
            'request_size_bytes': request_size,
            'response_size_bytes': response_size,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'performance_grade': self._calculate_performance_grade(response_time),
        }
        
        # Add additional context if provided
        if additional_context:
            log_data.update(additional_context)
        
        # Update performance metrics
        self.metrics.record_request_performance(method, endpoint, response_time, status_code)
        
        # Log with appropriate level based on performance
        if response_time > 5.0:  # 5 seconds threshold
            self.logger.warning("Slow request performance", **log_data)
        else:
            self.logger.info("Request performance", **log_data)
    
    def log_database_performance(
        self,
        operation: str,
        collection: str,
        query_time: float,
        record_count: Optional[int] = None,
        index_used: Optional[bool] = None,
        additional_context: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log database operation performance for MongoDB query optimization.
        
        Args:
            operation: Database operation (find, insert, update, delete)
            collection: MongoDB collection name
            query_time: Query execution time in seconds
            record_count: Number of records affected
            index_used: Whether database index was used
            additional_context: Additional database context
        """
        log_data = {
            'event_category': 'database_performance',
            'operation': operation,
            'collection': collection,
            'query_time_ms': round(query_time * 1000, 2),
            'record_count': record_count,
            'index_used': index_used,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'requires_optimization': query_time > 1.0,  # 1 second threshold
        }
        
        # Add additional context if provided
        if additional_context:
            log_data.update(additional_context)
        
        # Update database performance metrics
        self.metrics.record_database_performance(operation, collection, query_time)
        
        if query_time > 2.0:  # 2 seconds threshold for warnings
            self.logger.warning("Slow database query", **log_data)
        else:
            self.logger.info("Database performance", **log_data)
    
    def log_cache_performance(
        self,
        operation: str,
        cache_key: str,
        cache_hit: bool,
        operation_time: float,
        cache_size: Optional[int] = None,
        additional_context: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log Redis cache performance for optimization and monitoring.
        
        Args:
            operation: Cache operation (get, set, delete, exists)
            cache_key: Redis cache key pattern
            cache_hit: Whether operation resulted in cache hit
            operation_time: Cache operation time in seconds
            cache_size: Size of cached data in bytes
            additional_context: Additional cache context
        """
        log_data = {
            'event_category': 'cache_performance',
            'operation': operation,
            'cache_key_pattern': self._mask_cache_key(cache_key),
            'cache_hit': cache_hit,
            'operation_time_ms': round(operation_time * 1000, 2),
            'cache_size_bytes': cache_size,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'cache_efficiency': 'optimal' if cache_hit and operation_time < 0.1 else 'suboptimal',
        }
        
        # Add additional context if provided
        if additional_context:
            log_data.update(additional_context)
        
        # Update cache performance metrics
        self.metrics.record_cache_performance(operation, cache_hit, operation_time)
        
        self.logger.info("Cache performance", **log_data)
    
    def _calculate_performance_grade(self, response_time: float) -> str:
        """Calculate performance grade based on response time."""
        if response_time < 0.1:
            return 'EXCELLENT'
        elif response_time < 0.5:
            return 'GOOD'
        elif response_time < 1.0:
            return 'FAIR'
        elif response_time < 2.0:
            return 'POOR'
        else:
            return 'CRITICAL'
    
    def _mask_cache_key(self, cache_key: str) -> str:
        """Mask sensitive information in cache keys for logging."""
        # Replace user IDs and sensitive identifiers with placeholders
        import re
        masked_key = re.sub(r':\w{8,}:', ':***:', cache_key)
        masked_key = re.sub(r'user_id_\w+', 'user_id_***', masked_key)
        return masked_key


class SecurityMetrics:
    """
    Prometheus metrics collection for security events and monitoring integration.
    
    This class provides comprehensive metrics collection for security-related events
    including authentication, authorization, security violations, and threat detection
    for integration with enterprise monitoring and alerting systems.
    """
    
    def __init__(self):
        """Initialize security metrics collectors."""
        # Authentication metrics
        self.auth_requests_total = Counter(
            'auth_requests_total',
            'Total authentication requests by result',
            ['result', 'auth_method']
        )
        
        # Authorization metrics
        self.authz_decisions_total = Counter(
            'authz_decisions_total',
            'Total authorization decisions by result',
            ['result', 'resource_type']
        )
        
        # Security violation metrics
        self.security_violations_total = Counter(
            'security_violations_total',
            'Total security violations by type and severity',
            ['violation_type', 'severity']
        )
        
        # Rate limiting metrics
        self.rate_limit_violations_total = Counter(
            'rate_limit_violations_total',
            'Total rate limit violations by endpoint',
            ['endpoint']
        )
        
        # Circuit breaker metrics
        self.circuit_breaker_events_total = Counter(
            'circuit_breaker_events_total',
            'Total circuit breaker events by service and event type',
            ['service', 'event_type']
        )
        
        # Security event timing
        self.security_event_duration = Histogram(
            'security_event_duration_seconds',
            'Security event processing duration',
            ['event_type']
        )
    
    def record_authentication_event(self, result: str, auth_method: str = 'jwt') -> None:
        """Record authentication event metrics."""
        self.auth_requests_total.labels(result=result, auth_method=auth_method).inc()
    
    def record_authorization_event(self, result: str, resource_type: str = 'api') -> None:
        """Record authorization decision metrics."""
        self.authz_decisions_total.labels(result=result, resource_type=resource_type).inc()
    
    def record_security_violation(self, violation_type: str, severity: str) -> None:
        """Record security violation metrics."""
        self.security_violations_total.labels(
            violation_type=violation_type, 
            severity=severity
        ).inc()
    
    def record_rate_limit_violation(self, endpoint: str) -> None:
        """Record rate limit violation metrics."""
        self.rate_limit_violations_total.labels(endpoint=endpoint).inc()
    
    def record_circuit_breaker_event(self, service: str, event_type: str) -> None:
        """Record circuit breaker event metrics."""
        self.circuit_breaker_events_total.labels(
            service=service, 
            event_type=event_type
        ).inc()


class PerformanceMetrics:
    """
    Prometheus metrics collection for performance monitoring and baseline compliance.
    
    This class provides comprehensive performance metrics collection for request timing,
    database performance, cache efficiency, and external service integration performance
    to ensure ≤10% variance compliance monitoring.
    """
    
    def __init__(self):
        """Initialize performance metrics collectors."""
        # Request performance metrics
        self.request_duration_seconds = Histogram(
            'flask_request_duration_seconds',
            'Flask request duration in seconds',
            ['method', 'endpoint', 'status_code'],
            buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
        )
        
        # Database performance metrics
        self.database_query_duration_seconds = Histogram(
            'database_query_duration_seconds',
            'Database query duration in seconds',
            ['operation', 'collection'],
            buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0]
        )
        
        # Cache performance metrics
        self.cache_operation_duration_seconds = Histogram(
            'cache_operation_duration_seconds',
            'Cache operation duration in seconds',
            ['operation'],
            buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
        )
        
        self.cache_hit_ratio = Gauge(
            'cache_hit_ratio',
            'Cache hit ratio percentage',
            ['cache_type']
        )
        
        # External service performance
        self.external_service_duration_seconds = Histogram(
            'external_service_duration_seconds',
            'External service call duration in seconds',
            ['service', 'operation'],
            buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]
        )
    
    def record_request_performance(
        self, 
        method: str, 
        endpoint: str, 
        response_time: float, 
        status_code: int
    ) -> None:
        """Record request performance metrics."""
        self.request_duration_seconds.labels(
            method=method,
            endpoint=endpoint,
            status_code=status_code
        ).observe(response_time)
    
    def record_database_performance(
        self, 
        operation: str, 
        collection: str, 
        query_time: float
    ) -> None:
        """Record database performance metrics."""
        self.database_query_duration_seconds.labels(
            operation=operation,
            collection=collection
        ).observe(query_time)
    
    def record_cache_performance(
        self, 
        operation: str, 
        cache_hit: bool, 
        operation_time: float
    ) -> None:
        """Record cache performance metrics."""
        self.cache_operation_duration_seconds.labels(operation=operation).observe(operation_time)
        
        # Update cache hit ratio (simplified calculation)
        current_ratio = self.cache_hit_ratio.labels(cache_type='redis')._value.get() or 0.0
        new_ratio = (current_ratio + (1.0 if cache_hit else 0.0)) / 2
        self.cache_hit_ratio.labels(cache_type='redis').set(new_ratio)


def add_flask_request_context(logger, method_name, event_dict):
    """
    Add Flask request context to log entries for comprehensive request tracking.
    
    This processor adds Flask request context including request ID, user information,
    endpoint details, and request metadata to all log entries for enhanced traceability
    and debugging capabilities in enterprise environments.
    """
    try:
        from flask import request, g, has_request_context
        from flask_login import current_user
        
        if has_request_context():
            # Add request context information
            event_dict['request_id'] = getattr(g, 'request_id', None)
            event_dict['method'] = request.method
            event_dict['url'] = request.url
            event_dict['endpoint'] = request.endpoint
            event_dict['remote_addr'] = request.remote_addr
            event_dict['user_agent'] = request.headers.get('User-Agent', '')
            
            # Add user context if available
            if hasattr(current_user, 'id') and current_user.is_authenticated:
                event_dict['user_id'] = current_user.id
                event_dict['authenticated'] = True
            else:
                event_dict['authenticated'] = False
            
            # Add request headers (sanitized)
            event_dict['content_type'] = request.headers.get('Content-Type', '')
            event_dict['content_length'] = request.headers.get('Content-Length', 0)
            
    except (ImportError, RuntimeError):
        # Flask context not available or not in request context
        pass
    
    return event_dict


def add_environment_context(logger, method_name, event_dict):
    """
    Add environment and application context to log entries.
    
    This processor adds environment-specific information, application metadata,
    and deployment context to log entries for comprehensive operational visibility
    and troubleshooting support in enterprise environments.
    """
    config = get_config()
    
    event_dict['environment'] = getattr(config, 'ENVIRONMENT', 'unknown')
    event_dict['application'] = 'flask-security-system'
    event_dict['version'] = os.getenv('APP_VERSION', 'unknown')
    event_dict['hostname'] = os.getenv('HOSTNAME', 'unknown')
    event_dict['pod_name'] = os.getenv('POD_NAME', 'unknown')
    event_dict['namespace'] = os.getenv('KUBERNETES_NAMESPACE', 'default')
    
    return event_dict


def add_security_context(logger, method_name, event_dict):
    """
    Add security context and compliance tags to log entries.
    
    This processor enriches log entries with security context, compliance tags,
    and threat intelligence information for SIEM integration and security
    monitoring in enterprise environments.
    """
    # Add security metadata
    event_dict['log_classification'] = 'internal'
    event_dict['data_classification'] = 'business_sensitive'
    
    # Add compliance context based on event category
    event_category = event_dict.get('event_category', '')
    if event_category in ['authentication', 'authorization']:
        event_dict['compliance_required'] = True
        event_dict['retention_years'] = 7
    elif event_category == 'security_violation':
        event_dict['compliance_required'] = True
        event_dict['retention_years'] = 10
        event_dict['security_alert'] = True
    
    return event_dict


def configure_structured_logging():
    """
    Configure comprehensive structured logging with enterprise-grade features.
    
    This function sets up structlog 23.1+ with JSON formatting, security audit
    capabilities, performance monitoring, and enterprise SIEM integration
    per Section 3.6.1 and 6.4.2 requirements.
    
    Features:
    - JSON formatted logs for enterprise log aggregation
    - Security audit logging with compliance tags
    - Performance metrics integration
    - Flask request context enrichment
    - Error tracking with stack traces
    - Enterprise SIEM compatibility
    """
    config = get_config()
    
    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, config.LOG_LEVEL.upper(), logging.INFO),
    )
    
    # Configure structlog processors
    processors = [
        # Filter logs by level
        structlog.stdlib.filter_by_level,
        
        # Add logger name
        structlog.stdlib.add_logger_name,
        
        # Add log level
        structlog.stdlib.add_log_level,
        
        # Process positional arguments
        structlog.stdlib.PositionalArgumentsFormatter(),
        
        # Add timestamps in ISO format
        structlog.processors.TimeStamper(fmt="iso"),
        
        # Add stack info for debugging
        structlog.processors.StackInfoRenderer(),
        
        # Format exception information
        structlog.processors.format_exc_info,
        
        # Handle Unicode properly
        structlog.processors.UnicodeDecoder(),
        
        # Add Flask request context
        add_flask_request_context,
        
        # Add environment context
        add_environment_context,
        
        # Add security context
        add_security_context,
    ]
    
    # Add JSON renderer for structured output
    if config.LOG_FORMAT.lower() == 'json':
        processors.append(structlog.processors.JSONRenderer())
    else:
        # Use console renderer for development
        processors.append(structlog.dev.ConsoleRenderer())
    
    # Configure structlog
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.LoggerFactory(),
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
    
    # Configure application-specific loggers
    _configure_application_loggers(config)
    
    # Initialize security and performance loggers
    global security_audit_logger, performance_logger
    security_audit_logger = SecurityAuditLogger()
    performance_logger = PerformanceLogger()


def _configure_application_loggers(config):
    """
    Configure application-specific loggers with appropriate levels and handlers.
    
    This function sets up specialized loggers for different application components
    including security audit, performance monitoring, database operations, and
    external service integration with enterprise-grade logging configuration.
    """
    # Security audit logger configuration
    security_logger = logging.getLogger('security')
    security_logger.setLevel(logging.INFO)
    
    # Performance monitoring logger configuration
    performance_logger = logging.getLogger('performance')
    performance_logger.setLevel(logging.INFO)
    
    # Database operations logger configuration
    database_logger = logging.getLogger('database')
    database_logger.setLevel(getattr(logging, config.LOG_LEVEL.upper(), logging.INFO))
    
    # External services logger configuration
    external_logger = logging.getLogger('external_services')
    external_logger.setLevel(logging.INFO)
    
    # Flask application logger configuration
    flask_logger = logging.getLogger('flask')
    flask_logger.setLevel(getattr(logging, config.LOG_LEVEL.upper(), logging.INFO))
    
    # Suppress noisy third-party loggers in production
    if getattr(config, 'ENVIRONMENT', 'production') == 'production':
        logging.getLogger('urllib3').setLevel(logging.WARNING)
        logging.getLogger('requests').setLevel(logging.WARNING)
        logging.getLogger('boto3').setLevel(logging.WARNING)
        logging.getLogger('botocore').setLevel(logging.WARNING)


def get_logger(name: str = None) -> structlog.BoundLogger:
    """
    Get a configured structlog logger instance with enterprise-grade features.
    
    Args:
        name: Logger name (optional, defaults to caller's module name)
    
    Returns:
        Configured structlog BoundLogger instance with security and performance tracking
    
    Example:
        >>> logger = get_logger(__name__)
        >>> logger.info("Application started", component="auth_service")
    """
    return structlog.get_logger(name)


def get_security_logger() -> SecurityAuditLogger:
    """
    Get the security audit logger instance for security event logging.
    
    Returns:
        SecurityAuditLogger instance configured for enterprise security monitoring
    
    Example:
        >>> security_logger = get_security_logger()
        >>> security_logger.log_authentication_event("login", "user123", "success")
    """
    return security_audit_logger


def get_performance_logger() -> PerformanceLogger:
    """
    Get the performance logger instance for performance monitoring.
    
    Returns:
        PerformanceLogger instance configured for performance tracking and baseline compliance
    
    Example:
        >>> perf_logger = get_performance_logger()
        >>> perf_logger.log_request_performance("GET", "/api/users", 200, 0.250)
    """
    return performance_logger


def log_exception(
    logger: structlog.BoundLogger,
    exception: Exception,
    context: Optional[Dict[str, Any]] = None,
    user_id: Optional[str] = None,
    request_id: Optional[str] = None
) -> None:
    """
    Log exceptions with comprehensive context and stack trace information.
    
    This function provides standardized exception logging with security context,
    performance impact analysis, and comprehensive debugging information for
    enterprise-grade error tracking and incident response.
    
    Args:
        logger: Structlog logger instance
        exception: Exception to log
        context: Additional context information
        user_id: User identifier (if available)
        request_id: Request identifier for tracing
    
    Example:
        >>> try:
        ...     risky_operation()
        ... except Exception as e:
        ...     log_exception(logger, e, {"operation": "user_creation"}, "user123")
    """
    log_data = {
        'event_category': 'error',
        'exception_type': type(exception).__name__,
        'exception_message': str(exception),
        'stack_trace': traceback.format_exc(),
        'user_id': user_id,
        'request_id': request_id,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'severity': 'HIGH',
    }
    
    # Add additional context if provided
    if context:
        log_data.update(context)
    
    # Log the exception with error level
    logger.error("Application exception occurred", **log_data)


# Global logger instances (initialized by configure_structured_logging)
security_audit_logger: Optional[SecurityAuditLogger] = None
performance_logger: Optional[PerformanceLogger] = None


# Enterprise logging configuration decorator
def log_performance(operation_name: str):
    """
    Decorator for automatic performance logging of function execution.
    
    This decorator provides automatic performance monitoring for critical
    application functions with comprehensive timing analysis and performance
    grade calculation for baseline compliance monitoring.
    
    Args:
        operation_name: Name of the operation being monitored
    
    Example:
        >>> @log_performance("user_authentication")
        ... def authenticate_user(username, password):
        ...     # Authentication logic
        ...     return user
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = datetime.now(timezone.utc)
            
            try:
                result = func(*args, **kwargs)
                end_time = datetime.now(timezone.utc)
                duration = (end_time - start_time).total_seconds()
                
                # Log successful operation performance
                if performance_logger:
                    logger = get_logger(func.__module__)
                    logger.info(
                        "Operation completed",
                        operation=operation_name,
                        function=func.__name__,
                        duration_seconds=duration,
                        success=True,
                        timestamp=end_time.isoformat()
                    )
                
                return result
                
            except Exception as e:
                end_time = datetime.now(timezone.utc)
                duration = (end_time - start_time).total_seconds()
                
                # Log failed operation performance
                logger = get_logger(func.__module__)
                log_exception(
                    logger, 
                    e, 
                    {
                        'operation': operation_name,
                        'function': func.__name__,
                        'duration_seconds': duration,
                        'success': False
                    }
                )
                raise
        
        return wrapper
    return decorator


# Initialize logging configuration
configure_structured_logging()