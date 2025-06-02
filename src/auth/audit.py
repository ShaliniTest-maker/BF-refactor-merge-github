"""
Security Audit Logging Module

This module implements comprehensive security audit logging for the Flask authentication
and authorization system, providing enterprise-grade compliance support with structured
logging, security event tracking, and comprehensive monitoring integration.

The audit logging system provides:
- Structured JSON logging using structlog 23.1+ for enterprise log aggregation
- Comprehensive authentication and authorization event tracking
- Security violation monitoring and threat detection
- Rate limiting violation tracking and analysis
- Circuit breaker event monitoring for external service failures
- Prometheus metrics integration for security monitoring dashboards
- SIEM integration with standardized security event formatting
- Enterprise compliance support (SOC 2, ISO 27001, PCI DSS, GDPR)

Key Features:
- Real-time security event logging with correlation IDs for incident investigation
- PII protection and data sanitization for compliance with privacy regulations
- Integration with Flask-Limiter for rate limiting violation tracking
- Circuit breaker pattern monitoring for Auth0 and external service failures
- Comprehensive audit trail for all security decisions and policy enforcement
- Performance monitoring integration ensuring minimal logging overhead
- Enterprise security monitoring with automated alert generation

Architecture Integration:
- Seamless integration with existing monitoring infrastructure via monitoring.py
- Exception handling integration with comprehensive security exception taxonomy
- Prometheus metrics collection for security dashboard visualization
- Health check system integration for audit logging service monitoring
- Flask middleware integration for automated security event capture

Performance Requirements:
- Audit logging overhead: ≤2ms per security event (critical requirement)
- JSON log processing: >100 events/second throughput
- Memory usage: ≤50MB additional heap for audit buffer
- Enterprise log aggregation: Real-time streaming to Splunk/ELK systems

Compliance Standards:
- SOC 2 Type II: Comprehensive audit trail and access control logging
- ISO 27001: Information security event monitoring and incident logging
- PCI DSS: Authentication and authorization audit requirements
- GDPR: Privacy protection with PII sanitization and data minimization
- OWASP: Security event logging aligned with OWASP logging cheat sheet

References:
- Section 6.4.2 AUTHORIZATION SYSTEM: Security audit logging requirements
- Section 6.5 MONITORING AND OBSERVABILITY: Enterprise monitoring integration
- Section 3.6 MONITORING & OBSERVABILITY: Structured logging and metrics collection
- Section 0.2.5 Dependency Decisions: structlog 23.1+ and prometheus-client 0.17+
"""

import asyncio
import hashlib
import json
import time
import uuid
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps
from threading import Lock, Thread
from typing import Any, Dict, List, Optional, Union, Callable, Deque
from urllib.parse import urlparse

import structlog
from flask import Flask, request, g, session, current_app
from prometheus_client import Counter, Histogram, Gauge, Enum

# Import monitoring infrastructure
from src.config.monitoring import (
    StructuredLogger, 
    PrometheusMetrics,
    MonitoringConfig
)

# Import security exception framework
from src.auth.exceptions import (
    SecurityException,
    SecurityErrorCode,
    AuthenticationException,
    AuthorizationException,
    Auth0Exception,
    RateLimitException,
    CircuitBreakerException,
    ValidationException,
    SessionException,
    PermissionException,
    get_error_category,
    is_critical_security_error
)


class SecurityAuditConfig:
    """
    Configuration class for security audit logging with enterprise-grade settings
    and comprehensive compliance support for SOC 2, ISO 27001, and GDPR requirements.
    
    This configuration provides:
    - Environment-specific audit logging levels and retention policies
    - PII protection settings for privacy compliance
    - Enterprise log aggregation endpoint configuration
    - Security metric collection and threshold settings
    - Real-time alerting configuration for critical security events
    """
    
    # Core Audit Logging Configuration
    AUDIT_LOGGING_ENABLED = True
    AUDIT_LOG_LEVEL = "INFO"
    AUDIT_LOG_FORMAT = "json"  # json, console
    AUDIT_BUFFER_SIZE = 1000  # Events buffered before batch processing
    AUDIT_FLUSH_INTERVAL = 5.0  # Seconds between batch flushes
    
    # Enterprise Integration Configuration
    SIEM_INTEGRATION_ENABLED = True
    SPLUNK_ENDPOINT = None  # Set via environment variables
    ELK_ENDPOINT = None     # Set via environment variables
    ENTERPRISE_LOG_RETENTION_DAYS = 2555  # 7 years for SOC 2 compliance
    
    # Privacy and Data Protection Configuration
    PII_SANITIZATION_ENABLED = True
    DATA_MINIMIZATION_ENABLED = True
    PII_HASH_SALT = "flask-audit-security-salt"  # Override in production
    GDPR_COMPLIANCE_MODE = True
    
    # Security Event Classification Configuration
    CRITICAL_EVENTS_REAL_TIME = True
    SECURITY_METRICS_ENABLED = True
    SECURITY_ALERTING_ENABLED = True
    INCIDENT_CORRELATION_ENABLED = True
    
    # Performance and Resource Configuration
    MAX_AUDIT_OVERHEAD_MS = 2.0  # Maximum logging overhead per event
    AUDIT_MEMORY_LIMIT_MB = 50   # Maximum memory usage for audit buffers
    BATCH_PROCESSING_ENABLED = True
    ASYNC_LOGGING_ENABLED = True
    
    # Rate Limiting and Abuse Detection Configuration
    RATE_LIMIT_MONITORING_ENABLED = True
    BRUTE_FORCE_DETECTION_ENABLED = True
    SUSPICIOUS_ACTIVITY_TRACKING = True
    GEOGRAPHIC_ANOMALY_DETECTION = False  # Requires GeoIP integration
    
    # Circuit Breaker Monitoring Configuration
    CIRCUIT_BREAKER_MONITORING_ENABLED = True
    EXTERNAL_SERVICE_FAILURE_TRACKING = True
    SERVICE_DEGRADATION_ALERTING = True
    FALLBACK_MECHANISM_TRACKING = True


class SecurityEventType:
    """
    Standardized security event type definitions for consistent audit logging
    and enterprise security monitoring integration with SIEM systems.
    
    These event types align with industry standards including:
    - NIST Cybersecurity Framework event categories
    - ISO 27035 security incident classification
    - OWASP logging recommendations
    - SOC 2 audit trail requirements
    """
    
    # Authentication Events (AU.*)
    AUTH_LOGIN_SUCCESS = "AU.LOGIN.SUCCESS"
    AUTH_LOGIN_FAILURE = "AU.LOGIN.FAILURE"
    AUTH_LOGOUT = "AU.LOGOUT"
    AUTH_TOKEN_VALIDATION_SUCCESS = "AU.TOKEN.VALIDATION.SUCCESS"
    AUTH_TOKEN_VALIDATION_FAILURE = "AU.TOKEN.VALIDATION.FAILURE"
    AUTH_TOKEN_REFRESH = "AU.TOKEN.REFRESH"
    AUTH_SESSION_CREATED = "AU.SESSION.CREATED"
    AUTH_SESSION_EXPIRED = "AU.SESSION.EXPIRED"
    AUTH_SESSION_INVALIDATED = "AU.SESSION.INVALIDATED"
    AUTH_MFA_SUCCESS = "AU.MFA.SUCCESS"
    AUTH_MFA_FAILURE = "AU.MFA.FAILURE"
    
    # Authorization Events (AZ.*)
    AUTHZ_PERMISSION_GRANTED = "AZ.PERMISSION.GRANTED"
    AUTHZ_PERMISSION_DENIED = "AZ.PERMISSION.DENIED"
    AUTHZ_ROLE_ASSIGNMENT = "AZ.ROLE.ASSIGNMENT"
    AUTHZ_ROLE_REVOCATION = "AZ.ROLE.REVOCATION"
    AUTHZ_POLICY_EVALUATION = "AZ.POLICY.EVALUATION"
    AUTHZ_RESOURCE_ACCESS_GRANTED = "AZ.RESOURCE.ACCESS.GRANTED"
    AUTHZ_RESOURCE_ACCESS_DENIED = "AZ.RESOURCE.ACCESS.DENIED"
    AUTHZ_PRIVILEGE_ESCALATION_ATTEMPT = "AZ.PRIVILEGE.ESCALATION.ATTEMPT"
    
    # Security Violation Events (SV.*)
    SEC_RATE_LIMIT_VIOLATION = "SV.RATE.LIMIT.VIOLATION"
    SEC_BRUTE_FORCE_DETECTED = "SV.BRUTE.FORCE.DETECTED"
    SEC_SUSPICIOUS_ACTIVITY = "SV.SUSPICIOUS.ACTIVITY"
    SEC_XSS_ATTEMPT = "SV.XSS.ATTEMPT"
    SEC_SQL_INJECTION_ATTEMPT = "SV.SQL.INJECTION.ATTEMPT"
    SEC_CSRF_VIOLATION = "SV.CSRF.VIOLATION"
    SEC_INPUT_VALIDATION_FAILURE = "SV.INPUT.VALIDATION.FAILURE"
    SEC_SECURITY_HEADER_VIOLATION = "SV.SECURITY.HEADER.VIOLATION"
    
    # External Service Events (ES.*)
    EXT_AUTH0_SUCCESS = "ES.AUTH0.SUCCESS"
    EXT_AUTH0_FAILURE = "ES.AUTH0.FAILURE"
    EXT_AUTH0_TIMEOUT = "ES.AUTH0.TIMEOUT"
    EXT_CIRCUIT_BREAKER_OPEN = "ES.CIRCUIT.BREAKER.OPEN"
    EXT_CIRCUIT_BREAKER_CLOSED = "ES.CIRCUIT.BREAKER.CLOSED"
    EXT_SERVICE_DEGRADATION = "ES.SERVICE.DEGRADATION"
    EXT_FALLBACK_ACTIVATED = "ES.FALLBACK.ACTIVATED"
    
    # Administrative Events (AD.*)
    ADMIN_USER_CREATION = "AD.USER.CREATION"
    ADMIN_USER_DELETION = "AD.USER.DELETION"
    ADMIN_PERMISSION_MODIFICATION = "AD.PERMISSION.MODIFICATION"
    ADMIN_CONFIGURATION_CHANGE = "AD.CONFIGURATION.CHANGE"
    ADMIN_SECURITY_POLICY_UPDATE = "AD.SECURITY.POLICY.UPDATE"
    
    # Data Access Events (DA.*)
    DATA_READ_ACCESS = "DA.READ.ACCESS"
    DATA_WRITE_ACCESS = "DA.WRITE.ACCESS"
    DATA_DELETE_ACCESS = "DA.DELETE.ACCESS"
    DATA_EXPORT_ACCESS = "DA.EXPORT.ACCESS"
    DATA_PII_ACCESS = "DA.PII.ACCESS"


class SecurityAuditMetrics:
    """
    Prometheus metrics collection for comprehensive security monitoring
    and dashboard visualization with enterprise-grade observability.
    
    Provides metrics for:
    - Security event volume and distribution analysis
    - Authentication success/failure rate monitoring
    - Authorization decision tracking and policy effectiveness
    - Rate limiting violation detection and abuse prevention
    - Circuit breaker activation monitoring for service reliability
    - Security incident correlation and threat intelligence
    """
    
    def __init__(self):
        """Initialize comprehensive security audit metrics for Prometheus collection."""
        
        # Security Event Volume Metrics
        self.security_events_total = Counter(
            'flask_security_events_total',
            'Total number of security events processed',
            ['event_type', 'category', 'severity', 'source']
        )
        
        self.security_event_processing_duration = Histogram(
            'flask_security_event_processing_duration_seconds',
            'Time spent processing security events',
            ['event_type', 'processing_stage'],
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
        )
        
        # Authentication Metrics
        self.authentication_attempts_total = Counter(
            'flask_authentication_attempts_total',
            'Total authentication attempts by result and method',
            ['result', 'method', 'source', 'user_agent_category']
        )
        
        self.authentication_duration_seconds = Histogram(
            'flask_authentication_duration_seconds',
            'Authentication processing duration',
            ['method', 'result'],
            buckets=[0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0]
        )
        
        self.jwt_token_validation_total = Counter(
            'flask_jwt_token_validation_total',
            'JWT token validation attempts and results',
            ['result', 'error_type', 'issuer']
        )
        
        # Authorization Metrics
        self.authorization_decisions_total = Counter(
            'flask_authorization_decisions_total',
            'Authorization decisions by outcome and permission',
            ['decision', 'permission_type', 'resource_type', 'user_role']
        )
        
        self.permission_check_duration_seconds = Histogram(
            'flask_permission_check_duration_seconds',
            'Permission checking processing time',
            ['permission_type', 'decision'],
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25]
        )
        
        self.policy_evaluations_total = Counter(
            'flask_policy_evaluations_total',
            'Security policy evaluations and results',
            ['policy_name', 'result', 'resource_type']
        )
        
        # Security Violation Metrics
        self.security_violations_total = Counter(
            'flask_security_violations_total',
            'Security violations detected by type and severity',
            ['violation_type', 'severity', 'source_ip_category', 'user_category']
        )
        
        self.rate_limit_violations_total = Counter(
            'flask_rate_limit_violations_total',
            'Rate limiting violations by endpoint and user',
            ['endpoint', 'limit_type', 'user_category', 'violation_severity']
        )
        
        self.brute_force_attempts_total = Counter(
            'flask_brute_force_attempts_total',
            'Brute force attack attempts detected',
            ['target_type', 'source_ip_category', 'attack_pattern']
        )
        
        # External Service Monitoring Metrics
        self.external_service_auth_total = Counter(
            'flask_external_service_auth_total',
            'External service authentication attempts',
            ['service', 'result', 'error_type']
        )
        
        self.circuit_breaker_state = Enum(
            'flask_circuit_breaker_state',
            'Circuit breaker state for external services',
            ['service'],
            states=['closed', 'open', 'half_open']
        )
        
        self.circuit_breaker_failures_total = Counter(
            'flask_circuit_breaker_failures_total',
            'Circuit breaker failure events',
            ['service', 'failure_type', 'recovery_action']
        )
        
        # Session Management Metrics
        self.session_events_total = Counter(
            'flask_session_events_total',
            'Session management events by type and result',
            ['event_type', 'result', 'session_duration_category']
        )
        
        self.session_security_violations_total = Counter(
            'flask_session_security_violations_total',
            'Session security violations detected',
            ['violation_type', 'severity', 'source']
        )
        
        # Audit System Performance Metrics
        self.audit_buffer_size = Gauge(
            'flask_audit_buffer_size',
            'Current number of events in audit buffer'
        )
        
        self.audit_processing_lag_seconds = Gauge(
            'flask_audit_processing_lag_seconds',
            'Lag between event occurrence and processing'
        )
        
        self.audit_memory_usage_bytes = Gauge(
            'flask_audit_memory_usage_bytes',
            'Memory usage by audit logging system'
        )
        
        # Compliance and Data Protection Metrics
        self.pii_sanitization_events_total = Counter(
            'flask_pii_sanitization_events_total',
            'PII sanitization events for privacy compliance',
            ['data_type', 'sanitization_method', 'compliance_framework']
        )
        
        self.data_access_events_total = Counter(
            'flask_data_access_events_total',
            'Data access events for audit trail compliance',
            ['data_classification', 'access_type', 'user_role', 'compliance_requirement']
        )
    
    def record_security_event(
        self, 
        event_type: str, 
        category: str, 
        severity: str = "info",
        source: str = "application",
        processing_duration: float = 0.0
    ) -> None:
        """Record security event metrics with comprehensive categorization."""
        self.security_events_total.labels(
            event_type=event_type,
            category=category,
            severity=severity,
            source=source
        ).inc()
        
        if processing_duration > 0:
            self.security_event_processing_duration.labels(
                event_type=event_type,
                processing_stage="complete"
            ).observe(processing_duration)
    
    def record_authentication_attempt(
        self, 
        result: str, 
        method: str = "jwt",
        source: str = "web",
        duration: float = 0.0,
        user_agent_category: str = "browser"
    ) -> None:
        """Record authentication attempt with performance tracking."""
        self.authentication_attempts_total.labels(
            result=result,
            method=method,
            source=source,
            user_agent_category=user_agent_category
        ).inc()
        
        if duration > 0:
            self.authentication_duration_seconds.labels(
                method=method,
                result=result
            ).observe(duration)
    
    def record_authorization_decision(
        self,
        decision: str,
        permission_type: str,
        resource_type: str = "unknown",
        user_role: str = "user",
        duration: float = 0.0
    ) -> None:
        """Record authorization decision with performance tracking."""
        self.authorization_decisions_total.labels(
            decision=decision,
            permission_type=permission_type,
            resource_type=resource_type,
            user_role=user_role
        ).inc()
        
        if duration > 0:
            self.permission_check_duration_seconds.labels(
                permission_type=permission_type,
                decision=decision
            ).observe(duration)
    
    def record_security_violation(
        self,
        violation_type: str,
        severity: str = "medium",
        source_ip_category: str = "unknown",
        user_category: str = "authenticated"
    ) -> None:
        """Record security violation with threat intelligence categorization."""
        self.security_violations_total.labels(
            violation_type=violation_type,
            severity=severity,
            source_ip_category=source_ip_category,
            user_category=user_category
        ).inc()
    
    def record_rate_limit_violation(
        self,
        endpoint: str,
        limit_type: str,
        user_category: str = "authenticated",
        violation_severity: str = "warning"
    ) -> None:
        """Record rate limiting violation with endpoint analysis."""
        self.rate_limit_violations_total.labels(
            endpoint=endpoint,
            limit_type=limit_type,
            user_category=user_category,
            violation_severity=violation_severity
        ).inc()
    
    def record_circuit_breaker_event(
        self,
        service: str,
        state: str,
        failure_type: str = "timeout",
        recovery_action: str = "automatic"
    ) -> None:
        """Record circuit breaker state changes and failures."""
        self.circuit_breaker_state.labels(service=service).state(state)
        
        if state == "open":
            self.circuit_breaker_failures_total.labels(
                service=service,
                failure_type=failure_type,
                recovery_action=recovery_action
            ).inc()
    
    def update_audit_system_metrics(
        self,
        buffer_size: int,
        processing_lag: float,
        memory_usage: int
    ) -> None:
        """Update audit system performance metrics."""
        self.audit_buffer_size.set(buffer_size)
        self.audit_processing_lag_seconds.set(processing_lag)
        self.audit_memory_usage_bytes.set(memory_usage)


class PIISanitizer:
    """
    Comprehensive PII sanitization for GDPR compliance and privacy protection.
    
    This class provides enterprise-grade data sanitization capabilities including:
    - Email address hashing and domain preservation for analytics
    - IP address anonymization with geographic region preservation
    - User ID hashing with collision-resistant algorithms
    - Timestamp precision reduction for privacy-preserving analytics
    - Custom field sanitization with configurable policies
    - Audit trail of sanitization operations for compliance verification
    """
    
    def __init__(self, salt: str = SecurityAuditConfig.PII_HASH_SALT):
        """Initialize PII sanitizer with cryptographic salt for hashing."""
        self.salt = salt.encode('utf-8')
        self.sanitization_methods = {
            'email': self._sanitize_email,
            'ip_address': self._sanitize_ip_address,
            'user_id': self._sanitize_user_id,
            'phone': self._sanitize_phone,
            'timestamp': self._sanitize_timestamp,
            'user_agent': self._sanitize_user_agent,
            'session_id': self._sanitize_session_id
        }
    
    def sanitize_security_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize security event data for privacy compliance while preserving
        analytical value for security monitoring and threat detection.
        
        Args:
            event_data: Raw security event data containing potential PII
            
        Returns:
            Sanitized event data with PII removed or anonymized
        """
        if not SecurityAuditConfig.PII_SANITIZATION_ENABLED:
            return event_data
        
        sanitized_data = event_data.copy()
        
        # Sanitize common PII fields
        for field_name, sanitization_method in self.sanitization_methods.items():
            if field_name in sanitized_data and sanitized_data[field_name]:
                try:
                    sanitized_data[field_name] = sanitization_method(sanitized_data[field_name])
                except Exception as e:
                    # Log sanitization error but continue processing
                    sanitized_data[field_name] = f"[SANITIZATION_ERROR: {type(e).__name__}]"
        
        # Sanitize nested objects and metadata
        if 'metadata' in sanitized_data and isinstance(sanitized_data['metadata'], dict):
            sanitized_data['metadata'] = self._sanitize_metadata(sanitized_data['metadata'])
        
        # Add sanitization audit trail
        sanitized_data['_pii_sanitized'] = True
        sanitized_data['_sanitization_timestamp'] = datetime.utcnow().isoformat()
        
        return sanitized_data
    
    def _sanitize_email(self, email: str) -> str:
        """Sanitize email address while preserving domain for analytics."""
        if '@' not in email:
            return self._hash_value(email)
        
        local_part, domain = email.rsplit('@', 1)
        hashed_local = self._hash_value(local_part)[:8]  # Truncate for readability
        return f"{hashed_local}@{domain}"
    
    def _sanitize_ip_address(self, ip_address: str) -> str:
        """Anonymize IP address while preserving geographic region."""
        # IPv4 anonymization - zero out last octet
        if '.' in ip_address and ip_address.count('.') == 3:
            parts = ip_address.split('.')
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{parts[2]}.0"
        
        # IPv6 anonymization - zero out last 80 bits
        if ':' in ip_address:
            parts = ip_address.split(':')
            if len(parts) >= 4:
                return ':'.join(parts[:4]) + '::0'
        
        # Fallback to hashing for unrecognized formats
        return self._hash_value(ip_address)[:16]
    
    def _sanitize_user_id(self, user_id: str) -> str:
        """Generate consistent hash for user ID that preserves uniqueness."""
        return f"user_{self._hash_value(user_id)[:12]}"
    
    def _sanitize_phone(self, phone: str) -> str:
        """Sanitize phone number while preserving country code."""
        # Remove non-numeric characters
        digits_only = ''.join(filter(str.isdigit, phone))
        
        if len(digits_only) >= 10:
            # Preserve country code and area code, hash the rest
            country_area = digits_only[:6]
            rest = digits_only[6:]
            hashed_rest = self._hash_value(rest)[:4]
            return f"{country_area}xxxx{hashed_rest}"
        
        return self._hash_value(phone)[:10]
    
    def _sanitize_timestamp(self, timestamp: Union[str, datetime]) -> str:
        """Reduce timestamp precision for privacy while preserving analytics value."""
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except ValueError:
                return timestamp  # Return original if parsing fails
        
        # Round down to nearest hour for privacy
        rounded_timestamp = timestamp.replace(minute=0, second=0, microsecond=0)
        return rounded_timestamp.isoformat()
    
    def _sanitize_user_agent(self, user_agent: str) -> str:
        """Sanitize user agent while preserving browser/OS information."""
        # Extract browser and OS information, remove version details
        if 'Chrome' in user_agent:
            browser = 'Chrome'
        elif 'Firefox' in user_agent:
            browser = 'Firefox'
        elif 'Safari' in user_agent:
            browser = 'Safari'
        elif 'Edge' in user_agent:
            browser = 'Edge'
        else:
            browser = 'Other'
        
        if 'Windows' in user_agent:
            os_info = 'Windows'
        elif 'macOS' in user_agent or 'Mac OS' in user_agent:
            os_info = 'macOS'
        elif 'Linux' in user_agent:
            os_info = 'Linux'
        elif 'Android' in user_agent:
            os_info = 'Android'
        elif 'iOS' in user_agent:
            os_info = 'iOS'
        else:
            os_info = 'Other'
        
        return f"{browser}_on_{os_info}"
    
    def _sanitize_session_id(self, session_id: str) -> str:
        """Generate privacy-preserving session identifier."""
        return f"session_{self._hash_value(session_id)[:16]}"
    
    def _sanitize_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively sanitize metadata dictionary."""
        sanitized_metadata = {}
        
        for key, value in metadata.items():
            # Skip sanitization for non-PII fields
            if key in ['timestamp', 'event_type', 'severity', 'category', 'error_code']:
                sanitized_metadata[key] = value
                continue
            
            # Sanitize known PII fields
            if key in ['user_email', 'email']:
                sanitized_metadata[key] = self._sanitize_email(str(value))
            elif key in ['client_ip', 'source_ip', 'remote_addr']:
                sanitized_metadata[key] = self._sanitize_ip_address(str(value))
            elif key in ['user_id', 'subject', 'sub']:
                sanitized_metadata[key] = self._sanitize_user_id(str(value))
            elif key == 'user_agent':
                sanitized_metadata[key] = self._sanitize_user_agent(str(value))
            elif isinstance(value, dict):
                sanitized_metadata[key] = self._sanitize_metadata(value)
            elif isinstance(value, list):
                sanitized_metadata[key] = [
                    self._sanitize_metadata(item) if isinstance(item, dict) else item 
                    for item in value
                ]
            else:
                sanitized_metadata[key] = value
        
        return sanitized_metadata
    
    def _hash_value(self, value: str) -> str:
        """Generate SHA-256 hash with salt for consistent anonymization."""
        hasher = hashlib.sha256()
        hasher.update(self.salt)
        hasher.update(value.encode('utf-8'))
        return hasher.hexdigest()


class SecurityAuditLogger:
    """
    Enterprise-grade security audit logging system with comprehensive event tracking,
    structured logging, and enterprise integration for compliance and monitoring.
    
    This class provides the core security audit logging functionality including:
    - Structured JSON logging using structlog 23.1+ for enterprise log aggregation
    - Real-time security event processing with buffering and batch operations
    - Prometheus metrics integration for security monitoring dashboards
    - PII sanitization and privacy protection for GDPR compliance
    - Enterprise SIEM integration with standardized event formatting
    - Performance optimization ensuring ≤2ms logging overhead per event
    - Comprehensive audit trail for SOC 2 and ISO 27001 compliance
    
    The audit logger integrates seamlessly with the existing monitoring infrastructure
    and provides enterprise-grade security event tracking with minimal performance impact.
    """
    
    def __init__(
        self, 
        app: Optional[Flask] = None,
        monitoring_logger: Optional[StructuredLogger] = None,
        prometheus_metrics: Optional[PrometheusMetrics] = None
    ):
        """
        Initialize comprehensive security audit logging system.
        
        Args:
            app: Flask application instance for integration
            monitoring_logger: Existing monitoring logger for integration
            prometheus_metrics: Existing prometheus metrics for integration
        """
        self.app = app
        self.config = SecurityAuditConfig()
        
        # Initialize monitoring integration
        self.monitoring_logger = monitoring_logger
        self.prometheus_metrics = prometheus_metrics
        
        # Initialize security-specific components
        self.audit_metrics = SecurityAuditMetrics()
        self.pii_sanitizer = PIISanitizer()
        
        # Initialize structured logger for security events
        self._setup_structured_logging()
        
        # Initialize event buffering and batch processing
        self.event_buffer: Deque[Dict[str, Any]] = deque(maxlen=self.config.AUDIT_BUFFER_SIZE)
        self.buffer_lock = Lock()
        self.last_flush_time = time.time()
        
        # Initialize async processing if enabled
        if self.config.ASYNC_LOGGING_ENABLED:
            self._setup_async_processing()
        
        # Performance monitoring
        self.event_processing_times = deque(maxlen=100)
        self.total_events_processed = 0
        
        # Initialize Flask integration if app provided
        if app:
            self.init_app(app)
    
    def init_app(self, app: Flask) -> None:
        """Initialize Flask application integration with security audit logging."""
        app.config.setdefault('SECURITY_AUDIT_ENABLED', True)
        app.config.setdefault('SECURITY_AUDIT_CONFIG', self.config)
        
        # Store audit logger in app config for access
        app.config['SECURITY_AUDIT_LOGGER'] = self
        
        # Register request hooks for automatic audit logging
        self._register_request_hooks(app)
        
        # Register error handlers for security exception logging
        self._register_error_handlers(app)
    
    def _setup_structured_logging(self) -> None:
        """Configure structured logging specifically for security audit events."""
        processors = [
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer()
        ]
        
        structlog.configure(
            processors=processors,
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
        
        self.security_logger = structlog.get_logger("security.audit")
    
    def _setup_async_processing(self) -> None:
        """Setup asynchronous event processing for high-performance logging."""
        self.processing_thread = Thread(
            target=self._async_event_processor,
            daemon=True,
            name="SecurityAuditProcessor"
        )
        self.processing_thread.start()
    
    def _async_event_processor(self) -> None:
        """Asynchronous event processing loop for batch operations."""
        while True:
            try:
                current_time = time.time()
                
                # Check if flush interval exceeded or buffer is full
                if (current_time - self.last_flush_time >= self.config.AUDIT_FLUSH_INTERVAL or
                    len(self.event_buffer) >= self.config.AUDIT_BUFFER_SIZE * 0.8):
                    
                    self._flush_event_buffer()
                    self.last_flush_time = current_time
                
                # Update audit system metrics
                self._update_system_metrics()
                
                # Sleep to prevent excessive CPU usage
                time.sleep(0.1)
                
            except Exception as e:
                # Log error but continue processing
                if hasattr(self, 'security_logger'):
                    self.security_logger.error(
                        "Error in async audit processor",
                        error=str(e),
                        processor="async_event_processor"
                    )
    
    def _flush_event_buffer(self) -> None:
        """Flush buffered events to structured logging and metrics collection."""
        with self.buffer_lock:
            if not self.event_buffer:
                return
            
            # Process all buffered events
            events_to_process = list(self.event_buffer)
            self.event_buffer.clear()
        
        # Batch process events
        for event in events_to_process:
            try:
                self._process_single_event(event)
            except Exception as e:
                # Log processing error but continue with other events
                self.security_logger.error(
                    "Error processing buffered security event",
                    error=str(e),
                    event_id=event.get('event_id', 'unknown')
                )
    
    def _process_single_event(self, event: Dict[str, Any]) -> None:
        """Process a single security event with metrics and logging."""
        start_time = time.perf_counter()
        
        try:
            # Sanitize PII if enabled
            if self.config.PII_SANITIZATION_ENABLED:
                event = self.pii_sanitizer.sanitize_security_event(event)
            
            # Log to structured logger
            log_level = self._determine_log_level(event)
            log_method = getattr(self.security_logger, log_level)
            log_method(
                event.get('message', 'Security event occurred'),
                **event
            )
            
            # Record metrics
            self._record_event_metrics(event)
            
            # Handle critical events with real-time alerting
            if event.get('severity') == 'critical' and self.config.CRITICAL_EVENTS_REAL_TIME:
                self._handle_critical_event(event)
            
        finally:
            # Track processing performance
            processing_time = time.perf_counter() - start_time
            self.event_processing_times.append(processing_time)
            self.total_events_processed += 1
            
            # Alert if processing time exceeds threshold
            if processing_time > self.config.MAX_AUDIT_OVERHEAD_MS / 1000.0:
                self.security_logger.warning(
                    "Security audit processing exceeded performance threshold",
                    processing_time_ms=processing_time * 1000,
                    threshold_ms=self.config.MAX_AUDIT_OVERHEAD_MS,
                    event_type=event.get('event_type', 'unknown')
                )
    
    def _determine_log_level(self, event: Dict[str, Any]) -> str:
        """Determine appropriate log level based on event severity and type."""
        severity = event.get('severity', 'info').lower()
        event_type = event.get('event_type', '')
        
        # Critical security violations always get error level
        if severity == 'critical' or 'VIOLATION' in event_type:
            return 'error'
        elif severity == 'high' or 'FAILURE' in event_type:
            return 'warning'
        elif severity == 'medium':
            return 'info'
        else:
            return 'debug'
    
    def _record_event_metrics(self, event: Dict[str, Any]) -> None:
        """Record Prometheus metrics for security event."""
        event_type = event.get('event_type', 'unknown')
        category = event.get('category', 'unknown')
        severity = event.get('severity', 'info')
        source = event.get('source', 'application')
        
        # Record general security event metrics
        self.audit_metrics.record_security_event(
            event_type=event_type,
            category=category,
            severity=severity,
            source=source
        )
        
        # Record specific metrics based on event type
        if event_type.startswith('AU.'):
            self._record_authentication_metrics(event)
        elif event_type.startswith('AZ.'):
            self._record_authorization_metrics(event)
        elif event_type.startswith('SV.'):
            self._record_security_violation_metrics(event)
        elif event_type.startswith('ES.'):
            self._record_external_service_metrics(event)
    
    def _record_authentication_metrics(self, event: Dict[str, Any]) -> None:
        """Record authentication-specific metrics."""
        result = 'success' if 'SUCCESS' in event.get('event_type', '') else 'failure'
        method = event.get('auth_method', 'jwt')
        source = event.get('source', 'web')
        duration = event.get('processing_duration', 0.0)
        
        self.audit_metrics.record_authentication_attempt(
            result=result,
            method=method,
            source=source,
            duration=duration
        )
    
    def _record_authorization_metrics(self, event: Dict[str, Any]) -> None:
        """Record authorization-specific metrics."""
        decision = 'granted' if 'GRANTED' in event.get('event_type', '') else 'denied'
        permission_type = event.get('permission_type', 'unknown')
        resource_type = event.get('resource_type', 'unknown')
        user_role = event.get('user_role', 'user')
        duration = event.get('processing_duration', 0.0)
        
        self.audit_metrics.record_authorization_decision(
            decision=decision,
            permission_type=permission_type,
            resource_type=resource_type,
            user_role=user_role,
            duration=duration
        )
    
    def _record_security_violation_metrics(self, event: Dict[str, Any]) -> None:
        """Record security violation metrics."""
        violation_type = event.get('violation_type', 'unknown')
        severity = event.get('severity', 'medium')
        source_ip_category = event.get('source_ip_category', 'unknown')
        user_category = event.get('user_category', 'authenticated')
        
        self.audit_metrics.record_security_violation(
            violation_type=violation_type,
            severity=severity,
            source_ip_category=source_ip_category,
            user_category=user_category
        )
    
    def _record_external_service_metrics(self, event: Dict[str, Any]) -> None:
        """Record external service event metrics."""
        service = event.get('service', 'unknown')
        
        if 'CIRCUIT.BREAKER' in event.get('event_type', ''):
            state = 'open' if 'OPEN' in event.get('event_type', '') else 'closed'
            failure_type = event.get('failure_type', 'timeout')
            recovery_action = event.get('recovery_action', 'automatic')
            
            self.audit_metrics.record_circuit_breaker_event(
                service=service,
                state=state,
                failure_type=failure_type,
                recovery_action=recovery_action
            )
    
    def _handle_critical_event(self, event: Dict[str, Any]) -> None:
        """Handle critical security events with immediate alerting."""
        # Log critical event with high priority
        self.security_logger.critical(
            "CRITICAL SECURITY EVENT DETECTED",
            **event,
            alert_required=True,
            escalation_level="immediate"
        )
        
        # Integration point for enterprise alerting systems
        if self.config.SECURITY_ALERTING_ENABLED:
            self._trigger_security_alert(event)
    
    def _trigger_security_alert(self, event: Dict[str, Any]) -> None:
        """Trigger enterprise security alerting for critical events."""
        # This method would integrate with enterprise alerting systems
        # such as PagerDuty, Slack, or email notifications
        pass
    
    def _update_system_metrics(self) -> None:
        """Update audit system performance metrics."""
        with self.buffer_lock:
            buffer_size = len(self.event_buffer)
        
        # Calculate processing lag
        if self.event_processing_times:
            avg_processing_time = sum(self.event_processing_times) / len(self.event_processing_times)
            processing_lag = time.time() - self.last_flush_time + avg_processing_time
        else:
            processing_lag = 0.0
        
        # Estimate memory usage (rough approximation)
        memory_usage = buffer_size * 1024  # Assume ~1KB per event
        
        self.audit_metrics.update_audit_system_metrics(
            buffer_size=buffer_size,
            processing_lag=processing_lag,
            memory_usage=memory_usage
        )
    
    def _register_request_hooks(self, app: Flask) -> None:
        """Register Flask request hooks for automatic security event logging."""
        
        @app.before_request
        def before_request_audit():
            """Pre-request security context setup."""
            # Initialize security context for request
            g.security_context = {
                'request_id': str(uuid.uuid4()),
                'start_time': time.time(),
                'source_ip': request.remote_addr,
                'user_agent': request.headers.get('User-Agent', ''),
                'endpoint': request.endpoint,
                'method': request.method
            }
        
        @app.after_request
        def after_request_audit(response):
            """Post-request security audit logging."""
            if hasattr(g, 'security_context'):
                # Log successful request completion
                self.log_security_event(
                    event_type=SecurityEventType.DATA_READ_ACCESS if request.method == 'GET' 
                              else SecurityEventType.DATA_WRITE_ACCESS,
                    message=f"API request completed: {request.method} {request.path}",
                    severity="info",
                    metadata={
                        'request_id': g.security_context['request_id'],
                        'status_code': response.status_code,
                        'processing_time': time.time() - g.security_context['start_time'],
                        'endpoint': g.security_context['endpoint'],
                        'method': g.security_context['method']
                    }
                )
            
            return response
    
    def _register_error_handlers(self, app: Flask) -> None:
        """Register Flask error handlers for security exception logging."""
        
        @app.errorhandler(SecurityException)
        def handle_security_exception(error: SecurityException):
            """Handle security exceptions with comprehensive audit logging."""
            self.log_security_exception(error)
            
            # Return safe error response
            from flask import jsonify
            return jsonify({
                'error': True,
                'message': error.user_message,
                'error_code': error.error_code.value,
                'error_id': error.error_id
            }), error.http_status
    
    # Public API Methods
    
    def log_security_event(
        self,
        event_type: str,
        message: str,
        severity: str = "info",
        user_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None
    ) -> str:
        """
        Log a comprehensive security event with structured data and metrics.
        
        This method provides the primary interface for logging security events
        with enterprise-grade audit trail capabilities and compliance support.
        
        Args:
            event_type: Standardized security event type (SecurityEventType)
            message: Human-readable event description
            severity: Event severity level (info, low, medium, high, critical)
            user_id: User identifier associated with the event
            source_ip: Source IP address for the security event
            metadata: Additional event metadata and context
            correlation_id: Request correlation ID for distributed tracing
            
        Returns:
            Unique event identifier for tracking and correlation
            
        Example:
            event_id = audit_logger.log_security_event(
                event_type=SecurityEventType.AUTH_LOGIN_SUCCESS,
                message="User successfully authenticated",
                severity="info",
                user_id="user_12345",
                metadata={'auth_method': 'jwt', 'mfa_used': True}
            )
        """
        start_time = time.perf_counter()
        
        # Generate unique event identifier
        event_id = str(uuid.uuid4())
        
        # Build comprehensive event data
        event_data = {
            'event_id': event_id,
            'event_type': event_type,
            'message': message,
            'severity': severity,
            'timestamp': datetime.utcnow().isoformat(),
            'category': get_error_category_from_event_type(event_type),
            'source': 'flask_security_audit',
            'correlation_id': correlation_id or getattr(g, 'request_id', None),
            'user_id': user_id,
            'source_ip': source_ip or (request.remote_addr if request else None),
            'user_agent': request.headers.get('User-Agent') if request else None,
            'endpoint': request.endpoint if request else None,
            'method': request.method if request else None,
            'session_id': session.get('id') if session else None,
            'metadata': metadata or {},
            'processing_start_time': start_time
        }
        
        # Add request context if available
        if hasattr(g, 'security_context'):
            event_data.update({
                'request_id': g.security_context['request_id'],
                'request_start_time': g.security_context['start_time']
            })
        
        # Buffer event for processing
        with self.buffer_lock:
            self.event_buffer.append(event_data)
        
        # Process immediately if not using async processing or if critical
        if not self.config.ASYNC_LOGGING_ENABLED or severity == 'critical':
            self._flush_event_buffer()
        
        return event_id
    
    def log_authentication_event(
        self,
        event_type: str,
        result: str,
        user_id: Optional[str] = None,
        auth_method: str = "jwt",
        error_details: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Log authentication-specific events with comprehensive context.
        
        Args:
            event_type: Authentication event type (SecurityEventType.AUTH_*)
            result: Authentication result (success, failure, expired, etc.)
            user_id: User identifier for successful authentications
            auth_method: Authentication method used (jwt, oauth, mfa)
            error_details: Error details for failed authentications
            metadata: Additional authentication context
            
        Returns:
            Unique event identifier for tracking
        """
        severity = "info" if result == "success" else "warning"
        if result in ["brute_force", "account_locked"]:
            severity = "high"
        
        auth_metadata = {
            'auth_method': auth_method,
            'auth_result': result,
            'error_details': error_details,
            **(metadata or {})
        }
        
        return self.log_security_event(
            event_type=event_type,
            message=f"Authentication {result}: {auth_method}",
            severity=severity,
            user_id=user_id,
            metadata=auth_metadata
        )
    
    def log_authorization_event(
        self,
        event_type: str,
        decision: str,
        user_id: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        required_permissions: Optional[List[str]] = None,
        user_permissions: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Log authorization decisions with comprehensive permission context.
        
        Args:
            event_type: Authorization event type (SecurityEventType.AUTHZ_*)
            decision: Authorization decision (granted, denied)
            user_id: User identifier making the request
            resource_type: Type of resource being accessed
            resource_id: Specific resource identifier
            required_permissions: Permissions required for the operation
            user_permissions: User's current permission set
            metadata: Additional authorization context
            
        Returns:
            Unique event identifier for tracking
        """
        severity = "info" if decision == "granted" else "warning"
        
        authz_metadata = {
            'authorization_decision': decision,
            'resource_type': resource_type,
            'resource_id': resource_id,
            'required_permissions': required_permissions or [],
            'user_permissions_count': len(user_permissions) if user_permissions else 0,
            **(metadata or {})
        }
        
        return self.log_security_event(
            event_type=event_type,
            message=f"Authorization {decision} for {resource_type or 'resource'}",
            severity=severity,
            user_id=user_id,
            metadata=authz_metadata
        )
    
    def log_security_violation(
        self,
        violation_type: str,
        severity: str,
        description: str,
        user_id: Optional[str] = None,
        attack_indicators: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Log security violations and potential threats.
        
        Args:
            violation_type: Type of security violation (rate_limit, brute_force, etc.)
            severity: Violation severity (low, medium, high, critical)
            description: Human-readable violation description
            user_id: User associated with the violation (if applicable)
            attack_indicators: Indicators of compromise or attack patterns
            metadata: Additional violation context
            
        Returns:
            Unique event identifier for tracking
        """
        violation_metadata = {
            'violation_type': violation_type,
            'attack_indicators': attack_indicators or {},
            **(metadata or {})
        }
        
        return self.log_security_event(
            event_type=f"SV.{violation_type.upper()}",
            message=description,
            severity=severity,
            user_id=user_id,
            metadata=violation_metadata
        )
    
    def log_rate_limit_violation(
        self,
        endpoint: str,
        limit_type: str,
        current_rate: int,
        limit_threshold: int,
        user_id: Optional[str] = None,
        time_window: str = "minute",
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Log rate limiting violations with detailed metrics.
        
        Args:
            endpoint: API endpoint where rate limit was exceeded
            limit_type: Type of rate limit (user, ip, endpoint)
            current_rate: Current request rate that exceeded limit
            limit_threshold: Rate limit threshold that was exceeded
            user_id: User identifier (if applicable)
            time_window: Time window for rate limiting (minute, hour)
            metadata: Additional rate limiting context
            
        Returns:
            Unique event identifier for tracking
        """
        severity = "medium" if current_rate < limit_threshold * 1.5 else "high"
        
        rate_limit_metadata = {
            'endpoint': endpoint,
            'limit_type': limit_type,
            'current_rate': current_rate,
            'limit_threshold': limit_threshold,
            'time_window': time_window,
            'excess_percentage': ((current_rate - limit_threshold) / limit_threshold) * 100,
            **(metadata or {})
        }
        
        # Record specific rate limit metrics
        self.audit_metrics.record_rate_limit_violation(
            endpoint=endpoint,
            limit_type=limit_type,
            violation_severity=severity
        )
        
        return self.log_security_event(
            event_type=SecurityEventType.SEC_RATE_LIMIT_VIOLATION,
            message=f"Rate limit exceeded: {current_rate}/{limit_threshold} {time_window}",
            severity=severity,
            user_id=user_id,
            metadata=rate_limit_metadata
        )
    
    def log_circuit_breaker_event(
        self,
        service: str,
        event_type: str,
        state: str,
        failure_count: int = 0,
        error_details: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Log circuit breaker events for external service monitoring.
        
        Args:
            service: External service name (auth0, aws, redis)
            event_type: Circuit breaker event type (open, close, half_open)
            state: Current circuit breaker state
            failure_count: Number of consecutive failures
            error_details: Details of the service failure
            metadata: Additional circuit breaker context
            
        Returns:
            Unique event identifier for tracking
        """
        severity = "high" if state == "open" else "info"
        
        circuit_metadata = {
            'service': service,
            'circuit_state': state,
            'failure_count': failure_count,
            'error_details': error_details,
            **(metadata or {})
        }
        
        # Record circuit breaker metrics
        self.audit_metrics.record_circuit_breaker_event(
            service=service,
            state=state,
            failure_type=metadata.get('failure_type', 'timeout') if metadata else 'timeout'
        )
        
        return self.log_security_event(
            event_type=f"ES.CIRCUIT.BREAKER.{event_type.upper()}",
            message=f"Circuit breaker {event_type} for {service} service",
            severity=severity,
            metadata=circuit_metadata
        )
    
    def log_security_exception(self, exception: SecurityException) -> str:
        """
        Log security exceptions with comprehensive context and correlation.
        
        Args:
            exception: SecurityException instance with metadata
            
        Returns:
            Unique event identifier for tracking
        """
        # Determine event type from exception
        event_type = self._map_exception_to_event_type(exception)
        
        # Extract user context
        user_id = exception.metadata.get('user_id')
        
        # Build exception metadata
        exception_metadata = {
            'exception_type': type(exception).__name__,
            'error_code': exception.error_code.value,
            'error_category': get_error_category(exception.error_code),
            'http_status': exception.http_status,
            'is_critical': is_critical_security_error(exception.error_code),
            **exception.metadata
        }
        
        severity = self._determine_exception_severity(exception)
        
        return self.log_security_event(
            event_type=event_type,
            message=str(exception),
            severity=severity,
            user_id=user_id,
            metadata=exception_metadata,
            correlation_id=exception.error_id
        )
    
    def _map_exception_to_event_type(self, exception: SecurityException) -> str:
        """Map security exception to appropriate event type."""
        if isinstance(exception, AuthenticationException):
            return SecurityEventType.AUTH_TOKEN_VALIDATION_FAILURE
        elif isinstance(exception, AuthorizationException):
            return SecurityEventType.AUTHZ_PERMISSION_DENIED
        elif isinstance(exception, RateLimitException):
            return SecurityEventType.SEC_RATE_LIMIT_VIOLATION
        elif isinstance(exception, CircuitBreakerException):
            return SecurityEventType.EXT_CIRCUIT_BREAKER_OPEN
        elif isinstance(exception, ValidationException):
            return SecurityEventType.SEC_INPUT_VALIDATION_FAILURE
        else:
            return "SEC.GENERAL.SECURITY.EXCEPTION"
    
    def _determine_exception_severity(self, exception: SecurityException) -> str:
        """Determine severity level for security exception."""
        if is_critical_security_error(exception.error_code):
            return "critical"
        elif exception.http_status >= 500:
            return "high"
        elif exception.http_status >= 400:
            return "medium"
        else:
            return "low"
    
    @contextmanager
    def security_operation_context(
        self,
        operation_name: str,
        user_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Context manager for tracking security operations with automatic logging.
        
        Args:
            operation_name: Name of the security operation
            user_id: User performing the operation
            resource_type: Type of resource being accessed
            metadata: Additional operation context
            
        Yields:
            Operation context dictionary
            
        Example:
            with audit_logger.security_operation_context(
                operation_name="user_permission_check",
                user_id="user_123",
                resource_type="document"
            ) as ctx:
                # Perform security operation
                result = check_permissions(user_id, resource_id)
                ctx['result'] = result
        """
        operation_id = str(uuid.uuid4())
        start_time = time.perf_counter()
        
        operation_context = {
            'operation_id': operation_id,
            'operation_name': operation_name,
            'user_id': user_id,
            'resource_type': resource_type,
            'metadata': metadata or {},
            'start_time': start_time
        }
        
        try:
            # Log operation start
            self.log_security_event(
                event_type="SEC.OPERATION.START",
                message=f"Security operation started: {operation_name}",
                severity="debug",
                user_id=user_id,
                metadata=operation_context
            )
            
            yield operation_context
            
            # Log successful completion
            duration = time.perf_counter() - start_time
            operation_context['duration'] = duration
            operation_context['status'] = 'success'
            
            self.log_security_event(
                event_type="SEC.OPERATION.SUCCESS",
                message=f"Security operation completed: {operation_name}",
                severity="info",
                user_id=user_id,
                metadata=operation_context
            )
            
        except Exception as e:
            # Log operation failure
            duration = time.perf_counter() - start_time
            operation_context['duration'] = duration
            operation_context['status'] = 'failure'
            operation_context['error'] = str(e)
            
            self.log_security_event(
                event_type="SEC.OPERATION.FAILURE",
                message=f"Security operation failed: {operation_name}",
                severity="warning",
                user_id=user_id,
                metadata=operation_context
            )
            
            raise
    
    def get_audit_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive audit system statistics for monitoring and optimization.
        
        Returns:
            Dictionary containing audit system performance and health metrics
        """
        with self.buffer_lock:
            buffer_size = len(self.event_buffer)
        
        avg_processing_time = (
            sum(self.event_processing_times) / len(self.event_processing_times)
            if self.event_processing_times else 0.0
        )
        
        return {
            'total_events_processed': self.total_events_processed,
            'current_buffer_size': buffer_size,
            'max_buffer_size': self.config.AUDIT_BUFFER_SIZE,
            'average_processing_time_ms': avg_processing_time * 1000,
            'max_processing_time_ms': max(self.event_processing_times) * 1000 if self.event_processing_times else 0,
            'events_per_second': len(self.event_processing_times) / max(sum(self.event_processing_times), 0.001),
            'memory_usage_estimate_mb': buffer_size * 1024 / (1024 * 1024),
            'last_flush_time': self.last_flush_time,
            'time_since_last_flush': time.time() - self.last_flush_time,
            'pii_sanitization_enabled': self.config.PII_SANITIZATION_ENABLED,
            'async_processing_enabled': self.config.ASYNC_LOGGING_ENABLED,
            'config': {
                'audit_buffer_size': self.config.AUDIT_BUFFER_SIZE,
                'flush_interval': self.config.AUDIT_FLUSH_INTERVAL,
                'max_overhead_ms': self.config.MAX_AUDIT_OVERHEAD_MS,
                'memory_limit_mb': self.config.AUDIT_MEMORY_LIMIT_MB
            }
        }


def get_error_category_from_event_type(event_type: str) -> str:
    """
    Get error category from security event type for consistent categorization.
    
    Args:
        event_type: Security event type string
        
    Returns:
        Error category string for monitoring and alerting
    """
    if event_type.startswith('AU.'):
        return "authentication"
    elif event_type.startswith('AZ.'):
        return "authorization"
    elif event_type.startswith('SV.'):
        return "security_violation"
    elif event_type.startswith('ES.'):
        return "external_service"
    elif event_type.startswith('AD.'):
        return "administrative"
    elif event_type.startswith('DA.'):
        return "data_access"
    else:
        return "unknown"


def create_security_audit_decorator(
    event_type: str,
    operation_name: str,
    resource_type: Optional[str] = None
) -> Callable:
    """
    Create a decorator for automatic security audit logging of function calls.
    
    Args:
        event_type: Security event type for the decorated function
        operation_name: Name of the security operation
        resource_type: Type of resource being accessed (optional)
        
    Returns:
        Decorator function for security audit logging
        
    Example:
        @create_security_audit_decorator(
            event_type=SecurityEventType.AUTHZ_PERMISSION_GRANTED,
            operation_name="check_user_permissions",
            resource_type="document"
        )
        def check_permissions(user_id: str, resource_id: str) -> bool:
            # Permission checking logic
            return True
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get audit logger from current app
            if current_app and hasattr(current_app.config, 'SECURITY_AUDIT_LOGGER'):
                audit_logger = current_app.config['SECURITY_AUDIT_LOGGER']
                
                # Extract user context from function arguments
                user_id = kwargs.get('user_id') or (args[0] if args else None)
                
                with audit_logger.security_operation_context(
                    operation_name=operation_name,
                    user_id=str(user_id) if user_id else None,
                    resource_type=resource_type,
                    metadata={'function_name': func.__name__}
                ) as ctx:
                    result = func(*args, **kwargs)
                    ctx['result'] = bool(result) if isinstance(result, bool) else 'completed'
                    return result
            else:
                # Fallback to normal execution if audit logger not available
                return func(*args, **kwargs)
        
        return wrapper
    return decorator


# Convenience decorators for common security operations
audit_authentication = lambda func: create_security_audit_decorator(
    SecurityEventType.AUTH_TOKEN_VALIDATION_SUCCESS,
    "authentication_check"
)(func)

audit_authorization = lambda func: create_security_audit_decorator(
    SecurityEventType.AUTHZ_PERMISSION_GRANTED,
    "authorization_check"
)(func)

audit_data_access = lambda func: create_security_audit_decorator(
    SecurityEventType.DATA_READ_ACCESS,
    "data_access_operation"
)(func)


def init_security_audit(
    app: Flask,
    monitoring_logger: Optional[StructuredLogger] = None,
    prometheus_metrics: Optional[PrometheusMetrics] = None
) -> SecurityAuditLogger:
    """
    Initialize comprehensive security audit logging for Flask application.
    
    This function sets up enterprise-grade security audit logging including:
    - Structured JSON logging for SIEM integration
    - Prometheus metrics collection for security monitoring
    - PII sanitization for privacy compliance
    - Real-time security event processing with buffering
    - Integration with existing monitoring infrastructure
    
    Args:
        app: Flask application instance
        monitoring_logger: Existing monitoring logger (optional)
        prometheus_metrics: Existing prometheus metrics (optional)
        
    Returns:
        SecurityAuditLogger instance for application use
        
    Example:
        app = Flask(__name__)
        audit_logger = init_security_audit(app)
        
        # Use audit logger in route handlers
        @app.route('/api/login', methods=['POST'])
        def login():
            # Authentication logic
            audit_logger.log_authentication_event(
                event_type=SecurityEventType.AUTH_LOGIN_SUCCESS,
                result="success",
                user_id=user.id
            )
    """
    # Initialize security audit logger
    audit_logger = SecurityAuditLogger(
        app=app,
        monitoring_logger=monitoring_logger,
        prometheus_metrics=prometheus_metrics
    )
    
    # Initialize Flask application integration
    audit_logger.init_app(app)
    
    # Log audit system initialization
    audit_logger.log_security_event(
        event_type="AD.CONFIGURATION.CHANGE",
        message="Security audit logging system initialized",
        severity="info",
        metadata={
            'audit_system_version': '1.0.0',
            'flask_app_name': app.name,
            'pii_sanitization_enabled': SecurityAuditConfig.PII_SANITIZATION_ENABLED,
            'async_processing_enabled': SecurityAuditConfig.ASYNC_LOGGING_ENABLED,
            'siem_integration_enabled': SecurityAuditConfig.SIEM_INTEGRATION_ENABLED,
            'enterprise_compliance_mode': True
        }
    )
    
    return audit_logger


# Export public API
__all__ = [
    'SecurityAuditLogger',
    'SecurityAuditConfig', 
    'SecurityAuditMetrics',
    'SecurityEventType',
    'PIISanitizer',
    'init_security_audit',
    'create_security_audit_decorator',
    'audit_authentication',
    'audit_authorization', 
    'audit_data_access'
]