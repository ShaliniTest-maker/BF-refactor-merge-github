"""
Security Audit Logging Module

This module provides comprehensive security audit logging with structlog 23.1+ integration,
enterprise-grade compliance support, and comprehensive security event tracking. It implements
JSON-formatted structured logging, rate limiting violation monitoring, circuit breaker event
tracking, and Prometheus metrics integration for complete security observability.

The audit system is designed to:
- Provide enterprise-grade security audit logging for SOC 2, ISO 27001, and PCI DSS compliance
- Implement structured JSON logging for SIEM integration and centralized log aggregation
- Track comprehensive security events including authentication, authorization, and security violations
- Monitor rate limiting violations and suspicious activity patterns
- Integrate circuit breaker events and external service degradation monitoring
- Provide Prometheus metrics for real-time security posture monitoring

Dependencies:
- structlog 23.1+: Structured logging with JSON formatting
- prometheus_client 0.17+: Metrics collection and monitoring
- typing: Type annotations for enterprise code quality
- datetime: Timestamp generation for audit trails
- uuid: Unique event identifier generation
- flask: Request context and session management
- threading: Thread-safe logging operations
- json: JSON serialization for log formatting

Author: Flask Migration Team
Version: 1.0.0
Compliance: SOC 2, ISO 27001, PCI DSS, GDPR, OWASP Top 10
"""

import structlog
import json
import uuid
import threading
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Union, List, Callable
from enum import Enum
from dataclasses import dataclass, field
from functools import wraps
from flask import request, session, g, current_app
from prometheus_client import Counter, Histogram, Gauge, Enum as PrometheusEnum

# Import project dependencies
from src.auth.exceptions import (
    SecurityException, 
    SecurityErrorCode,
    AuthenticationException,
    AuthorizationException,
    RateLimitException,
    CircuitBreakerException,
    ValidationException,
    get_error_category,
    is_critical_security_error
)


class SecurityEventType(Enum):
    """
    Standardized security event types for comprehensive audit logging.
    
    These event types provide consistent categorization of security events for:
    - SIEM integration and automated threat detection
    - Compliance reporting and audit trail generation
    - Security metrics collection and alerting
    - Incident response and forensic analysis
    - Performance monitoring and capacity planning
    """
    
    # Authentication Events
    AUTH_LOGIN_SUCCESS = "auth_login_success"
    AUTH_LOGIN_FAILURE = "auth_login_failure"
    AUTH_LOGOUT = "auth_logout"
    AUTH_TOKEN_VALIDATED = "auth_token_validated"
    AUTH_TOKEN_INVALID = "auth_token_invalid"
    AUTH_TOKEN_EXPIRED = "auth_token_expired"
    AUTH_SESSION_CREATED = "auth_session_created"
    AUTH_SESSION_DESTROYED = "auth_session_destroyed"
    AUTH_MFA_SUCCESS = "auth_mfa_success"
    AUTH_MFA_FAILURE = "auth_mfa_failure"
    
    # Authorization Events
    AUTHZ_PERMISSION_GRANTED = "authz_permission_granted"
    AUTHZ_PERMISSION_DENIED = "authz_permission_denied"
    AUTHZ_RESOURCE_ACCESS_GRANTED = "authz_resource_access_granted"
    AUTHZ_RESOURCE_ACCESS_DENIED = "authz_resource_access_denied"
    AUTHZ_ROLE_ASSIGNMENT = "authz_role_assignment"
    AUTHZ_ROLE_REVOCATION = "authz_role_revocation"
    AUTHZ_POLICY_VIOLATION = "authz_policy_violation"
    
    # Security Violations
    SEC_RATE_LIMIT_EXCEEDED = "sec_rate_limit_exceeded"
    SEC_BRUTE_FORCE_DETECTED = "sec_brute_force_detected"
    SEC_SUSPICIOUS_ACTIVITY = "sec_suspicious_activity"
    SEC_IP_BLOCKED = "sec_ip_blocked"
    SEC_MALICIOUS_REQUEST = "sec_malicious_request"
    SEC_INPUT_VALIDATION_FAILURE = "sec_input_validation_failure"
    SEC_XSS_ATTEMPT = "sec_xss_attempt"
    SEC_SQL_INJECTION_ATTEMPT = "sec_sql_injection_attempt"
    SEC_CSRF_TOKEN_INVALID = "sec_csrf_token_invalid"
    
    # External Service Events
    EXT_AUTH0_SUCCESS = "ext_auth0_success"
    EXT_AUTH0_FAILURE = "ext_auth0_failure"
    EXT_CIRCUIT_BREAKER_OPEN = "ext_circuit_breaker_open"
    EXT_CIRCUIT_BREAKER_CLOSED = "ext_circuit_breaker_closed"
    EXT_SERVICE_TIMEOUT = "ext_service_timeout"
    EXT_SERVICE_ERROR = "ext_service_error"
    EXT_API_RATE_LIMITED = "ext_api_rate_limited"
    
    # System Events
    SYS_CONFIG_CHANGED = "sys_config_changed"
    SYS_SECURITY_POLICY_UPDATED = "sys_security_policy_updated"
    SYS_CERTIFICATE_RENEWAL = "sys_certificate_renewal"
    SYS_KEY_ROTATION = "sys_key_rotation"
    SYS_BACKUP_COMPLETED = "sys_backup_completed"
    SYS_MAINTENANCE_MODE = "sys_maintenance_mode"


class SecurityEventSeverity(Enum):
    """
    Security event severity levels for prioritization and alerting.
    
    Severity levels aligned with enterprise security operations:
    - CRITICAL: Immediate response required, potential security breach
    - HIGH: Urgent attention required, significant security risk
    - MEDIUM: Important security event requiring investigation
    - LOW: Informational security event for audit trail
    - INFO: Normal operational security events
    """
    
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class SecurityEventContext:
    """
    Comprehensive security event context for audit logging.
    
    This dataclass provides structured context information for security events,
    enabling comprehensive audit trails and forensic analysis capabilities.
    """
    
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: SecurityEventType = SecurityEventType.SYS_CONFIG_CHANGED
    severity: SecurityEventSeverity = SecurityEventSeverity.INFO
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    endpoint: Optional[str] = None
    method: Optional[str] = None
    resource_id: Optional[str] = None
    resource_type: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    additional_data: Dict[str, Any] = field(default_factory=dict)
    correlation_id: Optional[str] = None
    transaction_id: Optional[str] = None


class SecurityAuditLogger:
    """
    Comprehensive security audit logging system with structlog integration.
    
    This class provides enterprise-grade security audit logging capabilities with:
    - Structured JSON logging using structlog 23.1+ for SIEM integration
    - Comprehensive security event tracking and categorization
    - Prometheus metrics integration for real-time monitoring
    - Thread-safe logging operations for concurrent request handling
    - Configurable logging levels and filtering for different environments
    - Integration with Flask request context for complete audit trails
    
    Features:
    - Authentication and authorization event logging
    - Security violation detection and reporting
    - Rate limiting and circuit breaker monitoring
    - External service integration audit trails
    - Compliance-focused audit trail generation
    - Performance monitoring and capacity planning metrics
    
    Example:
        audit_logger = SecurityAuditLogger()
        
        # Log authentication success
        audit_logger.log_authentication_event(
            event_type=SecurityEventType.AUTH_LOGIN_SUCCESS,
            user_id="user123",
            additional_data={"auth_method": "jwt", "mfa_used": True}
        )
        
        # Log authorization failure
        audit_logger.log_authorization_event(
            event_type=SecurityEventType.AUTHZ_PERMISSION_DENIED,
            user_id="user456",
            permissions=["read:documents"],
            resource_id="doc789",
            severity=SecurityEventSeverity.HIGH
        )
    """
    
    def __init__(self, 
                 logger_name: str = "security.audit",
                 enable_metrics: bool = True,
                 correlation_header: str = "X-Correlation-ID"):
        """
        Initialize the security audit logger with comprehensive configuration.
        
        Args:
            logger_name: Logger name for structlog configuration
            enable_metrics: Whether to enable Prometheus metrics collection
            correlation_header: HTTP header name for request correlation
        """
        self.logger_name = logger_name
        self.enable_metrics = enable_metrics
        self.correlation_header = correlation_header
        self._lock = threading.RLock()
        
        # Initialize structured logger
        self.logger = self._configure_structured_logger()
        
        # Initialize Prometheus metrics
        if self.enable_metrics:
            self._setup_prometheus_metrics()
    
    def _configure_structured_logger(self) -> structlog.BoundLogger:
        """
        Configure structlog for enterprise-grade structured logging.
        
        This method sets up structlog with JSON formatting, comprehensive
        context processors, and enterprise logging standards for SIEM integration.
        
        Returns:
            Configured structlog bound logger
        """
        # Configure structlog processors for comprehensive logging
        processors = [
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            self._add_security_context,
            self._add_request_context,
            structlog.processors.JSONRenderer(sort_keys=True)
        ]
        
        # Configure structlog with enterprise settings
        structlog.configure(
            processors=processors,
            wrapper_class=structlog.stdlib.LoggerFactory(),
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            cache_logger_on_first_use=True,
        )
        
        return structlog.get_logger(self.logger_name)
    
    def _add_security_context(self, logger, method_name, event_dict):
        """
        Add security-specific context to log events.
        
        This processor adds consistent security context including event
        categorization, severity mapping, and compliance metadata.
        """
        # Add security event metadata
        event_dict.update({
            "security_event": True,
            "compliance_category": self._get_compliance_category(event_dict),
            "threat_level": self._assess_threat_level(event_dict),
            "audit_trail": True
        })
        
        return event_dict
    
    def _add_request_context(self, logger, method_name, event_dict):
        """
        Add Flask request context to log events.
        
        This processor extracts relevant request information for comprehensive
        audit trails including correlation IDs and request metadata.
        """
        try:
            if request:
                # Add request context
                event_dict.update({
                    "request_id": getattr(g, 'request_id', None),
                    "correlation_id": request.headers.get(self.correlation_header),
                    "source_ip": self._get_client_ip(),
                    "user_agent": request.headers.get('User-Agent'),
                    "endpoint": request.endpoint,
                    "method": request.method,
                    "url": request.url,
                    "referrer": request.headers.get('Referer'),
                    "content_length": request.content_length
                })
                
                # Add session context if available
                if session:
                    event_dict.update({
                        "session_id": session.get('session_id'),
                        "session_authenticated": session.get('authenticated', False)
                    })
        except RuntimeError:
            # Outside request context, skip request-specific data
            pass
        
        return event_dict
    
    def _setup_prometheus_metrics(self) -> None:
        """
        Initialize Prometheus metrics for security monitoring.
        
        This method creates comprehensive security metrics for real-time
        monitoring, alerting, and capacity planning purposes.
        """
        # Security event counters
        self.security_events_total = Counter(
            'security_events_total',
            'Total security events by type and severity',
            ['event_type', 'severity', 'category']
        )
        
        self.authentication_events_total = Counter(
            'authentication_events_total',
            'Total authentication events by result',
            ['event_type', 'result', 'auth_method']
        )
        
        self.authorization_events_total = Counter(
            'authorization_events_total',
            'Total authorization events by result',
            ['event_type', 'result', 'permission_type']
        )
        
        # Security violation metrics
        self.security_violations_total = Counter(
            'security_violations_total',
            'Total security violations by type',
            ['violation_type', 'severity', 'source_ip']
        )
        
        self.rate_limit_violations_total = Counter(
            'rate_limit_violations_total',
            'Total rate limiting violations',
            ['endpoint', 'user_id', 'limit_type']
        )
        
        # Circuit breaker metrics
        self.circuit_breaker_events_total = Counter(
            'circuit_breaker_events_total',
            'Total circuit breaker events',
            ['service', 'event', 'state']
        )
        
        # Performance metrics
        self.audit_log_duration = Histogram(
            'audit_log_duration_seconds',
            'Time spent processing audit log events',
            ['event_type', 'processing_stage']
        )
        
        # Security posture gauges
        self.active_sessions = Gauge(
            'active_security_sessions',
            'Number of active authenticated sessions'
        )
        
        self.failed_auth_rate = Gauge(
            'failed_authentication_rate',
            'Rate of failed authentication attempts per minute'
        )
        
        # Threat assessment metrics
        self.threat_level = PrometheusEnum(
            'current_threat_level',
            'Current assessed threat level',
            states=['low', 'medium', 'high', 'critical']
        )
    
    def log_authentication_event(self,
                                event_type: SecurityEventType,
                                user_id: Optional[str] = None,
                                result: str = "success",
                                auth_method: str = "jwt",
                                mfa_used: bool = False,
                                error_code: Optional[str] = None,
                                additional_data: Optional[Dict[str, Any]] = None,
                                severity: SecurityEventSeverity = SecurityEventSeverity.INFO) -> None:
        """
        Log comprehensive authentication events with enterprise audit standards.
        
        This method provides detailed authentication event logging for compliance
        requirements including SOC 2, ISO 27001, and enterprise security standards.
        
        Args:
            event_type: Type of authentication event
            user_id: User identifier for the authentication attempt
            result: Authentication result (success, failure, blocked)
            auth_method: Authentication method used (jwt, oauth, mfa)
            mfa_used: Whether multi-factor authentication was used
            error_code: Error code for failed authentication attempts
            additional_data: Additional context for the authentication event
            severity: Security event severity level
        """
        with self._lock:
            context = SecurityEventContext(
                event_type=event_type,
                severity=severity,
                user_id=user_id,
                error_code=error_code,
                additional_data=additional_data or {}
            )
            
            # Enhance context with authentication-specific data
            context.additional_data.update({
                "auth_result": result,
                "auth_method": auth_method,
                "mfa_used": mfa_used,
                "authentication_event": True
            })
            
            # Log the authentication event
            self._log_security_event(context)
            
            # Update Prometheus metrics
            if self.enable_metrics:
                self.authentication_events_total.labels(
                    event_type=event_type.value,
                    result=result,
                    auth_method=auth_method
                ).inc()
                
                # Update failed authentication rate
                if result == "failure":
                    self.failed_auth_rate.inc()
    
    def log_authorization_event(self,
                              event_type: SecurityEventType,
                              user_id: Optional[str] = None,
                              result: str = "granted",
                              permissions: Optional[List[str]] = None,
                              resource_id: Optional[str] = None,
                              resource_type: Optional[str] = None,
                              error_code: Optional[str] = None,
                              additional_data: Optional[Dict[str, Any]] = None,
                              severity: SecurityEventSeverity = SecurityEventSeverity.INFO) -> None:
        """
        Log comprehensive authorization events with detailed permission context.
        
        This method provides granular authorization event logging for enterprise
        compliance and security monitoring including RBAC decision tracking.
        
        Args:
            event_type: Type of authorization event
            user_id: User identifier for the authorization decision
            result: Authorization result (granted, denied, insufficient)
            permissions: List of permissions evaluated
            resource_id: Identifier of the protected resource
            resource_type: Type of the protected resource
            error_code: Error code for authorization failures
            additional_data: Additional context for the authorization event
            severity: Security event severity level
        """
        with self._lock:
            context = SecurityEventContext(
                event_type=event_type,
                severity=severity,
                user_id=user_id,
                resource_id=resource_id,
                resource_type=resource_type,
                permissions=permissions or [],
                error_code=error_code,
                additional_data=additional_data or {}
            )
            
            # Enhance context with authorization-specific data
            context.additional_data.update({
                "authz_result": result,
                "permission_count": len(permissions or []),
                "authorization_event": True
            })
            
            # Log the authorization event
            self._log_security_event(context)
            
            # Update Prometheus metrics
            if self.enable_metrics:
                permission_type = "resource" if resource_id else "global"
                self.authorization_events_total.labels(
                    event_type=event_type.value,
                    result=result,
                    permission_type=permission_type
                ).inc()
    
    def log_security_violation(self,
                             violation_type: str,
                             severity: SecurityEventSeverity,
                             user_id: Optional[str] = None,
                             source_ip: Optional[str] = None,
                             details: Optional[Dict[str, Any]] = None,
                             automatic_action: Optional[str] = None) -> None:
        """
        Log security violations with comprehensive threat analysis.
        
        This method provides detailed security violation logging for threat
        detection, incident response, and security analytics purposes.
        
        Args:
            violation_type: Type of security violation detected
            severity: Severity level of the security violation
            user_id: User identifier associated with the violation
            source_ip: Source IP address of the violation
            details: Detailed information about the violation
            automatic_action: Automatic action taken in response
        """
        with self._lock:
            context = SecurityEventContext(
                event_type=SecurityEventType.SEC_SUSPICIOUS_ACTIVITY,
                severity=severity,
                user_id=user_id,
                source_ip=source_ip or self._get_client_ip(),
                additional_data=details or {}
            )
            
            # Enhance context with violation-specific data
            context.additional_data.update({
                "violation_type": violation_type,
                "automatic_action": automatic_action,
                "security_violation": True,
                "requires_investigation": severity in [SecurityEventSeverity.HIGH, SecurityEventSeverity.CRITICAL]
            })
            
            # Log the security violation
            self._log_security_event(context)
            
            # Update Prometheus metrics
            if self.enable_metrics:
                self.security_violations_total.labels(
                    violation_type=violation_type,
                    severity=severity.value,
                    source_ip=source_ip or "unknown"
                ).inc()
                
                # Update threat level if critical
                if severity == SecurityEventSeverity.CRITICAL:
                    self.threat_level.state('critical')
    
    def log_rate_limiting_violation(self,
                                  endpoint: str,
                                  user_id: Optional[str] = None,
                                  limit_type: str = "requests_per_minute",
                                  current_rate: Optional[int] = None,
                                  limit_threshold: Optional[int] = None,
                                  action_taken: str = "request_blocked") -> None:
        """
        Log rate limiting violations with detailed metrics.
        
        This method provides comprehensive rate limiting violation logging for
        security monitoring and abuse prevention analytics.
        
        Args:
            endpoint: API endpoint where rate limit was exceeded
            user_id: User identifier for the rate limiting violation
            limit_type: Type of rate limit that was exceeded
            current_rate: Current request rate that triggered the violation
            limit_threshold: Rate limit threshold that was exceeded
            action_taken: Action taken in response to the violation
        """
        with self._lock:
            context = SecurityEventContext(
                event_type=SecurityEventType.SEC_RATE_LIMIT_EXCEEDED,
                severity=SecurityEventSeverity.MEDIUM,
                user_id=user_id,
                endpoint=endpoint,
                additional_data={
                    "limit_type": limit_type,
                    "current_rate": current_rate,
                    "limit_threshold": limit_threshold,
                    "action_taken": action_taken,
                    "rate_limiting_violation": True
                }
            )
            
            # Log the rate limiting violation
            self._log_security_event(context)
            
            # Update Prometheus metrics
            if self.enable_metrics:
                self.rate_limit_violations_total.labels(
                    endpoint=endpoint,
                    user_id=user_id or "anonymous",
                    limit_type=limit_type
                ).inc()
    
    def log_circuit_breaker_event(self,
                                service: str,
                                event: str,
                                state: str,
                                failure_count: Optional[int] = None,
                                threshold: Optional[int] = None,
                                timeout: Optional[int] = None,
                                additional_context: Optional[Dict[str, Any]] = None) -> None:
        """
        Log circuit breaker events for external service monitoring.
        
        This method provides detailed circuit breaker event logging for service
        resilience monitoring and capacity planning purposes.
        
        Args:
            service: Name of the external service
            event: Circuit breaker event (opened, closed, half_open)
            state: Current circuit breaker state
            failure_count: Number of consecutive failures
            threshold: Failure threshold for circuit activation
            timeout: Circuit breaker timeout duration
            additional_context: Additional service context
        """
        with self._lock:
            context = SecurityEventContext(
                event_type=SecurityEventType.EXT_CIRCUIT_BREAKER_OPEN,
                severity=SecurityEventSeverity.HIGH if event == "opened" else SecurityEventSeverity.INFO,
                additional_data=additional_context or {}
            )
            
            # Enhance context with circuit breaker data
            context.additional_data.update({
                "service": service,
                "circuit_event": event,
                "circuit_state": state,
                "failure_count": failure_count,
                "threshold": threshold,
                "timeout_seconds": timeout,
                "circuit_breaker_event": True
            })
            
            # Log the circuit breaker event
            self._log_security_event(context)
            
            # Update Prometheus metrics
            if self.enable_metrics:
                self.circuit_breaker_events_total.labels(
                    service=service,
                    event=event,
                    state=state
                ).inc()
    
    def log_external_service_event(self,
                                 service: str,
                                 event_type: SecurityEventType,
                                 result: str,
                                 response_time: Optional[float] = None,
                                 error_details: Optional[Dict[str, Any]] = None,
                                 severity: SecurityEventSeverity = SecurityEventSeverity.INFO) -> None:
        """
        Log external service integration events.
        
        This method provides comprehensive external service event logging for
        integration monitoring and service dependency analysis.
        
        Args:
            service: Name of the external service
            event_type: Type of external service event
            result: Result of the service call (success, failure, timeout)
            response_time: Response time for the service call
            error_details: Details of any errors that occurred
            severity: Severity level of the event
        """
        with self._lock:
            context = SecurityEventContext(
                event_type=event_type,
                severity=severity,
                additional_data=error_details or {}
            )
            
            # Enhance context with external service data
            context.additional_data.update({
                "service": service,
                "service_result": result,
                "response_time_ms": response_time * 1000 if response_time else None,
                "external_service_event": True
            })
            
            # Log the external service event
            self._log_security_event(context)
    
    def _log_security_event(self, context: SecurityEventContext) -> None:
        """
        Core security event logging with comprehensive context.
        
        This method performs the actual logging with timing metrics and
        comprehensive event processing for enterprise audit requirements.
        
        Args:
            context: Security event context with complete event information
        """
        start_time = datetime.now(timezone.utc)
        
        try:
            # Prepare log event data
            log_data = {
                "event_id": context.event_id,
                "timestamp": context.timestamp.isoformat(),
                "event_type": context.event_type.value,
                "severity": context.severity.value,
                "user_id": context.user_id,
                "session_id": context.session_id,
                "source_ip": context.source_ip,
                "user_agent": context.user_agent,
                "endpoint": context.endpoint,
                "method": context.method,
                "resource_id": context.resource_id,
                "resource_type": context.resource_type,
                "permissions": context.permissions,
                "error_code": context.error_code,
                "error_message": context.error_message,
                "correlation_id": context.correlation_id,
                "transaction_id": context.transaction_id
            }
            
            # Add additional data
            log_data.update(context.additional_data)
            
            # Filter out None values for cleaner logs
            log_data = {k: v for k, v in log_data.items() if v is not None}
            
            # Log based on severity
            if context.severity == SecurityEventSeverity.CRITICAL:
                self.logger.critical("Critical security event", **log_data)
            elif context.severity == SecurityEventSeverity.HIGH:
                self.logger.error("High severity security event", **log_data)
            elif context.severity == SecurityEventSeverity.MEDIUM:
                self.logger.warning("Medium severity security event", **log_data)
            elif context.severity == SecurityEventSeverity.LOW:
                self.logger.info("Low severity security event", **log_data)
            else:
                self.logger.info("Security event", **log_data)
            
            # Update general security metrics
            if self.enable_metrics:
                category = self._get_event_category(context.event_type)
                self.security_events_total.labels(
                    event_type=context.event_type.value,
                    severity=context.severity.value,
                    category=category
                ).inc()
                
                # Record processing time
                processing_time = (datetime.now(timezone.utc) - start_time).total_seconds()
                self.audit_log_duration.labels(
                    event_type=context.event_type.value,
                    processing_stage="complete"
                ).observe(processing_time)
        
        except Exception as e:
            # Fallback logging to prevent audit system failures
            self.logger.error(
                "Failed to log security event",
                event_id=context.event_id,
                error=str(e),
                fallback_logging=True
            )
    
    def _get_client_ip(self) -> Optional[str]:
        """
        Extract client IP address with proxy header support.
        
        This method handles various proxy configurations and header formats
        commonly used in enterprise environments.
        
        Returns:
            Client IP address or None if not available
        """
        try:
            if request:
                # Check for forwarded headers (common in load balancer setups)
                forwarded_for = request.headers.get('X-Forwarded-For')
                if forwarded_for:
                    # Take the first IP in the chain
                    return forwarded_for.split(',')[0].strip()
                
                # Check for real IP header
                real_ip = request.headers.get('X-Real-IP')
                if real_ip:
                    return real_ip.strip()
                
                # Fall back to remote address
                return request.remote_addr
        except RuntimeError:
            # Outside request context
            pass
        
        return None
    
    def _get_compliance_category(self, event_dict: Dict[str, Any]) -> str:
        """
        Determine compliance category for the security event.
        
        Args:
            event_dict: Event dictionary to categorize
            
        Returns:
            Compliance category string
        """
        event_type = event_dict.get('event_type', '')
        
        if 'auth_' in event_type:
            return "authentication_audit"
        elif 'authz_' in event_type:
            return "authorization_audit"
        elif 'sec_' in event_type:
            return "security_violation"
        elif 'ext_' in event_type:
            return "external_service_audit"
        else:
            return "system_audit"
    
    def _assess_threat_level(self, event_dict: Dict[str, Any]) -> str:
        """
        Assess threat level for the security event.
        
        Args:
            event_dict: Event dictionary to assess
            
        Returns:
            Threat level string
        """
        severity = event_dict.get('severity', 'info')
        event_type = event_dict.get('event_type', '')
        
        # Critical threats
        if severity == 'critical' or any(critical in event_type for critical in [
            'brute_force', 'injection', 'xss', 'malicious'
        ]):
            return "critical"
        
        # High threats
        if severity == 'high' or any(high in event_type for high in [
            'violation', 'blocked', 'denied'
        ]):
            return "high"
        
        # Medium threats
        if severity == 'medium' or 'rate_limit' in event_type:
            return "medium"
        
        return "low"
    
    def _get_event_category(self, event_type: SecurityEventType) -> str:
        """
        Get category for a security event type.
        
        Args:
            event_type: Security event type
            
        Returns:
            Event category string
        """
        event_value = event_type.value
        
        if event_value.startswith('auth_'):
            return "authentication"
        elif event_value.startswith('authz_'):
            return "authorization"
        elif event_value.startswith('sec_'):
            return "security_violation"
        elif event_value.startswith('ext_'):
            return "external_service"
        elif event_value.startswith('sys_'):
            return "system"
        else:
            return "unknown"


# Global audit logger instance
_audit_logger: Optional[SecurityAuditLogger] = None


def get_audit_logger() -> SecurityAuditLogger:
    """
    Get the global security audit logger instance.
    
    This function provides access to the singleton audit logger instance,
    creating it if necessary with default configuration.
    
    Returns:
        Global SecurityAuditLogger instance
    """
    global _audit_logger
    
    if _audit_logger is None:
        _audit_logger = SecurityAuditLogger()
    
    return _audit_logger


def configure_audit_logger(logger_name: str = "security.audit",
                         enable_metrics: bool = True,
                         correlation_header: str = "X-Correlation-ID") -> SecurityAuditLogger:
    """
    Configure the global security audit logger with custom settings.
    
    This function configures the global audit logger instance with enterprise
    settings and returns it for application use.
    
    Args:
        logger_name: Logger name for structlog configuration
        enable_metrics: Whether to enable Prometheus metrics
        correlation_header: HTTP header for request correlation
        
    Returns:
        Configured SecurityAuditLogger instance
    """
    global _audit_logger
    
    _audit_logger = SecurityAuditLogger(
        logger_name=logger_name,
        enable_metrics=enable_metrics,
        correlation_header=correlation_header
    )
    
    return _audit_logger


def audit_security_event(event_type: SecurityEventType,
                        severity: SecurityEventSeverity = SecurityEventSeverity.INFO,
                        **kwargs) -> None:
    """
    Convenience function for logging security events.
    
    This function provides a simple interface for logging security events
    without requiring direct access to the audit logger instance.
    
    Args:
        event_type: Type of security event to log
        severity: Severity level of the event
        **kwargs: Additional event context data
    """
    audit_logger = get_audit_logger()
    
    if event_type.value.startswith('auth_'):
        audit_logger.log_authentication_event(event_type, severity=severity, **kwargs)
    elif event_type.value.startswith('authz_'):
        audit_logger.log_authorization_event(event_type, severity=severity, **kwargs)
    else:
        # Create context and log directly
        context = SecurityEventContext(
            event_type=event_type,
            severity=severity,
            additional_data=kwargs
        )
        audit_logger._log_security_event(context)


def audit_exception(exception: SecurityException, 
                   additional_context: Optional[Dict[str, Any]] = None) -> None:
    """
    Audit security exceptions with comprehensive context.
    
    This function provides specialized logging for security exceptions,
    extracting relevant context and categorizing the event appropriately.
    
    Args:
        exception: Security exception to audit
        additional_context: Additional context for the exception
    """
    audit_logger = get_audit_logger()
    
    # Determine event type based on exception
    if isinstance(exception, AuthenticationException):
        event_type = SecurityEventType.AUTH_LOGIN_FAILURE
    elif isinstance(exception, AuthorizationException):
        event_type = SecurityEventType.AUTHZ_PERMISSION_DENIED
    elif isinstance(exception, RateLimitException):
        event_type = SecurityEventType.SEC_RATE_LIMIT_EXCEEDED
    elif isinstance(exception, CircuitBreakerException):
        event_type = SecurityEventType.EXT_CIRCUIT_BREAKER_OPEN
    elif isinstance(exception, ValidationException):
        event_type = SecurityEventType.SEC_INPUT_VALIDATION_FAILURE
    else:
        event_type = SecurityEventType.SEC_SUSPICIOUS_ACTIVITY
    
    # Determine severity
    severity = SecurityEventSeverity.CRITICAL if is_critical_security_error(exception.error_code) else SecurityEventSeverity.HIGH
    
    # Prepare context
    context_data = {
        "error_code": exception.error_code.value,
        "error_message": str(exception),
        "error_id": exception.error_id,
        "exception_type": type(exception).__name__,
        "http_status": exception.http_status
    }
    
    if additional_context:
        context_data.update(additional_context)
    
    context_data.update(exception.metadata)
    
    # Log the exception
    context = SecurityEventContext(
        event_type=event_type,
        severity=severity,
        error_code=exception.error_code.value,
        error_message=str(exception),
        additional_data=context_data
    )
    
    audit_logger._log_security_event(context)


# Decorator for automatic security event auditing
def audit_endpoint(event_type: SecurityEventType = SecurityEventType.SYS_CONFIG_CHANGED,
                  severity: SecurityEventSeverity = SecurityEventSeverity.INFO,
                  log_request: bool = True,
                  log_response: bool = False) -> Callable:
    """
    Decorator for automatic endpoint security auditing.
    
    This decorator automatically logs security events for Flask endpoints,
    capturing request context and performance metrics.
    
    Args:
        event_type: Type of security event to log
        severity: Severity level for the event
        log_request: Whether to log request data
        log_response: Whether to log response data
        
    Returns:
        Decorator function for endpoint auditing
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            audit_logger = get_audit_logger()
            start_time = datetime.now(timezone.utc)
            
            # Prepare request context
            context_data = {}
            if log_request:
                try:
                    context_data.update({
                        "request_method": request.method,
                        "request_url": request.url,
                        "request_args": dict(request.args),
                        "content_type": request.content_type
                    })
                except RuntimeError:
                    pass
            
            try:
                # Execute the endpoint function
                result = func(*args, **kwargs)
                
                # Log successful execution
                execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
                context_data.update({
                    "execution_time_ms": execution_time * 1000,
                    "endpoint_result": "success"
                })
                
                if log_response and hasattr(result, 'status_code'):
                    context_data["response_status"] = result.status_code
                
                context = SecurityEventContext(
                    event_type=event_type,
                    severity=severity,
                    additional_data=context_data
                )
                
                audit_logger._log_security_event(context)
                
                return result
                
            except Exception as e:
                # Log endpoint failure
                execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
                context_data.update({
                    "execution_time_ms": execution_time * 1000,
                    "endpoint_result": "failure",
                    "error_type": type(e).__name__,
                    "error_message": str(e)
                })
                
                context = SecurityEventContext(
                    event_type=SecurityEventType.SYS_CONFIG_CHANGED,
                    severity=SecurityEventSeverity.HIGH,
                    error_message=str(e),
                    additional_data=context_data
                )
                
                audit_logger._log_security_event(context)
                
                # Re-raise the exception
                raise
        
        return wrapper
    return decorator


# Export key components
__all__ = [
    'SecurityEventType',
    'SecurityEventSeverity', 
    'SecurityEventContext',
    'SecurityAuditLogger',
    'get_audit_logger',
    'configure_audit_logger',
    'audit_security_event',
    'audit_exception',
    'audit_endpoint'
]