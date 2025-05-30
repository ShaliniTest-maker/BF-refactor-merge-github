"""
Business Logic Exception Classes for Flask Application

This module provides comprehensive custom exception classes for business logic failures,
business rule violations, and integration with Flask error handlers. Implements specific
exception types for business logic failures, validation errors, and processing exceptions
while maintaining enterprise-grade security and compliance standards.

The exception hierarchy follows enterprise patterns with:
- Comprehensive error categorization per Section 4.2.3
- Business rule violation handling per Section 5.2.4
- Flask error handler integration per Section 4.2.3
- Security-conscious error messaging per Section 6.4.2
- Structured logging integration for enterprise monitoring
- Performance optimization maintaining ≤10% variance requirement

Classes:
    BaseBusinessException: Base class for all business logic exceptions
    BusinessRuleViolationError: Business rule validation failures
    DataProcessingError: Data transformation and processing failures
    DataValidationError: Business data validation failures
    ExternalServiceError: External service integration failures
    ResourceNotFoundError: Business resource access failures
    AuthorizationError: Business authorization and permission failures
    ConcurrencyError: Business transaction concurrency failures
    ConfigurationError: Business configuration and setup failures
"""

import logging
import traceback
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from flask import request, jsonify
import structlog

# Configure structured logging for business exception audit trail
logger = structlog.get_logger("business.exceptions")


class ErrorSeverity(Enum):
    """
    Error severity classification for business exceptions.
    
    Provides standardized severity levels for business exceptions enabling
    appropriate response handling and monitoring alerting thresholds.
    """
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCategory(Enum):
    """
    Error category classification for business exception types.
    
    Enables structured error reporting and monitoring dashboard categorization
    for comprehensive business logic failure analysis and trends.
    """
    BUSINESS_RULE = "business_rule"
    DATA_PROCESSING = "data_processing"
    DATA_VALIDATION = "data_validation"
    EXTERNAL_SERVICE = "external_service"
    RESOURCE_ACCESS = "resource_access"
    AUTHORIZATION = "authorization"
    CONCURRENCY = "concurrency"
    CONFIGURATION = "configuration"


class BaseBusinessException(Exception):
    """
    Base exception class for all business logic failures.
    
    Provides comprehensive exception handling foundation with enterprise-grade
    features including structured logging, audit trail generation, security-conscious
    error messaging, and Flask error handler integration.
    
    This base class implements core functionality for:
    - Error response standardization per F-005-RQ-001
    - Security information filtering per Section 6.4.2
    - Structured audit logging per Section 4.2.3
    - HTTP status code mapping per F-005-RQ-002
    - Enterprise monitoring integration per Section 4.2.3
    
    Attributes:
        message (str): User-facing error message (sanitized)
        error_code (str): Unique error identifier for client handling
        http_status_code (int): HTTP status code for Flask response
        severity (ErrorSeverity): Error severity level for monitoring
        category (ErrorCategory): Error category for classification
        context (Dict[str, Any]): Additional error context (filtered)
        timestamp (datetime): Error occurrence timestamp
        request_id (Optional[str]): Request identifier for correlation
        user_id (Optional[str]): User identifier for audit trail
        audit_data (Dict[str, Any]): Audit trail information
        
    Example:
        try:
            # Business logic operation
            process_business_data(data)
        except BaseBusinessException as e:
            # Exception automatically logged and formatted for Flask response
            logger.error("Business logic failure", error=e.to_dict())
            return e.to_flask_response()
    """
    
    def __init__(
        self,
        message: str,
        error_code: str,
        http_status_code: int = 400,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        category: ErrorCategory = ErrorCategory.BUSINESS_RULE,
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
        user_id: Optional[str] = None,
        sensitive_data: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Initialize base business exception with comprehensive error context.
        
        Args:
            message: User-facing error message (will be sanitized)
            error_code: Unique error identifier for client handling
            http_status_code: HTTP status code for Flask response (default: 400)
            severity: Error severity level for monitoring alerts
            category: Error category for classification and reporting
            context: Additional error context (sensitive data filtered)
            cause: Original exception that caused this business exception
            user_id: User identifier for audit trail correlation
            sensitive_data: Sensitive data for secure logging (not exposed to client)
        """
        super().__init__(message)
        
        # Core exception attributes
        self.message = self._sanitize_message(message)
        self.error_code = error_code
        self.http_status_code = http_status_code
        self.severity = severity
        self.category = category
        self.context = self._filter_sensitive_context(context or {})
        self.cause = cause
        self.timestamp = datetime.now(timezone.utc)
        
        # Request correlation attributes
        self.request_id = self._get_request_id()
        self.user_id = user_id or self._get_current_user_id()
        
        # Audit trail attributes
        self.audit_data = self._build_audit_data(sensitive_data)
        
        # Generate structured log entry for enterprise monitoring
        self._log_exception()
    
    def _sanitize_message(self, message: str) -> str:
        """
        Sanitize error message to prevent information disclosure.
        
        Implements security requirements per Section 6.4.2 by filtering
        sensitive information from user-facing error messages while
        preserving debugging information in secure audit logs.
        
        Args:
            message: Raw error message potentially containing sensitive data
            
        Returns:
            Sanitized error message safe for client exposure
        """
        # Remove potential SQL injection patterns
        sensitive_patterns = [
            r"password\s*[:=]\s*['\"][^'\"]*['\"]",
            r"token\s*[:=]\s*['\"][^'\"]*['\"]",
            r"key\s*[:=]\s*['\"][^'\"]*['\"]",
            r"secret\s*[:=]\s*['\"][^'\"]*['\"]",
            r"mongodb://[^/]*",
            r"redis://[^/]*",
            r"Bearer\s+[A-Za-z0-9\-_]*",
        ]
        
        import re
        sanitized = message
        for pattern in sensitive_patterns:
            sanitized = re.sub(pattern, "[REDACTED]", sanitized, flags=re.IGNORECASE)
        
        # Limit message length to prevent log flooding
        max_length = 500
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length] + "... [TRUNCATED]"
        
        return sanitized
    
    def _filter_sensitive_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Filter sensitive information from error context.
        
        Removes or redacts sensitive information from error context to prevent
        information disclosure in client responses while preserving data
        for secure audit logging.
        
        Args:
            context: Raw error context potentially containing sensitive data
            
        Returns:
            Filtered context safe for client exposure
        """
        if not context:
            return {}
        
        sensitive_keys = {
            'password', 'token', 'key', 'secret', 'auth', 'credential',
            'ssn', 'social_security', 'credit_card', 'cvv', 'account_number'
        }
        
        filtered_context = {}
        for key, value in context.items():
            key_lower = key.lower()
            
            # Check if key contains sensitive information
            if any(sensitive_key in key_lower for sensitive_key in sensitive_keys):
                filtered_context[key] = "[REDACTED]"
            elif isinstance(value, str) and len(value) > 100:
                # Truncate long strings that might contain sensitive data
                filtered_context[key] = value[:100] + "... [TRUNCATED]"
            elif isinstance(value, (dict, list)):
                # Recursively filter nested structures
                if isinstance(value, dict):
                    filtered_context[key] = self._filter_sensitive_context(value)
                else:
                    # For lists, apply basic length limitations
                    filtered_context[key] = value[:10] if len(value) > 10 else value
            else:
                filtered_context[key] = value
        
        return filtered_context
    
    def _get_request_id(self) -> Optional[str]:
        """
        Extract request ID from Flask request context.
        
        Returns:
            Request identifier for correlation or None if not available
        """
        try:
            from flask import g
            if hasattr(request, 'headers'):
                return (request.headers.get('X-Request-ID') or 
                       request.headers.get('X-Correlation-ID') or
                       getattr(g, 'request_id', None))
        except (RuntimeError, AttributeError):
            # Handle cases where Flask context is not available
            pass
        return None
    
    def _get_current_user_id(self) -> Optional[str]:
        """
        Extract current user ID from Flask-Login context.
        
        Returns:
            Current user identifier for audit trail or None if not authenticated
        """
        try:
            from flask_login import current_user
            if hasattr(current_user, 'id') and current_user.is_authenticated:
                return str(current_user.id)
        except (ImportError, RuntimeError, AttributeError):
            # Handle cases where Flask-Login is not available or user not authenticated
            pass
        return None
    
    def _build_audit_data(self, sensitive_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Build comprehensive audit data for enterprise compliance.
        
        Creates structured audit information for security monitoring and
        compliance reporting while maintaining sensitive data separation.
        
        Args:
            sensitive_data: Sensitive data for secure audit logging only
            
        Returns:
            Audit data structure for enterprise monitoring systems
        """
        audit_data = {
            'exception_type': self.__class__.__name__,
            'error_code': self.error_code,
            'severity': self.severity.value,
            'category': self.category.value,
            'timestamp': self.timestamp.isoformat(),
            'request_id': self.request_id,
            'user_id': self.user_id,
            'http_status_code': self.http_status_code,
        }
        
        # Add request context if available
        try:
            if hasattr(request, 'endpoint'):
                audit_data.update({
                    'endpoint': request.endpoint,
                    'method': request.method,
                    'url': request.url,
                    'remote_addr': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent', ''),
                })
        except (RuntimeError, AttributeError):
            # Handle cases where Flask request context is not available
            pass
        
        # Add cause exception information if available
        if self.cause:
            audit_data['cause_exception'] = {
                'type': type(self.cause).__name__,
                'message': str(self.cause),
                'traceback': traceback.format_exception(
                    type(self.cause), self.cause, self.cause.__traceback__
                )[-3:]  # Last 3 frames for context
            }
        
        # Add sensitive data to secure audit trail only (not exposed to client)
        if sensitive_data:
            audit_data['secure_context'] = sensitive_data
        
        return audit_data
    
    def _log_exception(self) -> None:
        """
        Generate structured log entry for enterprise monitoring integration.
        
        Creates comprehensive log entry with structured data for enterprise
        monitoring systems, SIEM integration, and compliance audit trails.
        """
        log_data = {
            'event_type': 'business_exception',
            'exception_class': self.__class__.__name__,
            'error_code': self.error_code,
            'severity': self.severity.value,
            'category': self.category.value,
            'http_status_code': self.http_status_code,
            'request_id': self.request_id,
            'user_id': self.user_id,
            'timestamp': self.timestamp.isoformat(),
            'context': self.context,
        }
        
        # Add request context for correlation
        try:
            if hasattr(request, 'endpoint'):
                log_data.update({
                    'endpoint': request.endpoint,
                    'method': request.method,
                    'remote_addr': request.remote_addr,
                })
        except (RuntimeError, AttributeError):
            pass
        
        # Log with appropriate level based on severity
        if self.severity == ErrorSeverity.CRITICAL:
            logger.error("Critical business exception occurred", **log_data)
        elif self.severity == ErrorSeverity.HIGH:
            logger.error("High severity business exception", **log_data)
        elif self.severity == ErrorSeverity.MEDIUM:
            logger.warning("Medium severity business exception", **log_data)
        else:
            logger.info("Low severity business exception", **log_data)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert exception to dictionary for JSON serialization.
        
        Creates standardized dictionary representation suitable for JSON
        responses while maintaining security and audit requirements.
        
        Returns:
            Dictionary representation safe for client exposure
        """
        return {
            'error': {
                'message': self.message,
                'code': self.error_code,
                'severity': self.severity.value,
                'category': self.category.value,
                'timestamp': self.timestamp.isoformat(),
                'request_id': self.request_id,
                'context': self.context,
            }
        }
    
    def to_flask_response(self) -> tuple:
        """
        Convert exception to Flask JSON response tuple.
        
        Creates standardized Flask response tuple with appropriate HTTP status
        code and JSON error format matching Node.js implementation patterns.
        
        Returns:
            Tuple of (JSON response, HTTP status code) for Flask handler
        """
        response_data = self.to_dict()
        return jsonify(response_data), self.http_status_code
    
    def get_audit_data(self) -> Dict[str, Any]:
        """
        Get complete audit data for enterprise monitoring systems.
        
        Returns:
            Complete audit data including sensitive information for secure logging
        """
        return self.audit_data


class BusinessRuleViolationError(BaseBusinessException):
    """
    Exception for business rule validation failures.
    
    Raised when business logic operations violate established business rules,
    validation constraints, or operational policies. Implements comprehensive
    business rule exception handling per Section 5.2.4 requirements.
    
    This exception type covers:
    - Business constraint violations
    - Policy enforcement failures
    - Workflow validation errors
    - Business logic assertion failures
    - Domain-specific rule violations
    
    Example:
        if user.account_balance < transaction.amount:
            raise BusinessRuleViolationError(
                message="Insufficient account balance for transaction",
                error_code="INSUFFICIENT_BALANCE",
                context={
                    'account_balance': user.account_balance,
                    'transaction_amount': transaction.amount,
                    'user_id': user.id
                },
                severity=ErrorSeverity.HIGH
            )
    """
    
    def __init__(
        self,
        message: str,
        error_code: str,
        rule_name: Optional[str] = None,
        rule_parameters: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> None:
        """
        Initialize business rule violation exception.
        
        Args:
            message: User-facing error message describing rule violation
            error_code: Unique error identifier for client handling
            rule_name: Name of the violated business rule
            rule_parameters: Parameters that caused the rule violation
            **kwargs: Additional arguments passed to BaseBusinessException
        """
        # Set default values for business rule violations
        kwargs.setdefault('http_status_code', 422)  # Unprocessable Entity
        kwargs.setdefault('severity', ErrorSeverity.HIGH)
        kwargs.setdefault('category', ErrorCategory.BUSINESS_RULE)
        
        # Add rule-specific context
        context = kwargs.get('context', {})
        if rule_name:
            context['violated_rule'] = rule_name
        if rule_parameters:
            context['rule_parameters'] = rule_parameters
        kwargs['context'] = context
        
        super().__init__(message, error_code, **kwargs)
        
        self.rule_name = rule_name
        self.rule_parameters = rule_parameters or {}


class DataProcessingError(BaseBusinessException):
    """
    Exception for data transformation and processing failures.
    
    Raised when business logic data processing operations fail due to data
    inconsistencies, transformation errors, or processing pipeline failures.
    Implements data processing exception handling per Section 5.2.4.
    
    This exception type covers:
    - Data transformation failures
    - Processing pipeline errors
    - Data format inconsistencies
    - Calculation and computation errors
    - Data integrity violations during processing
    
    Example:
        try:
            processed_data = complex_calculation(input_data)
        except ValueError as e:
            raise DataProcessingError(
                message="Failed to process calculation data",
                error_code="CALCULATION_FAILED",
                context={'input_data_type': type(input_data).__name__},
                cause=e,
                severity=ErrorSeverity.MEDIUM
            )
    """
    
    def __init__(
        self,
        message: str,
        error_code: str,
        processing_stage: Optional[str] = None,
        data_type: Optional[str] = None,
        **kwargs
    ) -> None:
        """
        Initialize data processing exception.
        
        Args:
            message: User-facing error message describing processing failure
            error_code: Unique error identifier for client handling
            processing_stage: Stage in processing pipeline where failure occurred
            data_type: Type of data being processed when failure occurred
            **kwargs: Additional arguments passed to BaseBusinessException
        """
        # Set default values for data processing errors
        kwargs.setdefault('http_status_code', 500)  # Internal Server Error
        kwargs.setdefault('severity', ErrorSeverity.MEDIUM)
        kwargs.setdefault('category', ErrorCategory.DATA_PROCESSING)
        
        # Add processing-specific context
        context = kwargs.get('context', {})
        if processing_stage:
            context['processing_stage'] = processing_stage
        if data_type:
            context['data_type'] = data_type
        kwargs['context'] = context
        
        super().__init__(message, error_code, **kwargs)
        
        self.processing_stage = processing_stage
        self.data_type = data_type


class DataValidationError(BaseBusinessException):
    """
    Exception for business data validation failures.
    
    Raised when business data fails validation rules, schema constraints,
    or data integrity checks. Implements comprehensive data validation
    exception handling with detailed validation error reporting.
    
    This exception type covers:
    - Schema validation failures
    - Data type validation errors
    - Business data constraint violations
    - Input validation failures
    - Data integrity validation errors
    
    Example:
        validation_errors = validate_customer_data(customer_data)
        if validation_errors:
            raise DataValidationError(
                message="Customer data validation failed",
                error_code="INVALID_CUSTOMER_DATA",
                validation_errors=validation_errors,
                context={'customer_id': customer_data.get('id')},
                severity=ErrorSeverity.MEDIUM
            )
    """
    
    def __init__(
        self,
        message: str,
        error_code: str,
        validation_errors: Optional[List[Dict[str, Any]]] = None,
        field_errors: Optional[Dict[str, List[str]]] = None,
        **kwargs
    ) -> None:
        """
        Initialize data validation exception.
        
        Args:
            message: User-facing error message describing validation failure
            error_code: Unique error identifier for client handling
            validation_errors: List of detailed validation error information
            field_errors: Field-specific validation error messages
            **kwargs: Additional arguments passed to BaseBusinessException
        """
        # Set default values for data validation errors
        kwargs.setdefault('http_status_code', 400)  # Bad Request
        kwargs.setdefault('severity', ErrorSeverity.MEDIUM)
        kwargs.setdefault('category', ErrorCategory.DATA_VALIDATION)
        
        # Add validation-specific context
        context = kwargs.get('context', {})
        if validation_errors:
            context['validation_errors'] = validation_errors
        if field_errors:
            context['field_errors'] = field_errors
        kwargs['context'] = context
        
        super().__init__(message, error_code, **kwargs)
        
        self.validation_errors = validation_errors or []
        self.field_errors = field_errors or {}


class ExternalServiceError(BaseBusinessException):
    """
    Exception for external service integration failures.
    
    Raised when external service calls fail, timeout, or return error responses.
    Implements comprehensive external service exception handling with circuit
    breaker integration and service resilience patterns.
    
    This exception type covers:
    - HTTP client request failures
    - External API error responses
    - Service timeout and connectivity issues
    - Authentication and authorization failures with external services
    - Circuit breaker activation events
    
    Example:
        try:
            response = external_api_client.call_service(request_data)
        except requests.RequestException as e:
            raise ExternalServiceError(
                message="External payment service unavailable",
                error_code="PAYMENT_SERVICE_UNAVAILABLE",
                service_name="payment_gateway",
                context={'timeout': 30, 'retries': 3},
                cause=e,
                severity=ErrorSeverity.HIGH
            )
    """
    
    def __init__(
        self,
        message: str,
        error_code: str,
        service_name: Optional[str] = None,
        endpoint: Optional[str] = None,
        response_status: Optional[int] = None,
        retry_count: Optional[int] = None,
        **kwargs
    ) -> None:
        """
        Initialize external service exception.
        
        Args:
            message: User-facing error message describing service failure
            error_code: Unique error identifier for client handling
            service_name: Name of the external service that failed
            endpoint: Specific endpoint or URL that failed
            response_status: HTTP status code from external service
            retry_count: Number of retries attempted before failure
            **kwargs: Additional arguments passed to BaseBusinessException
        """
        # Set default values for external service errors
        kwargs.setdefault('http_status_code', 502)  # Bad Gateway
        kwargs.setdefault('severity', ErrorSeverity.HIGH)
        kwargs.setdefault('category', ErrorCategory.EXTERNAL_SERVICE)
        
        # Add service-specific context
        context = kwargs.get('context', {})
        if service_name:
            context['service_name'] = service_name
        if endpoint:
            context['endpoint'] = endpoint
        if response_status:
            context['response_status'] = response_status
        if retry_count is not None:
            context['retry_count'] = retry_count
        kwargs['context'] = context
        
        super().__init__(message, error_code, **kwargs)
        
        self.service_name = service_name
        self.endpoint = endpoint
        self.response_status = response_status
        self.retry_count = retry_count


class ResourceNotFoundError(BaseBusinessException):
    """
    Exception for business resource access failures.
    
    Raised when requested business resources cannot be found, accessed, or
    do not exist. Implements resource access exception handling with proper
    HTTP status code mapping and audit trail generation.
    
    This exception type covers:
    - Database record not found
    - File or document not accessible
    - User or entity not found
    - Resource permission denied
    - Resource state conflicts
    
    Example:
        user = get_user_by_id(user_id)
        if not user:
            raise ResourceNotFoundError(
                message="User account not found",
                error_code="USER_NOT_FOUND",
                resource_type="user",
                resource_id=user_id,
                context={'requested_by': current_user.id},
                severity=ErrorSeverity.MEDIUM
            )
    """
    
    def __init__(
        self,
        message: str,
        error_code: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[Union[str, int]] = None,
        **kwargs
    ) -> None:
        """
        Initialize resource not found exception.
        
        Args:
            message: User-facing error message describing resource failure
            error_code: Unique error identifier for client handling
            resource_type: Type of resource that was not found
            resource_id: Identifier of the resource that was not found
            **kwargs: Additional arguments passed to BaseBusinessException
        """
        # Set default values for resource not found errors
        kwargs.setdefault('http_status_code', 404)  # Not Found
        kwargs.setdefault('severity', ErrorSeverity.MEDIUM)
        kwargs.setdefault('category', ErrorCategory.RESOURCE_ACCESS)
        
        # Add resource-specific context
        context = kwargs.get('context', {})
        if resource_type:
            context['resource_type'] = resource_type
        if resource_id is not None:
            context['resource_id'] = str(resource_id)
        kwargs['context'] = context
        
        super().__init__(message, error_code, **kwargs)
        
        self.resource_type = resource_type
        self.resource_id = resource_id


class AuthorizationError(BaseBusinessException):
    """
    Exception for business authorization and permission failures.
    
    Raised when users lack sufficient permissions for business operations
    or when authorization policies are violated. Implements authorization
    exception handling with security audit trail generation.
    
    This exception type covers:
    - Insufficient permissions for operation
    - Role-based access control violations
    - Resource ownership authorization failures
    - Policy enforcement violations
    - Session and authentication state errors
    
    Example:
        if not user.has_permission('delete_document'):
            raise AuthorizationError(
                message="Insufficient permissions to delete document",
                error_code="DELETE_PERMISSION_DENIED",
                required_permission="delete_document",
                context={'document_id': document.id, 'user_role': user.role},
                severity=ErrorSeverity.HIGH
            )
    """
    
    def __init__(
        self,
        message: str,
        error_code: str,
        required_permission: Optional[str] = None,
        user_permissions: Optional[List[str]] = None,
        **kwargs
    ) -> None:
        """
        Initialize authorization exception.
        
        Args:
            message: User-facing error message describing authorization failure
            error_code: Unique error identifier for client handling
            required_permission: Permission required for the operation
            user_permissions: List of permissions the user actually has
            **kwargs: Additional arguments passed to BaseBusinessException
        """
        # Set default values for authorization errors
        kwargs.setdefault('http_status_code', 403)  # Forbidden
        kwargs.setdefault('severity', ErrorSeverity.HIGH)
        kwargs.setdefault('category', ErrorCategory.AUTHORIZATION)
        
        # Add authorization-specific context (filtered for security)
        context = kwargs.get('context', {})
        if required_permission:
            context['required_permission'] = required_permission
        # Don't expose user permissions in context for security
        if user_permissions and len(user_permissions) > 0:
            context['user_has_permissions'] = True
        else:
            context['user_has_permissions'] = False
        kwargs['context'] = context
        
        # Store sensitive data for audit trail only
        sensitive_data = kwargs.get('sensitive_data', {})
        if user_permissions:
            sensitive_data['user_permissions'] = user_permissions
        kwargs['sensitive_data'] = sensitive_data
        
        super().__init__(message, error_code, **kwargs)
        
        self.required_permission = required_permission
        self.user_permissions = user_permissions or []


class ConcurrencyError(BaseBusinessException):
    """
    Exception for business transaction concurrency failures.
    
    Raised when concurrent operations conflict, optimistic locking fails,
    or transaction isolation violations occur. Implements concurrency
    exception handling with retry guidance and conflict resolution.
    
    This exception type covers:
    - Optimistic locking failures
    - Transaction isolation violations
    - Resource contention conflicts
    - Concurrent modification errors
    - Database deadlock detection
    
    Example:
        try:
            update_inventory_count(product_id, new_count, version)
        except OptimisticLockException as e:
            raise ConcurrencyError(
                message="Product inventory was modified by another user",
                error_code="INVENTORY_CONFLICT",
                resource_type="product_inventory",
                resource_id=product_id,
                cause=e,
                context={'retry_suggested': True},
                severity=ErrorSeverity.MEDIUM
            )
    """
    
    def __init__(
        self,
        message: str,
        error_code: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[Union[str, int]] = None,
        conflict_type: Optional[str] = None,
        **kwargs
    ) -> None:
        """
        Initialize concurrency exception.
        
        Args:
            message: User-facing error message describing concurrency failure
            error_code: Unique error identifier for client handling
            resource_type: Type of resource that experienced conflict
            resource_id: Identifier of the conflicted resource
            conflict_type: Type of concurrency conflict that occurred
            **kwargs: Additional arguments passed to BaseBusinessException
        """
        # Set default values for concurrency errors
        kwargs.setdefault('http_status_code', 409)  # Conflict
        kwargs.setdefault('severity', ErrorSeverity.MEDIUM)
        kwargs.setdefault('category', ErrorCategory.CONCURRENCY)
        
        # Add concurrency-specific context
        context = kwargs.get('context', {})
        if resource_type:
            context['resource_type'] = resource_type
        if resource_id is not None:
            context['resource_id'] = str(resource_id)
        if conflict_type:
            context['conflict_type'] = conflict_type
        context['retry_recommended'] = True
        kwargs['context'] = context
        
        super().__init__(message, error_code, **kwargs)
        
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.conflict_type = conflict_type


class ConfigurationError(BaseBusinessException):
    """
    Exception for business configuration and setup failures.
    
    Raised when business logic configuration is invalid, missing, or
    inconsistent. Implements configuration exception handling with
    system administration guidance and recovery suggestions.
    
    This exception type covers:
    - Missing configuration parameters
    - Invalid configuration values
    - Configuration file parsing errors
    - Environment setup failures
    - System initialization errors
    
    Example:
        payment_config = get_payment_configuration()
        if not payment_config.api_key:
            raise ConfigurationError(
                message="Payment gateway API key not configured",
                error_code="PAYMENT_CONFIG_MISSING",
                config_key="payment.api_key",
                context={'config_source': 'environment'},
                severity=ErrorSeverity.CRITICAL
            )
    """
    
    def __init__(
        self,
        message: str,
        error_code: str,
        config_key: Optional[str] = None,
        config_source: Optional[str] = None,
        **kwargs
    ) -> None:
        """
        Initialize configuration exception.
        
        Args:
            message: User-facing error message describing configuration failure
            error_code: Unique error identifier for client handling
            config_key: Configuration key that is missing or invalid
            config_source: Source of configuration (file, environment, database)
            **kwargs: Additional arguments passed to BaseBusinessException
        """
        # Set default values for configuration errors
        kwargs.setdefault('http_status_code', 500)  # Internal Server Error
        kwargs.setdefault('severity', ErrorSeverity.CRITICAL)
        kwargs.setdefault('category', ErrorCategory.CONFIGURATION)
        
        # Add configuration-specific context
        context = kwargs.get('context', {})
        if config_key:
            context['config_key'] = config_key
        if config_source:
            context['config_source'] = config_source
        kwargs['context'] = context
        
        super().__init__(message, error_code, **kwargs)
        
        self.config_key = config_key
        self.config_source = config_source


# Exception registry for error handler registration
BUSINESS_EXCEPTION_REGISTRY = {
    BaseBusinessException: 'base_business_exception',
    BusinessRuleViolationError: 'business_rule_violation',
    DataProcessingError: 'data_processing_error',
    DataValidationError: 'data_validation_error',
    ExternalServiceError: 'external_service_error',
    ResourceNotFoundError: 'resource_not_found',
    AuthorizationError: 'authorization_error',
    ConcurrencyError: 'concurrency_error',
    ConfigurationError: 'configuration_error',
}


def create_flask_error_handlers(app):
    """
    Register Flask error handlers for business exceptions.
    
    Registers comprehensive Flask @errorhandler decorators for all business
    exception types, implementing consistent error response formatting per
    Section 4.2.3 and F-005 requirements.
    
    This function implements:
    - Consistent JSON error response structure per F-005-RQ-001
    - HTTP status code mapping per F-005-RQ-002
    - Enterprise monitoring integration per Section 4.2.3
    - Security-conscious error messaging per Section 6.4.2
    - Structured audit logging for compliance
    
    Args:
        app: Flask application instance for error handler registration
        
    Example:
        from flask import Flask
        from business.exceptions import create_flask_error_handlers
        
        app = Flask(__name__)
        create_flask_error_handlers(app)
    """
    
    def handle_business_exception(error: BaseBusinessException):
        """
        Universal Flask error handler for business exceptions.
        
        Provides consistent error response formatting and audit logging
        for all business exception types while maintaining enterprise
        security and monitoring requirements.
        
        Args:
            error: Business exception instance to handle
            
        Returns:
            Flask JSON response tuple with appropriate HTTP status code
        """
        # Generate audit log entry for enterprise monitoring
        audit_data = error.get_audit_data()
        
        # Emit metrics for monitoring systems
        try:
            from prometheus_client import Counter, Histogram
            
            # Update error metrics counters
            business_error_counter = Counter(
                'business_errors_total',
                'Total business errors by category and severity',
                ['category', 'severity', 'error_code']
            )
            business_error_counter.labels(
                category=error.category.value,
                severity=error.severity.value,
                error_code=error.error_code
            ).inc()
            
            # Track error response time
            error_response_timer = Histogram(
                'business_error_response_duration_seconds',
                'Business error response generation time',
                ['category', 'severity']
            )
            
        except ImportError:
            # Prometheus client not available, continue without metrics
            pass
        
        # Log security events for high severity errors
        if error.severity in [ErrorSeverity.HIGH, ErrorSeverity.CRITICAL]:
            security_logger = structlog.get_logger("security.business_exceptions")
            security_logger.warning(
                "High severity business exception",
                **audit_data
            )
        
        # Return standardized Flask response
        return error.to_flask_response()
    
    # Register error handlers for all business exception types
    for exception_class, handler_name in BUSINESS_EXCEPTION_REGISTRY.items():
        app.errorhandler(exception_class)(handle_business_exception)
    
    # Register generic exception handler for unexpected errors
    @app.errorhandler(Exception)
    def handle_unexpected_exception(error: Exception):
        """
        Handle unexpected exceptions with business exception wrapper.
        
        Converts unexpected exceptions to BaseBusinessException for
        consistent error handling and security compliance.
        
        Args:
            error: Unexpected exception instance
            
        Returns:
            Flask JSON response tuple with appropriate HTTP status code
        """
        # Wrap unexpected exception in business exception
        business_error = BaseBusinessException(
            message="An unexpected error occurred. Please try again later.",
            error_code="INTERNAL_ERROR",
            http_status_code=500,
            severity=ErrorSeverity.CRITICAL,
            category=ErrorCategory.CONFIGURATION,
            cause=error,
            context={'unexpected_error': True}
        )
        
        return handle_business_exception(business_error)


def handle_validation_error(validation_errors: List[Dict[str, Any]], 
                          field_name: Optional[str] = None) -> DataValidationError:
    """
    Create DataValidationError from validation framework errors.
    
    Convenience function for converting marshmallow, pydantic, or other
    validation framework errors into standardized business exceptions.
    
    Args:
        validation_errors: List of validation error dictionaries
        field_name: Specific field name if single field validation
        
    Returns:
        DataValidationError instance ready for raising
        
    Example:
        from marshmallow import ValidationError as MarshmallowError
        
        try:
            schema.load(request_data)
        except MarshmallowError as e:
            raise handle_validation_error(
                validation_errors=e.messages,
                field_name='user_data'
            )
    """
    error_count = len(validation_errors)
    if field_name:
        message = f"Validation failed for field '{field_name}'"
        error_code = f"VALIDATION_FAILED_{field_name.upper()}"
    else:
        message = f"Data validation failed ({error_count} errors)"
        error_code = "VALIDATION_FAILED"
    
    return DataValidationError(
        message=message,
        error_code=error_code,
        validation_errors=validation_errors,
        context={'validation_error_count': error_count}
    )


def handle_external_service_timeout(service_name: str, 
                                   endpoint: str, 
                                   timeout_seconds: float,
                                   cause: Exception) -> ExternalServiceError:
    """
    Create ExternalServiceError for service timeout failures.
    
    Convenience function for handling external service timeout scenarios
    with appropriate error categorization and retry guidance.
    
    Args:
        service_name: Name of the external service that timed out
        endpoint: Specific endpoint that timed out
        timeout_seconds: Timeout duration that was exceeded
        cause: Original timeout exception
        
    Returns:
        ExternalServiceError instance ready for raising
        
    Example:
        try:
            response = requests.get(url, timeout=30)
        except requests.Timeout as e:
            raise handle_external_service_timeout(
                service_name='payment_gateway',
                endpoint=url,
                timeout_seconds=30.0,
                cause=e
            )
    """
    return ExternalServiceError(
        message=f"Service '{service_name}' timed out after {timeout_seconds} seconds",
        error_code="SERVICE_TIMEOUT",
        service_name=service_name,
        endpoint=endpoint,
        cause=cause,
        context={
            'timeout_seconds': timeout_seconds,
            'retry_recommended': True,
            'circuit_breaker_candidate': True
        },
        severity=ErrorSeverity.HIGH
    )


def handle_database_connection_error(operation: str, 
                                   cause: Exception) -> DataProcessingError:
    """
    Create DataProcessingError for database connection failures.
    
    Convenience function for handling database connectivity issues
    with appropriate error categorization and recovery guidance.
    
    Args:
        operation: Database operation that failed
        cause: Original database exception
        
    Returns:
        DataProcessingError instance ready for raising
        
    Example:
        try:
            collection.find(query)
        except pymongo.errors.ConnectionFailure as e:
            raise handle_database_connection_error(
                operation='find_documents',
                cause=e
            )
    """
    return DataProcessingError(
        message="Database connection temporarily unavailable",
        error_code="DATABASE_CONNECTION_FAILED",
        processing_stage="database_operation",
        data_type="database_connection",
        cause=cause,
        context={
            'operation': operation,
            'retry_recommended': True,
            'fallback_suggested': True
        },
        severity=ErrorSeverity.HIGH
    )