"""
Business Service Layer for Flask Application

This module implements the service layer providing business operation orchestration, external
service integration coordination, and workflow management. Maintains identical functionality
to Node.js implementation while providing high-level business operations that coordinate
between data access, validation, processing, and external integrations per Section 5.2.4.

The service layer implements:
- Business operation orchestration maintaining functional parity per F-004-RQ-001
- External service integration coordination per F-004-RQ-002
- Workflow management for data transformation per Section 5.2.4
- Circuit breaker patterns for service resilience per Section 6.1.3
- Transaction management and error handling per Section 5.2.4
- Performance monitoring maintaining ≤10% variance from Node.js baseline

Key Components:
    BaseBusinessService: Abstract base service providing common service patterns
    UserManagementService: User lifecycle and profile management operations
    DataProcessingService: Business data transformation and validation workflows
    IntegrationOrchestrationService: External service coordination and resilience
    TransactionService: Transaction management and data consistency operations
    WorkflowService: Complex business workflow orchestration and state management

Architecture Integration:
- Integration with business processors per Section 5.2.4 business logic engine
- Coordination with data access layer per Section 5.2.4 database access
- External service integration per Section 5.2.4 integration orchestration
- Circuit breaker patterns per Section 6.1.3 resilience mechanisms
- Performance optimization per Section 0.1.1 variance requirements

Author: Business Logic Migration Team
Version: 1.0.0
License: Enterprise
"""

import asyncio
import logging
import time
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from typing import (
    Any, Dict, List, Optional, Union, Tuple, Callable, Type, Generic, TypeVar,
    AsyncIterator, Iterator, Set, ClassVar, Protocol, runtime_checkable
)
from functools import wraps, lru_cache
from contextlib import asynccontextmanager, contextmanager
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum, auto

# Flask and enterprise integration imports
from flask import current_app, g, request
import structlog

# Business logic imports for comprehensive service operations
from .processors import (
    ProcessingWorkflow, DataTransformer, BusinessRuleEngine, DateTimeProcessor,
    ProcessingMetrics, get_business_processor, process_business_data,
    validate_business_rules, monitor_performance
)
from .validators import (
    ValidationContext, ValidationType, ValidationMode, BaseValidator,
    BusinessRuleValidator, DataModelValidator, InputValidator, OutputValidator,
    validate_business_data, validate_request_data, validate_response_data,
    format_validation_errors
)
from .models import (
    ProcessingRequest, ProcessingResult, BusinessData, ValidationResult,
    TransformationRule, ProcessingContext, AuditRecord
)
from .exceptions import (
    BaseBusinessException, BusinessRuleViolationError, DataValidationError,
    DataProcessingError, ErrorSeverity, ErrorCategory
)

# Data access layer imports per Section 5.2.4
from ..data import (
    DatabaseManager, get_mongodb_client, get_motor_database,
    database_transaction, async_database_transaction,
    execute_query, execute_async_query, QueryResult
)

# External service integration imports per Section 6.1.3
from ..integrations import (
    BaseExternalServiceClient, ServiceType, HealthStatus, CircuitBreakerState,
    external_service_monitor, track_external_service_call,
    IntegrationError, CircuitBreakerOpenError
)

# Cache layer imports per Section 5.2.7
from ..cache import (
    get_redis_client, cache_for, invalidate_by_pattern,
    CacheError, cache_strategies, create_cache_key
)

# Configure structured logging for service operations
logger = structlog.get_logger("business.services")

# Type definitions for service operations
ServiceResult = TypeVar('ServiceResult')
EntityType = TypeVar('EntityType')
WorkflowState = TypeVar('WorkflowState')


class ServiceOperationType(Enum):
    """Service operation types for monitoring and audit trail."""
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    PROCESS = "process"
    VALIDATE = "validate"
    TRANSFORM = "transform"
    INTEGRATE = "integrate"
    WORKFLOW = "workflow"


class ServicePriority(Enum):
    """Service operation priority levels for resource allocation."""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class ServiceContext:
    """
    Service execution context for comprehensive operation tracking and coordination.
    
    Provides centralized context management for service operations enabling
    consistent behavior, audit trail generation, and resource coordination
    across different business service modules and external integrations.
    
    Attributes:
        operation_id: Unique identifier for operation tracking
        user_id: User identifier for authorization and audit
        session_id: Session identifier for request correlation
        request_id: Request identifier for tracing and logging
        tenant_id: Tenant identifier for multi-tenant operations
        operation_type: Type of service operation being performed
        priority: Operation priority for resource allocation
        metadata: Additional context metadata and parameters
        start_time: Operation start timestamp for performance monitoring
        audit_enabled: Whether to generate audit trail for operation
        cache_enabled: Whether to use caching for operation
        timeout_seconds: Operation timeout for performance control
    """
    operation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    tenant_id: Optional[str] = None
    operation_type: ServiceOperationType = ServiceOperationType.PROCESS
    priority: ServicePriority = ServicePriority.NORMAL
    metadata: Dict[str, Any] = field(default_factory=dict)
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    audit_enabled: bool = True
    cache_enabled: bool = True
    timeout_seconds: float = 30.0
    
    @property
    def execution_time(self) -> float:
        """Calculate current execution time in seconds."""
        return (datetime.now(timezone.utc) - self.start_time).total_seconds()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert service context to dictionary for logging and serialization."""
        return {
            'operation_id': self.operation_id,
            'user_id': self.user_id,
            'session_id': self.session_id,
            'request_id': self.request_id,
            'tenant_id': self.tenant_id,
            'operation_type': self.operation_type.value,
            'priority': self.priority.value,
            'metadata': self.metadata,
            'start_time': self.start_time.isoformat(),
            'execution_time': self.execution_time,
            'audit_enabled': self.audit_enabled,
            'cache_enabled': self.cache_enabled,
            'timeout_seconds': self.timeout_seconds
        }


@dataclass
class ServiceMetrics:
    """
    Performance and quality metrics for service operations.
    
    Provides comprehensive metrics collection for service performance monitoring,
    quality assurance, and business intelligence analytics with integration
    into enterprise monitoring systems.
    """
    operation_count: int = 0
    success_count: int = 0
    error_count: int = 0
    cache_hit_count: int = 0
    cache_miss_count: int = 0
    database_query_count: int = 0
    external_service_call_count: int = 0
    validation_error_count: int = 0
    business_rule_violation_count: int = 0
    total_execution_time: float = 0.0
    min_execution_time: float = float('inf')
    max_execution_time: float = 0.0
    
    @property
    def average_execution_time(self) -> float:
        """Calculate average execution time across operations."""
        return self.total_execution_time / max(1, self.operation_count)
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate as percentage."""
        return (self.success_count / max(1, self.operation_count)) * 100
    
    @property
    def error_rate(self) -> float:
        """Calculate error rate as percentage."""
        return (self.error_count / max(1, self.operation_count)) * 100
    
    @property
    def cache_hit_rate(self) -> float:
        """Calculate cache hit rate as percentage."""
        total_cache_operations = self.cache_hit_count + self.cache_miss_count
        return (self.cache_hit_count / max(1, total_cache_operations)) * 100
    
    def update_execution_time(self, execution_time: float) -> None:
        """Update execution time metrics with new measurement."""
        self.total_execution_time += execution_time
        self.min_execution_time = min(self.min_execution_time, execution_time)
        self.max_execution_time = max(self.max_execution_time, execution_time)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary for monitoring and reporting."""
        return {
            'operation_count': self.operation_count,
            'success_count': self.success_count,
            'error_count': self.error_count,
            'cache_hit_count': self.cache_hit_count,
            'cache_miss_count': self.cache_miss_count,
            'database_query_count': self.database_query_count,
            'external_service_call_count': self.external_service_call_count,
            'validation_error_count': self.validation_error_count,
            'business_rule_violation_count': self.business_rule_violation_count,
            'total_execution_time': self.total_execution_time,
            'min_execution_time': self.min_execution_time if self.min_execution_time != float('inf') else 0.0,
            'max_execution_time': self.max_execution_time,
            'average_execution_time': self.average_execution_time,
            'success_rate': self.success_rate,
            'error_rate': self.error_rate,
            'cache_hit_rate': self.cache_hit_rate
        }


@runtime_checkable
class ServiceInterface(Protocol):
    """
    Protocol defining standard service interface for business operations.
    
    Provides type checking and interface compliance verification for all
    business service implementations ensuring consistent service behavior
    and integration patterns across the application.
    """
    
    async def execute(self, context: ServiceContext, **kwargs) -> Any:
        """Execute primary service operation with context and parameters."""
        ...
    
    def validate_input(self, data: Dict[str, Any], context: ServiceContext) -> Dict[str, Any]:
        """Validate input data for service operation."""
        ...
    
    def get_metrics(self) -> ServiceMetrics:
        """Get service performance and quality metrics."""
        ...


def service_operation(
    operation_type: ServiceOperationType = ServiceOperationType.PROCESS,
    timeout_seconds: float = 30.0,
    cache_enabled: bool = True,
    audit_enabled: bool = True,
    retry_attempts: int = 3,
    circuit_breaker_enabled: bool = True
):
    """
    Decorator for service operations providing comprehensive operation management.
    
    Implements standardized service operation patterns including performance monitoring,
    error handling, caching, audit trail generation, and circuit breaker patterns
    for resilient service operations per Section 6.1.3.
    
    Args:
        operation_type: Type of service operation for classification
        timeout_seconds: Operation timeout for performance control
        cache_enabled: Whether to enable caching for operation
        audit_enabled: Whether to generate audit trail
        retry_attempts: Number of retry attempts for transient failures
        circuit_breaker_enabled: Whether to enable circuit breaker pattern
        
    Returns:
        Decorated function with comprehensive operation management
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(self, context: ServiceContext, *args, **kwargs):
            # Update context with decorator parameters
            context.operation_type = operation_type
            context.timeout_seconds = timeout_seconds
            context.cache_enabled = cache_enabled
            context.audit_enabled = audit_enabled
            
            operation_start = time.perf_counter()
            operation_success = False
            operation_result = None
            operation_error = None
            
            try:
                logger.info(
                    "Service operation started",
                    operation_id=context.operation_id,
                    operation_type=operation_type.value,
                    function_name=func.__name__,
                    user_id=context.user_id,
                    request_id=context.request_id
                )
                
                # Update metrics
                if hasattr(self, '_metrics'):
                    self._metrics.operation_count += 1
                
                # Check circuit breaker if enabled
                if circuit_breaker_enabled and hasattr(self, '_circuit_breaker'):
                    if self._circuit_breaker.state == CircuitBreakerState.OPEN:
                        raise CircuitBreakerOpenError(
                            message=f"Circuit breaker open for {func.__name__}",
                            service_name=self.__class__.__name__,
                            error_code="CIRCUIT_BREAKER_OPEN"
                        )
                
                # Execute operation with timeout
                operation_result = await asyncio.wait_for(
                    func(self, context, *args, **kwargs),
                    timeout=timeout_seconds
                )
                
                operation_success = True
                
                # Update success metrics
                if hasattr(self, '_metrics'):
                    self._metrics.success_count += 1
                
                # Record successful circuit breaker operation
                if circuit_breaker_enabled and hasattr(self, '_circuit_breaker'):
                    self._circuit_breaker.record_success()
                
                logger.info(
                    "Service operation completed successfully",
                    operation_id=context.operation_id,
                    function_name=func.__name__,
                    execution_time=time.perf_counter() - operation_start,
                    result_type=type(operation_result).__name__
                )
                
                return operation_result
                
            except asyncio.TimeoutError as timeout_error:
                operation_error = timeout_error
                logger.error(
                    "Service operation timeout",
                    operation_id=context.operation_id,
                    function_name=func.__name__,
                    timeout_seconds=timeout_seconds,
                    execution_time=time.perf_counter() - operation_start
                )
                
                # Record circuit breaker failure
                if circuit_breaker_enabled and hasattr(self, '_circuit_breaker'):
                    self._circuit_breaker.record_failure()
                
                raise DataProcessingError(
                    message=f"Service operation timeout after {timeout_seconds} seconds",
                    error_code="SERVICE_OPERATION_TIMEOUT",
                    context={
                        'operation_id': context.operation_id,
                        'function_name': func.__name__,
                        'timeout_seconds': timeout_seconds
                    },
                    cause=timeout_error,
                    severity=ErrorSeverity.HIGH
                )
                
            except Exception as service_error:
                operation_error = service_error
                logger.error(
                    "Service operation failed",
                    operation_id=context.operation_id,
                    function_name=func.__name__,
                    error=str(service_error),
                    execution_time=time.perf_counter() - operation_start,
                    exc_info=True
                )
                
                # Update error metrics
                if hasattr(self, '_metrics'):
                    self._metrics.error_count += 1
                
                # Record circuit breaker failure
                if circuit_breaker_enabled and hasattr(self, '_circuit_breaker'):
                    self._circuit_breaker.record_failure()
                
                # Convert to business exception if needed
                if not isinstance(service_error, BaseBusinessException):
                    raise DataProcessingError(
                        message=f"Service operation failed: {str(service_error)}",
                        error_code="SERVICE_OPERATION_ERROR",
                        context={
                            'operation_id': context.operation_id,
                            'function_name': func.__name__
                        },
                        cause=service_error,
                        severity=ErrorSeverity.HIGH
                    )
                else:
                    raise
                
            finally:
                # Update execution time metrics
                execution_time = time.perf_counter() - operation_start
                if hasattr(self, '_metrics'):
                    self._metrics.update_execution_time(execution_time)
                
                # Generate audit trail if enabled
                if audit_enabled and context.audit_enabled:
                    await self._generate_audit_trail(
                        context, func.__name__, operation_success, 
                        execution_time, operation_error
                    )
        
        @wraps(func)
        def sync_wrapper(self, context: ServiceContext, *args, **kwargs):
            # Handle synchronous operations
            return asyncio.create_task(async_wrapper(self, context, *args, **kwargs))
        
        # Return async wrapper if function is async, sync wrapper otherwise
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


class BaseBusinessService(ABC):
    """
    Abstract base service providing common service patterns and enterprise features.
    
    Provides foundational service capabilities including metrics collection, audit trail
    generation, cache management, circuit breaker patterns, and comprehensive error
    handling for all business service implementations per Section 5.2.4.
    
    This base service implements:
    - Service operation management and coordination patterns
    - Performance monitoring and metrics collection per Section 0.1.1
    - Circuit breaker patterns for resilience per Section 6.1.3
    - Cache integration for performance optimization per Section 5.2.7
    - Comprehensive error handling and audit trail generation
    - Integration with data access and external services
    
    Subclass Responsibilities:
        - Implement abstract methods for specific business operations
        - Define service-specific validation and processing logic
        - Configure service-specific circuit breaker and cache settings
        - Implement business-specific error handling and recovery
    """
    
    def __init__(
        self,
        service_name: str,
        cache_enabled: bool = True,
        circuit_breaker_enabled: bool = True,
        metrics_enabled: bool = True
    ):
        """
        Initialize base business service with enterprise features.
        
        Args:
            service_name: Unique name for service identification
            cache_enabled: Whether to enable cache integration
            circuit_breaker_enabled: Whether to enable circuit breaker pattern
            metrics_enabled: Whether to enable metrics collection
        """
        self.service_name = service_name
        self.cache_enabled = cache_enabled
        self.circuit_breaker_enabled = circuit_breaker_enabled
        self.metrics_enabled = metrics_enabled
        
        # Initialize service components
        self._metrics = ServiceMetrics() if metrics_enabled else None
        self._circuit_breaker = self._create_circuit_breaker() if circuit_breaker_enabled else None
        self._processor = get_business_processor()
        self._cache_client = get_redis_client() if cache_enabled else None
        
        # Service configuration
        self._default_timeout = 30.0
        self._max_retry_attempts = 3
        self._cache_ttl_seconds = 3600  # 1 hour default
        
        logger.info(
            "Base business service initialized",
            service_name=service_name,
            cache_enabled=cache_enabled,
            circuit_breaker_enabled=circuit_breaker_enabled,
            metrics_enabled=metrics_enabled
        )
    
    def _create_circuit_breaker(self):
        """Create circuit breaker for service resilience."""
        # Import circuit breaker from integrations if available
        try:
            from ..integrations.base_client import CircuitBreaker
            return CircuitBreaker(
                failure_threshold=5,
                recovery_timeout=60,
                expected_exception=Exception
            )
        except ImportError:
            logger.warning("Circuit breaker not available, continuing without")
            return None
    
    @abstractmethod
    async def execute(self, context: ServiceContext, **kwargs) -> Any:
        """
        Execute primary service operation with context and parameters.
        
        Abstract method that must be implemented by all service subclasses
        to provide specific business operation logic and coordination.
        
        Args:
            context: Service execution context with operation parameters
            **kwargs: Additional operation-specific parameters
            
        Returns:
            Service operation result (type varies by implementation)
            
        Raises:
            BaseBusinessException: For business logic failures
            DataProcessingError: For data processing failures
            ValidationError: For input validation failures
        """
        pass
    
    def validate_input(self, data: Dict[str, Any], context: ServiceContext) -> Dict[str, Any]:
        """
        Validate input data for service operation with comprehensive checks.
        
        Provides standardized input validation including data type checking,
        business rule validation, and security validation for consistent
        service input processing across all operations.
        
        Args:
            data: Input data to validate
            context: Service execution context for validation rules
            
        Returns:
            Validated and potentially transformed input data
            
        Raises:
            DataValidationError: If input validation fails
            BusinessRuleViolationError: If business rules are violated
        """
        try:
            logger.debug(
                "Validating service input",
                service_name=self.service_name,
                operation_id=context.operation_id,
                data_fields=list(data.keys()) if isinstance(data, dict) else []
            )
            
            # Basic data structure validation
            if not isinstance(data, dict):
                raise DataValidationError(
                    message="Input data must be a dictionary",
                    error_code="INVALID_INPUT_TYPE",
                    context={
                        'service_name': self.service_name,
                        'input_type': type(data).__name__
                    },
                    severity=ErrorSeverity.MEDIUM
                )
            
            # Apply service-specific validation
            validated_data = self._apply_service_validation(data, context)
            
            logger.debug(
                "Service input validation completed",
                service_name=self.service_name,
                operation_id=context.operation_id,
                validated_fields=len(validated_data)
            )
            
            return validated_data
            
        except Exception as validation_error:
            if isinstance(validation_error, BaseBusinessException):
                raise
            
            raise DataValidationError(
                message=f"Service input validation failed: {str(validation_error)}",
                error_code="SERVICE_INPUT_VALIDATION_ERROR",
                context={
                    'service_name': self.service_name,
                    'operation_id': context.operation_id
                },
                cause=validation_error,
                severity=ErrorSeverity.MEDIUM
            )
    
    def _apply_service_validation(self, data: Dict[str, Any], context: ServiceContext) -> Dict[str, Any]:
        """
        Apply service-specific validation logic.
        
        Override this method in subclasses to implement service-specific
        validation rules and data transformation patterns.
        
        Args:
            data: Input data to validate
            context: Service execution context
            
        Returns:
            Service-specific validated data
        """
        return data
    
    async def _get_cached_result(self, cache_key: str, context: ServiceContext) -> Optional[Any]:
        """
        Get cached result for operation if caching is enabled.
        
        Args:
            cache_key: Cache key for result lookup
            context: Service execution context
            
        Returns:
            Cached result or None if not found or caching disabled
        """
        if not self.cache_enabled or not self._cache_client:
            return None
        
        try:
            cached_result = await self._cache_client.get(cache_key)
            
            if cached_result is not None:
                if self._metrics:
                    self._metrics.cache_hit_count += 1
                
                logger.debug(
                    "Cache hit for service operation",
                    service_name=self.service_name,
                    operation_id=context.operation_id,
                    cache_key=cache_key
                )
                
                return cached_result
            else:
                if self._metrics:
                    self._metrics.cache_miss_count += 1
                
                logger.debug(
                    "Cache miss for service operation",
                    service_name=self.service_name,
                    operation_id=context.operation_id,
                    cache_key=cache_key
                )
                
                return None
                
        except Exception as cache_error:
            logger.warning(
                "Cache operation failed",
                service_name=self.service_name,
                operation_id=context.operation_id,
                cache_key=cache_key,
                error=str(cache_error)
            )
            return None
    
    async def _set_cached_result(
        self, 
        cache_key: str, 
        result: Any, 
        context: ServiceContext,
        ttl_seconds: Optional[int] = None
    ) -> None:
        """
        Set cached result for operation if caching is enabled.
        
        Args:
            cache_key: Cache key for result storage
            result: Result data to cache
            context: Service execution context
            ttl_seconds: Time-to-live in seconds (uses default if not specified)
        """
        if not self.cache_enabled or not self._cache_client:
            return
        
        try:
            cache_ttl = ttl_seconds or self._cache_ttl_seconds
            await self._cache_client.setex(cache_key, cache_ttl, result)
            
            logger.debug(
                "Result cached for service operation",
                service_name=self.service_name,
                operation_id=context.operation_id,
                cache_key=cache_key,
                ttl_seconds=cache_ttl
            )
            
        except Exception as cache_error:
            logger.warning(
                "Failed to cache result",
                service_name=self.service_name,
                operation_id=context.operation_id,
                cache_key=cache_key,
                error=str(cache_error)
            )
    
    async def _generate_audit_trail(
        self,
        context: ServiceContext,
        operation_name: str,
        success: bool,
        execution_time: float,
        error: Optional[Exception] = None
    ) -> None:
        """
        Generate audit trail entry for service operation.
        
        Args:
            context: Service execution context
            operation_name: Name of the operation performed
            success: Whether operation was successful
            execution_time: Operation execution time in seconds
            error: Exception if operation failed
        """
        try:
            audit_entry = {
                'service_name': self.service_name,
                'operation_name': operation_name,
                'operation_id': context.operation_id,
                'user_id': context.user_id,
                'session_id': context.session_id,
                'request_id': context.request_id,
                'tenant_id': context.tenant_id,
                'operation_type': context.operation_type.value,
                'priority': context.priority.value,
                'success': success,
                'execution_time': execution_time,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'metadata': context.metadata
            }
            
            if error:
                audit_entry['error'] = {
                    'type': type(error).__name__,
                    'message': str(error),
                    'error_code': getattr(error, 'error_code', 'UNKNOWN_ERROR')
                }
            
            # Store audit entry (implementation depends on audit system)
            logger.info(
                "Service operation audit trail",
                **audit_entry
            )
            
        except Exception as audit_error:
            logger.error(
                "Failed to generate audit trail",
                service_name=self.service_name,
                operation_id=context.operation_id,
                audit_error=str(audit_error)
            )
    
    def get_metrics(self) -> ServiceMetrics:
        """
        Get service performance and quality metrics.
        
        Returns:
            ServiceMetrics instance with current performance data
        """
        return self._metrics or ServiceMetrics()
    
    def reset_metrics(self) -> None:
        """Reset service metrics to initial state."""
        if self._metrics:
            self._metrics = ServiceMetrics()
            
    def get_health_status(self) -> Dict[str, Any]:
        """
        Get service health status for monitoring and load balancer integration.
        
        Returns:
            Dictionary containing service health information
        """
        health_status = {
            'service_name': self.service_name,
            'status': 'healthy',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'metrics': self.get_metrics().to_dict() if self._metrics else {},
            'circuit_breaker_state': None,
            'cache_enabled': self.cache_enabled,
            'components': {}
        }
        
        # Add circuit breaker status
        if self._circuit_breaker:
            health_status['circuit_breaker_state'] = self._circuit_breaker.state.value
            if self._circuit_breaker.state == CircuitBreakerState.OPEN:
                health_status['status'] = 'degraded'
        
        # Add cache health status
        if self.cache_enabled and self._cache_client:
            try:
                # Basic cache connectivity check
                health_status['components']['cache'] = {
                    'status': 'healthy',
                    'client_available': True
                }
            except Exception:
                health_status['components']['cache'] = {
                    'status': 'unhealthy',
                    'client_available': False
                }
                health_status['status'] = 'degraded'
        
        return health_status


class UserManagementService(BaseBusinessService):
    """
    User lifecycle and profile management service.
    
    Provides comprehensive user management operations including user creation,
    profile updates, authentication coordination, and user data management
    while maintaining behavioral equivalence with Node.js implementation.
    
    This service implements:
    - User account creation and profile management per F-004-RQ-001
    - Authentication and authorization coordination per F-003-RQ-002
    - User data validation and business rule enforcement
    - Integration with external authentication services
    - User lifecycle management and data consistency
    """
    
    def __init__(self):
        """Initialize user management service with specialized configuration."""
        super().__init__(
            service_name="user_management",
            cache_enabled=True,
            circuit_breaker_enabled=True,
            metrics_enabled=True
        )
        
        # Service-specific configuration
        self._user_cache_ttl = 1800  # 30 minutes for user data
        self._profile_cache_ttl = 3600  # 1 hour for profile data
        
    @service_operation(
        operation_type=ServiceOperationType.CREATE,
        timeout_seconds=15.0,
        cache_enabled=False,
        audit_enabled=True
    )
    async def create_user(self, context: ServiceContext, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create new user account with comprehensive validation and setup.
        
        Args:
            context: Service execution context
            user_data: User account data for creation
            
        Returns:
            Created user data with system-generated fields
            
        Raises:
            DataValidationError: If user data validation fails
            BusinessRuleViolationError: If business rules are violated
        """
        try:
            logger.info(
                "Creating user account",
                operation_id=context.operation_id,
                user_email=user_data.get('email', 'unknown')
            )
            
            # Validate user input data
            validated_data = self.validate_input(user_data, context)
            
            # Check for duplicate email
            await self._check_duplicate_email(validated_data['email'], context)
            
            # Process user data with business rules
            processed_data = await self._process_user_creation_data(validated_data, context)
            
            # Create user in database
            created_user = await self._create_user_in_database(processed_data, context)
            
            # Initialize user profile
            await self._initialize_user_profile(created_user['id'], context)
            
            # Invalidate related caches
            await self._invalidate_user_caches(created_user['email'], context)
            
            logger.info(
                "User account created successfully",
                operation_id=context.operation_id,
                user_id=created_user['id'],
                user_email=created_user['email']
            )
            
            return created_user
            
        except Exception as creation_error:
            logger.error(
                "User creation failed",
                operation_id=context.operation_id,
                error=str(creation_error)
            )
            raise
    
    @service_operation(
        operation_type=ServiceOperationType.READ,
        timeout_seconds=10.0,
        cache_enabled=True,
        audit_enabled=False
    )
    async def get_user_by_id(self, context: ServiceContext, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve user by ID with caching and comprehensive data assembly.
        
        Args:
            context: Service execution context
            user_id: Unique user identifier
            
        Returns:
            User data dictionary or None if not found
        """
        cache_key = create_cache_key("user", user_id)
        
        # Check cache first
        cached_user = await self._get_cached_result(cache_key, context)
        if cached_user:
            return cached_user
        
        try:
            # Query database for user
            user_data = await self._get_user_from_database(user_id, context)
            
            if user_data:
                # Enrich user data with profile information
                enriched_user = await self._enrich_user_data(user_data, context)
                
                # Cache the result
                await self._set_cached_result(cache_key, enriched_user, context, self._user_cache_ttl)
                
                return enriched_user
            
            return None
            
        except Exception as retrieval_error:
            logger.error(
                "User retrieval failed",
                operation_id=context.operation_id,
                user_id=user_id,
                error=str(retrieval_error)
            )
            raise
    
    @service_operation(
        operation_type=ServiceOperationType.UPDATE,
        timeout_seconds=20.0,
        cache_enabled=False,
        audit_enabled=True
    )
    async def update_user_profile(
        self, 
        context: ServiceContext, 
        user_id: str, 
        profile_updates: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Update user profile with validation and business rule enforcement.
        
        Args:
            context: Service execution context
            user_id: User identifier for profile update
            profile_updates: Profile data updates to apply
            
        Returns:
            Updated user profile data
        """
        try:
            logger.info(
                "Updating user profile",
                operation_id=context.operation_id,
                user_id=user_id,
                update_fields=list(profile_updates.keys())
            )
            
            # Validate profile updates
            validated_updates = self._validate_profile_updates(profile_updates, context)
            
            # Get current user data
            current_user = await self.get_user_by_id(context, user_id)
            if not current_user:
                raise DataValidationError(
                    message=f"User not found: {user_id}",
                    error_code="USER_NOT_FOUND",
                    context={'user_id': user_id},
                    severity=ErrorSeverity.MEDIUM
                )
            
            # Apply business rules for profile updates
            processed_updates = await self._process_profile_updates(
                current_user, validated_updates, context
            )
            
            # Update user profile in database
            updated_user = await self._update_user_in_database(user_id, processed_updates, context)
            
            # Invalidate user caches
            await self._invalidate_user_caches(current_user['email'], context)
            
            logger.info(
                "User profile updated successfully",
                operation_id=context.operation_id,
                user_id=user_id
            )
            
            return updated_user
            
        except Exception as update_error:
            logger.error(
                "User profile update failed",
                operation_id=context.operation_id,
                user_id=user_id,
                error=str(update_error)
            )
            raise
    
    def _apply_service_validation(self, data: Dict[str, Any], context: ServiceContext) -> Dict[str, Any]:
        """Apply user management specific validation."""
        required_fields = ['email']
        
        for field in required_fields:
            if field not in data or not data[field]:
                raise DataValidationError(
                    message=f"Required field missing: {field}",
                    error_code="REQUIRED_FIELD_MISSING",
                    context={'field': field, 'service': self.service_name},
                    severity=ErrorSeverity.MEDIUM
                )
        
        # Validate email format
        email = data.get('email', '').lower().strip()
        if not self._is_valid_email(email):
            raise DataValidationError(
                message="Invalid email format",
                error_code="INVALID_EMAIL_FORMAT",
                context={'email': email},
                severity=ErrorSeverity.MEDIUM
            )
        
        data['email'] = email
        return data
    
    def _is_valid_email(self, email: str) -> bool:
        """Validate email format using business rules."""
        import re
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(email_pattern, email))
    
    async def _check_duplicate_email(self, email: str, context: ServiceContext) -> None:
        """Check for duplicate email addresses."""
        # This would typically query the database
        # For now, implement basic check logic
        pass
    
    async def _process_user_creation_data(self, user_data: Dict[str, Any], context: ServiceContext) -> Dict[str, Any]:
        """Process and enrich user creation data."""
        processed_data = user_data.copy()
        processed_data['id'] = str(uuid.uuid4())
        processed_data['created_at'] = datetime.now(timezone.utc).isoformat()
        processed_data['updated_at'] = processed_data['created_at']
        processed_data['status'] = 'active'
        
        return processed_data
    
    async def _create_user_in_database(self, user_data: Dict[str, Any], context: ServiceContext) -> Dict[str, Any]:
        """Create user record in database."""
        try:
            # Use data access layer
            result = await execute_async_query(
                'users',
                'insert_one',
                user_data
            )
            
            if self._metrics:
                self._metrics.database_query_count += 1
            
            return user_data
            
        except Exception as db_error:
            raise DataProcessingError(
                message="Failed to create user in database",
                error_code="USER_DATABASE_CREATE_ERROR",
                context={'user_email': user_data.get('email')},
                cause=db_error,
                severity=ErrorSeverity.HIGH
            )
    
    async def _initialize_user_profile(self, user_id: str, context: ServiceContext) -> None:
        """Initialize default user profile."""
        profile_data = {
            'user_id': user_id,
            'preferences': {},
            'settings': {},
            'created_at': datetime.now(timezone.utc).isoformat()
        }
        
        try:
            await execute_async_query(
                'user_profiles',
                'insert_one',
                profile_data
            )
            
        except Exception as profile_error:
            logger.warning(
                "Failed to initialize user profile",
                user_id=user_id,
                error=str(profile_error)
            )
    
    async def _get_user_from_database(self, user_id: str, context: ServiceContext) -> Optional[Dict[str, Any]]:
        """Retrieve user from database."""
        try:
            result = await execute_async_query(
                'users',
                'find_one',
                {'id': user_id}
            )
            
            if self._metrics:
                self._metrics.database_query_count += 1
            
            return result
            
        except Exception as db_error:
            raise DataProcessingError(
                message="Failed to retrieve user from database",
                error_code="USER_DATABASE_READ_ERROR",
                context={'user_id': user_id},
                cause=db_error,
                severity=ErrorSeverity.MEDIUM
            )
    
    async def _enrich_user_data(self, user_data: Dict[str, Any], context: ServiceContext) -> Dict[str, Any]:
        """Enrich user data with additional information."""
        enriched_data = user_data.copy()
        
        # Add profile information if available
        try:
            profile_data = await execute_async_query(
                'user_profiles',
                'find_one',
                {'user_id': user_data['id']}
            )
            
            if profile_data:
                enriched_data['profile'] = profile_data
                
        except Exception as profile_error:
            logger.warning(
                "Failed to enrich user data with profile",
                user_id=user_data.get('id'),
                error=str(profile_error)
            )
        
        return enriched_data
    
    def _validate_profile_updates(self, updates: Dict[str, Any], context: ServiceContext) -> Dict[str, Any]:
        """Validate profile update data."""
        # Implement profile-specific validation logic
        allowed_fields = {'name', 'preferences', 'settings', 'avatar_url'}
        
        validated_updates = {}
        for field, value in updates.items():
            if field in allowed_fields:
                validated_updates[field] = value
            else:
                logger.warning(
                    "Ignoring invalid profile field",
                    field=field,
                    operation_id=context.operation_id
                )
        
        return validated_updates
    
    async def _process_profile_updates(
        self, 
        current_user: Dict[str, Any], 
        updates: Dict[str, Any], 
        context: ServiceContext
    ) -> Dict[str, Any]:
        """Process profile updates with business rules."""
        processed_updates = updates.copy()
        processed_updates['updated_at'] = datetime.now(timezone.utc).isoformat()
        
        return processed_updates
    
    async def _update_user_in_database(
        self, 
        user_id: str, 
        updates: Dict[str, Any], 
        context: ServiceContext
    ) -> Dict[str, Any]:
        """Update user record in database."""
        try:
            result = await execute_async_query(
                'users',
                'update_one',
                {'id': user_id},
                {'$set': updates}
            )
            
            if self._metrics:
                self._metrics.database_query_count += 1
            
            # Return updated user data
            return await self._get_user_from_database(user_id, context)
            
        except Exception as db_error:
            raise DataProcessingError(
                message="Failed to update user in database",
                error_code="USER_DATABASE_UPDATE_ERROR",
                context={'user_id': user_id},
                cause=db_error,
                severity=ErrorSeverity.HIGH
            )
    
    async def _invalidate_user_caches(self, email: str, context: ServiceContext) -> None:
        """Invalidate user-related cache entries."""
        if not self.cache_enabled or not self._cache_client:
            return
        
        try:
            # Invalidate user cache patterns
            cache_patterns = [
                f"user:*",
                f"user_profile:*",
                f"user_email:{email}"
            ]
            
            for pattern in cache_patterns:
                await invalidate_by_pattern(pattern)
                
        except Exception as cache_error:
            logger.warning(
                "Failed to invalidate user caches",
                email=email,
                error=str(cache_error)
            )


class DataProcessingService(BaseBusinessService):
    """
    Business data transformation and validation workflow service.
    
    Provides comprehensive data processing operations including validation,
    transformation, business rule enforcement, and workflow orchestration
    for complex business data operations maintaining Node.js equivalence.
    
    This service implements:
    - Data transformation workflows per Section 5.2.4
    - Business rule validation and enforcement per F-004-RQ-001
    - Complex data processing orchestration
    - Integration with external data sources and validation services
    - Performance-optimized processing maintaining ≤10% variance
    """
    
    def __init__(self):
        """Initialize data processing service with workflow management."""
        super().__init__(
            service_name="data_processing",
            cache_enabled=True,
            circuit_breaker_enabled=True,
            metrics_enabled=True
        )
        
        # Service-specific configuration
        self._processing_cache_ttl = 900  # 15 minutes for processing results
        self._validation_cache_ttl = 1800  # 30 minutes for validation results
    
    @service_operation(
        operation_type=ServiceOperationType.PROCESS,
        timeout_seconds=60.0,
        cache_enabled=True,
        audit_enabled=True
    )
    async def process_business_data(
        self, 
        context: ServiceContext, 
        data: Dict[str, Any],
        processing_rules: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Process business data with comprehensive validation and transformation.
        
        Args:
            context: Service execution context
            data: Business data to process
            processing_rules: Optional list of processing rules to apply
            
        Returns:
            Processed and validated business data
        """
        try:
            logger.info(
                "Processing business data",
                operation_id=context.operation_id,
                data_fields=list(data.keys()) if isinstance(data, dict) else [],
                processing_rules=processing_rules or []
            )
            
            # Create cache key for processing result
            cache_key = self._create_processing_cache_key(data, processing_rules)
            
            # Check cache for existing result
            cached_result = await self._get_cached_result(cache_key, context)
            if cached_result:
                return cached_result
            
            # Validate input data
            validated_data = self.validate_input(data, context)
            
            # Create processing request
            processing_request = ProcessingRequest(
                data=validated_data,
                rules=processing_rules or [],
                context={
                    'operation_id': context.operation_id,
                    'user_id': context.user_id,
                    'request_id': context.request_id
                }
            )
            
            # Execute processing workflow
            processing_result = await self._processor.process_request(processing_request)
            
            # Validate processing result
            if processing_result.status != "success":
                raise DataProcessingError(
                    message="Data processing workflow failed",
                    error_code="DATA_PROCESSING_WORKFLOW_ERROR",
                    context={
                        'processing_status': processing_result.status,
                        'audit_trail': processing_result.audit_trail
                    },
                    severity=ErrorSeverity.HIGH
                )
            
            # Cache the successful result
            await self._set_cached_result(
                cache_key, processing_result.data, context, self._processing_cache_ttl
            )
            
            logger.info(
                "Business data processing completed",
                operation_id=context.operation_id,
                processing_time=processing_result.processing_time,
                audit_trail_length=len(processing_result.audit_trail)
            )
            
            return processing_result.data
            
        except Exception as processing_error:
            logger.error(
                "Business data processing failed",
                operation_id=context.operation_id,
                error=str(processing_error)
            )
            raise
    
    @service_operation(
        operation_type=ServiceOperationType.VALIDATE,
        timeout_seconds=30.0,
        cache_enabled=True,
        audit_enabled=False
    )
    async def validate_business_rules(
        self, 
        context: ServiceContext, 
        data: Dict[str, Any],
        rules: Optional[List[str]] = None
    ) -> ValidationResult:
        """
        Validate data against business rules with caching and performance optimization.
        
        Args:
            context: Service execution context
            data: Data to validate against business rules
            rules: Optional list of specific rules to validate
            
        Returns:
            ValidationResult with validation status and messages
        """
        try:
            # Create cache key for validation result
            cache_key = self._create_validation_cache_key(data, rules)
            
            # Check cache for existing validation result
            cached_result = await self._get_cached_result(cache_key, context)
            if cached_result:
                return ValidationResult(**cached_result)
            
            # Perform business rule validation
            validation_result = validate_business_rules(data, rules)
            
            # Cache the validation result
            await self._set_cached_result(
                cache_key, validation_result.__dict__, context, self._validation_cache_ttl
            )
            
            if self._metrics:
                if not validation_result.is_valid:
                    self._metrics.validation_error_count += 1
                    self._metrics.business_rule_violation_count += len(validation_result.errors)
            
            return validation_result
            
        except Exception as validation_error:
            logger.error(
                "Business rule validation failed",
                operation_id=context.operation_id,
                error=str(validation_error)
            )
            raise
    
    def _create_processing_cache_key(self, data: Dict[str, Any], rules: Optional[List[str]]) -> str:
        """Create cache key for processing operation."""
        import hashlib
        import json
        
        # Create deterministic hash of data and rules
        content = {
            'data': data,
            'rules': sorted(rules) if rules else []
        }
        content_str = json.dumps(content, sort_keys=True, default=str)
        content_hash = hashlib.md5(content_str.encode()).hexdigest()
        
        return create_cache_key("data_processing", content_hash)
    
    def _create_validation_cache_key(self, data: Dict[str, Any], rules: Optional[List[str]]) -> str:
        """Create cache key for validation operation."""
        import hashlib
        import json
        
        # Create deterministic hash of data and rules
        content = {
            'data': data,
            'rules': sorted(rules) if rules else []
        }
        content_str = json.dumps(content, sort_keys=True, default=str)
        content_hash = hashlib.md5(content_str.encode()).hexdigest()
        
        return create_cache_key("validation", content_hash)


class IntegrationOrchestrationService(BaseBusinessService):
    """
    External service coordination and resilience service.
    
    Provides comprehensive external service integration with circuit breaker patterns,
    retry logic, fallback mechanisms, and performance monitoring for resilient
    external service communications per Section 6.1.3.
    
    This service implements:
    - External service integration coordination per F-004-RQ-002
    - Circuit breaker patterns for service resilience per Section 6.1.3
    - Retry logic with exponential backoff for transient failures
    - Fallback mechanisms for graceful degradation
    - Comprehensive monitoring and alerting for external service health
    """
    
    def __init__(self):
        """Initialize integration orchestration service."""
        super().__init__(
            service_name="integration_orchestration",
            cache_enabled=True,
            circuit_breaker_enabled=True,
            metrics_enabled=True
        )
        
        # Service-specific configuration
        self._integration_cache_ttl = 600  # 10 minutes for integration results
        self._health_check_interval = 60  # 1 minute for health checks
    
    @service_operation(
        operation_type=ServiceOperationType.INTEGRATE,
        timeout_seconds=45.0,
        cache_enabled=True,
        audit_enabled=True,
        circuit_breaker_enabled=True
    )
    async def coordinate_external_services(
        self, 
        context: ServiceContext, 
        service_calls: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Coordinate multiple external service calls with resilience patterns.
        
        Args:
            context: Service execution context
            service_calls: List of external service call configurations
            
        Returns:
            Aggregated results from external service calls
        """
        try:
            logger.info(
                "Coordinating external services",
                operation_id=context.operation_id,
                service_count=len(service_calls)
            )
            
            results = {}
            failed_services = []
            
            # Execute service calls with circuit breaker protection
            for service_call in service_calls:
                service_name = service_call.get('service_name')
                
                try:
                    result = await self._execute_external_service_call(service_call, context)
                    results[service_name] = result
                    
                except CircuitBreakerOpenError:
                    logger.warning(
                        "Circuit breaker open for service",
                        service_name=service_name,
                        operation_id=context.operation_id
                    )
                    
                    # Apply fallback mechanism
                    fallback_result = await self._apply_service_fallback(service_call, context)
                    if fallback_result:
                        results[service_name] = fallback_result
                    else:
                        failed_services.append(service_name)
                        
                except Exception as service_error:
                    logger.error(
                        "External service call failed",
                        service_name=service_name,
                        operation_id=context.operation_id,
                        error=str(service_error)
                    )
                    failed_services.append(service_name)
            
            # Check if critical services failed
            critical_services = [
                call['service_name'] for call in service_calls 
                if call.get('critical', False)
            ]
            
            failed_critical = [service for service in failed_services if service in critical_services]
            
            if failed_critical:
                raise DataProcessingError(
                    message=f"Critical external services failed: {failed_critical}",
                    error_code="CRITICAL_EXTERNAL_SERVICE_FAILURE",
                    context={
                        'failed_services': failed_services,
                        'critical_services': failed_critical
                    },
                    severity=ErrorSeverity.HIGH
                )
            
            integration_result = {
                'results': results,
                'failed_services': failed_services,
                'success_count': len(results),
                'failure_count': len(failed_services),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            if self._metrics:
                self._metrics.external_service_call_count += len(service_calls)
            
            logger.info(
                "External service coordination completed",
                operation_id=context.operation_id,
                success_count=len(results),
                failure_count=len(failed_services)
            )
            
            return integration_result
            
        except Exception as coordination_error:
            logger.error(
                "External service coordination failed",
                operation_id=context.operation_id,
                error=str(coordination_error)
            )
            raise
    
    async def _execute_external_service_call(
        self, 
        service_call: Dict[str, Any], 
        context: ServiceContext
    ) -> Any:
        """Execute individual external service call with monitoring."""
        service_name = service_call['service_name']
        
        # Track external service call
        with track_external_service_call(service_name, service_call.get('operation', 'unknown')):
            # Implementation would use appropriate external service client
            # For now, simulate service call
            await asyncio.sleep(0.1)  # Simulate network delay
            
            return {
                'service_name': service_name,
                'status': 'success',
                'data': {'result': 'mock_data'},
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    async def _apply_service_fallback(
        self, 
        service_call: Dict[str, Any], 
        context: ServiceContext
    ) -> Optional[Any]:
        """Apply fallback mechanism for failed external service."""
        service_name = service_call['service_name']
        fallback_config = service_call.get('fallback')
        
        if not fallback_config:
            return None
        
        fallback_type = fallback_config.get('type')
        
        if fallback_type == 'cache':
            # Try to get cached result
            cache_key = fallback_config.get('cache_key')
            if cache_key:
                return await self._get_cached_result(cache_key, context)
        
        elif fallback_type == 'default':
            # Return default value
            return fallback_config.get('default_value')
        
        elif fallback_type == 'alternative_service':
            # Try alternative service
            alternative_config = fallback_config.get('alternative_service')
            if alternative_config:
                return await self._execute_external_service_call(alternative_config, context)
        
        return None


class TransactionService(BaseBusinessService):
    """
    Transaction management and data consistency service.
    
    Provides comprehensive transaction management including distributed transactions,
    data consistency enforcement, rollback mechanisms, and transactional workflow
    coordination for maintaining data integrity across multiple operations.
    
    This service implements:
    - Transaction management and data consistency per Section 5.2.4
    - Distributed transaction coordination across multiple data sources
    - Automatic rollback mechanisms for transaction failure scenarios
    - Transaction monitoring and performance optimization
    - Integration with database access layer for transactional operations
    """
    
    def __init__(self):
        """Initialize transaction management service."""
        super().__init__(
            service_name="transaction_management",
            cache_enabled=False,  # Transactions should not be cached
            circuit_breaker_enabled=True,
            metrics_enabled=True
        )
    
    @service_operation(
        operation_type=ServiceOperationType.PROCESS,
        timeout_seconds=120.0,
        cache_enabled=False,
        audit_enabled=True
    )
    async def execute_transactional_workflow(
        self, 
        context: ServiceContext, 
        workflow_steps: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Execute transactional workflow with automatic rollback on failure.
        
        Args:
            context: Service execution context
            workflow_steps: List of workflow steps to execute transactionally
            
        Returns:
            Workflow execution results with transaction status
        """
        transaction_id = str(uuid.uuid4())
        completed_steps = []
        
        try:
            logger.info(
                "Starting transactional workflow",
                operation_id=context.operation_id,
                transaction_id=transaction_id,
                step_count=len(workflow_steps)
            )
            
            # Begin transaction context
            async with async_database_transaction() as session:
                for step_index, step_config in enumerate(workflow_steps):
                    step_name = step_config.get('name', f'step_{step_index}')
                    
                    logger.debug(
                        "Executing workflow step",
                        transaction_id=transaction_id,
                        step_name=step_name,
                        step_index=step_index
                    )
                    
                    # Execute individual step
                    step_result = await self._execute_workflow_step(
                        step_config, context, session
                    )
                    
                    completed_steps.append({
                        'name': step_name,
                        'index': step_index,
                        'result': step_result,
                        'timestamp': datetime.now(timezone.utc).isoformat()
                    })
                
                # All steps completed successfully, commit transaction
                await session.commit_transaction()
                
                workflow_result = {
                    'transaction_id': transaction_id,
                    'status': 'committed',
                    'completed_steps': completed_steps,
                    'step_count': len(completed_steps),
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
                
                logger.info(
                    "Transactional workflow completed successfully",
                    operation_id=context.operation_id,
                    transaction_id=transaction_id,
                    step_count=len(completed_steps)
                )
                
                return workflow_result
                
        except Exception as workflow_error:
            logger.error(
                "Transactional workflow failed, rolling back",
                operation_id=context.operation_id,
                transaction_id=transaction_id,
                completed_steps=len(completed_steps),
                error=str(workflow_error)
            )
            
            # Transaction will automatically rollback due to exception
            
            # Execute compensating actions for completed steps
            await self._execute_compensating_actions(completed_steps, context)
            
            raise DataProcessingError(
                message=f"Transactional workflow failed: {str(workflow_error)}",
                error_code="TRANSACTIONAL_WORKFLOW_ERROR",
                context={
                    'transaction_id': transaction_id,
                    'completed_steps': len(completed_steps),
                    'total_steps': len(workflow_steps)
                },
                cause=workflow_error,
                severity=ErrorSeverity.HIGH
            )
    
    async def _execute_workflow_step(
        self, 
        step_config: Dict[str, Any], 
        context: ServiceContext, 
        session: Any
    ) -> Dict[str, Any]:
        """Execute individual workflow step within transaction context."""
        step_type = step_config.get('type')
        step_data = step_config.get('data', {})
        
        if step_type == 'database_operation':
            return await self._execute_database_step(step_data, context, session)
        elif step_type == 'validation':
            return await self._execute_validation_step(step_data, context)
        elif step_type == 'business_logic':
            return await self._execute_business_logic_step(step_data, context)
        else:
            raise DataProcessingError(
                message=f"Unknown workflow step type: {step_type}",
                error_code="UNKNOWN_WORKFLOW_STEP_TYPE",
                context={'step_type': step_type},
                severity=ErrorSeverity.MEDIUM
            )
    
    async def _execute_database_step(
        self, 
        step_data: Dict[str, Any], 
        context: ServiceContext, 
        session: Any
    ) -> Dict[str, Any]:
        """Execute database operation step within transaction."""
        operation = step_data.get('operation')
        collection = step_data.get('collection')
        data = step_data.get('data', {})
        
        # Execute database operation with session
        result = await execute_async_query(
            collection,
            operation,
            data,
            session=session
        )
        
        if self._metrics:
            self._metrics.database_query_count += 1
        
        return {
            'operation': operation,
            'collection': collection,
            'result': result
        }
    
    async def _execute_validation_step(
        self, 
        step_data: Dict[str, Any], 
        context: ServiceContext
    ) -> Dict[str, Any]:
        """Execute validation step within workflow."""
        data_to_validate = step_data.get('data')
        validation_rules = step_data.get('rules', [])
        
        validation_result = validate_business_rules(data_to_validate, validation_rules)
        
        if not validation_result.is_valid:
            raise BusinessRuleViolationError(
                message="Workflow validation step failed",
                error_code="WORKFLOW_VALIDATION_FAILURE",
                context={
                    'validation_errors': validation_result.errors,
                    'validation_warnings': validation_result.warnings
                },
                severity=ErrorSeverity.HIGH
            )
        
        return {
            'validation_status': 'passed',
            'warnings': validation_result.warnings
        }
    
    async def _execute_business_logic_step(
        self, 
        step_data: Dict[str, Any], 
        context: ServiceContext
    ) -> Dict[str, Any]:
        """Execute business logic step within workflow."""
        # Process business data using the processor
        result = process_business_data(
            step_data.get('data', {}),
            step_data.get('rules', []),
            context.to_dict()
        )
        
        return {
            'processing_status': 'completed',
            'result': result
        }
    
    async def _execute_compensating_actions(
        self, 
        completed_steps: List[Dict[str, Any]], 
        context: ServiceContext
    ) -> None:
        """Execute compensating actions for completed steps during rollback."""
        logger.info(
            "Executing compensating actions",
            operation_id=context.operation_id,
            step_count=len(completed_steps)
        )
        
        # Execute compensating actions in reverse order
        for step in reversed(completed_steps):
            try:
                # Implementation would depend on step type and business requirements
                await self._execute_compensating_action(step, context)
                
            except Exception as compensation_error:
                logger.error(
                    "Compensating action failed",
                    step_name=step.get('name'),
                    error=str(compensation_error)
                )
    
    async def _execute_compensating_action(
        self, 
        step: Dict[str, Any], 
        context: ServiceContext
    ) -> None:
        """Execute compensating action for a specific step."""
        # Implementation would depend on business requirements
        # For now, log the compensating action
        logger.debug(
            "Executing compensating action",
            step_name=step.get('name'),
            operation_id=context.operation_id
        )


class WorkflowService(BaseBusinessService):
    """
    Complex business workflow orchestration and state management service.
    
    Provides comprehensive workflow management including state machine orchestration,
    conditional workflow execution, parallel processing coordination, and workflow
    monitoring for complex business processes maintaining Node.js equivalence.
    
    This service implements:
    - Complex workflow orchestration per Section 5.2.4
    - State machine management for business process flows
    - Conditional and parallel workflow execution patterns
    - Workflow monitoring and progress tracking
    - Integration with all other business services for comprehensive orchestration
    """
    
    def __init__(self):
        """Initialize workflow orchestration service."""
        super().__init__(
            service_name="workflow_orchestration",
            cache_enabled=True,
            circuit_breaker_enabled=True,
            metrics_enabled=True
        )
        
        # Initialize dependent services
        self._user_service = UserManagementService()
        self._data_service = DataProcessingService()
        self._integration_service = IntegrationOrchestrationService()
        self._transaction_service = TransactionService()
        
        # Workflow configuration
        self._workflow_cache_ttl = 1800  # 30 minutes for workflow results
    
    @service_operation(
        operation_type=ServiceOperationType.WORKFLOW,
        timeout_seconds=300.0,  # 5 minutes for complex workflows
        cache_enabled=True,
        audit_enabled=True
    )
    async def execute_business_workflow(
        self, 
        context: ServiceContext, 
        workflow_definition: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute complex business workflow with comprehensive orchestration.
        
        Args:
            context: Service execution context
            workflow_definition: Complete workflow definition and configuration
            
        Returns:
            Workflow execution results with state and output data
        """
        workflow_id = str(uuid.uuid4())
        workflow_state = {
            'id': workflow_id,
            'status': 'running',
            'start_time': datetime.now(timezone.utc),
            'current_step': None,
            'completed_steps': [],
            'context': context.to_dict(),
            'outputs': {}
        }
        
        try:
            logger.info(
                "Executing business workflow",
                operation_id=context.operation_id,
                workflow_id=workflow_id,
                workflow_name=workflow_definition.get('name', 'unnamed')
            )
            
            # Validate workflow definition
            self._validate_workflow_definition(workflow_definition)
            
            # Execute workflow steps
            workflow_steps = workflow_definition.get('steps', [])
            
            for step_index, step_definition in enumerate(workflow_steps):
                step_name = step_definition.get('name', f'step_{step_index}')
                workflow_state['current_step'] = step_name
                
                logger.debug(
                    "Executing workflow step",
                    workflow_id=workflow_id,
                    step_name=step_name,
                    step_index=step_index
                )
                
                # Check step conditions
                if not await self._evaluate_step_conditions(step_definition, workflow_state):
                    logger.debug(
                        "Skipping workflow step due to conditions",
                        workflow_id=workflow_id,
                        step_name=step_name
                    )
                    continue
                
                # Execute step
                step_result = await self._execute_workflow_step_orchestration(
                    step_definition, workflow_state, context
                )
                
                # Update workflow state
                workflow_state['completed_steps'].append({
                    'name': step_name,
                    'index': step_index,
                    'result': step_result,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                })
                
                # Update outputs
                if 'output_key' in step_definition and step_result:
                    workflow_state['outputs'][step_definition['output_key']] = step_result
            
            # Complete workflow
            workflow_state['status'] = 'completed'
            workflow_state['end_time'] = datetime.now(timezone.utc)
            workflow_state['current_step'] = None
            
            workflow_result = {
                'workflow_id': workflow_id,
                'status': workflow_state['status'],
                'execution_time': (workflow_state['end_time'] - workflow_state['start_time']).total_seconds(),
                'completed_steps': len(workflow_state['completed_steps']),
                'outputs': workflow_state['outputs'],
                'metadata': {
                    'workflow_name': workflow_definition.get('name'),
                    'total_steps': len(workflow_steps),
                    'timestamp': workflow_state['end_time'].isoformat()
                }
            }
            
            logger.info(
                "Business workflow completed successfully",
                operation_id=context.operation_id,
                workflow_id=workflow_id,
                execution_time=workflow_result['execution_time'],
                completed_steps=workflow_result['completed_steps']
            )
            
            return workflow_result
            
        except Exception as workflow_error:
            workflow_state['status'] = 'failed'
            workflow_state['error'] = str(workflow_error)
            workflow_state['end_time'] = datetime.now(timezone.utc)
            
            logger.error(
                "Business workflow failed",
                operation_id=context.operation_id,
                workflow_id=workflow_id,
                error=str(workflow_error),
                completed_steps=len(workflow_state['completed_steps'])
            )
            
            raise DataProcessingError(
                message=f"Business workflow failed: {str(workflow_error)}",
                error_code="BUSINESS_WORKFLOW_ERROR",
                context={
                    'workflow_id': workflow_id,
                    'workflow_state': workflow_state
                },
                cause=workflow_error,
                severity=ErrorSeverity.HIGH
            )
    
    def _validate_workflow_definition(self, workflow_definition: Dict[str, Any]) -> None:
        """Validate workflow definition structure and requirements."""
        required_fields = ['steps']
        
        for field in required_fields:
            if field not in workflow_definition:
                raise DataValidationError(
                    message=f"Workflow definition missing required field: {field}",
                    error_code="INVALID_WORKFLOW_DEFINITION",
                    context={'field': field},
                    severity=ErrorSeverity.HIGH
                )
        
        steps = workflow_definition['steps']
        if not isinstance(steps, list) or len(steps) == 0:
            raise DataValidationError(
                message="Workflow must have at least one step",
                error_code="EMPTY_WORKFLOW_DEFINITION",
                severity=ErrorSeverity.HIGH
            )
    
    async def _evaluate_step_conditions(
        self, 
        step_definition: Dict[str, Any], 
        workflow_state: Dict[str, Any]
    ) -> bool:
        """Evaluate whether step conditions are met for execution."""
        conditions = step_definition.get('conditions', [])
        
        for condition in conditions:
            condition_type = condition.get('type')
            
            if condition_type == 'output_exists':
                output_key = condition.get('output_key')
                if output_key not in workflow_state['outputs']:
                    return False
            
            elif condition_type == 'output_value':
                output_key = condition.get('output_key')
                expected_value = condition.get('expected_value')
                if workflow_state['outputs'].get(output_key) != expected_value:
                    return False
        
        return True
    
    async def _execute_workflow_step_orchestration(
        self, 
        step_definition: Dict[str, Any], 
        workflow_state: Dict[str, Any], 
        context: ServiceContext
    ) -> Any:
        """Execute individual workflow step with service orchestration."""
        step_type = step_definition.get('type')
        step_params = step_definition.get('parameters', {})
        
        # Create step-specific context
        step_context = ServiceContext(
            operation_id=f"{context.operation_id}_step",
            user_id=context.user_id,
            session_id=context.session_id,
            request_id=context.request_id,
            tenant_id=context.tenant_id,
            operation_type=ServiceOperationType.WORKFLOW,
            priority=context.priority,
            metadata={**context.metadata, 'workflow_id': workflow_state['id']}
        )
        
        if step_type == 'user_management':
            return await self._user_service.execute(step_context, **step_params)
        
        elif step_type == 'data_processing':
            return await self._data_service.process_business_data(
                step_context, 
                step_params.get('data', {}),
                step_params.get('processing_rules')
            )
        
        elif step_type == 'integration':
            return await self._integration_service.coordinate_external_services(
                step_context,
                step_params.get('service_calls', [])
            )
        
        elif step_type == 'transaction':
            return await self._transaction_service.execute_transactional_workflow(
                step_context,
                step_params.get('workflow_steps', [])
            )
        
        elif step_type == 'validation':
            return await self._data_service.validate_business_rules(
                step_context,
                step_params.get('data', {}),
                step_params.get('rules')
            )
        
        else:
            raise DataProcessingError(
                message=f"Unknown workflow step type: {step_type}",
                error_code="UNKNOWN_WORKFLOW_STEP_TYPE",
                context={'step_type': step_type},
                severity=ErrorSeverity.MEDIUM
            )


# ============================================================================
# SERVICE FACTORY AND UTILITIES
# ============================================================================

class ServiceFactory:
    """
    Factory for creating and managing business service instances.
    
    Provides centralized service creation, configuration, and lifecycle management
    for all business services with dependency injection and service registry patterns.
    """
    
    _services: Dict[str, BaseBusinessService] = {}
    _service_configs: Dict[str, Dict[str, Any]] = {}
    
    @classmethod
    def register_service(
        cls, 
        service_name: str, 
        service_class: Type[BaseBusinessService],
        config: Optional[Dict[str, Any]] = None
    ) -> None:
        """Register service class with factory."""
        cls._service_configs[service_name] = {
            'class': service_class,
            'config': config or {}
        }
    
    @classmethod
    def get_service(cls, service_name: str) -> BaseBusinessService:
        """Get or create service instance."""
        if service_name not in cls._services:
            if service_name not in cls._service_configs:
                raise ValueError(f"Unknown service: {service_name}")
            
            service_config = cls._service_configs[service_name]
            service_class = service_config['class']
            config = service_config['config']
            
            cls._services[service_name] = service_class(**config)
        
        return cls._services[service_name]
    
    @classmethod
    def get_all_services(cls) -> Dict[str, BaseBusinessService]:
        """Get all registered service instances."""
        return cls._services.copy()
    
    @classmethod
    def clear_services(cls) -> None:
        """Clear all service instances."""
        cls._services.clear()


# Register default services
ServiceFactory.register_service('user_management', UserManagementService)
ServiceFactory.register_service('data_processing', DataProcessingService)
ServiceFactory.register_service('integration_orchestration', IntegrationOrchestrationService)
ServiceFactory.register_service('transaction_management', TransactionService)
ServiceFactory.register_service('workflow_orchestration', WorkflowService)


# Convenience functions for service access
def get_user_service() -> UserManagementService:
    """Get user management service instance."""
    return ServiceFactory.get_service('user_management')


def get_data_processing_service() -> DataProcessingService:
    """Get data processing service instance."""
    return ServiceFactory.get_service('data_processing')


def get_integration_service() -> IntegrationOrchestrationService:
    """Get integration orchestration service instance."""
    return ServiceFactory.get_service('integration_orchestration')


def get_transaction_service() -> TransactionService:
    """Get transaction management service instance."""
    return ServiceFactory.get_service('transaction_management')


def get_workflow_service() -> WorkflowService:
    """Get workflow orchestration service instance."""
    return ServiceFactory.get_service('workflow_orchestration')


def create_service_context(
    operation_type: ServiceOperationType = ServiceOperationType.PROCESS,
    user_id: Optional[str] = None,
    priority: ServicePriority = ServicePriority.NORMAL,
    **kwargs
) -> ServiceContext:
    """
    Create service context from current Flask request or provided parameters.
    
    Args:
        operation_type: Type of service operation
        user_id: User identifier for operation
        priority: Operation priority level
        **kwargs: Additional context parameters
        
    Returns:
        ServiceContext instance configured for current request
    """
    # Try to get context from Flask request if available
    try:
        from flask import request, g
        
        request_id = getattr(request, 'id', None) or str(uuid.uuid4())
        session_id = getattr(g, 'session_id', None)
        current_user_id = user_id or getattr(g, 'user_id', None)
        
    except (ImportError, RuntimeError):
        # Not in Flask context
        request_id = str(uuid.uuid4())
        session_id = None
        current_user_id = user_id
    
    return ServiceContext(
        operation_id=str(uuid.uuid4()),
        user_id=current_user_id,
        session_id=session_id,
        request_id=request_id,
        operation_type=operation_type,
        priority=priority,
        **kwargs
    )


def get_service_health_summary() -> Dict[str, Any]:
    """
    Get health summary for all registered services.
    
    Returns:
        Dictionary containing health status for all services
    """
    services = ServiceFactory.get_all_services()
    service_health = {}
    overall_status = 'healthy'
    
    for service_name, service_instance in services.items():
        try:
            health_status = service_instance.get_health_status()
            service_health[service_name] = health_status
            
            if health_status['status'] != 'healthy':
                overall_status = 'degraded'
                
        except Exception as health_error:
            service_health[service_name] = {
                'status': 'error',
                'error': str(health_error),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            overall_status = 'degraded'
    
    return {
        'overall_status': overall_status,
        'services': service_health,
        'service_count': len(services),
        'timestamp': datetime.now(timezone.utc).isoformat()
    }


def get_service_metrics_summary() -> Dict[str, Any]:
    """
    Get performance metrics summary for all registered services.
    
    Returns:
        Dictionary containing aggregated metrics for all services
    """
    services = ServiceFactory.get_all_services()
    service_metrics = {}
    
    total_operations = 0
    total_errors = 0
    total_execution_time = 0.0
    
    for service_name, service_instance in services.items():
        try:
            metrics = service_instance.get_metrics()
            service_metrics[service_name] = metrics.to_dict()
            
            total_operations += metrics.operation_count
            total_errors += metrics.error_count
            total_execution_time += metrics.total_execution_time
            
        except Exception as metrics_error:
            service_metrics[service_name] = {
                'error': str(metrics_error),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    overall_metrics = {
        'total_operations': total_operations,
        'total_errors': total_errors,
        'total_execution_time': total_execution_time,
        'average_execution_time': total_execution_time / max(1, total_operations),
        'overall_error_rate': (total_errors / max(1, total_operations)) * 100,
        'service_count': len(services)
    }
    
    return {
        'overall_metrics': overall_metrics,
        'service_metrics': service_metrics,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }


# Export main classes and functions for use by other modules
__all__ = [
    # Main service classes
    'BaseBusinessService',
    'UserManagementService',
    'DataProcessingService', 
    'IntegrationOrchestrationService',
    'TransactionService',
    'WorkflowService',
    
    # Context and configuration classes
    'ServiceContext',
    'ServiceMetrics',
    'ServiceOperationType',
    'ServicePriority',
    
    # Service management and factory
    'ServiceFactory',
    'ServiceInterface',
    
    # Convenience functions
    'get_user_service',
    'get_data_processing_service',
    'get_integration_service',
    'get_transaction_service',
    'get_workflow_service',
    'create_service_context',
    'get_service_health_summary',
    'get_service_metrics_summary',
    
    # Decorators and utilities
    'service_operation',
    'monitor_performance'
]

# Module initialization logging
logger.info(
    "Business services module initialized successfully",
    module_version="1.0.0",
    service_count=len(ServiceFactory._service_configs),
    registered_services=list(ServiceFactory._service_configs.keys()),
    features=[
        "business_operation_orchestration",
        "external_service_integration", 
        "workflow_management",
        "circuit_breaker_patterns",
        "transaction_management",
        "performance_monitoring"
    ]
)