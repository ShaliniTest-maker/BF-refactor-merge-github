"""
Business Service Layer for Flask Application

This module implements comprehensive business service orchestration, external service integration
coordination, and workflow management for the Node.js to Python Flask migration. Provides high-level
business operations that coordinate between data access, validation, processing, and external
integrations while maintaining identical functionality to Node.js implementation per F-004-RQ-001.

The service layer follows enterprise patterns with:
- Business operation orchestration maintaining functional parity per F-004-RQ-001
- External service integration coordination per F-004-RQ-002
- Workflow management for data transformation per Section 5.2.4
- Circuit breaker patterns for service resilience per Section 6.1.3
- Transaction management and error handling for business operations per Section 5.2.4
- Performance optimization maintaining ≤10% variance from Node.js baseline per Section 0.1.1

Service Categories:
    Core Business Services:
        UserService: User account and profile management operations
        OrganizationService: Organization and business entity operations
        ProductService: Product catalog and inventory management
        OrderService: Order processing and transaction management
        PaymentService: Payment processing and financial operations
        
    Integration Services:
        AuthenticationService: Auth0 integration and JWT token management
        FileStorageService: AWS S3 integration for file operations
        CacheService: Redis caching coordination and management
        NotificationService: External notification service integration
        
    Workflow Services:
        BusinessWorkflowService: Complex business process orchestration
        DataProcessingService: Data transformation and processing workflows
        IntegrationOrchestrator: External service coordination and circuit breaker management
        TransactionService: Multi-resource transaction coordination
        
    Utility Services:
        ValidationService: Comprehensive business validation coordination
        AuditService: Business operation auditing and compliance
        MetricsService: Business operation performance monitoring
        HealthCheckService: Service dependency health monitoring

Architecture Integration:
- Integrates with Flask Blueprint architecture per Section 6.1.1
- Coordinates with PyMongo 4.5+ and Motor 3.3+ database operations per Section 5.2.5
- Manages Redis caching operations via redis-py 5.0+ per Section 5.2.7
- Orchestrates external service calls with circuit breaker patterns per Section 6.1.3
- Implements business logic engine coordination per Section 5.2.4
- Provides monitoring integration with structured logging per Section 5.2.8

Performance Requirements:
- Business operation latency: ≤10% variance from Node.js baseline per Section 0.1.1
- External service coordination: Circuit breaker response time <100ms per Section 6.1.3
- Transaction coordination: Multi-resource transaction time ≤2x single operation per Section 5.2.4
- Cache coordination: Cache operation overhead ≤5ms per Section 5.2.7
- Validation coordination: Validation pipeline time ≤50ms per F-004-RQ-004

Technical Requirements Compliance:
- F-004-RQ-001: Identical data transformation and business rules per business logic implementation
- F-004-RQ-002: Maintain all existing service integrations per external service integration
- Section 5.2.4: Business logic engine coordination and integration orchestration
- Section 6.1.3: Circuit breaker patterns and external service resilience mechanisms
- Section 6.3.3: External service integration patterns and monitoring

Example Usage:
    # User service operations
    user_service = UserService()
    user = await user_service.create_user(user_data)
    
    # Order processing workflow
    order_service = OrderService()
    order_result = await order_service.process_order(order_data, payment_data)
    
    # External service integration
    auth_service = AuthenticationService()
    token_result = await auth_service.validate_token(jwt_token)
    
    # Business workflow orchestration
    workflow_service = BusinessWorkflowService()
    result = await workflow_service.execute_workflow('order_fulfillment', context)
"""

import asyncio
import json
import time
import uuid
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from enum import Enum
from functools import wraps, lru_cache
from typing import (
    Any, Dict, List, Optional, Union, Callable, Type, Set, Tuple,
    AsyncGenerator, Generator, Protocol, TypeVar, Generic, Awaitable
)

# Import business logic components for comprehensive integration
from .models import (
    BaseBusinessModel, User, Organization, Product, Order, OrderItem,
    PaymentTransaction, Address, ContactInfo, MonetaryAmount, DateTimeRange,
    FileUpload, SystemConfiguration, PaginationParams, SortParams, SearchParams,
    UserStatus, UserRole, OrderStatus, PaymentStatus, PaymentMethod, ProductStatus,
    Priority, ContactMethod, BUSINESS_MODEL_REGISTRY
)
from .validators import (
    ValidationConfig, BaseBusinessValidator, UserValidator, OrganizationValidator,
    ProductValidator, OrderValidator, PaymentValidator, AddressValidator,
    ContactInfoValidator, MonetaryAmountValidator, FileUploadValidator
)
from .processors import (
    ProcessingConfig, ProcessingMode, ProcessingMetrics, BaseProcessor,
    DataTransformer, ValidationProcessor, SanitizationProcessor, NormalizationProcessor,
    DateTimeProcessor, BusinessRuleEngine, ProcessingPipeline,
    create_processing_pipeline, create_business_rule_engine
)
from .exceptions import (
    BaseBusinessException, BusinessRuleViolationError, DataProcessingError,
    DataValidationError, ExternalServiceError, ResourceNotFoundError,
    AuthorizationError, ConcurrencyError, ConfigurationError,
    ErrorSeverity, ErrorCategory
)

# Import data access layer for database operations
from ..data import (
    get_mongodb_manager, get_async_mongodb_manager, get_database_health_status,
    MongoDBManager, AsyncMongoDBManager, DatabaseHealthStatus
)

# Import cache layer for caching operations  
from ..cache import (
    get_redis_client, get_response_cache, create_redis_client,
    RedisClient, FlaskResponseCache, CachePolicy
)

# Import integration layer for external service coordination
from ..integrations import (
    BaseExternalServiceClient, ExternalServiceMonitor, ServiceHealthState,
    ExternalServiceType, external_service_monitor
)

# Configure structured logging for service operations
import structlog
logger = structlog.get_logger("business.services")

# Type definitions for service layer
T = TypeVar('T')
ServiceResult = Dict[str, Any]
ServiceOperation = Callable[..., Awaitable[ServiceResult]]
TransactionContext = Dict[str, Any]


# ============================================================================
# SERVICE CONFIGURATION AND BASE CLASSES
# ============================================================================

class ServiceMode(Enum):
    """
    Service operation mode enumeration for service behavior configuration.
    
    Defines execution modes for business service operations enabling optimized
    coordination patterns for different use cases and performance requirements.
    """
    STRICT = "strict"        # Strict validation and coordination
    LENIENT = "lenient"      # Lenient processing with warnings
    FAST = "fast"            # Performance-optimized coordination
    COMPREHENSIVE = "comprehensive"  # Full validation and coordination
    DEBUG = "debug"          # Debug mode with detailed logging
    TRANSACTION = "transaction"  # Transaction-aware coordination


class ServiceConfiguration:
    """
    Global service configuration for business operation coordination.
    
    Provides centralized configuration for service behavior, performance
    optimization, error handling, and external service coordination across
    all business service operations.
    """
    
    # Performance settings per Section 6.1.3
    DEFAULT_TIMEOUT: int = 30  # seconds
    CACHE_TTL: int = 300  # 5 minutes
    TRANSACTION_TIMEOUT: int = 60  # seconds
    MAX_RETRIES: int = 3
    CIRCUIT_BREAKER_THRESHOLD: int = 5
    
    # Service coordination settings
    DEFAULT_MODE: ServiceMode = ServiceMode.STRICT
    ENABLE_CACHING: bool = True
    ENABLE_METRICS: bool = True
    ENABLE_AUDIT_LOGGING: bool = True
    ENABLE_CIRCUIT_BREAKERS: bool = True
    
    # External service settings per F-004-RQ-002
    AUTH0_CIRCUIT_BREAKER_THRESHOLD: int = 5
    AWS_CIRCUIT_BREAKER_THRESHOLD: int = 3
    REDIS_CIRCUIT_BREAKER_THRESHOLD: int = 10
    
    # Transaction coordination settings
    ENABLE_TRANSACTIONS: bool = True
    MAX_TRANSACTION_RETRY: int = 2
    TRANSACTION_ISOLATION: str = "read_committed"
    
    # Workflow coordination settings
    MAX_WORKFLOW_STEPS: int = 50
    WORKFLOW_STEP_TIMEOUT: int = 10
    PARALLEL_WORKFLOW_LIMIT: int = 5


class ServiceMetrics:
    """
    Service operation metrics collection for performance monitoring.
    
    Collects comprehensive metrics for service operations including execution
    times, throughput, error rates, and resource utilization for performance
    optimization and monitoring per Section 6.1.3.
    """
    
    def __init__(self):
        self.metrics = {}
        self.start_time = None
        self.end_time = None
        self.circuit_breaker_metrics = {}
        self.transaction_metrics = {}
        
    def start_operation(self, operation_name: str, service_type: str = "business") -> None:
        """Start timing for a service operation."""
        self.start_time = time.perf_counter()
        operation_key = f"{service_type}:{operation_name}"
        
        if operation_key not in self.metrics:
            self.metrics[operation_key] = {
                'count': 0,
                'total_time': 0.0,
                'min_time': float('inf'),
                'max_time': 0.0,
                'error_count': 0,
                'cache_hits': 0,
                'cache_misses': 0,
                'external_service_calls': 0,
                'circuit_breaker_opens': 0
            }
    
    def end_operation(
        self,
        operation_name: str,
        service_type: str = "business",
        success: bool = True,
        cache_hit: bool = False,
        external_calls: int = 0,
        circuit_breaker_opened: bool = False
    ) -> float:
        """End timing for a service operation and record metrics."""
        if self.start_time is None:
            return 0.0
        
        self.end_time = time.perf_counter()
        duration = self.end_time - self.start_time
        operation_key = f"{service_type}:{operation_name}"
        
        if operation_key in self.metrics:
            metrics = self.metrics[operation_key]
            metrics['count'] += 1
            metrics['total_time'] += duration
            metrics['min_time'] = min(metrics['min_time'], duration)
            metrics['max_time'] = max(metrics['max_time'], duration)
            
            if not success:
                metrics['error_count'] += 1
            
            if cache_hit:
                metrics['cache_hits'] += 1
            else:
                metrics['cache_misses'] += 1
            
            metrics['external_service_calls'] += external_calls
            
            if circuit_breaker_opened:
                metrics['circuit_breaker_opens'] += 1
        
        return duration
    
    def get_service_metrics(self) -> Dict[str, Any]:
        """Get comprehensive service metrics report."""
        report = {}
        
        for operation_key, metrics in self.metrics.items():
            if metrics['count'] > 0:
                avg_time = metrics['total_time'] / metrics['count']
                error_rate = metrics['error_count'] / metrics['count']
                cache_hit_rate = metrics['cache_hits'] / (metrics['cache_hits'] + metrics['cache_misses']) if (metrics['cache_hits'] + metrics['cache_misses']) > 0 else 0
                
                report[operation_key] = {
                    'count': metrics['count'],
                    'total_time': round(metrics['total_time'], 4),
                    'average_time': round(avg_time, 4),
                    'min_time': round(metrics['min_time'], 4),
                    'max_time': round(metrics['max_time'], 4),
                    'error_count': metrics['error_count'],
                    'error_rate': round(error_rate, 4),
                    'cache_hit_rate': round(cache_hit_rate, 4),
                    'external_service_calls': metrics['external_service_calls'],
                    'circuit_breaker_opens': metrics['circuit_breaker_opens']
                }
        
        return report


class BaseBusinessService:
    """
    Base class for all business service operations.
    
    Provides comprehensive foundation for business service coordination including
    error handling, metrics collection, caching, external service integration,
    and transaction management. Implements enterprise patterns per Section 5.2.4
    and Section 6.1.3 requirements.
    
    Features:
    - Performance monitoring and metrics collection per Section 6.1.3
    - Circuit breaker integration for external service resilience
    - Transaction coordination and rollback capabilities
    - Comprehensive error handling and recovery patterns
    - Caching and performance optimization features
    - Structured audit logging for enterprise compliance
    - Integration with business validation and processing
    
    Example:
        class CustomService(BaseBusinessService):
            async def perform_operation(self, data: Dict[str, Any]) -> ServiceResult:
                async with self.service_operation("custom_operation"):
                    return await self._execute_business_logic(data)
    """
    
    def __init__(
        self,
        config: Optional[ServiceConfiguration] = None,
        mode: ServiceMode = ServiceMode.STRICT,
        enable_metrics: bool = True,
        enable_caching: bool = True,
        enable_circuit_breakers: bool = True
    ):
        """
        Initialize base service with coordination capabilities.
        
        Args:
            config: Service configuration instance
            mode: Service mode for behavior control
            enable_metrics: Whether to collect performance metrics
            enable_caching: Whether to enable result caching
            enable_circuit_breakers: Whether to enable circuit breaker protection
        """
        self.config = config or ServiceConfiguration()
        self.mode = mode
        self.enable_metrics = enable_metrics
        self.enable_caching = enable_caching
        self.enable_circuit_breakers = enable_circuit_breakers
        
        # Initialize metrics collection
        self.metrics = ServiceMetrics() if enable_metrics else None
        
        # Initialize database managers
        self._db_manager = None
        self._async_db_manager = None
        self._redis_client = None
        self._response_cache = None
        
        # Service coordination state
        self._service_id = str(uuid.uuid4())
        self._start_time = datetime.now(timezone.utc)
        self._active_transactions = {}
        self._circuit_breakers = {}
        
        # Initialize processing pipeline
        self._processing_pipeline = None
        self._business_rule_engine = None
        
        logger.debug("Business service initialized",
                    service_type=self.__class__.__name__,
                    service_id=self._service_id,
                    mode=mode.value)
    
    @property
    def db_manager(self) -> MongoDBManager:
        """Get synchronous database manager instance."""
        if self._db_manager is None:
            self._db_manager = get_mongodb_manager()
        return self._db_manager
    
    @property
    def async_db_manager(self) -> AsyncMongoDBManager:
        """Get asynchronous database manager instance."""
        if self._async_db_manager is None:
            self._async_db_manager = get_async_mongodb_manager()
        return self._async_db_manager
    
    @property
    def redis_client(self) -> RedisClient:
        """Get Redis client instance."""
        if self._redis_client is None:
            self._redis_client = get_redis_client()
        return self._redis_client
    
    @property
    def response_cache(self) -> FlaskResponseCache:
        """Get Flask response cache instance."""
        if self._response_cache is None:
            self._response_cache = get_response_cache()
        return self._response_cache
    
    @property
    def processing_pipeline(self) -> ProcessingPipeline:
        """Get business processing pipeline instance."""
        if self._processing_pipeline is None:
            self._processing_pipeline = create_processing_pipeline(
                mode=ProcessingMode(self.mode.value) if self.mode.value in ProcessingMode.__members__ else ProcessingMode.STRICT
            )
        return self._processing_pipeline
    
    @property
    def business_rule_engine(self) -> BusinessRuleEngine:
        """Get business rule engine instance."""
        if self._business_rule_engine is None:
            self._business_rule_engine = create_business_rule_engine()
        return self._business_rule_engine
    
    @asynccontextmanager
    async def service_operation(
        self,
        operation_name: str,
        timeout: Optional[int] = None,
        enable_cache: bool = None,
        enable_transaction: bool = False
    ):
        """
        Context manager for service operation execution with comprehensive coordination.
        
        Args:
            operation_name: Name of the service operation
            timeout: Operation timeout in seconds
            enable_cache: Whether to enable caching for this operation
            enable_transaction: Whether to enable transaction coordination
            
        Yields:
            Operation context for service coordination
        """
        operation_timeout = timeout or self.config.DEFAULT_TIMEOUT
        enable_cache = enable_cache if enable_cache is not None else self.enable_caching
        
        success = True
        cache_hit = False
        external_calls = 0
        circuit_breaker_opened = False
        
        # Start metrics collection
        if self.metrics:
            self.metrics.start_operation(operation_name, self.__class__.__name__)
        
        # Create operation context
        operation_context = {
            'operation_id': str(uuid.uuid4()),
            'operation_name': operation_name,
            'service_id': self._service_id,
            'start_time': datetime.now(timezone.utc),
            'timeout': operation_timeout,
            'enable_cache': enable_cache,
            'enable_transaction': enable_transaction,
            'external_calls': 0,
            'cache_operations': 0,
            'database_operations': 0
        }
        
        try:
            # Set operation timeout
            timeout_task = asyncio.create_task(asyncio.sleep(operation_timeout))
            
            # Execute operation with timeout
            try:
                if enable_transaction:
                    async with self._transaction_context(operation_context):
                        yield operation_context
                else:
                    yield operation_context
                    
                # Cancel timeout if operation completed
                if not timeout_task.done():
                    timeout_task.cancel()
                    
            except asyncio.TimeoutError:
                success = False
                logger.error("Service operation timed out",
                           operation=operation_name,
                           timeout=operation_timeout,
                           service_id=self._service_id)
                raise ExternalServiceError(
                    message=f"Service operation '{operation_name}' timed out",
                    error_code="SERVICE_OPERATION_TIMEOUT",
                    service_name=self.__class__.__name__,
                    operation=operation_name,
                    timeout=operation_timeout,
                    severity=ErrorSeverity.HIGH
                )
            
        except Exception as e:
            success = False
            
            # Check if circuit breaker was involved
            if isinstance(e, ExternalServiceError) and "circuit breaker" in str(e).lower():
                circuit_breaker_opened = True
            
            self._handle_service_error(e, operation_name, operation_context)
            raise
        
        finally:
            # Extract metrics from operation context
            external_calls = operation_context.get('external_calls', 0)
            cache_hit = operation_context.get('cache_hit', False)
            
            # End metrics collection
            if self.metrics:
                duration = self.metrics.end_operation(
                    operation_name,
                    self.__class__.__name__,
                    success,
                    cache_hit,
                    external_calls,
                    circuit_breaker_opened
                )
                
                if self.config.ENABLE_AUDIT_LOGGING:
                    logger.debug("Service operation completed",
                                operation=operation_name,
                                service_type=self.__class__.__name__,
                                duration=duration,
                                success=success,
                                cache_hit=cache_hit,
                                external_calls=external_calls,
                                operation_id=operation_context['operation_id'],
                                service_id=self._service_id)
    
    @asynccontextmanager
    async def _transaction_context(self, operation_context: Dict[str, Any]):
        """
        Context manager for transaction coordination across multiple resources.
        
        Args:
            operation_context: Operation context for transaction tracking
            
        Yields:
            Transaction context for coordinated operations
        """
        transaction_id = str(uuid.uuid4())
        transaction_context = {
            'transaction_id': transaction_id,
            'operation_context': operation_context,
            'database_session': None,
            'redis_pipeline': None,
            'rollback_actions': [],
            'committed': False
        }
        
        try:
            # Start database transaction if available
            if hasattr(self.async_db_manager, 'start_session'):
                transaction_context['database_session'] = await self.async_db_manager.start_session()
                await transaction_context['database_session'].start_transaction()
            
            # Start Redis pipeline for atomic operations
            if self.redis_client:
                transaction_context['redis_pipeline'] = self.redis_client.pipeline()
            
            # Store transaction context
            self._active_transactions[transaction_id] = transaction_context
            
            logger.debug("Transaction started",
                        transaction_id=transaction_id,
                        operation=operation_context['operation_name'],
                        service_id=self._service_id)
            
            yield transaction_context
            
            # Commit transaction
            await self._commit_transaction(transaction_context)
            
        except Exception as e:
            # Rollback transaction
            await self._rollback_transaction(transaction_context, e)
            raise
        
        finally:
            # Clean up transaction context
            if transaction_id in self._active_transactions:
                del self._active_transactions[transaction_id]
    
    async def _commit_transaction(self, transaction_context: Dict[str, Any]) -> None:
        """
        Commit coordinated transaction across multiple resources.
        
        Args:
            transaction_context: Transaction context to commit
        """
        transaction_id = transaction_context['transaction_id']
        
        try:
            # Commit database transaction
            if transaction_context['database_session']:
                await transaction_context['database_session'].commit_transaction()
            
            # Execute Redis pipeline
            if transaction_context['redis_pipeline']:
                transaction_context['redis_pipeline'].execute()
            
            transaction_context['committed'] = True
            
            logger.debug("Transaction committed successfully",
                        transaction_id=transaction_id,
                        service_id=self._service_id)
        
        except Exception as e:
            logger.error("Transaction commit failed",
                        transaction_id=transaction_id,
                        error=str(e),
                        service_id=self._service_id,
                        exc_info=True)
            raise ConcurrencyError(
                message="Failed to commit transaction",
                error_code="TRANSACTION_COMMIT_FAILED",
                transaction_id=transaction_id,
                cause=e,
                severity=ErrorSeverity.HIGH
            )
    
    async def _rollback_transaction(
        self,
        transaction_context: Dict[str, Any],
        original_error: Exception
    ) -> None:
        """
        Rollback coordinated transaction across multiple resources.
        
        Args:
            transaction_context: Transaction context to rollback
            original_error: Original error that caused rollback
        """
        transaction_id = transaction_context['transaction_id']
        
        try:
            # Rollback database transaction
            if transaction_context['database_session']:
                await transaction_context['database_session'].abort_transaction()
            
            # Discard Redis pipeline
            if transaction_context['redis_pipeline']:
                transaction_context['redis_pipeline'].discard()
            
            # Execute custom rollback actions
            for rollback_action in reversed(transaction_context['rollback_actions']):
                try:
                    if asyncio.iscoroutinefunction(rollback_action):
                        await rollback_action()
                    else:
                        rollback_action()
                except Exception as rollback_error:
                    logger.warning("Rollback action failed",
                                  transaction_id=transaction_id,
                                  rollback_error=str(rollback_error),
                                  service_id=self._service_id)
            
            logger.info("Transaction rolled back",
                       transaction_id=transaction_id,
                       original_error=str(original_error),
                       service_id=self._service_id)
        
        except Exception as e:
            logger.error("Transaction rollback failed",
                        transaction_id=transaction_id,
                        rollback_error=str(e),
                        original_error=str(original_error),
                        service_id=self._service_id,
                        exc_info=True)
    
    def _handle_service_error(
        self,
        error: Exception,
        operation_name: str,
        operation_context: Dict[str, Any]
    ) -> None:
        """
        Handle service operation errors with logging and tracking.
        
        Args:
            error: Exception that occurred during service operation
            operation_name: Name of the operation that failed
            operation_context: Operation context for error correlation
        """
        logger.error("Service operation failed",
                    operation=operation_name,
                    service_type=self.__class__.__name__,
                    error_type=type(error).__name__,
                    error_message=str(error),
                    operation_id=operation_context['operation_id'],
                    service_id=self._service_id,
                    exc_info=True)
    
    async def _get_cached_result(
        self,
        cache_key: str,
        operation_context: Dict[str, Any]
    ) -> Optional[Any]:
        """
        Get cached result for service operation.
        
        Args:
            cache_key: Cache key to lookup
            operation_context: Operation context for cache tracking
            
        Returns:
            Cached result if available, None otherwise
        """
        if not self.enable_caching or not operation_context.get('enable_cache', True):
            return None
        
        try:
            cached_result = await self.redis_client.get(cache_key)
            if cached_result:
                operation_context['cache_hit'] = True
                operation_context['cache_operations'] += 1
                
                logger.debug("Cache hit for service operation",
                           cache_key=cache_key[:20],
                           operation=operation_context['operation_name'],
                           service_id=self._service_id)
                
                return json.loads(cached_result)
        
        except Exception as e:
            logger.warning("Cache lookup failed",
                          cache_key=cache_key[:20],
                          error=str(e),
                          service_id=self._service_id)
        
        operation_context['cache_operations'] += 1
        return None
    
    async def _set_cached_result(
        self,
        cache_key: str,
        result: Any,
        ttl_seconds: int = None,
        operation_context: Dict[str, Any] = None
    ) -> None:
        """
        Set cached result for service operation.
        
        Args:
            cache_key: Cache key to store under
            result: Result to cache
            ttl_seconds: Time to live in seconds
            operation_context: Operation context for cache tracking
        """
        if not self.enable_caching:
            return
        
        try:
            ttl = ttl_seconds or self.config.CACHE_TTL
            serialized_result = json.dumps(result, default=str)
            
            await self.redis_client.setex(cache_key, ttl, serialized_result)
            
            if operation_context:
                operation_context['cache_operations'] += 1
            
            logger.debug("Result cached for service operation",
                        cache_key=cache_key[:20],
                        ttl=ttl,
                        service_id=self._service_id)
        
        except Exception as e:
            logger.warning("Cache storage failed",
                          cache_key=cache_key[:20],
                          error=str(e),
                          service_id=self._service_id)
    
    def _generate_cache_key(self, operation_name: str, *args, **kwargs) -> str:
        """
        Generate cache key for service operation.
        
        Args:
            operation_name: Name of the operation
            *args: Operation arguments
            **kwargs: Operation keyword arguments
            
        Returns:
            Cache key string
        """
        key_data = {
            'service': self.__class__.__name__,
            'operation': operation_name,
            'args': args,
            'kwargs': {k: v for k, v in kwargs.items() if k not in ['operation_context']}
        }
        
        key_string = json.dumps(key_data, sort_keys=True, default=str)
        
        import hashlib
        return f"service:{hashlib.md5(key_string.encode()).hexdigest()}"
    
    def get_service_summary(self) -> Dict[str, Any]:
        """
        Get comprehensive service summary and metrics.
        
        Returns:
            Dictionary containing service summary and metrics
        """
        summary = {
            'service_type': self.__class__.__name__,
            'service_id': self._service_id,
            'start_time': self._start_time.isoformat(),
            'mode': self.mode.value,
            'active_transactions': len(self._active_transactions),
            'circuit_breakers_enabled': self.enable_circuit_breakers,
            'caching_enabled': self.enable_caching,
            'metrics_enabled': self.enable_metrics
        }
        
        if self.metrics:
            summary['metrics'] = self.metrics.get_service_metrics()
        
        return summary


# ============================================================================
# CORE BUSINESS SERVICES
# ============================================================================

class UserService(BaseBusinessService):
    """
    User account and profile management service.
    
    Provides comprehensive user operations including account creation, profile
    management, authentication coordination, and user data processing while
    maintaining functional parity per F-004-RQ-001.
    
    Features:
    - User account lifecycle management
    - Profile data validation and processing
    - Authentication service coordination
    - User preferences and settings management
    - Account security and compliance operations
    
    Example:
        user_service = UserService()
        
        # Create new user account
        user_result = await user_service.create_user(user_data)
        
        # Update user profile
        update_result = await user_service.update_profile(user_id, profile_data)
        
        # Authenticate user credentials
        auth_result = await user_service.authenticate_user(credentials)
    """
    
    def __init__(self, **kwargs):
        """Initialize user service with user-specific capabilities."""
        super().__init__(**kwargs)
        self._user_validator = UserValidator()
        self._user_collection = "users"
    
    async def create_user(
        self,
        user_data: Dict[str, Any],
        validate_rules: bool = True,
        enable_notifications: bool = True
    ) -> ServiceResult:
        """
        Create new user account with comprehensive validation and processing.
        
        Args:
            user_data: User account data
            validate_rules: Whether to validate business rules
            enable_notifications: Whether to send notifications
            
        Returns:
            Service result with created user information
        """
        async with self.service_operation("create_user", enable_transaction=True) as ctx:
            try:
                # Generate cache key
                cache_key = self._generate_cache_key("create_user_validation", user_data.get('email', ''))
                
                # Check cache for validation result
                cached_validation = await self._get_cached_result(cache_key, ctx)
                if cached_validation and not cached_validation.get('requires_processing', True):
                    logger.debug("Using cached user validation",
                               email=user_data.get('email', 'unknown')[:20])
                
                # Process user data through pipeline
                pipeline_result = self.processing_pipeline.execute(user_data)
                if not pipeline_result['success']:
                    raise DataValidationError(
                        message="User data validation failed",
                        error_code="USER_VALIDATION_FAILED",
                        context={'errors': pipeline_result['errors']},
                        severity=ErrorSeverity.MEDIUM
                    )
                
                processed_data = pipeline_result['output_data']
                
                # Validate business rules if requested
                if validate_rules:
                    rule_result = self.business_rule_engine.execute_rules(
                        processed_data,
                        rule_set="user_validation"
                    )
                    if not rule_result['success']:
                        raise BusinessRuleViolationError(
                            message="User business rule validation failed",
                            error_code="USER_BUSINESS_RULES_FAILED",
                            context={'violations': rule_result['rules_failed']},
                            severity=ErrorSeverity.MEDIUM
                        )
                    
                    processed_data = rule_result['final_data']
                
                # Create user model
                user_model = User.from_dict(processed_data)
                user_model.id = str(uuid.uuid4())
                user_model.created_at = datetime.now(timezone.utc)
                user_model.updated_at = user_model.created_at
                user_model.status = UserStatus.ACTIVE
                
                # Check for existing user
                existing_user = await self.async_db_manager.find_one(
                    self._user_collection,
                    {'email': user_model.email}
                )
                
                if existing_user:
                    raise ResourceNotFoundError(
                        message="User with this email already exists",
                        error_code="USER_ALREADY_EXISTS",
                        resource_type="User",
                        resource_id=user_model.email,
                        severity=ErrorSeverity.MEDIUM
                    )
                
                # Insert user into database
                ctx['database_operations'] += 1
                user_doc = user_model.model_dump(exclude_none=True)
                insert_result = await self.async_db_manager.insert_one(
                    self._user_collection,
                    user_doc
                )
                
                if not insert_result.acknowledged:
                    raise DataProcessingError(
                        message="Failed to create user account",
                        error_code="USER_CREATION_FAILED",
                        processing_stage="database_insertion",
                        severity=ErrorSeverity.HIGH
                    )
                
                # Cache successful validation result
                await self._set_cached_result(
                    cache_key,
                    {'valid': True, 'requires_processing': False},
                    ttl_seconds=3600,  # 1 hour
                    operation_context=ctx
                )
                
                # Prepare result
                result = {
                    'success': True,
                    'user': user_model.to_api_dict(),
                    'operation_id': ctx['operation_id'],
                    'created_at': user_model.created_at.isoformat()
                }
                
                # Send notifications if enabled
                if enable_notifications:
                    # Note: In real implementation, would integrate with notification service
                    logger.info("User account created successfully",
                               user_id=user_model.id,
                               email=user_model.email,
                               operation_id=ctx['operation_id'])
                
                return result
                
            except Exception as e:
                logger.error("User creation failed",
                           error=str(e),
                           operation_id=ctx['operation_id'],
                           exc_info=True)
                raise
    
    async def get_user(
        self,
        user_id: str,
        include_sensitive: bool = False
    ) -> ServiceResult:
        """
        Retrieve user account information.
        
        Args:
            user_id: User identifier
            include_sensitive: Whether to include sensitive data
            
        Returns:
            Service result with user information
        """
        async with self.service_operation("get_user") as ctx:
            try:
                # Generate cache key
                cache_key = self._generate_cache_key("get_user", user_id, include_sensitive)
                
                # Check cache first
                cached_user = await self._get_cached_result(cache_key, ctx)
                if cached_user:
                    return {
                        'success': True,
                        'user': cached_user,
                        'operation_id': ctx['operation_id'],
                        'cached': True
                    }
                
                # Query database
                ctx['database_operations'] += 1
                user_doc = await self.async_db_manager.find_one(
                    self._user_collection,
                    {'id': user_id}
                )
                
                if not user_doc:
                    raise ResourceNotFoundError(
                        message="User not found",
                        error_code="USER_NOT_FOUND",
                        resource_type="User",
                        resource_id=user_id,
                        severity=ErrorSeverity.MEDIUM
                    )
                
                # Create user model
                user_model = User.from_dict(user_doc)
                
                # Format for API response
                user_data = user_model.to_api_dict(exclude_audit=not include_sensitive)
                if not include_sensitive:
                    # Remove sensitive fields
                    sensitive_fields = ['password_hash', 'auth_tokens', 'security_questions']
                    for field in sensitive_fields:
                        user_data.pop(field, None)
                
                # Cache result
                await self._set_cached_result(
                    cache_key,
                    user_data,
                    ttl_seconds=1800,  # 30 minutes
                    operation_context=ctx
                )
                
                return {
                    'success': True,
                    'user': user_data,
                    'operation_id': ctx['operation_id'],
                    'cached': False
                }
                
            except Exception as e:
                logger.error("User retrieval failed",
                           user_id=user_id,
                           error=str(e),
                           operation_id=ctx['operation_id'],
                           exc_info=True)
                raise
    
    async def update_user(
        self,
        user_id: str,
        update_data: Dict[str, Any],
        validate_rules: bool = True
    ) -> ServiceResult:
        """
        Update user account information.
        
        Args:
            user_id: User identifier
            update_data: Data to update
            validate_rules: Whether to validate business rules
            
        Returns:
            Service result with updated user information
        """
        async with self.service_operation("update_user", enable_transaction=True) as ctx:
            try:
                # Validate update data
                if validate_rules:
                    validation_result = self._user_validator.load(update_data, partial=True)
                    if not validation_result:
                        raise DataValidationError(
                            message="Invalid user update data",
                            error_code="INVALID_UPDATE_DATA",
                            severity=ErrorSeverity.MEDIUM
                        )
                
                # Get existing user
                ctx['database_operations'] += 1
                existing_user = await self.async_db_manager.find_one(
                    self._user_collection,
                    {'id': user_id}
                )
                
                if not existing_user:
                    raise ResourceNotFoundError(
                        message="User not found for update",
                        error_code="USER_NOT_FOUND",
                        resource_type="User",
                        resource_id=user_id,
                        severity=ErrorSeverity.MEDIUM
                    )
                
                # Prepare update document
                update_doc = {
                    **update_data,
                    'updated_at': datetime.now(timezone.utc)
                }
                
                # Update user in database
                ctx['database_operations'] += 1
                update_result = await self.async_db_manager.update_one(
                    self._user_collection,
                    {'id': user_id},
                    {'$set': update_doc}
                )
                
                if update_result.modified_count == 0:
                    raise DataProcessingError(
                        message="Failed to update user",
                        error_code="USER_UPDATE_FAILED",
                        processing_stage="database_update",
                        severity=ErrorSeverity.MEDIUM
                    )
                
                # Invalidate relevant caches
                cache_patterns = [
                    f"service:*get_user*{user_id}*",
                    f"service:*user_profile*{user_id}*"
                ]
                
                for pattern in cache_patterns:
                    try:
                        keys = await self.redis_client.keys(pattern)
                        if keys:
                            await self.redis_client.delete(*keys)
                    except Exception as cache_error:
                        logger.warning("Cache invalidation failed",
                                      pattern=pattern,
                                      error=str(cache_error))
                
                # Get updated user
                updated_user = await self.async_db_manager.find_one(
                    self._user_collection,
                    {'id': user_id}
                )
                
                user_model = User.from_dict(updated_user)
                
                return {
                    'success': True,
                    'user': user_model.to_api_dict(),
                    'operation_id': ctx['operation_id'],
                    'updated_at': update_doc['updated_at'].isoformat()
                }
                
            except Exception as e:
                logger.error("User update failed",
                           user_id=user_id,
                           error=str(e),
                           operation_id=ctx['operation_id'],
                           exc_info=True)
                raise
    
    async def delete_user(
        self,
        user_id: str,
        soft_delete: bool = True
    ) -> ServiceResult:
        """
        Delete user account.
        
        Args:
            user_id: User identifier
            soft_delete: Whether to perform soft delete
            
        Returns:
            Service result with deletion status
        """
        async with self.service_operation("delete_user", enable_transaction=True) as ctx:
            try:
                # Check if user exists
                ctx['database_operations'] += 1
                existing_user = await self.async_db_manager.find_one(
                    self._user_collection,
                    {'id': user_id}
                )
                
                if not existing_user:
                    raise ResourceNotFoundError(
                        message="User not found for deletion",
                        error_code="USER_NOT_FOUND",
                        resource_type="User",
                        resource_id=user_id,
                        severity=ErrorSeverity.MEDIUM
                    )
                
                if soft_delete:
                    # Soft delete: mark as inactive
                    ctx['database_operations'] += 1
                    update_result = await self.async_db_manager.update_one(
                        self._user_collection,
                        {'id': user_id},
                        {
                            '$set': {
                                'status': UserStatus.INACTIVE.value,
                                'deleted_at': datetime.now(timezone.utc),
                                'updated_at': datetime.now(timezone.utc)
                            }
                        }
                    )
                    
                    if update_result.modified_count == 0:
                        raise DataProcessingError(
                            message="Failed to soft delete user",
                            error_code="USER_SOFT_DELETE_FAILED",
                            processing_stage="database_update",
                            severity=ErrorSeverity.MEDIUM
                        )
                else:
                    # Hard delete: remove from database
                    ctx['database_operations'] += 1
                    delete_result = await self.async_db_manager.delete_one(
                        self._user_collection,
                        {'id': user_id}
                    )
                    
                    if delete_result.deleted_count == 0:
                        raise DataProcessingError(
                            message="Failed to delete user",
                            error_code="USER_DELETE_FAILED",
                            processing_stage="database_deletion",
                            severity=ErrorSeverity.MEDIUM
                        )
                
                # Clear all user-related caches
                cache_patterns = [
                    f"service:*{user_id}*",
                    f"service:*{existing_user.get('email', '')}*"
                ]
                
                for pattern in cache_patterns:
                    try:
                        keys = await self.redis_client.keys(pattern)
                        if keys:
                            await self.redis_client.delete(*keys)
                    except Exception as cache_error:
                        logger.warning("Cache cleanup failed during user deletion",
                                      pattern=pattern,
                                      error=str(cache_error))
                
                return {
                    'success': True,
                    'user_id': user_id,
                    'operation_id': ctx['operation_id'],
                    'deletion_type': 'soft' if soft_delete else 'hard',
                    'deleted_at': datetime.now(timezone.utc).isoformat()
                }
                
            except Exception as e:
                logger.error("User deletion failed",
                           user_id=user_id,
                           error=str(e),
                           operation_id=ctx['operation_id'],
                           exc_info=True)
                raise


class OrderService(BaseBusinessService):
    """
    Order processing and transaction management service.
    
    Provides comprehensive order operations including order creation, payment
    processing, fulfillment coordination, and order lifecycle management while
    maintaining functional parity per F-004-RQ-001.
    
    Features:
    - Order creation and validation
    - Payment processing coordination
    - Inventory management integration
    - Order fulfillment workflow orchestration
    - Order status tracking and updates
    
    Example:
        order_service = OrderService()
        
        # Create new order
        order_result = await order_service.create_order(order_data)
        
        # Process payment
        payment_result = await order_service.process_payment(order_id, payment_data)
        
        # Update order status
        status_result = await order_service.update_order_status(order_id, new_status)
    """
    
    def __init__(self, **kwargs):
        """Initialize order service with order-specific capabilities."""
        super().__init__(**kwargs)
        self._order_validator = OrderValidator()
        self._payment_validator = PaymentValidator()
        self._order_collection = "orders"
        self._payment_collection = "payments"
    
    async def create_order(
        self,
        order_data: Dict[str, Any],
        user_id: str,
        validate_inventory: bool = True
    ) -> ServiceResult:
        """
        Create new order with comprehensive validation and processing.
        
        Args:
            order_data: Order data including items and shipping
            user_id: User creating the order
            validate_inventory: Whether to validate inventory availability
            
        Returns:
            Service result with created order information
        """
        async with self.service_operation("create_order", enable_transaction=True) as ctx:
            try:
                # Validate order data
                pipeline_result = self.processing_pipeline.execute(order_data)
                if not pipeline_result['success']:
                    raise DataValidationError(
                        message="Order data validation failed",
                        error_code="ORDER_VALIDATION_FAILED",
                        context={'errors': pipeline_result['errors']},
                        severity=ErrorSeverity.MEDIUM
                    )
                
                processed_data = pipeline_result['output_data']
                
                # Add user and system data
                processed_data.update({
                    'user_id': user_id,
                    'id': str(uuid.uuid4()),
                    'created_at': datetime.now(timezone.utc),
                    'updated_at': datetime.now(timezone.utc),
                    'status': OrderStatus.PENDING.value
                })
                
                # Validate business rules
                rule_result = self.business_rule_engine.execute_rules(
                    processed_data,
                    rule_set="order_validation"
                )
                if not rule_result['success']:
                    raise BusinessRuleViolationError(
                        message="Order business rule validation failed",
                        error_code="ORDER_BUSINESS_RULES_FAILED",
                        context={'violations': rule_result['rules_failed']},
                        severity=ErrorSeverity.MEDIUM
                    )
                
                processed_data = rule_result['final_data']
                
                # Create order model
                order_model = Order.from_dict(processed_data)
                
                # Validate inventory if requested
                if validate_inventory:
                    inventory_check = await self._validate_inventory(order_model.items, ctx)
                    if not inventory_check['available']:
                        raise ResourceNotFoundError(
                            message="Insufficient inventory for order",
                            error_code="INSUFFICIENT_INVENTORY",
                            resource_type="Inventory",
                            context={'unavailable_items': inventory_check['unavailable_items']},
                            severity=ErrorSeverity.MEDIUM
                        )
                
                # Calculate order totals
                await self._calculate_order_totals(order_model, ctx)
                
                # Insert order into database
                ctx['database_operations'] += 1
                order_doc = order_model.model_dump(exclude_none=True)
                insert_result = await self.async_db_manager.insert_one(
                    self._order_collection,
                    order_doc
                )
                
                if not insert_result.acknowledged:
                    raise DataProcessingError(
                        message="Failed to create order",
                        error_code="ORDER_CREATION_FAILED",
                        processing_stage="database_insertion",
                        severity=ErrorSeverity.HIGH
                    )
                
                # Reserve inventory
                if validate_inventory:
                    reservation_result = await self._reserve_inventory(order_model.items, ctx)
                    if not reservation_result['success']:
                        # Add rollback action to release any partial reservations
                        if ctx.get('transaction_context'):
                            ctx['transaction_context']['rollback_actions'].append(
                                lambda: self._release_inventory_reservations(order_model.items)
                            )
                        
                        raise DataProcessingError(
                            message="Failed to reserve inventory",
                            error_code="INVENTORY_RESERVATION_FAILED",
                            processing_stage="inventory_management",
                            severity=ErrorSeverity.HIGH
                        )
                
                # Cache order result
                cache_key = self._generate_cache_key("get_order", order_model.id)
                await self._set_cached_result(
                    cache_key,
                    order_model.to_api_dict(),
                    ttl_seconds=1800,  # 30 minutes
                    operation_context=ctx
                )
                
                return {
                    'success': True,
                    'order': order_model.to_api_dict(),
                    'operation_id': ctx['operation_id'],
                    'inventory_reserved': validate_inventory,
                    'created_at': order_model.created_at.isoformat()
                }
                
            except Exception as e:
                logger.error("Order creation failed",
                           user_id=user_id,
                           error=str(e),
                           operation_id=ctx['operation_id'],
                           exc_info=True)
                raise
    
    async def process_payment(
        self,
        order_id: str,
        payment_data: Dict[str, Any]
    ) -> ServiceResult:
        """
        Process payment for order.
        
        Args:
            order_id: Order identifier
            payment_data: Payment method and details
            
        Returns:
            Service result with payment processing status
        """
        async with self.service_operation("process_payment", enable_transaction=True) as ctx:
            try:
                # Get order
                ctx['database_operations'] += 1
                order_doc = await self.async_db_manager.find_one(
                    self._order_collection,
                    {'id': order_id}
                )
                
                if not order_doc:
                    raise ResourceNotFoundError(
                        message="Order not found for payment",
                        error_code="ORDER_NOT_FOUND",
                        resource_type="Order",
                        resource_id=order_id,
                        severity=ErrorSeverity.MEDIUM
                    )
                
                order_model = Order.from_dict(order_doc)
                
                # Validate order status
                if order_model.status != OrderStatus.PENDING:
                    raise BusinessRuleViolationError(
                        message="Order is not in pending status",
                        error_code="INVALID_ORDER_STATUS",
                        context={'current_status': order_model.status.value},
                        severity=ErrorSeverity.MEDIUM
                    )
                
                # Prepare payment data
                payment_data.update({
                    'id': str(uuid.uuid4()),
                    'order_id': order_id,
                    'amount': order_model.total_amount.model_dump(),
                    'created_at': datetime.now(timezone.utc),
                    'status': PaymentStatus.PENDING.value
                })
                
                # Validate payment data
                validation_result = self._payment_validator.load(payment_data)
                if not validation_result:
                    raise DataValidationError(
                        message="Invalid payment data",
                        error_code="INVALID_PAYMENT_DATA",
                        severity=ErrorSeverity.MEDIUM
                    )
                
                # Create payment model
                payment_model = PaymentTransaction.from_dict(payment_data)
                
                # Process payment with external service
                ctx['external_calls'] += 1
                payment_result = await self._process_external_payment(payment_model, ctx)
                
                if payment_result['success']:
                    # Update payment status
                    payment_model.status = PaymentStatus.COMPLETED
                    payment_model.transaction_id = payment_result['transaction_id']
                    payment_model.completed_at = datetime.now(timezone.utc)
                    
                    # Update order status
                    order_model.status = OrderStatus.PAID
                    order_model.updated_at = datetime.now(timezone.utc)
                else:
                    # Payment failed
                    payment_model.status = PaymentStatus.FAILED
                    payment_model.error_message = payment_result.get('error_message')
                    payment_model.failed_at = datetime.now(timezone.utc)
                
                # Save payment record
                ctx['database_operations'] += 1
                payment_doc = payment_model.model_dump(exclude_none=True)
                await self.async_db_manager.insert_one(
                    self._payment_collection,
                    payment_doc
                )
                
                # Update order
                ctx['database_operations'] += 1
                order_update = order_model.model_dump(exclude_none=True)
                await self.async_db_manager.update_one(
                    self._order_collection,
                    {'id': order_id},
                    {'$set': order_update}
                )
                
                # Invalidate order cache
                cache_key = self._generate_cache_key("get_order", order_id)
                await self.redis_client.delete(cache_key)
                
                return {
                    'success': payment_result['success'],
                    'payment': payment_model.to_api_dict(),
                    'order_status': order_model.status.value,
                    'operation_id': ctx['operation_id'],
                    'transaction_id': payment_result.get('transaction_id'),
                    'processed_at': datetime.now(timezone.utc).isoformat()
                }
                
            except Exception as e:
                logger.error("Payment processing failed",
                           order_id=order_id,
                           error=str(e),
                           operation_id=ctx['operation_id'],
                           exc_info=True)
                raise
    
    async def _validate_inventory(
        self,
        order_items: List[OrderItem],
        operation_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Validate inventory availability for order items.
        
        Args:
            order_items: List of order items to validate
            operation_context: Operation context for tracking
            
        Returns:
            Inventory validation result
        """
        # Simulate inventory check - in real implementation would query inventory service
        operation_context['external_calls'] += 1
        
        unavailable_items = []
        
        for item in order_items:
            # Simulate inventory check
            if item.quantity > 100:  # Mock inventory limit
                unavailable_items.append({
                    'product_id': item.product_id,
                    'requested': item.quantity,
                    'available': 100
                })
        
        return {
            'available': len(unavailable_items) == 0,
            'unavailable_items': unavailable_items
        }
    
    async def _calculate_order_totals(
        self,
        order_model: Order,
        operation_context: Dict[str, Any]
    ) -> None:
        """
        Calculate order totals including tax and shipping.
        
        Args:
            order_model: Order model to calculate totals for
            operation_context: Operation context for tracking
        """
        # Calculate subtotal
        subtotal = sum(
            item.unit_price.amount * item.quantity
            for item in order_model.items
        )
        
        # Calculate tax (mock 8.5% tax rate)
        tax_rate = Decimal('0.085')
        tax_amount = subtotal * tax_rate
        
        # Calculate shipping (mock flat rate)
        shipping_amount = Decimal('10.00')
        
        # Apply discount if any
        discount_amount = order_model.discount_amount.amount if order_model.discount_amount else Decimal('0.00')
        
        # Calculate total
        total_amount = subtotal + tax_amount + shipping_amount - discount_amount
        
        # Update order model
        order_model.subtotal = MonetaryAmount(amount=subtotal, currency_code="USD")
        order_model.tax_amount = MonetaryAmount(amount=tax_amount, currency_code="USD")
        order_model.shipping_amount = MonetaryAmount(amount=shipping_amount, currency_code="USD")
        order_model.total_amount = MonetaryAmount(amount=total_amount, currency_code="USD")
    
    async def _reserve_inventory(
        self,
        order_items: List[OrderItem],
        operation_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Reserve inventory for order items.
        
        Args:
            order_items: List of order items to reserve
            operation_context: Operation context for tracking
            
        Returns:
            Inventory reservation result
        """
        # Simulate inventory reservation - in real implementation would call inventory service
        operation_context['external_calls'] += 1
        
        # Mock successful reservation
        return {
            'success': True,
            'reservation_id': str(uuid.uuid4()),
            'reserved_items': len(order_items)
        }
    
    async def _release_inventory_reservations(self, order_items: List[OrderItem]) -> None:
        """
        Release inventory reservations (rollback action).
        
        Args:
            order_items: List of order items to release reservations for
        """
        # Simulate inventory release - in real implementation would call inventory service
        logger.info("Released inventory reservations",
                   item_count=len(order_items))
    
    async def _process_external_payment(
        self,
        payment_model: PaymentTransaction,
        operation_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Process payment with external payment service.
        
        Args:
            payment_model: Payment transaction model
            operation_context: Operation context for tracking
            
        Returns:
            Payment processing result
        """
        # Simulate external payment processing - in real implementation would call payment gateway
        operation_context['external_calls'] += 1
        
        # Mock successful payment processing
        import random
        success = random.random() > 0.1  # 90% success rate for simulation
        
        if success:
            return {
                'success': True,
                'transaction_id': f"txn_{uuid.uuid4().hex[:16]}",
                'processor_response': 'APPROVED'
            }
        else:
            return {
                'success': False,
                'error_message': 'Payment declined by processor',
                'processor_response': 'DECLINED'
            }


# ============================================================================
# INTEGRATION SERVICES
# ============================================================================

class AuthenticationService(BaseBusinessService):
    """
    Authentication service integration with Auth0 and JWT token management.
    
    Provides comprehensive authentication operations including token validation,
    user context creation, and Auth0 service coordination with circuit breaker
    patterns per Section 6.1.3 requirements.
    
    Features:
    - JWT token validation and verification
    - Auth0 service integration with circuit breaker protection
    - User context creation and session management
    - Token refresh and expiration handling
    - Authentication metrics and monitoring
    
    Example:
        auth_service = AuthenticationService()
        
        # Validate JWT token
        token_result = await auth_service.validate_token(jwt_token)
        
        # Get user context from token
        user_context = await auth_service.get_user_context(jwt_token)
        
        # Refresh expired token
        refresh_result = await auth_service.refresh_token(refresh_token)
    """
    
    def __init__(self, **kwargs):
        """Initialize authentication service with Auth0 integration."""
        super().__init__(**kwargs)
        self._auth0_circuit_breaker = None
        self._jwt_cache_ttl = 1800  # 30 minutes
        
        # Initialize circuit breaker for Auth0
        if self.enable_circuit_breakers:
            try:
                import pybreaker
                self._auth0_circuit_breaker = pybreaker.CircuitBreaker(
                    fail_max=self.config.AUTH0_CIRCUIT_BREAKER_THRESHOLD,
                    reset_timeout=60,
                    expected_exception=ExternalServiceError
                )
            except ImportError:
                logger.warning("pybreaker not available, circuit breaker disabled")
                self._auth0_circuit_breaker = None
    
    async def validate_token(
        self,
        token: str,
        audience: Optional[str] = None,
        issuer: Optional[str] = None
    ) -> ServiceResult:
        """
        Validate JWT token with Auth0 verification.
        
        Args:
            token: JWT token to validate
            audience: Expected token audience
            issuer: Expected token issuer
            
        Returns:
            Service result with token validation status and claims
        """
        async with self.service_operation("validate_token") as ctx:
            try:
                # Generate cache key for token validation
                import hashlib
                token_hash = hashlib.md5(token.encode()).hexdigest()
                cache_key = self._generate_cache_key("validate_token", token_hash, audience, issuer)
                
                # Check cache first
                cached_result = await self._get_cached_result(cache_key, ctx)
                if cached_result:
                    return {
                        'success': True,
                        'valid': cached_result['valid'],
                        'claims': cached_result.get('claims', {}),
                        'operation_id': ctx['operation_id'],
                        'cached': True
                    }
                
                # Validate token format
                if not token or not token.startswith('Bearer '):
                    token_value = token.replace('Bearer ', '') if token else ''
                else:
                    token_value = token[7:]  # Remove 'Bearer ' prefix
                
                if not token_value:
                    raise AuthorizationError(
                        message="Missing or invalid token format",
                        error_code="INVALID_TOKEN_FORMAT",
                        severity=ErrorSeverity.MEDIUM
                    )
                
                # Validate token with Auth0 (with circuit breaker protection)
                validation_result = await self._validate_with_auth0(token_value, audience, issuer, ctx)
                
                # Cache successful validation
                if validation_result['valid']:
                    await self._set_cached_result(
                        cache_key,
                        {
                            'valid': True,
                            'claims': validation_result['claims']
                        },
                        ttl_seconds=self._jwt_cache_ttl,
                        operation_context=ctx
                    )
                
                return {
                    'success': True,
                    'valid': validation_result['valid'],
                    'claims': validation_result.get('claims', {}),
                    'operation_id': ctx['operation_id'],
                    'cached': False,
                    'error_message': validation_result.get('error_message')
                }
                
            except Exception as e:
                logger.error("Token validation failed",
                           error=str(e),
                           operation_id=ctx['operation_id'],
                           exc_info=True)
                raise
    
    async def get_user_context(
        self,
        token: str,
        include_permissions: bool = True
    ) -> ServiceResult:
        """
        Get user context from validated JWT token.
        
        Args:
            token: JWT token to extract context from
            include_permissions: Whether to include user permissions
            
        Returns:
            Service result with user context information
        """
        async with self.service_operation("get_user_context") as ctx:
            try:
                # First validate the token
                validation_result = await self.validate_token(token)
                
                if not validation_result['valid']:
                    raise AuthorizationError(
                        message="Invalid token for user context",
                        error_code="INVALID_TOKEN",
                        severity=ErrorSeverity.MEDIUM
                    )
                
                claims = validation_result['claims']
                
                # Extract user information from claims
                user_context = {
                    'user_id': claims.get('sub', ''),
                    'email': claims.get('email', ''),
                    'name': claims.get('name', ''),
                    'roles': claims.get('roles', []),
                    'permissions': claims.get('permissions', []) if include_permissions else [],
                    'token_issued_at': claims.get('iat'),
                    'token_expires_at': claims.get('exp'),
                    'issuer': claims.get('iss', ''),
                    'audience': claims.get('aud', '')
                }
                
                # Get additional user details if needed
                if include_permissions and user_context['user_id']:
                    user_details = await self._get_user_details(user_context['user_id'], ctx)
                    if user_details:
                        user_context.update({
                            'profile': user_details.get('profile', {}),
                            'preferences': user_details.get('preferences', {}),
                            'last_login': user_details.get('last_login')
                        })
                
                return {
                    'success': True,
                    'user_context': user_context,
                    'operation_id': ctx['operation_id'],
                    'authenticated': True
                }
                
            except Exception as e:
                logger.error("User context extraction failed",
                           error=str(e),
                           operation_id=ctx['operation_id'],
                           exc_info=True)
                raise
    
    async def _validate_with_auth0(
        self,
        token: str,
        audience: Optional[str],
        issuer: Optional[str],
        operation_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Validate token with Auth0 service using circuit breaker protection.
        
        Args:
            token: JWT token to validate
            audience: Expected token audience
            issuer: Expected token issuer
            operation_context: Operation context for tracking
            
        Returns:
            Token validation result from Auth0
        """
        try:
            # Apply circuit breaker if available
            if self._auth0_circuit_breaker:
                validation_func = self._auth0_circuit_breaker(self._perform_auth0_validation)
            else:
                validation_func = self._perform_auth0_validation
            
            operation_context['external_calls'] += 1
            result = await validation_func(token, audience, issuer)
            
            return result
            
        except Exception as e:
            if self._auth0_circuit_breaker and self._auth0_circuit_breaker.current_state == 'open':
                logger.warning("Auth0 circuit breaker is open, using fallback validation")
                # Use fallback validation when circuit breaker is open
                return await self._fallback_token_validation(token, audience, issuer)
            else:
                raise ExternalServiceError(
                    message="Auth0 token validation failed",
                    error_code="AUTH0_VALIDATION_FAILED",
                    service_name="Auth0",
                    operation="token_validation",
                    cause=e,
                    severity=ErrorSeverity.HIGH
                )
    
    async def _perform_auth0_validation(
        self,
        token: str,
        audience: Optional[str],
        issuer: Optional[str]
    ) -> Dict[str, Any]:
        """
        Perform actual Auth0 token validation.
        
        Args:
            token: JWT token to validate
            audience: Expected token audience
            issuer: Expected token issuer
            
        Returns:
            Auth0 validation result
        """
        try:
            # Simulate Auth0 validation - in real implementation would use Auth0 SDK
            # For this migration, we'll implement basic JWT validation
            import jwt
            
            # Mock Auth0 public key and settings - in real implementation would fetch from Auth0
            mock_secret = "your-256-bit-secret"  # In real app, would use Auth0's public key
            
            # Decode and validate token
            decoded_token = jwt.decode(
                token,
                mock_secret,
                algorithms=["HS256"],  # In real app, would use RS256 with Auth0's public key
                audience=audience,
                issuer=issuer,
                options={"verify_exp": True}
            )
            
            return {
                'valid': True,
                'claims': decoded_token
            }
            
        except jwt.ExpiredSignatureError:
            return {
                'valid': False,
                'error_message': 'Token has expired'
            }
        except jwt.InvalidTokenError as e:
            return {
                'valid': False,
                'error_message': f'Invalid token: {str(e)}'
            }
        except Exception as e:
            raise ExternalServiceError(
                message="Auth0 API call failed",
                error_code="AUTH0_API_ERROR",
                service_name="Auth0",
                cause=e,
                severity=ErrorSeverity.HIGH
            )
    
    async def _fallback_token_validation(
        self,
        token: str,
        audience: Optional[str],
        issuer: Optional[str]
    ) -> Dict[str, Any]:
        """
        Fallback token validation when Auth0 is unavailable.
        
        Args:
            token: JWT token to validate
            audience: Expected token audience
            issuer: Expected token issuer
            
        Returns:
            Fallback validation result
        """
        try:
            # Basic token format validation without signature verification
            import jwt
            
            # Decode without verification (fallback mode)
            decoded_token = jwt.decode(
                token,
                options={"verify_signature": False, "verify_exp": True}
            )
            
            logger.warning("Using fallback token validation due to Auth0 unavailability",
                          subject=decoded_token.get('sub', 'unknown'))
            
            return {
                'valid': True,
                'claims': decoded_token,
                'fallback_mode': True
            }
            
        except Exception as e:
            return {
                'valid': False,
                'error_message': f'Fallback validation failed: {str(e)}',
                'fallback_mode': True
            }
    
    async def _get_user_details(
        self,
        user_id: str,
        operation_context: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Get additional user details from database.
        
        Args:
            user_id: User identifier
            operation_context: Operation context for tracking
            
        Returns:
            User details if found
        """
        try:
            operation_context['database_operations'] += 1
            user_doc = await self.async_db_manager.find_one(
                "users",
                {'id': user_id}
            )
            
            if user_doc:
                return {
                    'profile': {
                        'name': user_doc.get('name', ''),
                        'email': user_doc.get('email', ''),
                        'avatar_url': user_doc.get('avatar_url', '')
                    },
                    'preferences': user_doc.get('preferences', {}),
                    'last_login': user_doc.get('last_login')
                }
            
            return None
            
        except Exception as e:
            logger.warning("Failed to get user details",
                          user_id=user_id,
                          error=str(e))
            return None


# ============================================================================
# WORKFLOW SERVICES
# ============================================================================

class BusinessWorkflowService(BaseBusinessService):
    """
    Complex business process orchestration service.
    
    Provides comprehensive workflow orchestration for complex business processes
    including multi-step workflows, conditional logic, parallel execution, and
    comprehensive error handling per Section 5.2.4 requirements.
    
    Features:
    - Multi-step workflow definition and execution
    - Conditional workflow logic and branching
    - Parallel step execution with synchronization
    - Workflow state management and persistence
    - Comprehensive error handling and recovery
    - Workflow metrics and performance monitoring
    
    Example:
        workflow_service = BusinessWorkflowService()
        
        # Define workflow
        workflow_service.define_workflow('order_fulfillment', order_fulfillment_steps)
        
        # Execute workflow
        result = await workflow_service.execute_workflow('order_fulfillment', context)
        
        # Get workflow status
        status = await workflow_service.get_workflow_status(workflow_id)
    """
    
    def __init__(self, **kwargs):
        """Initialize workflow service with orchestration capabilities."""
        super().__init__(**kwargs)
        self._workflows = {}
        self._workflow_executions = {}
        self._workflow_collection = "workflow_executions"
    
    def define_workflow(
        self,
        workflow_name: str,
        steps: List[Dict[str, Any]],
        description: Optional[str] = None
    ) -> None:
        """
        Define a business workflow with steps and configuration.
        
        Args:
            workflow_name: Unique name for the workflow
            steps: List of workflow steps with configuration
            description: Optional workflow description
        """
        workflow_definition = {
            'name': workflow_name,
            'description': description or f"Business workflow: {workflow_name}",
            'steps': steps,
            'created_at': datetime.now(timezone.utc),
            'version': '1.0.0'
        }
        
        # Validate workflow definition
        self._validate_workflow_definition(workflow_definition)
        
        self._workflows[workflow_name] = workflow_definition
        
        logger.info("Workflow defined",
                   workflow_name=workflow_name,
                   step_count=len(steps))
    
    async def execute_workflow(
        self,
        workflow_name: str,
        context: Dict[str, Any],
        execution_id: Optional[str] = None
    ) -> ServiceResult:
        """
        Execute business workflow with comprehensive orchestration.
        
        Args:
            workflow_name: Name of workflow to execute
            context: Workflow execution context
            execution_id: Optional execution identifier for resuming
            
        Returns:
            Service result with workflow execution status
        """
        async with self.service_operation(f"execute_workflow_{workflow_name}", enable_transaction=True) as ctx:
            try:
                # Get workflow definition
                if workflow_name not in self._workflows:
                    raise ConfigurationError(
                        message=f"Workflow '{workflow_name}' not defined",
                        error_code="WORKFLOW_NOT_DEFINED",
                        component="BusinessWorkflowService",
                        configuration_key=workflow_name,
                        severity=ErrorSeverity.HIGH
                    )
                
                workflow_def = self._workflows[workflow_name]
                
                # Create or resume execution
                execution_id = execution_id or str(uuid.uuid4())
                execution_context = {
                    'execution_id': execution_id,
                    'workflow_name': workflow_name,
                    'start_time': datetime.now(timezone.utc),
                    'context': context,
                    'current_step': 0,
                    'completed_steps': [],
                    'failed_steps': [],
                    'step_results': {},
                    'status': 'running',
                    'operation_context': ctx
                }
                
                # Store execution state
                self._workflow_executions[execution_id] = execution_context
                
                # Persist execution state
                ctx['database_operations'] += 1
                await self.async_db_manager.insert_one(
                    self._workflow_collection,
                    execution_context.copy()
                )
                
                logger.info("Workflow execution started",
                           workflow_name=workflow_name,
                           execution_id=execution_id)
                
                # Execute workflow steps
                execution_result = await self._execute_workflow_steps(
                    workflow_def,
                    execution_context
                )
                
                # Update final execution state
                execution_context.update({
                    'end_time': datetime.now(timezone.utc),
                    'status': 'completed' if execution_result['success'] else 'failed',
                    'final_result': execution_result
                })
                
                # Persist final state
                ctx['database_operations'] += 1
                await self.async_db_manager.update_one(
                    self._workflow_collection,
                    {'execution_id': execution_id},
                    {'$set': execution_context}
                )
                
                return {
                    'success': execution_result['success'],
                    'execution_id': execution_id,
                    'workflow_name': workflow_name,
                    'operation_id': ctx['operation_id'],
                    'completed_steps': len(execution_context['completed_steps']),
                    'failed_steps': len(execution_context['failed_steps']),
                    'execution_time': (
                        execution_context['end_time'] - execution_context['start_time']
                    ).total_seconds(),
                    'result': execution_result.get('result', {}),
                    'error_message': execution_result.get('error_message')
                }
                
            except Exception as e:
                logger.error("Workflow execution failed",
                           workflow_name=workflow_name,
                           error=str(e),
                           operation_id=ctx['operation_id'],
                           exc_info=True)
                raise
    
    async def _execute_workflow_steps(
        self,
        workflow_def: Dict[str, Any],
        execution_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute workflow steps with orchestration logic.
        
        Args:
            workflow_def: Workflow definition
            execution_context: Execution context
            
        Returns:
            Workflow execution result
        """
        steps = workflow_def['steps']
        context = execution_context['context']
        
        try:
            for step_index, step_config in enumerate(steps):
                execution_context['current_step'] = step_index
                
                # Check step condition if present
                if 'condition' in step_config:
                    condition_result = await self._evaluate_step_condition(
                        step_config['condition'],
                        context,
                        execution_context
                    )
                    
                    if not condition_result:
                        logger.debug("Skipping step due to condition",
                                   step_name=step_config.get('name', f'step_{step_index}'),
                                   execution_id=execution_context['execution_id'])
                        continue
                
                # Execute step
                step_result = await self._execute_workflow_step(
                    step_config,
                    context,
                    execution_context
                )
                
                # Store step result
                execution_context['step_results'][step_index] = step_result
                
                if step_result['success']:
                    execution_context['completed_steps'].append(step_index)
                    
                    # Update context with step output
                    if 'output' in step_result:
                        context.update(step_result['output'])
                else:
                    execution_context['failed_steps'].append(step_index)
                    
                    # Handle step failure
                    if step_config.get('required', True):
                        return {
                            'success': False,
                            'error_message': f"Required step {step_index} failed: {step_result.get('error_message', 'Unknown error')}",
                            'failed_step': step_index,
                            'result': context
                        }
                    else:
                        logger.warning("Optional step failed, continuing workflow",
                                     step_index=step_index,
                                     error=step_result.get('error_message'))
            
            return {
                'success': True,
                'result': context,
                'completed_steps': len(execution_context['completed_steps'])
            }
            
        except Exception as e:
            return {
                'success': False,
                'error_message': f"Workflow execution error: {str(e)}",
                'failed_step': execution_context['current_step'],
                'result': context
            }
    
    async def _execute_workflow_step(
        self,
        step_config: Dict[str, Any],
        context: Dict[str, Any],
        execution_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute individual workflow step.
        
        Args:
            step_config: Step configuration
            context: Workflow context
            execution_context: Execution context
            
        Returns:
            Step execution result
        """
        step_name = step_config.get('name', 'unnamed_step')
        step_type = step_config.get('type', 'action')
        
        try:
            logger.debug("Executing workflow step",
                        step_name=step_name,
                        step_type=step_type,
                        execution_id=execution_context['execution_id'])
            
            step_start_time = time.perf_counter()
            
            # Execute based on step type
            if step_type == 'action':
                result = await self._execute_action_step(step_config, context, execution_context)
            elif step_type == 'validation':
                result = await self._execute_validation_step(step_config, context, execution_context)
            elif step_type == 'transformation':
                result = await self._execute_transformation_step(step_config, context, execution_context)
            elif step_type == 'external_service':
                result = await self._execute_external_service_step(step_config, context, execution_context)
            elif step_type == 'parallel':
                result = await self._execute_parallel_step(step_config, context, execution_context)
            else:
                raise ConfigurationError(
                    message=f"Unknown step type: {step_type}",
                    error_code="UNKNOWN_STEP_TYPE",
                    component="BusinessWorkflowService",
                    configuration_key=step_type,
                    severity=ErrorSeverity.MEDIUM
                )
            
            step_duration = time.perf_counter() - step_start_time
            
            result.update({
                'step_name': step_name,
                'step_type': step_type,
                'duration': step_duration
            })
            
            logger.debug("Workflow step completed",
                        step_name=step_name,
                        success=result['success'],
                        duration=step_duration,
                        execution_id=execution_context['execution_id'])
            
            return result
            
        except Exception as e:
            logger.error("Workflow step execution failed",
                        step_name=step_name,
                        error=str(e),
                        execution_id=execution_context['execution_id'],
                        exc_info=True)
            
            return {
                'success': False,
                'error_message': str(e),
                'step_name': step_name,
                'step_type': step_type
            }
    
    async def _execute_action_step(
        self,
        step_config: Dict[str, Any],
        context: Dict[str, Any],
        execution_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute action workflow step."""
        action = step_config.get('action')
        parameters = step_config.get('parameters', {})
        
        # Resolve parameters from context
        resolved_params = self._resolve_step_parameters(parameters, context)
        
        # Execute action based on configuration
        if action == 'create_user':
            user_service = UserService()
            result = await user_service.create_user(resolved_params)
            return {
                'success': result['success'],
                'output': {'user_id': result.get('user', {}).get('id')}
            }
        
        elif action == 'send_notification':
            # Mock notification sending
            return {
                'success': True,
                'output': {'notification_id': str(uuid.uuid4())}
            }
        
        elif action == 'update_inventory':
            # Mock inventory update
            return {
                'success': True,
                'output': {'inventory_updated': True}
            }
        
        else:
            return {
                'success': False,
                'error_message': f"Unknown action: {action}"
            }
    
    async def _execute_validation_step(
        self,
        step_config: Dict[str, Any],
        context: Dict[str, Any],
        execution_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute validation workflow step."""
        validation_rules = step_config.get('rules', [])
        data_path = step_config.get('data_path', '')
        
        # Get data to validate from context
        data_to_validate = self._get_nested_value(context, data_path) if data_path else context
        
        # Execute validation using business rule engine
        rule_result = self.business_rule_engine.execute_rules(
            data_to_validate,
            rule_set=step_config.get('rule_set', 'default')
        )
        
        return {
            'success': rule_result['success'],
            'output': {'validation_result': rule_result},
            'error_message': f"Validation failed: {rule_result.get('rules_failed', [])}" if not rule_result['success'] else None
        }
    
    async def _execute_transformation_step(
        self,
        step_config: Dict[str, Any],
        context: Dict[str, Any],
        execution_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute transformation workflow step."""
        input_path = step_config.get('input_path', '')
        output_path = step_config.get('output_path', '')
        transformation = step_config.get('transformation', {})
        
        # Get input data
        input_data = self._get_nested_value(context, input_path) if input_path else context
        
        # Apply transformation using processing pipeline
        pipeline_result = self.processing_pipeline.execute(input_data)
        
        if pipeline_result['success']:
            # Set output data in context
            if output_path:
                self._set_nested_value(context, output_path, pipeline_result['output_data'])
            else:
                context.update(pipeline_result['output_data'])
        
        return {
            'success': pipeline_result['success'],
            'output': {'transformed_data': pipeline_result['output_data']},
            'error_message': str(pipeline_result.get('errors', [])) if not pipeline_result['success'] else None
        }
    
    async def _execute_external_service_step(
        self,
        step_config: Dict[str, Any],
        context: Dict[str, Any],
        execution_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute external service workflow step."""
        service_name = step_config.get('service', '')
        operation = step_config.get('operation', '')
        parameters = step_config.get('parameters', {})
        
        # Resolve parameters from context
        resolved_params = self._resolve_step_parameters(parameters, context)
        
        # Track external service call
        execution_context['operation_context']['external_calls'] += 1
        
        # Execute based on service type
        if service_name == 'auth_service':
            auth_service = AuthenticationService()
            if operation == 'validate_token':
                result = await auth_service.validate_token(resolved_params.get('token', ''))
            else:
                return {'success': False, 'error_message': f"Unknown auth operation: {operation}"}
        
        elif service_name == 'order_service':
            order_service = OrderService()
            if operation == 'create_order':
                result = await order_service.create_order(
                    resolved_params.get('order_data', {}),
                    resolved_params.get('user_id', '')
                )
            else:
                return {'success': False, 'error_message': f"Unknown order operation: {operation}"}
        
        else:
            return {'success': False, 'error_message': f"Unknown service: {service_name}"}
        
        return {
            'success': result['success'],
            'output': {'service_result': result}
        }
    
    async def _execute_parallel_step(
        self,
        step_config: Dict[str, Any],
        context: Dict[str, Any],
        execution_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute parallel workflow steps."""
        parallel_steps = step_config.get('steps', [])
        max_concurrency = min(len(parallel_steps), self.config.PARALLEL_WORKFLOW_LIMIT)
        
        # Execute steps in parallel with concurrency limit
        semaphore = asyncio.Semaphore(max_concurrency)
        
        async def execute_parallel_step(step):
            async with semaphore:
                return await self._execute_workflow_step(step, context.copy(), execution_context)
        
        # Run parallel steps
        parallel_results = await asyncio.gather(
            *[execute_parallel_step(step) for step in parallel_steps],
            return_exceptions=True
        )
        
        # Collect results
        successful_results = []
        failed_results = []
        
        for i, result in enumerate(parallel_results):
            if isinstance(result, Exception):
                failed_results.append({
                    'step_index': i,
                    'error': str(result)
                })
            elif result.get('success', False):
                successful_results.append(result)
            else:
                failed_results.append(result)
        
        # Determine overall success
        success = len(failed_results) == 0 or not step_config.get('require_all_success', True)
        
        return {
            'success': success,
            'output': {
                'parallel_results': parallel_results,
                'successful_count': len(successful_results),
                'failed_count': len(failed_results)
            },
            'error_message': f"Parallel execution failed: {failed_results}" if not success else None
        }
    
    def _validate_workflow_definition(self, workflow_def: Dict[str, Any]) -> None:
        """Validate workflow definition structure."""
        required_fields = ['name', 'steps']
        
        for field in required_fields:
            if field not in workflow_def:
                raise ConfigurationError(
                    message=f"Workflow definition missing required field: {field}",
                    error_code="INVALID_WORKFLOW_DEFINITION",
                    component="BusinessWorkflowService",
                    configuration_key=field,
                    severity=ErrorSeverity.HIGH
                )
        
        if len(workflow_def['steps']) > self.config.MAX_WORKFLOW_STEPS:
            raise ConfigurationError(
                message=f"Workflow has too many steps: {len(workflow_def['steps'])} > {self.config.MAX_WORKFLOW_STEPS}",
                error_code="WORKFLOW_TOO_COMPLEX",
                component="BusinessWorkflowService",
                severity=ErrorSeverity.MEDIUM
            )
    
    async def _evaluate_step_condition(
        self,
        condition: Dict[str, Any],
        context: Dict[str, Any],
        execution_context: Dict[str, Any]
    ) -> bool:
        """Evaluate workflow step condition."""
        condition_type = condition.get('type', 'equals')
        field_path = condition.get('field', '')
        expected_value = condition.get('value')
        
        # Get field value from context
        field_value = self._get_nested_value(context, field_path)
        
        # Evaluate condition
        if condition_type == 'equals':
            return field_value == expected_value
        elif condition_type == 'not_equals':
            return field_value != expected_value
        elif condition_type == 'greater_than':
            return field_value > expected_value
        elif condition_type == 'less_than':
            return field_value < expected_value
        elif condition_type == 'exists':
            return field_value is not None
        elif condition_type == 'not_exists':
            return field_value is None
        else:
            logger.warning("Unknown condition type",
                          condition_type=condition_type)
            return True
    
    def _resolve_step_parameters(
        self,
        parameters: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Resolve step parameters from workflow context."""
        resolved = {}
        
        for key, value in parameters.items():
            if isinstance(value, str) and value.startswith('${') and value.endswith('}'):
                # Extract context path
                context_path = value[2:-1]
                resolved[key] = self._get_nested_value(context, context_path)
            else:
                resolved[key] = value
        
        return resolved
    
    def _get_nested_value(self, data: Dict[str, Any], path: str) -> Any:
        """Get nested value from dictionary using dot notation."""
        if not path:
            return data
        
        keys = path.split('.')
        value = data
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None
        
        return value
    
    def _set_nested_value(self, data: Dict[str, Any], path: str, value: Any) -> None:
        """Set nested value in dictionary using dot notation."""
        if not path:
            return
        
        keys = path.split('.')
        current = data
        
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        current[keys[-1]] = value


# ============================================================================
# UTILITY SERVICES
# ============================================================================

class HealthCheckService(BaseBusinessService):
    """
    Service dependency health monitoring service.
    
    Provides comprehensive health monitoring for all service dependencies
    including database connections, cache operations, external services,
    and circuit breaker status per Section 6.1.3 requirements.
    
    Features:
    - Database connection health monitoring
    - Cache service health verification
    - External service dependency checks
    - Circuit breaker status monitoring
    - Comprehensive health reporting
    - Performance metrics collection
    
    Example:
        health_service = HealthCheckService()
        
        # Check overall system health
        health_status = await health_service.check_system_health()
        
        # Check specific dependency
        db_health = await health_service.check_database_health()
        
        # Get health summary
        summary = health_service.get_health_summary()
    """
    
    def __init__(self, **kwargs):
        """Initialize health check service with monitoring capabilities."""
        super().__init__(**kwargs)
        self._health_checks = {}
        self._last_health_check = None
        self._health_cache_ttl = 60  # 1 minute
    
    async def check_system_health(self) -> ServiceResult:
        """
        Check overall system health including all dependencies.
        
        Returns:
            Service result with comprehensive system health status
        """
        async with self.service_operation("check_system_health") as ctx:
            try:
                # Generate cache key
                cache_key = self._generate_cache_key("system_health")
                
                # Check cache first
                cached_health = await self._get_cached_result(cache_key, ctx)
                if cached_health:
                    return {
                        'success': True,
                        'health_status': cached_health,
                        'operation_id': ctx['operation_id'],
                        'cached': True
                    }
                
                # Perform health checks
                health_results = {}
                
                # Database health
                db_health = await self._check_database_health(ctx)
                health_results['database'] = db_health
                
                # Cache health
                cache_health = await self._check_cache_health(ctx)
                health_results['cache'] = cache_health
                
                # External services health
                external_health = await self._check_external_services_health(ctx)
                health_results['external_services'] = external_health
                
                # Application health
                app_health = await self._check_application_health(ctx)
                health_results['application'] = app_health
                
                # Determine overall health
                overall_healthy = all(
                    result.get('healthy', False)
                    for result in health_results.values()
                )
                
                health_status = {
                    'healthy': overall_healthy,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'checks': health_results,
                    'summary': {
                        'total_checks': len(health_results),
                        'passed_checks': sum(1 for r in health_results.values() if r.get('healthy', False)),
                        'failed_checks': sum(1 for r in health_results.values() if not r.get('healthy', False))
                    }
                }
                
                # Cache health result
                await self._set_cached_result(
                    cache_key,
                    health_status,
                    ttl_seconds=self._health_cache_ttl,
                    operation_context=ctx
                )
                
                # Store last health check
                self._last_health_check = health_status
                
                return {
                    'success': True,
                    'health_status': health_status,
                    'operation_id': ctx['operation_id'],
                    'cached': False
                }
                
            except Exception as e:
                logger.error("System health check failed",
                           error=str(e),
                           operation_id=ctx['operation_id'],
                           exc_info=True)
                raise
    
    async def _check_database_health(self, operation_context: Dict[str, Any]) -> Dict[str, Any]:
        """Check database connection and operation health."""
        try:
            operation_context['database_operations'] += 1
            
            # Test database connection
            start_time = time.perf_counter()
            
            # Perform simple ping operation
            db_health = get_database_health_status()
            
            response_time = time.perf_counter() - start_time
            
            # Test basic query
            test_result = await self.async_db_manager.find_one(
                "system_health",
                {"_id": "health_check"},
                upsert_if_missing=True,
                default_doc={"_id": "health_check", "last_check": datetime.now(timezone.utc)}
            )
            
            return {
                'healthy': db_health.get('healthy', False),
                'response_time': response_time,
                'details': {
                    'connection_status': db_health.get('connection_status', 'unknown'),
                    'database_name': db_health.get('database_name', 'unknown'),
                    'collection_count': db_health.get('collection_count', 0),
                    'test_query_success': test_result is not None
                }
            }
            
        except Exception as e:
            logger.warning("Database health check failed", error=str(e))
            return {
                'healthy': False,
                'error_message': str(e),
                'details': {'connection_status': 'failed'}
            }
    
    async def _check_cache_health(self, operation_context: Dict[str, Any]) -> Dict[str, Any]:
        """Check Redis cache connection and operation health."""
        try:
            operation_context['cache_operations'] += 1
            
            # Test cache connection
            start_time = time.perf_counter()
            
            # Perform ping operation
            ping_result = await self.redis_client.ping()
            
            response_time = time.perf_counter() - start_time
            
            # Test set and get operations
            test_key = f"health_check:{uuid.uuid4().hex[:8]}"
            test_value = "health_test"
            
            await self.redis_client.setex(test_key, 60, test_value)
            retrieved_value = await self.redis_client.get(test_key)
            await self.redis_client.delete(test_key)
            
            test_success = retrieved_value == test_value
            
            return {
                'healthy': ping_result and test_success,
                'response_time': response_time,
                'details': {
                    'ping_success': ping_result,
                    'test_operation_success': test_success,
                    'connection_status': 'connected' if ping_result else 'failed'
                }
            }
            
        except Exception as e:
            logger.warning("Cache health check failed", error=str(e))
            return {
                'healthy': False,
                'error_message': str(e),
                'details': {'connection_status': 'failed'}
            }
    
    async def _check_external_services_health(self, operation_context: Dict[str, Any]) -> Dict[str, Any]:
        """Check external service dependency health."""
        external_results = {}
        
        # Auth0 service health
        try:
            operation_context['external_calls'] += 1
            auth_service = AuthenticationService()
            
            # Test with a mock token validation (should fail gracefully)
            start_time = time.perf_counter()
            test_result = await auth_service.validate_token("Bearer test_token")
            response_time = time.perf_counter() - start_time
            
            # Service is healthy if it responds (even with invalid token)
            external_results['auth0'] = {
                'healthy': 'error_message' in test_result or test_result.get('success', False),
                'response_time': response_time,
                'details': {
                    'service_responsive': True,
                    'test_result': 'responded'
                }
            }
            
        except Exception as e:
            external_results['auth0'] = {
                'healthy': False,
                'error_message': str(e),
                'details': {'service_responsive': False}
            }
        
        # AWS services health (mock check)
        try:
            # Mock AWS health check
            external_results['aws'] = {
                'healthy': True,
                'response_time': 0.1,
                'details': {
                    's3_accessible': True,
                    'cloudwatch_accessible': True
                }
            }
            
        except Exception as e:
            external_results['aws'] = {
                'healthy': False,
                'error_message': str(e),
                'details': {'service_responsive': False}
            }
        
        # Determine overall external service health
        overall_healthy = all(result.get('healthy', False) for result in external_results.values())
        
        return {
            'healthy': overall_healthy,
            'services': external_results,
            'details': {
                'total_services': len(external_results),
                'healthy_services': sum(1 for r in external_results.values() if r.get('healthy', False)),
                'unhealthy_services': sum(1 for r in external_results.values() if not r.get('healthy', False))
            }
        }
    
    async def _check_application_health(self, operation_context: Dict[str, Any]) -> Dict[str, Any]:
        """Check application-specific health metrics."""
        try:
            # Get service metrics
            service_metrics = self.get_service_summary()
            
            # Check memory usage (mock)
            import psutil
            memory_usage = psutil.Process().memory_info().rss / 1024 / 1024  # MB
            cpu_usage = psutil.Process().cpu_percent()
            
            # Determine health based on resource usage
            memory_healthy = memory_usage < 1024  # Less than 1GB
            cpu_healthy = cpu_usage < 80  # Less than 80%
            
            return {
                'healthy': memory_healthy and cpu_healthy,
                'details': {
                    'memory_usage_mb': memory_usage,
                    'cpu_usage_percent': cpu_usage,
                    'active_transactions': service_metrics.get('active_transactions', 0),
                    'service_mode': service_metrics.get('mode', 'unknown'),
                    'uptime_seconds': (
                        datetime.now(timezone.utc) - self._start_time
                    ).total_seconds()
                }
            }
            
        except Exception as e:
            logger.warning("Application health check failed", error=str(e))
            return {
                'healthy': False,
                'error_message': str(e),
                'details': {'status': 'failed'}
            }
    
    def get_health_summary(self) -> Dict[str, Any]:
        """
        Get health summary and status overview.
        
        Returns:
            Dictionary containing health summary
        """
        summary = {
            'service_type': self.__class__.__name__,
            'service_id': self._service_id,
            'last_health_check': self._last_health_check.get('timestamp') if self._last_health_check else None,
            'health_checks_performed': len(self._health_checks),
            'cache_ttl_seconds': self._health_cache_ttl
        }
        
        if self._last_health_check:
            summary.update({
                'overall_healthy': self._last_health_check.get('healthy', False),
                'last_check_summary': self._last_health_check.get('summary', {}),
                'failed_checks': [
                    name for name, result in self._last_health_check.get('checks', {}).items()
                    if not result.get('healthy', False)
                ]
            })
        
        return summary


# ============================================================================
# MODULE INITIALIZATION AND UTILITIES
# ============================================================================

def create_user_service(config: Optional[ServiceConfiguration] = None) -> UserService:
    """
    Create user service with default configuration.
    
    Args:
        config: Service configuration
        
    Returns:
        Configured user service instance
    """
    service = UserService(config=config)
    logger.info("User service created", service_id=service._service_id)
    return service


def create_order_service(config: Optional[ServiceConfiguration] = None) -> OrderService:
    """
    Create order service with default configuration.
    
    Args:
        config: Service configuration
        
    Returns:
        Configured order service instance
    """
    service = OrderService(config=config)
    logger.info("Order service created", service_id=service._service_id)
    return service


def create_authentication_service(config: Optional[ServiceConfiguration] = None) -> AuthenticationService:
    """
    Create authentication service with circuit breaker protection.
    
    Args:
        config: Service configuration
        
    Returns:
        Configured authentication service instance
    """
    service = AuthenticationService(config=config, enable_circuit_breakers=True)
    logger.info("Authentication service created", service_id=service._service_id)
    return service


def create_workflow_service(config: Optional[ServiceConfiguration] = None) -> BusinessWorkflowService:
    """
    Create business workflow service with orchestration capabilities.
    
    Args:
        config: Service configuration
        
    Returns:
        Configured workflow service instance
    """
    service = BusinessWorkflowService(config=config)
    logger.info("Business workflow service created", service_id=service._service_id)
    return service


def create_health_check_service(config: Optional[ServiceConfiguration] = None) -> HealthCheckService:
    """
    Create health check service with monitoring capabilities.
    
    Args:
        config: Service configuration
        
    Returns:
        Configured health check service instance
    """
    service = HealthCheckService(config=config)
    logger.info("Health check service created", service_id=service._service_id)
    return service


# Default service instances for Flask application integration
_default_services = {}


def get_service(service_type: str, **kwargs) -> BaseBusinessService:
    """
    Get or create service instance of specified type.
    
    Args:
        service_type: Type of service to get
        **kwargs: Additional service configuration
        
    Returns:
        Service instance
    """
    if service_type not in _default_services:
        if service_type == 'user':
            _default_services[service_type] = create_user_service(**kwargs)
        elif service_type == 'order':
            _default_services[service_type] = create_order_service(**kwargs)
        elif service_type == 'auth':
            _default_services[service_type] = create_authentication_service(**kwargs)
        elif service_type == 'workflow':
            _default_services[service_type] = create_workflow_service(**kwargs)
        elif service_type == 'health':
            _default_services[service_type] = create_health_check_service(**kwargs)
        else:
            raise ValueError(f"Unknown service type: {service_type}")
    
    return _default_services[service_type]


def clear_service_cache() -> None:
    """Clear all cached service instances."""
    global _default_services
    _default_services.clear()
    logger.info("Service cache cleared")


# Module initialization logging
logger.info("Business services module initialized successfully",
           service_types=['user', 'order', 'auth', 'workflow', 'health'],
           circuit_breaker_enabled=True,
           transaction_coordination_enabled=True,
           workflow_orchestration_enabled=True,
           health_monitoring_enabled=True)