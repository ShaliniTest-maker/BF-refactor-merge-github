"""
Base class for external service clients implementing comprehensive HTTP client patterns.

This module provides the foundational infrastructure for all third-party API integrations with
enterprise-grade resilience patterns, monitoring instrumentation, and standardized error handling.
It serves as the base class for Auth0, AWS S3, and other external service integrations.

Key Features:
- Dual HTTP client support (requests 2.31+ and httpx 0.24+) per Section 0.1.2
- Circuit breaker integration for external service protection per Section 6.3.3
- Exponential backoff retry logic with intelligent error classification per Section 4.2.3
- Comprehensive monitoring with Prometheus metrics collection per Section 6.3.3
- Connection pooling optimization for performance per Section 6.3.5
- Structured logging with correlation ID tracking per Section 6.3.3

Aligned with:
- Section 0.1.2: External Integration Components - HTTP client library replacement
- Section 6.3.3: External Systems - Resilience patterns and monitoring
- Section 6.3.5: Performance and Scalability - Connection pooling and metrics
- Section 4.2.3: Error Handling and Recovery - Comprehensive exception management
- Section 3.2.3: HTTP Client & Integration Libraries specifications
"""

import asyncio
import time
import uuid
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union, Callable, Type, TypeVar
from urllib.parse import urljoin, urlparse

import structlog
import requests
import httpx
from prometheus_client import Counter, Histogram, Gauge

# HTTP client management per Section 3.2.3
from .http_client import (
    HTTPClientManager,
    SynchronousHTTPClient,
    AsynchronousHTTPClient,
    create_client_manager
)

# Circuit breaker integration per Section 6.3.3
from .circuit_breaker import (
    EnhancedCircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerPolicy,
    global_circuit_breaker_manager
)

# Retry logic with exponential backoff per Section 4.2.3
from .retry import (
    RetryManager,
    RetryConfiguration,
    retry_manager,
    with_retry,
    with_retry_async
)

# Comprehensive exception handling per Section 4.2.3
from .exceptions import (
    IntegrationError,
    HTTPClientError,
    ConnectionError,
    TimeoutError,
    HTTPResponseError,
    CircuitBreakerOpenError,
    RetryExhaustedError,
    IntegrationExceptionFactory
)

# Monitoring and metrics integration per Section 6.3.3
from .monitoring import (
    ExternalServiceMonitor,
    external_service_monitor,
    ExternalServiceType,
    ServiceMetrics,
    ServiceHealthState
)

# Type variables for generic typing
T = TypeVar('T')
ResponseType = TypeVar('ResponseType', requests.Response, httpx.Response)

# Initialize structured logger for base client operations
logger = structlog.get_logger(__name__)

# Base client metrics per Section 6.3.3
base_client_operations = Counter(
    'base_client_operations_total',
    'Total operations performed by base clients',
    ['client_name', 'service_type', 'operation', 'client_mode']
)

base_client_duration = Histogram(
    'base_client_operation_duration_seconds',
    'Duration of base client operations',
    ['client_name', 'service_type', 'operation', 'client_mode'],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0]
)

base_client_errors = Counter(
    'base_client_errors_total',
    'Total errors in base client operations',
    ['client_name', 'service_type', 'operation', 'error_type', 'client_mode']
)

base_client_active_requests = Gauge(
    'base_client_active_requests',
    'Number of active requests per client',
    ['client_name', 'service_type', 'client_mode']
)


class BaseClientConfiguration:
    """
    Comprehensive configuration for base external service clients.
    
    Provides centralized configuration management for HTTP clients, circuit breakers,
    retry strategies, and monitoring settings per Section 6.3.5 requirements.
    """
    
    def __init__(
        self,
        service_name: str,
        service_type: ExternalServiceType,
        base_url: Optional[str] = None,
        
        # HTTP client configuration per Section 3.2.3
        timeout: Union[float, tuple] = 30.0,
        verify_ssl: bool = True,
        default_headers: Optional[Dict[str, str]] = None,
        
        # Connection pooling configuration per Section 6.3.5
        sync_pool_connections: int = 20,
        sync_pool_maxsize: int = 50,
        async_max_connections: int = 100,
        async_max_keepalive_connections: int = 50,
        keepalive_expiry: float = 30.0,
        enable_http2: bool = True,
        
        # Circuit breaker configuration per Section 6.3.3
        circuit_breaker_enabled: bool = True,
        circuit_breaker_policy: CircuitBreakerPolicy = CircuitBreakerPolicy.MODERATE,
        circuit_breaker_fail_max: int = 5,
        circuit_breaker_recovery_timeout: int = 60,
        circuit_breaker_fallback_enabled: bool = True,
        
        # Retry configuration per Section 4.2.3
        retry_enabled: bool = True,
        retry_max_attempts: int = 3,
        retry_min_wait: float = 1.0,
        retry_max_wait: float = 30.0,
        retry_jitter_max: float = 2.0,
        retry_exponential_base: float = 2.0,
        
        # Monitoring configuration per Section 6.3.3
        monitoring_enabled: bool = True,
        health_check_enabled: bool = True,
        metrics_collection_enabled: bool = True,
        performance_tracking_enabled: bool = True,
        
        # Advanced configuration
        request_id_header: str = 'X-Request-ID',
        correlation_id_header: str = 'X-Correlation-ID',
        rate_limit_respect: bool = True,
        custom_error_handlers: Optional[Dict[Type[Exception], Callable]] = None,
        **kwargs
    ):
        """
        Initialize base client configuration with enterprise-grade defaults.
        
        Args:
            service_name: Unique identifier for the external service
            service_type: Type of external service (auth, storage, api, etc.)
            base_url: Base URL for all service requests
            timeout: Request timeout configuration
            verify_ssl: SSL certificate verification flag
            default_headers: Default headers for all requests
            sync_pool_connections: Synchronous client connection pool size
            sync_pool_maxsize: Maximum synchronous connections per pool
            async_max_connections: Maximum asynchronous connections
            async_max_keepalive_connections: Maximum keepalive connections
            keepalive_expiry: Keepalive connection expiry time
            enable_http2: Enable HTTP/2 support for async client
            circuit_breaker_enabled: Enable circuit breaker protection
            circuit_breaker_policy: Circuit breaker policy type
            circuit_breaker_fail_max: Maximum failures before circuit opens
            circuit_breaker_recovery_timeout: Recovery timeout in seconds
            circuit_breaker_fallback_enabled: Enable fallback responses
            retry_enabled: Enable retry logic
            retry_max_attempts: Maximum retry attempts
            retry_min_wait: Minimum wait time between retries
            retry_max_wait: Maximum wait time between retries
            retry_jitter_max: Maximum jitter for retry backoff
            retry_exponential_base: Exponential backoff base
            monitoring_enabled: Enable comprehensive monitoring
            health_check_enabled: Enable health check functionality
            metrics_collection_enabled: Enable Prometheus metrics
            performance_tracking_enabled: Enable performance monitoring
            request_id_header: Header name for request ID
            correlation_id_header: Header name for correlation ID
            rate_limit_respect: Respect rate limit headers from service
            custom_error_handlers: Custom exception handlers
            **kwargs: Additional configuration parameters
        """
        self.service_name = service_name
        self.service_type = service_type
        self.base_url = base_url.rstrip('/') if base_url else None
        
        # HTTP client settings
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.default_headers = default_headers or {}
        
        # Connection pooling settings per Section 6.3.5
        self.sync_pool_connections = sync_pool_connections
        self.sync_pool_maxsize = sync_pool_maxsize
        self.async_max_connections = async_max_connections
        self.async_max_keepalive_connections = async_max_keepalive_connections
        self.keepalive_expiry = keepalive_expiry
        self.enable_http2 = enable_http2
        
        # Circuit breaker settings per Section 6.3.3
        self.circuit_breaker_enabled = circuit_breaker_enabled
        self.circuit_breaker_policy = circuit_breaker_policy
        self.circuit_breaker_fail_max = circuit_breaker_fail_max
        self.circuit_breaker_recovery_timeout = circuit_breaker_recovery_timeout
        self.circuit_breaker_fallback_enabled = circuit_breaker_fallback_enabled
        
        # Retry settings per Section 4.2.3
        self.retry_enabled = retry_enabled
        self.retry_max_attempts = retry_max_attempts
        self.retry_min_wait = retry_min_wait
        self.retry_max_wait = retry_max_wait
        self.retry_jitter_max = retry_jitter_max
        self.retry_exponential_base = retry_exponential_base
        
        # Monitoring settings per Section 6.3.3
        self.monitoring_enabled = monitoring_enabled
        self.health_check_enabled = health_check_enabled
        self.metrics_collection_enabled = metrics_collection_enabled
        self.performance_tracking_enabled = performance_tracking_enabled
        
        # Advanced settings
        self.request_id_header = request_id_header
        self.correlation_id_header = correlation_id_header
        self.rate_limit_respect = rate_limit_respect
        self.custom_error_handlers = custom_error_handlers or {}
        
        # Store additional configuration
        for key, value in kwargs.items():
            setattr(self, key, value)
        
        logger.info(
            "Base client configuration initialized",
            service_name=service_name,
            service_type=service_type.value,
            base_url=base_url,
            circuit_breaker_enabled=circuit_breaker_enabled,
            retry_enabled=retry_enabled,
            monitoring_enabled=monitoring_enabled
        )


class BaseExternalServiceClient(ABC):
    """
    Abstract base class for all external service clients implementing enterprise-grade patterns.
    
    Provides comprehensive foundation for external service integration with standardized
    HTTP client patterns, circuit breaker protection, retry logic, and monitoring
    instrumentation per Section 6.3.3 and Section 6.3.5 requirements.
    
    This class serves as the foundation for all third-party API integrations including
    Auth0, AWS S3, external APIs, and other enterprise services.
    """
    
    def __init__(self, config: BaseClientConfiguration):
        """
        Initialize base external service client with comprehensive configuration.
        
        Args:
            config: Base client configuration containing all operational parameters
        """
        self.config = config
        self.client_id = f"{config.service_name}_{uuid.uuid4().hex[:8]}"
        
        # Initialize HTTP client manager per Section 3.2.3
        self.http_manager = self._initialize_http_client_manager()
        
        # Initialize circuit breaker per Section 6.3.3
        self.circuit_breaker = self._initialize_circuit_breaker() if config.circuit_breaker_enabled else None
        
        # Initialize retry manager per Section 4.2.3
        self.retry_config = self._initialize_retry_configuration() if config.retry_enabled else None
        
        # Initialize monitoring per Section 6.3.3
        if config.monitoring_enabled:
            self._initialize_monitoring()
        
        # Request context tracking
        self._active_requests: Dict[str, Dict[str, Any]] = {}
        self._request_history: List[Dict[str, Any]] = []
        
        # Performance baseline tracking per Section 0.3.2
        self._performance_baselines: Dict[str, float] = {}
        
        logger.info(
            "Base external service client initialized",
            client_id=self.client_id,
            service_name=config.service_name,
            service_type=config.service_type.value,
            circuit_breaker_enabled=config.circuit_breaker_enabled,
            retry_enabled=config.retry_enabled,
            monitoring_enabled=config.monitoring_enabled
        )
    
    def _initialize_http_client_manager(self) -> HTTPClientManager:
        """
        Initialize HTTP client manager with optimized configuration per Section 6.3.5.
        
        Returns:
            Configured HTTP client manager with dual-client support
        """
        return create_client_manager(
            base_url=self.config.base_url,
            timeout=self.config.timeout,
            headers=self.config.default_headers,
            sync_pool_connections=self.config.sync_pool_connections,
            sync_pool_maxsize=self.config.sync_pool_maxsize,
            async_max_connections=self.config.async_max_connections,
            async_max_keepalive_connections=self.config.async_max_keepalive_connections,
            verify_ssl=self.config.verify_ssl,
            enable_http2=self.config.enable_http2
        )
    
    def _initialize_circuit_breaker(self) -> EnhancedCircuitBreaker:
        """
        Initialize circuit breaker with service-specific configuration per Section 6.3.3.
        
        Returns:
            Configured enhanced circuit breaker instance
        """
        circuit_config = CircuitBreakerConfig(
            service_name=self.config.service_name,
            service_type=self.config.service_type,
            fail_max=self.config.circuit_breaker_fail_max,
            recovery_timeout=self.config.circuit_breaker_recovery_timeout,
            policy=self.config.circuit_breaker_policy,
            timeout_seconds=self._get_timeout_seconds(),
            fallback_enabled=self.config.circuit_breaker_fallback_enabled,
            enable_metrics=self.config.metrics_collection_enabled,
            enable_health_monitoring=self.config.health_check_enabled
        )
        
        return global_circuit_breaker_manager.register_circuit_breaker(
            service_name=self.config.service_name,
            config=circuit_config
        )
    
    def _initialize_retry_configuration(self) -> RetryConfiguration:
        """
        Initialize retry configuration with intelligent error classification per Section 4.2.3.
        
        Returns:
            Configured retry strategy for the service
        """
        return RetryConfiguration(
            service_name=self.config.service_name,
            operation='base_operation',
            max_attempts=self.config.retry_max_attempts,
            min_wait=self.config.retry_min_wait,
            max_wait=self.config.retry_max_wait,
            jitter_max=self.config.retry_jitter_max,
            exponential_base=self.config.retry_exponential_base,
            custom_error_classifier=self._custom_error_classifier
        )
    
    def _initialize_monitoring(self) -> None:
        """
        Initialize comprehensive monitoring and metrics collection per Section 6.3.3.
        """
        if self.config.metrics_collection_enabled:
            # Register service with external service monitor
            service_metrics = ServiceMetrics(
                service_name=self.config.service_name,
                service_type=self.config.service_type,
                health_endpoint=self._get_health_check_endpoint(),
                timeout_seconds=self._get_timeout_seconds(),
                critical_threshold_ms=self._get_timeout_seconds() * 1000 * 0.8,
                warning_threshold_ms=self._get_timeout_seconds() * 1000 * 0.5
            )
            external_service_monitor.register_service(service_metrics)
        
        logger.debug(
            "Monitoring initialized for base client",
            service_name=self.config.service_name,
            metrics_enabled=self.config.metrics_collection_enabled,
            health_checks_enabled=self.config.health_check_enabled
        )
    
    def _get_timeout_seconds(self) -> float:
        """Extract timeout value in seconds from configuration."""
        if isinstance(self.config.timeout, (int, float)):
            return float(self.config.timeout)
        elif isinstance(self.config.timeout, tuple):
            return float(max(self.config.timeout))
        else:
            return 30.0  # Default timeout
    
    def _get_health_check_endpoint(self) -> Optional[str]:
        """
        Get health check endpoint for the service.
        
        Subclasses should override this method to provide service-specific health endpoints.
        
        Returns:
            Health check endpoint path or None
        """
        return None
    
    def _custom_error_classifier(self, exception: Exception) -> Optional[bool]:
        """
        Custom error classification for retry decisions.
        
        Implements intelligent error classification per Section 6.3.3 with
        service-specific logic for retry decision making.
        
        Args:
            exception: Exception to classify
            
        Returns:
            True if retryable, False if not retryable, None for default handling
        """
        # Check for custom error handlers
        for error_type, handler in self.config.custom_error_handlers.items():
            if isinstance(exception, error_type):
                try:
                    return handler(exception)
                except Exception as handler_error:
                    logger.warning(
                        "Custom error handler failed",
                        service_name=self.config.service_name,
                        error_type=error_type.__name__,
                        handler_error=str(handler_error)
                    )
        
        # Default classification logic
        if isinstance(exception, (ConnectionError, TimeoutError)):
            return True  # Always retry connection and timeout errors
        elif isinstance(exception, HTTPResponseError):
            status_code = getattr(exception, 'status_code', None)
            if status_code:
                # Retry on server errors and rate limits
                return status_code in [429, 502, 503, 504, 408]
        elif isinstance(exception, CircuitBreakerOpenError):
            return False  # Never retry when circuit breaker is open
        
        return None  # Use default classification
    
    def _generate_request_id(self) -> str:
        """
        Generate unique request ID for correlation tracking.
        
        Returns:
            Unique request identifier
        """
        return f"{self.config.service_name}_{uuid.uuid4().hex}"
    
    def _generate_correlation_id(self) -> str:
        """
        Generate correlation ID for distributed tracing.
        
        Returns:
            Unique correlation identifier
        """
        return f"corr_{uuid.uuid4().hex}"
    
    def _prepare_request_headers(
        self, 
        additional_headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, str]:
        """
        Prepare comprehensive request headers with tracking identifiers.
        
        Args:
            additional_headers: Additional headers to include
            
        Returns:
            Complete headers dictionary with tracking information
        """
        headers = self.config.default_headers.copy()
        
        # Add request tracking headers
        headers[self.config.request_id_header] = self._generate_request_id()
        headers[self.config.correlation_id_header] = self._generate_correlation_id()
        
        # Add standard headers
        if 'User-Agent' not in headers:
            headers['User-Agent'] = f"BaseClient/{self.config.service_name}"
        if 'Accept' not in headers:
            headers['Accept'] = 'application/json'
        if 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/json'
        
        # Merge additional headers
        if additional_headers:
            headers.update(additional_headers)
        
        return headers
    
    def _track_request_start(self, operation: str, **context) -> str:
        """
        Track request start for monitoring and metrics.
        
        Args:
            operation: Operation being performed
            **context: Additional context information
            
        Returns:
            Request tracking ID
        """
        request_id = self._generate_request_id()
        
        request_context = {
            'request_id': request_id,
            'operation': operation,
            'start_time': time.time(),
            'service_name': self.config.service_name,
            'service_type': self.config.service_type.value,
            'client_mode': 'sync',  # Default, can be overridden
            **context
        }
        
        self._active_requests[request_id] = request_context
        
        # Update active requests metric
        if self.config.metrics_collection_enabled:
            base_client_active_requests.labels(
                client_name=self.config.service_name,
                service_type=self.config.service_type.value,
                client_mode=request_context['client_mode']
            ).inc()
        
        return request_id
    
    def _track_request_completion(
        self, 
        request_id: str, 
        success: bool = True, 
        error_type: Optional[str] = None
    ) -> None:
        """
        Track request completion for monitoring and metrics.
        
        Args:
            request_id: Request tracking ID
            success: Whether the request was successful
            error_type: Type of error if unsuccessful
        """
        if request_id not in self._active_requests:
            return
        
        request_context = self._active_requests.pop(request_id)
        duration = time.time() - request_context['start_time']
        
        # Update metrics if enabled
        if self.config.metrics_collection_enabled:
            # Update operation counter
            base_client_operations.labels(
                client_name=self.config.service_name,
                service_type=self.config.service_type.value,
                operation=request_context['operation'],
                client_mode=request_context['client_mode']
            ).inc()
            
            # Update duration histogram
            base_client_duration.labels(
                client_name=self.config.service_name,
                service_type=self.config.service_type.value,
                operation=request_context['operation'],
                client_mode=request_context['client_mode']
            ).observe(duration)
            
            # Update error counter if failed
            if not success and error_type:
                base_client_errors.labels(
                    client_name=self.config.service_name,
                    service_type=self.config.service_type.value,
                    operation=request_context['operation'],
                    error_type=error_type,
                    client_mode=request_context['client_mode']
                ).inc()
            
            # Update active requests gauge
            base_client_active_requests.labels(
                client_name=self.config.service_name,
                service_type=self.config.service_type.value,
                client_mode=request_context['client_mode']
            ).dec()
        
        # Add to request history for debugging
        request_context.update({
            'end_time': time.time(),
            'duration': duration,
            'success': success,
            'error_type': error_type
        })
        self._request_history.append(request_context)
        
        # Keep only last 100 requests in history
        if len(self._request_history) > 100:
            self._request_history = self._request_history[-100:]
        
        logger.debug(
            "Request tracking completed",
            request_id=request_id,
            operation=request_context['operation'],
            duration=duration,
            success=success,
            error_type=error_type
        )
    
    def _execute_with_resilience(
        self, 
        operation: str, 
        func: Callable, 
        *args, 
        **kwargs
    ) -> Any:
        """
        Execute operation with comprehensive resilience patterns.
        
        Implements circuit breaker protection, retry logic, and monitoring
        per Section 6.3.3 and Section 4.2.3 requirements.
        
        Args:
            operation: Name of the operation being performed
            func: Function to execute with resilience patterns
            *args: Arguments for the function
            **kwargs: Keyword arguments for the function
            
        Returns:
            Result of successful function execution
            
        Raises:
            IntegrationError: For various integration failures
        """
        request_id = self._track_request_start(operation)
        
        try:
            if self.circuit_breaker and self.config.circuit_breaker_enabled:
                # Execute with circuit breaker protection
                if self.retry_config and self.config.retry_enabled:
                    # Execute with both circuit breaker and retry
                    result = self.circuit_breaker.call(
                        lambda: retry_manager.execute_with_retry(
                            func, 
                            self.config.service_name, 
                            operation, 
                            *args, 
                            **kwargs
                        )
                    )
                else:
                    # Execute with circuit breaker only
                    result = self.circuit_breaker.call(func, *args, **kwargs)
            elif self.retry_config and self.config.retry_enabled:
                # Execute with retry only
                result = retry_manager.execute_with_retry(
                    func, 
                    self.config.service_name, 
                    operation, 
                    *args, 
                    **kwargs
                )
            else:
                # Execute without resilience patterns
                result = func(*args, **kwargs)
            
            self._track_request_completion(request_id, success=True)
            return result
            
        except Exception as e:
            error_type = type(e).__name__
            self._track_request_completion(request_id, success=False, error_type=error_type)
            
            logger.error(
                "Operation failed with resilience patterns",
                operation=operation,
                service_name=self.config.service_name,
                error_type=error_type,
                error_message=str(e),
                request_id=request_id
            )
            
            # Re-raise the exception
            raise
    
    async def _execute_with_resilience_async(
        self, 
        operation: str, 
        func: Callable, 
        *args, 
        **kwargs
    ) -> Any:
        """
        Execute async operation with comprehensive resilience patterns.
        
        Implements circuit breaker protection, retry logic, and monitoring
        for asynchronous operations per Section 6.3.3 requirements.
        
        Args:
            operation: Name of the operation being performed
            func: Async function to execute with resilience patterns
            *args: Arguments for the function
            **kwargs: Keyword arguments for the function
            
        Returns:
            Result of successful async function execution
            
        Raises:
            IntegrationError: For various integration failures
        """
        request_id = self._track_request_start(operation, client_mode='async')
        
        try:
            if self.circuit_breaker and self.config.circuit_breaker_enabled:
                # Execute with circuit breaker protection
                if self.retry_config and self.config.retry_enabled:
                    # Execute with both circuit breaker and retry
                    result = await self.circuit_breaker.call_async(
                        lambda: retry_manager.execute_with_retry_async(
                            func, 
                            self.config.service_name, 
                            operation, 
                            *args, 
                            **kwargs
                        )
                    )
                else:
                    # Execute with circuit breaker only
                    result = await self.circuit_breaker.call_async(func, *args, **kwargs)
            elif self.retry_config and self.config.retry_enabled:
                # Execute with retry only
                result = await retry_manager.execute_with_retry_async(
                    func, 
                    self.config.service_name, 
                    operation, 
                    *args, 
                    **kwargs
                )
            else:
                # Execute without resilience patterns
                result = await func(*args, **kwargs)
            
            self._track_request_completion(request_id, success=True)
            return result
            
        except Exception as e:
            error_type = type(e).__name__
            self._track_request_completion(request_id, success=False, error_type=error_type)
            
            logger.error(
                "Async operation failed with resilience patterns",
                operation=operation,
                service_name=self.config.service_name,
                error_type=error_type,
                error_message=str(e),
                request_id=request_id
            )
            
            # Re-raise the exception
            raise
    
    def make_request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        data: Optional[Union[Dict[str, Any], str, bytes]] = None,
        timeout: Optional[Union[float, tuple]] = None,
        **kwargs
    ) -> requests.Response:
        """
        Make synchronous HTTP request with comprehensive resilience patterns.
        
        Implements the complete enterprise-grade request processing pipeline
        with circuit breaker protection, retry logic, and monitoring integration
        per Section 6.3.3 and Section 6.3.5 requirements.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            path: Request path or complete URL
            params: Query parameters
            headers: Additional request headers
            json_data: JSON payload for request body
            data: Raw data for request body
            timeout: Request timeout override
            **kwargs: Additional request parameters
            
        Returns:
            HTTP response object
            
        Raises:
            HTTPClientError: For various HTTP client failures
            CircuitBreakerOpenError: When circuit breaker is open
            RetryExhaustedError: When retry attempts are exhausted
        """
        operation = f"{method.upper()}_{path}"
        
        # Prepare comprehensive headers
        request_headers = self._prepare_request_headers(headers)
        
        # Override timeout if specified
        request_timeout = timeout or self.config.timeout
        
        def execute_request():
            """Internal function for request execution with monitoring."""
            if self.config.monitoring_enabled:
                return external_service_monitor.monitor_request(
                    service_name=self.config.service_name,
                    service_type=self.config.service_type,
                    method=method
                )(lambda: self.http_manager.get_sync_client().request(
                    method=method,
                    path=path,
                    params=params,
                    headers=request_headers,
                    json_data=json_data,
                    data=data,
                    timeout=request_timeout,
                    **kwargs
                ))()
            else:
                return self.http_manager.get_sync_client().request(
                    method=method,
                    path=path,
                    params=params,
                    headers=request_headers,
                    json_data=json_data,
                    data=data,
                    timeout=request_timeout,
                    **kwargs
                )
        
        return self._execute_with_resilience(operation, execute_request)
    
    async def make_request_async(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        data: Optional[Union[Dict[str, Any], str, bytes]] = None,
        timeout: Optional[Union[float, httpx.Timeout]] = None,
        **kwargs
    ) -> httpx.Response:
        """
        Make asynchronous HTTP request with comprehensive resilience patterns.
        
        Implements the complete enterprise-grade async request processing pipeline
        with circuit breaker protection, retry logic, and monitoring integration
        per Section 6.3.3 and Section 6.3.5 requirements.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            path: Request path or complete URL
            params: Query parameters
            headers: Additional request headers
            json_data: JSON payload for request body
            data: Raw data for request body
            timeout: Request timeout override
            **kwargs: Additional request parameters
            
        Returns:
            HTTP response object
            
        Raises:
            HTTPClientError: For various HTTP client failures
            CircuitBreakerOpenError: When circuit breaker is open
            RetryExhaustedError: When retry attempts are exhausted
        """
        operation = f"{method.upper()}_{path}"
        
        # Prepare comprehensive headers
        request_headers = self._prepare_request_headers(headers)
        
        # Override timeout if specified
        request_timeout = timeout or self.config.timeout
        
        async def execute_request():
            """Internal async function for request execution with monitoring."""
            if self.config.monitoring_enabled:
                return await external_service_monitor.monitor_request(
                    service_name=self.config.service_name,
                    service_type=self.config.service_type,
                    method=method
                )(lambda: self.http_manager.get_async_client().request(
                    method=method,
                    path=path,
                    params=params,
                    headers=request_headers,
                    json_data=json_data,
                    data=data,
                    timeout=request_timeout,
                    **kwargs
                ))()
            else:
                return await self.http_manager.get_async_client().request(
                    method=method,
                    path=path,
                    params=params,
                    headers=request_headers,
                    json_data=json_data,
                    data=data,
                    timeout=request_timeout,
                    **kwargs
                )
        
        return await self._execute_with_resilience_async(operation, execute_request)
    
    # Convenience methods for common HTTP methods
    
    def get(self, path: str, **kwargs) -> requests.Response:
        """Make synchronous GET request."""
        return self.make_request('GET', path, **kwargs)
    
    def post(self, path: str, **kwargs) -> requests.Response:
        """Make synchronous POST request."""
        return self.make_request('POST', path, **kwargs)
    
    def put(self, path: str, **kwargs) -> requests.Response:
        """Make synchronous PUT request."""
        return self.make_request('PUT', path, **kwargs)
    
    def patch(self, path: str, **kwargs) -> requests.Response:
        """Make synchronous PATCH request."""
        return self.make_request('PATCH', path, **kwargs)
    
    def delete(self, path: str, **kwargs) -> requests.Response:
        """Make synchronous DELETE request."""
        return self.make_request('DELETE', path, **kwargs)
    
    async def get_async(self, path: str, **kwargs) -> httpx.Response:
        """Make asynchronous GET request."""
        return await self.make_request_async('GET', path, **kwargs)
    
    async def post_async(self, path: str, **kwargs) -> httpx.Response:
        """Make asynchronous POST request."""
        return await self.make_request_async('POST', path, **kwargs)
    
    async def put_async(self, path: str, **kwargs) -> httpx.Response:
        """Make asynchronous PUT request."""
        return await self.make_request_async('PUT', path, **kwargs)
    
    async def patch_async(self, path: str, **kwargs) -> httpx.Response:
        """Make asynchronous PATCH request."""
        return await self.make_request_async('PATCH', path, **kwargs)
    
    async def delete_async(self, path: str, **kwargs) -> httpx.Response:
        """Make asynchronous DELETE request."""
        return await self.make_request_async('DELETE', path, **kwargs)
    
    # Health monitoring and diagnostics
    
    def check_health(self) -> Dict[str, Any]:
        """
        Perform comprehensive health check for the external service.
        
        Implements health verification per Section 6.3.3 service health monitoring
        with circuit breaker status, connection pool metrics, and performance data.
        
        Returns:
            Dictionary containing comprehensive health status
        """
        health_status = {
            'service_name': self.config.service_name,
            'service_type': self.config.service_type.value,
            'client_id': self.client_id,
            'timestamp': datetime.utcnow().isoformat(),
            'overall_status': 'healthy',
            'components': {}
        }
        
        try:
            # Check circuit breaker status
            if self.circuit_breaker:
                cb_health = self.circuit_breaker.get_health_status()
                health_status['components']['circuit_breaker'] = cb_health
                
                if cb_health['circuit_state'] == 'OPEN':
                    health_status['overall_status'] = 'degraded'
            
            # Check active requests
            active_count = len(self._active_requests)
            health_status['components']['active_requests'] = {
                'count': active_count,
                'status': 'healthy' if active_count < 50 else 'warning'
            }
            
            # Check recent request history
            recent_requests = [
                req for req in self._request_history 
                if req.get('end_time', 0) > time.time() - 300  # Last 5 minutes
            ]
            
            failed_requests = [req for req in recent_requests if not req.get('success', True)]
            error_rate = len(failed_requests) / len(recent_requests) if recent_requests else 0
            
            health_status['components']['error_rate'] = {
                'rate': error_rate,
                'recent_requests': len(recent_requests),
                'failed_requests': len(failed_requests),
                'status': 'healthy' if error_rate < 0.05 else 'degraded' if error_rate < 0.2 else 'unhealthy'
            }
            
            # Determine overall status
            component_statuses = [comp.get('status', 'healthy') for comp in health_status['components'].values()]
            if 'unhealthy' in component_statuses:
                health_status['overall_status'] = 'unhealthy'
            elif 'degraded' in component_statuses or 'warning' in component_statuses:
                health_status['overall_status'] = 'degraded'
            
            # Perform service-specific health check
            service_health = self._perform_service_health_check()
            if service_health:
                health_status['components']['service_specific'] = service_health
                if service_health.get('status') != 'healthy':
                    health_status['overall_status'] = service_health.get('status', 'degraded')
            
        except Exception as e:
            health_status['overall_status'] = 'error'
            health_status['error'] = str(e)
            
            logger.error(
                "Health check failed",
                service_name=self.config.service_name,
                error=str(e)
            )
        
        return health_status
    
    def _perform_service_health_check(self) -> Optional[Dict[str, Any]]:
        """
        Perform service-specific health check.
        
        Subclasses should override this method to implement service-specific
        health verification logic.
        
        Returns:
            Service-specific health status or None
        """
        return None
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """
        Get comprehensive performance metrics for monitoring and analysis.
        
        Returns:
            Dictionary containing performance metrics and statistics
        """
        current_time = time.time()
        recent_requests = [
            req for req in self._request_history 
            if req.get('end_time', 0) > current_time - 3600  # Last hour
        ]
        
        if not recent_requests:
            return {
                'service_name': self.config.service_name,
                'timestamp': datetime.utcnow().isoformat(),
                'no_recent_requests': True
            }
        
        # Calculate performance statistics
        durations = [req.get('duration', 0) for req in recent_requests]
        successful_requests = [req for req in recent_requests if req.get('success', True)]
        
        metrics = {
            'service_name': self.config.service_name,
            'service_type': self.config.service_type.value,
            'timestamp': datetime.utcnow().isoformat(),
            'time_window': '1_hour',
            'total_requests': len(recent_requests),
            'successful_requests': len(successful_requests),
            'failed_requests': len(recent_requests) - len(successful_requests),
            'success_rate': len(successful_requests) / len(recent_requests),
            'performance': {
                'avg_duration': sum(durations) / len(durations),
                'min_duration': min(durations),
                'max_duration': max(durations),
                'p95_duration': sorted(durations)[int(len(durations) * 0.95)] if durations else 0,
                'p99_duration': sorted(durations)[int(len(durations) * 0.99)] if durations else 0
            },
            'active_requests': len(self._active_requests),
            'circuit_breaker': {}
        }
        
        # Add circuit breaker metrics
        if self.circuit_breaker:
            cb_metrics = self.circuit_breaker.get_metrics()
            metrics['circuit_breaker'] = {
                'state': self.circuit_breaker.state.name,
                'failure_count': self.circuit_breaker.failure_count,
                'total_calls': cb_metrics.total_calls,
                'successful_calls': cb_metrics.successful_calls,
                'failed_calls': cb_metrics.failed_calls,
                'fallback_calls': cb_metrics.fallback_calls,
                'success_rate': cb_metrics.successful_calls / cb_metrics.total_calls if cb_metrics.total_calls > 0 else 0
            }
        
        return metrics
    
    def reset_circuit_breaker(self) -> bool:
        """
        Manually reset circuit breaker to CLOSED state.
        
        Returns:
            True if circuit breaker was reset, False if not available
        """
        if self.circuit_breaker:
            self.circuit_breaker.reset_circuit()
            
            logger.info(
                "Circuit breaker manually reset",
                service_name=self.config.service_name,
                client_id=self.client_id
            )
            
            return True
        
        return False
    
    def set_performance_baseline(self, operation: str, baseline_duration: float) -> None:
        """
        Set performance baseline for comparison per Section 0.3.2.
        
        Args:
            operation: Operation name
            baseline_duration: Baseline duration in seconds
        """
        self._performance_baselines[operation] = baseline_duration
        
        if self.config.monitoring_enabled:
            external_service_monitor.set_performance_baseline(
                service_name=self.config.service_name,
                service_type=self.config.service_type,
                method=operation,
                baseline_duration=baseline_duration
            )
        
        logger.info(
            "Performance baseline set",
            service_name=self.config.service_name,
            operation=operation,
            baseline_duration=baseline_duration
        )
    
    @contextmanager
    def circuit_breaker_context(self):
        """
        Context manager for circuit breaker operations.
        
        Yields:
            Circuit breaker instance or None if not enabled
        """
        try:
            yield self.circuit_breaker
        except Exception as e:
            logger.error(
                "Circuit breaker context error",
                service_name=self.config.service_name,
                error=str(e)
            )
            raise
    
    @asynccontextmanager
    async def async_circuit_breaker_context(self):
        """
        Async context manager for circuit breaker operations.
        
        Yields:
            Circuit breaker instance or None if not enabled
        """
        try:
            yield self.circuit_breaker
        except Exception as e:
            logger.error(
                "Async circuit breaker context error",
                service_name=self.config.service_name,
                error=str(e)
            )
            raise
    
    async def close(self) -> None:
        """
        Close all client resources and cleanup.
        
        Performs comprehensive cleanup of HTTP clients, monitoring resources,
        and internal state per enterprise resource management practices.
        """
        try:
            # Close HTTP client manager
            await self.http_manager.close_all()
            
            # Clear active request tracking
            self._active_requests.clear()
            
            # Clear request history (keep for debugging)
            # self._request_history.clear()
            
            logger.info(
                "Base external service client closed",
                service_name=self.config.service_name,
                client_id=self.client_id
            )
            
        except Exception as e:
            logger.error(
                "Error during client cleanup",
                service_name=self.config.service_name,
                client_id=self.client_id,
                error=str(e)
            )
            raise
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        # Run async cleanup in sync context
        try:
            asyncio.run(self.close())
        except RuntimeError:
            # If we're already in an event loop, schedule cleanup
            loop = asyncio.get_event_loop()
            loop.create_task(self.close())
    
    async def __aenter__(self):
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit with cleanup."""
        await self.close()
    
    # Abstract methods for subclass implementation
    
    @abstractmethod
    def authenticate(self, **kwargs) -> Dict[str, Any]:
        """
        Perform authentication with the external service.
        
        Subclasses must implement service-specific authentication logic.
        
        Args:
            **kwargs: Authentication parameters
            
        Returns:
            Authentication result
        """
        pass
    
    @abstractmethod
    async def authenticate_async(self, **kwargs) -> Dict[str, Any]:
        """
        Perform async authentication with the external service.
        
        Subclasses must implement service-specific async authentication logic.
        
        Args:
            **kwargs: Authentication parameters
            
        Returns:
            Authentication result
        """
        pass


# Factory functions for convenient base client creation

def create_base_client_config(
    service_name: str,
    service_type: ExternalServiceType,
    base_url: Optional[str] = None,
    **kwargs
) -> BaseClientConfiguration:
    """
    Factory function to create base client configuration with enterprise defaults.
    
    Args:
        service_name: Unique identifier for the external service
        service_type: Type of external service
        base_url: Base URL for the service
        **kwargs: Additional configuration parameters
        
    Returns:
        Configured base client configuration
    """
    return BaseClientConfiguration(
        service_name=service_name,
        service_type=service_type,
        base_url=base_url,
        **kwargs
    )


def create_auth0_config(base_url: str, **kwargs) -> BaseClientConfiguration:
    """
    Create Auth0-specific configuration with optimized settings.
    
    Args:
        base_url: Auth0 domain URL
        **kwargs: Additional configuration overrides
        
    Returns:
        Auth0-optimized configuration
    """
    auth0_defaults = {
        'circuit_breaker_policy': CircuitBreakerPolicy.STRICT,
        'circuit_breaker_fail_max': 5,
        'circuit_breaker_recovery_timeout': 60,
        'retry_max_attempts': 3,
        'retry_min_wait': 1.0,
        'retry_max_wait': 30.0,
        'timeout': 5.0
    }
    auth0_defaults.update(kwargs)
    
    return create_base_client_config(
        service_name='auth0',
        service_type=ExternalServiceType.AUTH_PROVIDER,
        base_url=base_url,
        **auth0_defaults
    )


def create_aws_s3_config(region: str = 'us-east-1', **kwargs) -> BaseClientConfiguration:
    """
    Create AWS S3-specific configuration with optimized settings.
    
    Args:
        region: AWS region
        **kwargs: Additional configuration overrides
        
    Returns:
        AWS S3-optimized configuration
    """
    s3_defaults = {
        'circuit_breaker_policy': CircuitBreakerPolicy.MODERATE,
        'circuit_breaker_fail_max': 5,
        'circuit_breaker_recovery_timeout': 60,
        'retry_max_attempts': 4,
        'retry_min_wait': 0.5,
        'retry_max_wait': 60.0,
        'timeout': 10.0
    }
    s3_defaults.update(kwargs)
    
    return create_base_client_config(
        service_name='aws_s3',
        service_type=ExternalServiceType.CLOUD_STORAGE,
        base_url=f'https://s3.{region}.amazonaws.com',
        **s3_defaults
    )


def create_external_api_config(
    service_name: str,
    base_url: str,
    **kwargs
) -> BaseClientConfiguration:
    """
    Create external API configuration with balanced settings.
    
    Args:
        service_name: Name of the external API
        base_url: Base URL for the API
        **kwargs: Additional configuration overrides
        
    Returns:
        External API-optimized configuration
    """
    api_defaults = {
        'circuit_breaker_policy': CircuitBreakerPolicy.MODERATE,
        'circuit_breaker_fail_max': 5,
        'circuit_breaker_recovery_timeout': 60,
        'retry_max_attempts': 3,
        'retry_min_wait': 2.0,
        'retry_max_wait': 60.0,
        'timeout': 30.0
    }
    api_defaults.update(kwargs)
    
    return create_base_client_config(
        service_name=service_name,
        service_type=ExternalServiceType.HTTP_API,
        base_url=base_url,
        **api_defaults
    )


# Export public interface
__all__ = [
    # Main classes
    'BaseExternalServiceClient',
    'BaseClientConfiguration',
    
    # Factory functions
    'create_base_client_config',
    'create_auth0_config',
    'create_aws_s3_config',
    'create_external_api_config',
    
    # Type exports from dependencies for convenience
    'ExternalServiceType',
    'CircuitBreakerPolicy',
    'ServiceHealthState'
]