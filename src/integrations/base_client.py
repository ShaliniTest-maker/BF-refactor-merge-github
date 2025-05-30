"""
Base class for external service clients implementing comprehensive HTTP client patterns.

This module provides a standardized foundation for all third-party API integrations with 
enterprise-grade resilience patterns including circuit breaker integration, retry logic 
with exponential backoff, comprehensive monitoring instrumentation, and dual HTTP client 
support (requests/httpx). Implements performance optimization and fault tolerance patterns 
aligned with Section 0.1.2, 6.3.3, and 6.3.5 specifications.

Key Features:
- Dual HTTP client support (requests 2.31+ and httpx 0.24+) per Section 0.1.2
- Circuit breaker integration with pybreaker for service protection per Section 6.3.3
- Tenacity exponential backoff retry strategies per Section 4.2.3
- Comprehensive monitoring with prometheus-client per Section 6.3.5
- Connection pooling optimization for performance per Section 6.3.5
- Structured logging with enterprise integration per Section 6.3.3
- Graceful degradation and fallback mechanisms per Section 6.3.3

Performance Requirements:
- Maintains ≤10% variance from Node.js baseline per Section 0.3.2
- Enterprise-grade monitoring integration per Section 6.5.1.1
- Optimized connection pooling for external service calls per Section 6.3.5
"""

import asyncio
import json
import logging
import time
import uuid
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union, Callable, Type, Tuple
from urllib.parse import urljoin, urlparse

import structlog
from prometheus_client import Counter, Histogram, Gauge

# Import dependency modules for comprehensive integration
from .http_client import (
    HTTPClientManager,
    SynchronousHTTPClient,
    AsynchronousHTTPClient,
    create_sync_client,
    create_async_client,
    create_client_manager
)
from .circuit_breaker import (
    ExternalServiceCircuitBreaker,
    CircuitBreakerManager,
    create_circuit_breaker,
    circuit_breaker,
    get_circuit_breaker_health,
    circuit_breaker_manager
)
from .retry import (
    RetryManager,
    with_retry,
    with_retry_async,
    retry_manager,
    get_retry_metrics,
    reset_circuit_breaker as reset_retry_circuit_breaker
)
from .exceptions import (
    IntegrationError,
    HTTPClientError,
    ConnectionError,
    TimeoutError,
    HTTPResponseError,
    CircuitBreakerOpenError,
    CircuitBreakerHalfOpenError,
    RetryExhaustedError,
    Auth0Error,
    AWSServiceError,
    MongoDBError,
    RedisError,
    IntegrationExceptionFactory
)
from .monitoring import (
    external_service_monitor,
    ServiceType,
    CircuitBreakerState,
    HealthStatus,
    ExternalServiceMonitoring
)

# Initialize structured logger for enterprise integration
logger = structlog.get_logger(__name__)


class BaseClientConfiguration:
    """
    Configuration class for base external service client patterns.
    
    Provides comprehensive configuration management for HTTP client settings,
    circuit breaker parameters, retry strategies, and monitoring configuration
    with service-specific optimization per Section 6.3.5 requirements.
    """
    
    def __init__(
        self,
        service_name: str,
        service_type: ServiceType,
        base_url: str,
        
        # HTTP client configuration per Section 0.1.2
        timeout: Union[float, Tuple[float, float]] = 30.0,
        verify_ssl: bool = True,
        enable_http2: bool = True,
        
        # Connection pooling optimization per Section 6.3.5
        sync_pool_connections: int = 20,
        sync_pool_maxsize: int = 50,
        async_max_connections: int = 100,
        async_max_keepalive_connections: int = 50,
        keepalive_expiry: float = 30.0,
        
        # Circuit breaker configuration per Section 6.3.3
        enable_circuit_breaker: bool = True,
        circuit_breaker_failure_threshold: Optional[int] = None,
        circuit_breaker_reset_timeout: Optional[int] = None,
        circuit_breaker_fallback: Optional[Callable] = None,
        
        # Retry configuration per Section 4.2.3
        enable_retry: bool = True,
        max_retry_attempts: Optional[int] = None,
        retry_min_wait: Optional[float] = None,
        retry_max_wait: Optional[float] = None,
        retry_jitter_max: Optional[float] = None,
        
        # Monitoring and observability per Section 6.3.5
        enable_monitoring: bool = True,
        enable_detailed_logging: bool = True,
        correlation_id_header: str = "X-Correlation-ID",
        
        # Authentication and headers
        default_headers: Optional[Dict[str, str]] = None,
        auth_token_header: str = "Authorization",
        
        # Service-specific metadata
        service_version: Optional[str] = None,
        service_description: Optional[str] = None,
        health_check_endpoint: Optional[str] = None,
        
        **kwargs
    ):
        """
        Initialize base client configuration with comprehensive settings.
        
        Args:
            service_name: Unique service identifier for monitoring and logging
            service_type: Service type classification for configuration defaults
            base_url: Base URL for all service requests
            timeout: Request timeout configuration (connect, read) or single value
            verify_ssl: Enable SSL certificate verification
            enable_http2: Enable HTTP/2 support for async client
            sync_pool_connections: Synchronous client connection pool size
            sync_pool_maxsize: Maximum synchronous connections per pool
            async_max_connections: Maximum async client connections
            async_max_keepalive_connections: Maximum async keepalive connections
            keepalive_expiry: Async connection keepalive expiry time
            enable_circuit_breaker: Enable circuit breaker protection
            circuit_breaker_failure_threshold: Circuit breaker failure threshold
            circuit_breaker_reset_timeout: Circuit breaker reset timeout
            circuit_breaker_fallback: Fallback function for circuit breaker
            enable_retry: Enable retry logic with exponential backoff
            max_retry_attempts: Maximum retry attempts
            retry_min_wait: Minimum retry wait time
            retry_max_wait: Maximum retry wait time
            retry_jitter_max: Maximum jitter for retry timing
            enable_monitoring: Enable Prometheus metrics collection
            enable_detailed_logging: Enable detailed request/response logging
            correlation_id_header: Header name for correlation ID tracking
            default_headers: Default headers for all requests
            auth_token_header: Header name for authentication tokens
            service_version: Service version for monitoring labels
            service_description: Service description for documentation
            health_check_endpoint: Endpoint for service health checks
            **kwargs: Additional configuration parameters
        """
        self.service_name = service_name
        self.service_type = service_type
        self.base_url = base_url.rstrip('/')
        
        # HTTP client settings
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.enable_http2 = enable_http2
        
        # Connection pooling settings per Section 6.3.5
        self.sync_pool_connections = sync_pool_connections
        self.sync_pool_maxsize = sync_pool_maxsize
        self.async_max_connections = async_max_connections
        self.async_max_keepalive_connections = async_max_keepalive_connections
        self.keepalive_expiry = keepalive_expiry
        
        # Circuit breaker settings per Section 6.3.3
        self.enable_circuit_breaker = enable_circuit_breaker
        self.circuit_breaker_failure_threshold = circuit_breaker_failure_threshold
        self.circuit_breaker_reset_timeout = circuit_breaker_reset_timeout
        self.circuit_breaker_fallback = circuit_breaker_fallback
        
        # Retry settings per Section 4.2.3
        self.enable_retry = enable_retry
        self.max_retry_attempts = max_retry_attempts
        self.retry_min_wait = retry_min_wait
        self.retry_max_wait = retry_max_wait
        self.retry_jitter_max = retry_jitter_max
        
        # Monitoring and observability settings
        self.enable_monitoring = enable_monitoring
        self.enable_detailed_logging = enable_detailed_logging
        self.correlation_id_header = correlation_id_header
        
        # Authentication and headers
        self.default_headers = default_headers or {}
        self.auth_token_header = auth_token_header
        
        # Service metadata
        self.service_version = service_version
        self.service_description = service_description
        self.health_check_endpoint = health_check_endpoint or "/health"
        
        # Store additional configuration
        self.additional_config = kwargs
        
        logger.info(
            "base_client_configuration_initialized",
            service_name=service_name,
            service_type=service_type.value,
            base_url=base_url,
            timeout=timeout,
            enable_circuit_breaker=enable_circuit_breaker,
            enable_retry=enable_retry,
            enable_monitoring=enable_monitoring,
            component="integrations.base_client"
        )
    
    def get_circuit_breaker_config(self) -> Dict[str, Any]:
        """
        Get circuit breaker configuration with service-specific defaults.
        
        Returns:
            Circuit breaker configuration dictionary
        """
        config = {}
        
        if self.circuit_breaker_failure_threshold is not None:
            config['fail_max'] = self.circuit_breaker_failure_threshold
        
        if self.circuit_breaker_reset_timeout is not None:
            config['reset_timeout'] = self.circuit_breaker_reset_timeout
        
        return config
    
    def get_retry_config(self) -> Dict[str, Any]:
        """
        Get retry configuration with service-specific defaults.
        
        Returns:
            Retry configuration dictionary
        """
        config = {}
        
        if self.max_retry_attempts is not None:
            config['max_attempts'] = self.max_retry_attempts
        
        if self.retry_min_wait is not None:
            config['min_wait'] = self.retry_min_wait
        
        if self.retry_max_wait is not None:
            config['max_wait'] = self.retry_max_wait
        
        if self.retry_jitter_max is not None:
            config['jitter_max'] = self.retry_jitter_max
        
        return config
    
    def get_http_client_config(self) -> Dict[str, Any]:
        """
        Get HTTP client configuration for both sync and async clients.
        
        Returns:
            HTTP client configuration dictionary
        """
        return {
            'base_url': self.base_url,
            'timeout': self.timeout,
            'headers': self.default_headers,
            'verify_ssl': self.verify_ssl,
            'sync_pool_connections': self.sync_pool_connections,
            'sync_pool_maxsize': self.sync_pool_maxsize,
            'async_max_connections': self.async_max_connections,
            'async_max_keepalive_connections': self.async_max_keepalive_connections,
            'enable_http2': self.enable_http2
        }


class BaseExternalServiceClient(ABC):
    """
    Abstract base class for external service clients with comprehensive integration patterns.
    
    Provides enterprise-grade foundation for third-party API integrations including:
    - Dual HTTP client support (requests 2.31+ and httpx 0.24+) per Section 0.1.2
    - Circuit breaker integration with pybreaker per Section 6.3.3
    - Tenacity exponential backoff retry logic per Section 4.2.3
    - Prometheus metrics collection per Section 6.3.5
    - Structured logging with correlation tracking per Section 6.3.3
    - Connection pooling optimization per Section 6.3.5
    - Graceful degradation and fallback mechanisms per Section 6.3.3
    
    Subclasses must implement service-specific methods while inheriting
    comprehensive resilience patterns and monitoring capabilities.
    """
    
    def __init__(self, config: BaseClientConfiguration):
        """
        Initialize base external service client with comprehensive configuration.
        
        Args:
            config: BaseClientConfiguration instance with service settings
        """
        self.config = config
        self.service_name = config.service_name
        self.service_type = config.service_type
        self.base_url = config.base_url
        
        # Initialize correlation tracking
        self._correlation_context: Dict[str, str] = {}
        
        # Initialize HTTP client manager with dual-client support per Section 0.1.2
        self._initialize_http_clients()
        
        # Initialize circuit breaker with pybreaker integration per Section 6.3.3
        self._initialize_circuit_breaker()
        
        # Initialize monitoring with prometheus-client per Section 6.3.5
        self._initialize_monitoring()
        
        # Register service for health monitoring
        self._register_service_monitoring()
        
        logger.info(
            "base_external_service_client_initialized",
            service_name=self.service_name,
            service_type=self.service_type.value,
            base_url=self.base_url,
            circuit_breaker_enabled=self.config.enable_circuit_breaker,
            retry_enabled=self.config.enable_retry,
            monitoring_enabled=self.config.enable_monitoring,
            component="integrations.base_client"
        )
    
    def _initialize_http_clients(self) -> None:
        """
        Initialize HTTP client manager with dual-client support.
        
        Implements requests 2.31+ and httpx 0.24+ integration per Section 0.1.2
        with optimized connection pooling per Section 6.3.5.
        """
        try:
            client_config = self.config.get_http_client_config()
            
            self.http_client_manager = create_client_manager(**client_config)
            self.sync_client = self.http_client_manager.get_sync_client()
            self.async_client = self.http_client_manager.get_async_client()
            
            # Add request/response interceptors for monitoring and correlation
            self._setup_client_interceptors()
            
            logger.info(
                "http_clients_initialized",
                service_name=self.service_name,
                sync_pool_maxsize=self.config.sync_pool_maxsize,
                async_max_connections=self.config.async_max_connections,
                component="integrations.base_client"
            )
            
        except Exception as e:
            logger.error(
                "http_clients_initialization_failed",
                service_name=self.service_name,
                error=str(e),
                component="integrations.base_client",
                exc_info=e
            )
            raise IntegrationError(
                message=f"Failed to initialize HTTP clients for {self.service_name}",
                service_name=self.service_name,
                operation="client_initialization",
                error_context={'initialization_error': str(e)}
            ) from e
    
    def _initialize_circuit_breaker(self) -> None:
        """
        Initialize circuit breaker with pybreaker integration per Section 6.3.3.
        
        Implements service-specific failure thresholds and recovery patterns
        with fallback mechanisms for graceful degradation.
        """
        if not self.config.enable_circuit_breaker:
            self.circuit_breaker = None
            return
        
        try:
            circuit_config = self.config.get_circuit_breaker_config()
            
            self.circuit_breaker = create_circuit_breaker(
                service_name=self.service_name,
                service_type=self.service_type,
                fallback_function=self.config.circuit_breaker_fallback,
                custom_config=circuit_config
            )
            
            logger.info(
                "circuit_breaker_initialized",
                service_name=self.service_name,
                failure_threshold=circuit_config.get('fail_max'),
                reset_timeout=circuit_config.get('reset_timeout'),
                component="integrations.base_client"
            )
            
        except Exception as e:
            logger.error(
                "circuit_breaker_initialization_failed",
                service_name=self.service_name,
                error=str(e),
                component="integrations.base_client",
                exc_info=e
            )
            self.circuit_breaker = None
    
    def _initialize_monitoring(self) -> None:
        """
        Initialize monitoring with prometheus-client integration per Section 6.3.5.
        
        Implements comprehensive metrics collection for response times, error rates,
        and circuit breaker states with enterprise monitoring integration.
        """
        if not self.config.enable_monitoring:
            return
        
        try:
            # Register with external service monitor
            external_service_monitor.register_service(
                service_name=self.service_name,
                service_type=self.service_type,
                endpoint_url=self.base_url,
                health_check_path=self.config.health_check_endpoint,
                metadata={
                    'service_version': self.config.service_version,
                    'service_description': self.config.service_description,
                    'circuit_breaker_enabled': self.config.enable_circuit_breaker,
                    'retry_enabled': self.config.enable_retry
                }
            )
            
            logger.info(
                "monitoring_initialized",
                service_name=self.service_name,
                health_check_endpoint=self.config.health_check_endpoint,
                component="integrations.base_client"
            )
            
        except Exception as e:
            logger.warning(
                "monitoring_initialization_failed",
                service_name=self.service_name,
                error=str(e),
                component="integrations.base_client"
            )
    
    def _register_service_monitoring(self) -> None:
        """Register service with comprehensive monitoring system."""
        try:
            external_service_monitor.register_service(
                service_name=self.service_name,
                service_type=self.service_type,
                endpoint_url=self.base_url,
                health_check_path=self.config.health_check_endpoint,
                metadata={
                    'base_url': self.base_url,
                    'service_version': self.config.service_version,
                    'timeout': str(self.config.timeout),
                    'circuit_breaker_enabled': self.config.enable_circuit_breaker,
                    'retry_enabled': self.config.enable_retry
                }
            )
        except Exception as e:
            logger.warning(
                "service_monitoring_registration_failed",
                service_name=self.service_name,
                error=str(e),
                component="integrations.base_client"
            )
    
    def _setup_client_interceptors(self) -> None:
        """
        Setup request/response interceptors for monitoring and correlation tracking.
        
        Implements structured logging and correlation ID injection per Section 6.3.3
        with comprehensive request/response monitoring.
        """
        def request_interceptor(**kwargs):
            """Add correlation ID and monitoring headers to requests."""
            headers = kwargs.get('headers', {})
            
            # Add correlation ID if not present
            if self.config.correlation_id_header not in headers:
                correlation_id = self._get_or_create_correlation_id()
                headers[self.config.correlation_id_header] = correlation_id
            
            # Add service metadata headers
            headers.setdefault('User-Agent', f"{self.service_name}-client")
            if self.config.service_version:
                headers.setdefault('X-Service-Version', self.config.service_version)
            
            kwargs['headers'] = headers
            return kwargs
        
        def response_interceptor(response):
            """Log response details and update monitoring metrics."""
            if self.config.enable_detailed_logging:
                correlation_id = response.request.headers.get(self.config.correlation_id_header)
                
                logger.info(
                    "external_service_response",
                    service_name=self.service_name,
                    method=response.request.method,
                    url=str(response.url),
                    status_code=response.status_code,
                    correlation_id=correlation_id,
                    response_time_ms=getattr(response, 'elapsed', None),
                    component="integrations.base_client"
                )
            
            return response
        
        # Add interceptors to both clients
        self.http_client_manager.add_request_interceptor(request_interceptor)
        self.http_client_manager.add_response_interceptor(response_interceptor)
    
    def _get_or_create_correlation_id(self) -> str:
        """
        Get existing correlation ID from context or create new one.
        
        Returns:
            Correlation ID for request tracking
        """
        correlation_id = self._correlation_context.get('correlation_id')
        if not correlation_id:
            correlation_id = str(uuid.uuid4())
            self._correlation_context['correlation_id'] = correlation_id
        
        return correlation_id
    
    @contextmanager
    def correlation_context(self, correlation_id: Optional[str] = None):
        """
        Context manager for correlation ID tracking across requests.
        
        Args:
            correlation_id: Optional correlation ID, generates new if not provided
            
        Yields:
            Correlation ID for the context
        """
        if correlation_id is None:
            correlation_id = str(uuid.uuid4())
        
        previous_id = self._correlation_context.get('correlation_id')
        self._correlation_context['correlation_id'] = correlation_id
        
        try:
            yield correlation_id
        finally:
            if previous_id:
                self._correlation_context['correlation_id'] = previous_id
            else:
                self._correlation_context.pop('correlation_id', None)
    
    def _execute_with_resilience(
        self,
        func: Callable,
        operation: str,
        *args,
        **kwargs
    ) -> Any:
        """
        Execute function with comprehensive resilience patterns.
        
        Implements circuit breaker protection and retry logic with exponential
        backoff per Section 6.3.3 and 4.2.3 specifications.
        
        Args:
            func: Function to execute with resilience patterns
            operation: Operation name for monitoring and logging
            *args: Function arguments
            **kwargs: Function keyword arguments
            
        Returns:
            Function result with resilience protection
            
        Raises:
            CircuitBreakerOpenError: When circuit breaker is open
            RetryExhaustedError: When retry attempts are exhausted
            IntegrationError: For other integration failures
        """
        start_time = time.time()
        correlation_id = self._get_or_create_correlation_id()
        
        try:
            # Track request start in monitoring
            if self.config.enable_monitoring:
                external_service_monitor.track_request_start(
                    service_name=self.service_name,
                    service_type=self.service_type,
                    method=kwargs.get('method', 'CALL'),
                    endpoint=operation
                )
            
            # Execute with circuit breaker protection
            if self.circuit_breaker and self.config.enable_circuit_breaker:
                if self.config.enable_retry:
                    # Execute with both circuit breaker and retry
                    result = retry_manager.execute_with_retry(
                        lambda: self.circuit_breaker.call_with_circuit_breaker(func, *args, **kwargs),
                        service_name=self.service_name,
                        operation=operation
                    )
                else:
                    # Execute with circuit breaker only
                    result = self.circuit_breaker.call_with_circuit_breaker(func, *args, **kwargs)
            
            elif self.config.enable_retry:
                # Execute with retry only
                result = retry_manager.execute_with_retry(
                    func, self.service_name, operation, *args, **kwargs
                )
            
            else:
                # Execute without resilience patterns
                result = func(*args, **kwargs)
            
            # Record successful execution
            duration = time.time() - start_time
            
            if self.config.enable_monitoring:
                external_service_monitor.record_request_success(
                    service_name=self.service_name,
                    service_type=self.service_type,
                    method=kwargs.get('method', 'CALL'),
                    endpoint=operation,
                    duration=duration
                )
            
            logger.info(
                "resilient_execution_success",
                service_name=self.service_name,
                operation=operation,
                duration_ms=round(duration * 1000, 2),
                correlation_id=correlation_id,
                component="integrations.base_client"
            )
            
            return result
            
        except (CircuitBreakerOpenError, CircuitBreakerHalfOpenError) as e:
            duration = time.time() - start_time
            
            if self.config.enable_monitoring:
                external_service_monitor.record_circuit_breaker_event(
                    service_name=self.service_name,
                    service_type=self.service_type,
                    state=CircuitBreakerState.OPEN,
                    failure_reason=type(e).__name__
                )
            
            logger.warning(
                "circuit_breaker_triggered",
                service_name=self.service_name,
                operation=operation,
                duration_ms=round(duration * 1000, 2),
                correlation_id=correlation_id,
                error_type=type(e).__name__,
                component="integrations.base_client"
            )
            
            raise
            
        except RetryExhaustedError as e:
            duration = time.time() - start_time
            
            if self.config.enable_monitoring:
                external_service_monitor.record_request_failure(
                    service_name=self.service_name,
                    service_type=self.service_type,
                    method=kwargs.get('method', 'CALL'),
                    endpoint=operation,
                    error_type='RetryExhausted',
                    duration=duration
                )
            
            logger.error(
                "retry_exhausted",
                service_name=self.service_name,
                operation=operation,
                duration_ms=round(duration * 1000, 2),
                correlation_id=correlation_id,
                max_retries=e.max_retries,
                component="integrations.base_client"
            )
            
            raise
            
        except Exception as e:
            duration = time.time() - start_time
            
            if self.config.enable_monitoring:
                external_service_monitor.record_request_failure(
                    service_name=self.service_name,
                    service_type=self.service_type,
                    method=kwargs.get('method', 'CALL'),
                    endpoint=operation,
                    error_type=type(e).__name__,
                    duration=duration
                )
            
            logger.error(
                "resilient_execution_failed",
                service_name=self.service_name,
                operation=operation,
                duration_ms=round(duration * 1000, 2),
                correlation_id=correlation_id,
                error=str(e),
                error_type=type(e).__name__,
                component="integrations.base_client",
                exc_info=e
            )
            
            # Convert unknown exceptions to IntegrationError
            if not isinstance(e, IntegrationError):
                raise IntegrationError(
                    message=f"Unexpected error in {self.service_name}.{operation}: {str(e)}",
                    service_name=self.service_name,
                    operation=operation,
                    error_context={'original_exception': str(e)},
                    correlation_id=correlation_id
                ) from e
            
            raise
    
    async def _execute_with_resilience_async(
        self,
        func: Callable,
        operation: str,
        *args,
        **kwargs
    ) -> Any:
        """
        Execute async function with comprehensive resilience patterns.
        
        Implements async circuit breaker protection and retry logic with exponential
        backoff for async operations per Section 6.3.3 and 4.2.3 specifications.
        
        Args:
            func: Async function to execute with resilience patterns
            operation: Operation name for monitoring and logging
            *args: Function arguments
            **kwargs: Function keyword arguments
            
        Returns:
            Function result with resilience protection
            
        Raises:
            CircuitBreakerOpenError: When circuit breaker is open
            RetryExhaustedError: When retry attempts are exhausted
            IntegrationError: For other integration failures
        """
        start_time = time.time()
        correlation_id = self._get_or_create_correlation_id()
        
        try:
            # Track request start in monitoring
            if self.config.enable_monitoring:
                external_service_monitor.track_request_start(
                    service_name=self.service_name,
                    service_type=self.service_type,
                    method=kwargs.get('method', 'ASYNC_CALL'),
                    endpoint=operation
                )
            
            # Execute with circuit breaker protection
            if self.circuit_breaker and self.config.enable_circuit_breaker:
                if self.config.enable_retry:
                    # Execute with both circuit breaker and retry
                    result = await retry_manager.execute_with_retry_async(
                        lambda: self.circuit_breaker.call_with_circuit_breaker_async(func, *args, **kwargs),
                        service_name=self.service_name,
                        operation=operation
                    )
                else:
                    # Execute with circuit breaker only
                    result = await self.circuit_breaker.call_with_circuit_breaker_async(func, *args, **kwargs)
            
            elif self.config.enable_retry:
                # Execute with retry only
                result = await retry_manager.execute_with_retry_async(
                    func, self.service_name, operation, *args, **kwargs
                )
            
            else:
                # Execute without resilience patterns
                result = await func(*args, **kwargs)
            
            # Record successful execution
            duration = time.time() - start_time
            
            if self.config.enable_monitoring:
                external_service_monitor.record_request_success(
                    service_name=self.service_name,
                    service_type=self.service_type,
                    method=kwargs.get('method', 'ASYNC_CALL'),
                    endpoint=operation,
                    duration=duration
                )
            
            logger.info(
                "async_resilient_execution_success",
                service_name=self.service_name,
                operation=operation,
                duration_ms=round(duration * 1000, 2),
                correlation_id=correlation_id,
                component="integrations.base_client"
            )
            
            return result
            
        except (CircuitBreakerOpenError, CircuitBreakerHalfOpenError) as e:
            duration = time.time() - start_time
            
            if self.config.enable_monitoring:
                external_service_monitor.record_circuit_breaker_event(
                    service_name=self.service_name,
                    service_type=self.service_type,
                    state=CircuitBreakerState.OPEN,
                    failure_reason=type(e).__name__
                )
            
            logger.warning(
                "async_circuit_breaker_triggered",
                service_name=self.service_name,
                operation=operation,
                duration_ms=round(duration * 1000, 2),
                correlation_id=correlation_id,
                error_type=type(e).__name__,
                component="integrations.base_client"
            )
            
            raise
            
        except RetryExhaustedError as e:
            duration = time.time() - start_time
            
            if self.config.enable_monitoring:
                external_service_monitor.record_request_failure(
                    service_name=self.service_name,
                    service_type=self.service_type,
                    method=kwargs.get('method', 'ASYNC_CALL'),
                    endpoint=operation,
                    error_type='RetryExhausted',
                    duration=duration
                )
            
            logger.error(
                "async_retry_exhausted",
                service_name=self.service_name,
                operation=operation,
                duration_ms=round(duration * 1000, 2),
                correlation_id=correlation_id,
                max_retries=e.max_retries,
                component="integrations.base_client"
            )
            
            raise
            
        except Exception as e:
            duration = time.time() - start_time
            
            if self.config.enable_monitoring:
                external_service_monitor.record_request_failure(
                    service_name=self.service_name,
                    service_type=self.service_type,
                    method=kwargs.get('method', 'ASYNC_CALL'),
                    endpoint=operation,
                    error_type=type(e).__name__,
                    duration=duration
                )
            
            logger.error(
                "async_resilient_execution_failed",
                service_name=self.service_name,
                operation=operation,
                duration_ms=round(duration * 1000, 2),
                correlation_id=correlation_id,
                error=str(e),
                error_type=type(e).__name__,
                component="integrations.base_client",
                exc_info=e
            )
            
            # Convert unknown exceptions to IntegrationError
            if not isinstance(e, IntegrationError):
                raise IntegrationError(
                    message=f"Unexpected error in {self.service_name}.{operation}: {str(e)}",
                    service_name=self.service_name,
                    operation=operation,
                    error_context={'original_exception': str(e)},
                    correlation_id=correlation_id
                ) from e
            
            raise
    
    def make_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        data: Optional[Union[Dict[str, Any], str, bytes]] = None,
        timeout: Optional[Union[float, Tuple[float, float]]] = None,
        **kwargs
    ) -> Any:
        """
        Make synchronous HTTP request with comprehensive resilience patterns.
        
        Implements requests 2.31+ client with circuit breaker protection,
        retry logic, and monitoring per Section 0.1.2, 6.3.3, and 6.3.5.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            endpoint: API endpoint path
            params: Query parameters
            headers: Request headers
            json_data: JSON payload for request body
            data: Raw data for request body
            timeout: Request timeout override
            **kwargs: Additional request parameters
            
        Returns:
            Response object from external service
            
        Raises:
            CircuitBreakerOpenError: When circuit breaker is open
            RetryExhaustedError: When retry attempts are exhausted
            HTTPClientError: For HTTP client failures
            IntegrationError: For other integration failures
        """
        def _make_request():
            return self.sync_client.request(
                method=method,
                path=endpoint,
                params=params,
                headers=headers,
                json_data=json_data,
                data=data,
                timeout=timeout,
                **kwargs
            )
        
        return self._execute_with_resilience(
            _make_request,
            f"{method.upper()}_{endpoint}",
            method=method
        )
    
    async def make_request_async(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        data: Optional[Union[Dict[str, Any], str, bytes]] = None,
        timeout: Optional[Union[float, Tuple[float, float]]] = None,
        **kwargs
    ) -> Any:
        """
        Make asynchronous HTTP request with comprehensive resilience patterns.
        
        Implements httpx 0.24+ client with circuit breaker protection,
        retry logic, and monitoring per Section 0.1.2, 6.3.3, and 6.3.5.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            endpoint: API endpoint path
            params: Query parameters
            headers: Request headers
            json_data: JSON payload for request body
            data: Raw data for request body
            timeout: Request timeout override
            **kwargs: Additional request parameters
            
        Returns:
            Response object from external service
            
        Raises:
            CircuitBreakerOpenError: When circuit breaker is open
            RetryExhaustedError: When retry attempts are exhausted
            HTTPClientError: For HTTP client failures
            IntegrationError: For other integration failures
        """
        async def _make_request():
            return await self.async_client.request(
                method=method,
                path=endpoint,
                params=params,
                headers=headers,
                json_data=json_data,
                data=data,
                timeout=timeout,
                **kwargs
            )
        
        return await self._execute_with_resilience_async(
            _make_request,
            f"{method.upper()}_{endpoint}",
            method=method
        )
    
    # Convenience methods for common HTTP operations
    
    def get(self, endpoint: str, **kwargs) -> Any:
        """Make synchronous GET request with resilience patterns."""
        return self.make_request('GET', endpoint, **kwargs)
    
    def post(self, endpoint: str, **kwargs) -> Any:
        """Make synchronous POST request with resilience patterns."""
        return self.make_request('POST', endpoint, **kwargs)
    
    def put(self, endpoint: str, **kwargs) -> Any:
        """Make synchronous PUT request with resilience patterns."""
        return self.make_request('PUT', endpoint, **kwargs)
    
    def patch(self, endpoint: str, **kwargs) -> Any:
        """Make synchronous PATCH request with resilience patterns."""
        return self.make_request('PATCH', endpoint, **kwargs)
    
    def delete(self, endpoint: str, **kwargs) -> Any:
        """Make synchronous DELETE request with resilience patterns."""
        return self.make_request('DELETE', endpoint, **kwargs)
    
    async def get_async(self, endpoint: str, **kwargs) -> Any:
        """Make asynchronous GET request with resilience patterns."""
        return await self.make_request_async('GET', endpoint, **kwargs)
    
    async def post_async(self, endpoint: str, **kwargs) -> Any:
        """Make asynchronous POST request with resilience patterns."""
        return await self.make_request_async('POST', endpoint, **kwargs)
    
    async def put_async(self, endpoint: str, **kwargs) -> Any:
        """Make asynchronous PUT request with resilience patterns."""
        return await self.make_request_async('PUT', endpoint, **kwargs)
    
    async def patch_async(self, endpoint: str, **kwargs) -> Any:
        """Make asynchronous PATCH request with resilience patterns."""
        return await self.make_request_async('PATCH', endpoint, **kwargs)
    
    async def delete_async(self, endpoint: str, **kwargs) -> Any:
        """Make asynchronous DELETE request with resilience patterns."""
        return await self.make_request_async('DELETE', endpoint, **kwargs)
    
    def health_check(self, timeout: Optional[float] = 5.0) -> Dict[str, Any]:
        """
        Perform synchronous health check for the external service.
        
        Args:
            timeout: Health check timeout in seconds
            
        Returns:
            Health check result with service status and metrics
        """
        start_time = time.time()
        
        try:
            response = self.get(
                self.config.health_check_endpoint,
                timeout=timeout
            )
            
            duration = time.time() - start_time
            is_healthy = 200 <= response.status_code < 300
            
            health_result = {
                'service_name': self.service_name,
                'service_type': self.service_type.value,
                'status': 'healthy' if is_healthy else 'unhealthy',
                'status_code': response.status_code,
                'response_time_ms': round(duration * 1000, 2),
                'timestamp': datetime.utcnow().isoformat(),
                'endpoint': self.config.health_check_endpoint
            }
            
            if self.config.enable_monitoring:
                external_service_monitor.update_service_health(
                    service_name=self.service_name,
                    service_type=self.service_type,
                    status=HealthStatus.HEALTHY if is_healthy else HealthStatus.UNHEALTHY,
                    duration=duration,
                    metadata={'health_check_result': health_result}
                )
            
            logger.info(
                "health_check_completed",
                service_name=self.service_name,
                status=health_result['status'],
                duration_ms=health_result['response_time_ms'],
                component="integrations.base_client"
            )
            
            return health_result
            
        except Exception as e:
            duration = time.time() - start_time
            
            health_result = {
                'service_name': self.service_name,
                'service_type': self.service_type.value,
                'status': 'unhealthy',
                'error': str(e),
                'response_time_ms': round(duration * 1000, 2),
                'timestamp': datetime.utcnow().isoformat(),
                'endpoint': self.config.health_check_endpoint
            }
            
            if self.config.enable_monitoring:
                external_service_monitor.update_service_health(
                    service_name=self.service_name,
                    service_type=self.service_type,
                    status=HealthStatus.UNHEALTHY,
                    duration=duration,
                    metadata={'health_check_error': str(e)}
                )
            
            logger.error(
                "health_check_failed",
                service_name=self.service_name,
                error=str(e),
                duration_ms=health_result['response_time_ms'],
                component="integrations.base_client",
                exc_info=e
            )
            
            return health_result
    
    async def health_check_async(self, timeout: Optional[float] = 5.0) -> Dict[str, Any]:
        """
        Perform asynchronous health check for the external service.
        
        Args:
            timeout: Health check timeout in seconds
            
        Returns:
            Health check result with service status and metrics
        """
        start_time = time.time()
        
        try:
            response = await self.get_async(
                self.config.health_check_endpoint,
                timeout=timeout
            )
            
            duration = time.time() - start_time
            is_healthy = 200 <= response.status_code < 300
            
            health_result = {
                'service_name': self.service_name,
                'service_type': self.service_type.value,
                'status': 'healthy' if is_healthy else 'unhealthy',
                'status_code': response.status_code,
                'response_time_ms': round(duration * 1000, 2),
                'timestamp': datetime.utcnow().isoformat(),
                'endpoint': self.config.health_check_endpoint
            }
            
            if self.config.enable_monitoring:
                external_service_monitor.update_service_health(
                    service_name=self.service_name,
                    service_type=self.service_type,
                    status=HealthStatus.HEALTHY if is_healthy else HealthStatus.UNHEALTHY,
                    duration=duration,
                    metadata={'health_check_result': health_result}
                )
            
            logger.info(
                "async_health_check_completed",
                service_name=self.service_name,
                status=health_result['status'],
                duration_ms=health_result['response_time_ms'],
                component="integrations.base_client"
            )
            
            return health_result
            
        except Exception as e:
            duration = time.time() - start_time
            
            health_result = {
                'service_name': self.service_name,
                'service_type': self.service_type.value,
                'status': 'unhealthy',
                'error': str(e),
                'response_time_ms': round(duration * 1000, 2),
                'timestamp': datetime.utcnow().isoformat(),
                'endpoint': self.config.health_check_endpoint
            }
            
            if self.config.enable_monitoring:
                external_service_monitor.update_service_health(
                    service_name=self.service_name,
                    service_type=self.service_type,
                    status=HealthStatus.UNHEALTHY,
                    duration=duration,
                    metadata={'health_check_error': str(e)}
                )
            
            logger.error(
                "async_health_check_failed",
                service_name=self.service_name,
                error=str(e),
                duration_ms=health_result['response_time_ms'],
                component="integrations.base_client",
                exc_info=e
            )
            
            return health_result
    
    def get_service_status(self) -> Dict[str, Any]:
        """
        Get comprehensive service status including circuit breaker and monitoring info.
        
        Returns:
            Complete service status with resilience pattern states
        """
        status = {
            'service_name': self.service_name,
            'service_type': self.service_type.value,
            'base_url': self.base_url,
            'timestamp': datetime.utcnow().isoformat(),
            'configuration': {
                'circuit_breaker_enabled': self.config.enable_circuit_breaker,
                'retry_enabled': self.config.enable_retry,
                'monitoring_enabled': self.config.enable_monitoring,
                'timeout': str(self.config.timeout),
                'verify_ssl': self.config.verify_ssl
            }
        }
        
        # Add circuit breaker status
        if self.circuit_breaker:
            status['circuit_breaker'] = self.circuit_breaker.get_state()
        
        # Add retry metrics
        if self.config.enable_retry:
            status['retry_metrics'] = get_retry_metrics()
        
        # Add monitoring status
        if self.config.enable_monitoring:
            try:
                health_summary = get_circuit_breaker_health()
                status['monitoring'] = {
                    'circuit_breaker_health': health_summary,
                    'service_registered': self.service_name in external_service_monitor._registered_services
                }
            except Exception as e:
                status['monitoring'] = {'error': str(e)}
        
        return status
    
    def reset_circuit_breaker(self) -> bool:
        """
        Reset circuit breaker to closed state for emergency recovery.
        
        Returns:
            True if circuit breaker was reset successfully
        """
        if self.circuit_breaker:
            try:
                self.circuit_breaker.force_close()
                
                logger.warning(
                    "circuit_breaker_manually_reset",
                    service_name=self.service_name,
                    component="integrations.base_client"
                )
                
                return True
                
            except Exception as e:
                logger.error(
                    "circuit_breaker_reset_failed",
                    service_name=self.service_name,
                    error=str(e),
                    component="integrations.base_client"
                )
                return False
        
        return False
    
    async def close(self) -> None:
        """
        Close client connections and cleanup resources.
        
        Performs graceful shutdown of HTTP clients and releases resources
        for proper application shutdown procedures.
        """
        try:
            # Close HTTP client manager
            if hasattr(self, 'http_client_manager'):
                await self.http_client_manager.close_all()
            
            logger.info(
                "base_client_closed",
                service_name=self.service_name,
                component="integrations.base_client"
            )
            
        except Exception as e:
            logger.error(
                "base_client_close_failed",
                service_name=self.service_name,
                error=str(e),
                component="integrations.base_client",
                exc_info=e
            )
    
    # Abstract methods for subclass implementation
    
    @abstractmethod
    def authenticate(self, credentials: Dict[str, Any]) -> Dict[str, Any]:
        """
        Authenticate with the external service.
        
        Args:
            credentials: Authentication credentials
            
        Returns:
            Authentication result with tokens/session info
        """
        pass
    
    @abstractmethod
    def validate_response(self, response: Any) -> bool:
        """
        Validate external service response format and content.
        
        Args:
            response: Response object from external service
            
        Returns:
            True if response is valid, False otherwise
        """
        pass
    
    @abstractmethod
    def get_service_endpoints(self) -> List[str]:
        """
        Get list of available service endpoints.
        
        Returns:
            List of endpoint paths for the external service
        """
        pass


# Factory functions for common service types

def create_auth_service_client(
    service_name: str,
    base_url: str,
    **kwargs
) -> BaseClientConfiguration:
    """
    Factory function for creating Auth0/authentication service client configuration.
    
    Args:
        service_name: Service identifier
        base_url: Authentication service base URL
        **kwargs: Additional configuration parameters
        
    Returns:
        Configured BaseClientConfiguration for authentication services
    """
    return BaseClientConfiguration(
        service_name=service_name,
        service_type=ServiceType.AUTH,
        base_url=base_url,
        max_retry_attempts=3,
        circuit_breaker_failure_threshold=5,
        circuit_breaker_reset_timeout=60,
        health_check_endpoint="/health",
        **kwargs
    )


def create_aws_service_client(
    service_name: str,
    base_url: str,
    **kwargs
) -> BaseClientConfiguration:
    """
    Factory function for creating AWS service client configuration.
    
    Args:
        service_name: Service identifier
        base_url: AWS service base URL
        **kwargs: Additional configuration parameters
        
    Returns:
        Configured BaseClientConfiguration for AWS services
    """
    return BaseClientConfiguration(
        service_name=service_name,
        service_type=ServiceType.AWS,
        base_url=base_url,
        max_retry_attempts=4,
        circuit_breaker_failure_threshold=3,
        circuit_breaker_reset_timeout=60,
        retry_min_wait=0.5,
        retry_max_wait=60.0,
        health_check_endpoint="/health",
        **kwargs
    )


def create_api_service_client(
    service_name: str,
    base_url: str,
    **kwargs
) -> BaseClientConfiguration:
    """
    Factory function for creating external API service client configuration.
    
    Args:
        service_name: Service identifier
        base_url: External API base URL
        **kwargs: Additional configuration parameters
        
    Returns:
        Configured BaseClientConfiguration for external APIs
    """
    return BaseClientConfiguration(
        service_name=service_name,
        service_type=ServiceType.API,
        base_url=base_url,
        max_retry_attempts=3,
        circuit_breaker_failure_threshold=5,
        circuit_breaker_reset_timeout=60,
        retry_min_wait=2.0,
        retry_max_wait=60.0,
        health_check_endpoint="/health",
        **kwargs
    )


# Export public interface
__all__ = [
    # Main classes
    'BaseClientConfiguration',
    'BaseExternalServiceClient',
    
    # Factory functions
    'create_auth_service_client',
    'create_aws_service_client',
    'create_api_service_client',
    
    # Service types for configuration
    'ServiceType',
    'HealthStatus',
    'CircuitBreakerState',
    
    # Exception classes
    'IntegrationError',
    'HTTPClientError',
    'CircuitBreakerOpenError',
    'RetryExhaustedError',
]