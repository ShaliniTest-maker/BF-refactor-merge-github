"""
HTTP client utilities implementing requests 2.31+ and httpx 0.24+ for external service communication
with circuit breaker patterns, retry logic, and connection pooling.

This module provides standardized HTTP client functionality with enterprise-grade resilience patterns
and monitoring integration as specified in Section 0.1.2 external integration components and
Section 5.4.2 error recovery mechanisms.

Key Features:
- Synchronous HTTP client using requests 2.31+ for external service communication
- Asynchronous HTTP client using httpx 0.24+ for high-performance operations
- Circuit breaker patterns using PyBreaker for external service resilience
- Retry logic with exponential backoff using Tenacity for transient failures
- Connection pooling with urllib3 for efficient resource management
- Enterprise monitoring integration with Prometheus metrics
- Structured logging with correlation tracking
- Timeout handling and error response patterns matching Node.js implementation
"""

import asyncio
import json
import time
from contextlib import asynccontextmanager, contextmanager
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urljoin, urlparse

import httpx
import requests
import structlog
import urllib3
from prometheus_client import Counter, Histogram, Gauge
from pybreaker import CircuitBreaker, CircuitBreakerError as PyBreakerError
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
    after_log
)

from src.utils.exceptions import (
    ExternalServiceError,
    CircuitBreakerError,
    create_error_context,
    safe_str
)

# Get structured logger
logger = structlog.get_logger(__name__)

# Prometheus metrics for HTTP client monitoring
http_requests_total = Counter(
    'http_client_requests_total',
    'Total number of HTTP requests made',
    ['method', 'service', 'status_code', 'client_type']
)

http_request_duration_seconds = Histogram(
    'http_client_request_duration_seconds',
    'HTTP request duration in seconds',
    ['method', 'service', 'client_type'],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
)

http_retry_attempts_total = Counter(
    'http_client_retry_attempts_total',
    'Total number of HTTP retry attempts',
    ['method', 'service', 'retry_reason']
)

circuit_breaker_state = Gauge(
    'http_client_circuit_breaker_state',
    'Circuit breaker state (0=closed, 1=open, 2=half-open)',
    ['service']
)

active_connections = Gauge(
    'http_client_active_connections',
    'Number of active HTTP connections',
    ['service', 'client_type']
)


class HTTPClientConfig:
    """
    Configuration class for HTTP client settings with enterprise-grade defaults.
    
    Provides centralized configuration management for timeout handling, retry logic,
    circuit breaker settings, and connection pooling parameters per Section 3.8.4
    external service client migration requirements.
    """
    
    def __init__(
        self,
        # Timeout settings equivalent to Node.js patterns
        connect_timeout: float = 5.0,
        read_timeout: float = 30.0,
        total_timeout: float = 60.0,
        
        # Retry configuration with exponential backoff
        max_retries: int = 3,
        retry_delay_min: float = 1.0,
        retry_delay_max: float = 60.0,
        retry_multiplier: float = 2.0,
        
        # Circuit breaker settings for service protection
        circuit_breaker_failure_threshold: int = 5,
        circuit_breaker_recovery_timeout: int = 30,
        circuit_breaker_expected_exception: tuple = (
            requests.exceptions.RequestException,
            httpx.HTTPError,
            ExternalServiceError
        ),
        
        # Connection pooling configuration
        max_connections: int = 100,
        max_connections_per_host: int = 20,
        keepalive_connections: int = 20,
        keepalive_expiry: float = 5.0,
        
        # Security and headers
        verify_ssl: bool = True,
        default_headers: Optional[Dict[str, str]] = None,
        user_agent: str = "Python-Flask-App/1.0",
        
        # Performance monitoring
        enable_metrics: bool = True,
        log_requests: bool = True,
        log_responses: bool = False  # Enable for debugging, disable in production
    ):
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.total_timeout = total_timeout
        
        self.max_retries = max_retries
        self.retry_delay_min = retry_delay_min
        self.retry_delay_max = retry_delay_max
        self.retry_multiplier = retry_multiplier
        
        self.circuit_breaker_failure_threshold = circuit_breaker_failure_threshold
        self.circuit_breaker_recovery_timeout = circuit_breaker_recovery_timeout
        self.circuit_breaker_expected_exception = circuit_breaker_expected_exception
        
        self.max_connections = max_connections
        self.max_connections_per_host = max_connections_per_host
        self.keepalive_connections = keepalive_connections
        self.keepalive_expiry = keepalive_expiry
        
        self.verify_ssl = verify_ssl
        self.default_headers = default_headers or {
            'User-Agent': user_agent,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        self.enable_metrics = enable_metrics
        self.log_requests = log_requests
        self.log_responses = log_responses


class HTTPClientBase:
    """
    Base class for HTTP clients providing common functionality and monitoring.
    
    Implements enterprise-grade HTTP client patterns with circuit breaker integration,
    retry logic, and comprehensive monitoring per Section 5.4.2 error recovery mechanisms.
    """
    
    def __init__(self, service_name: str, config: Optional[HTTPClientConfig] = None):
        self.service_name = service_name
        self.config = config or HTTPClientConfig()
        self.correlation_ids: Dict[str, str] = {}
        
        # Initialize circuit breaker for service protection
        self._circuit_breaker = CircuitBreaker(
            failure_threshold=self.config.circuit_breaker_failure_threshold,
            recovery_timeout=self.config.circuit_breaker_recovery_timeout,
            expected_exception=self.config.circuit_breaker_expected_exception,
            name=f"{service_name}_circuit_breaker"
        )
        
        # Set up circuit breaker state monitoring
        self._circuit_breaker.add_listener(self._on_circuit_breaker_state_change)
        
        # Initialize request session with connection pooling
        self._session = None
        self._async_client = None
    
    def _on_circuit_breaker_state_change(self, previous_state, new_state, triggered_by):
        """
        Handle circuit breaker state changes with monitoring integration.
        
        Args:
            previous_state: Previous circuit breaker state
            new_state: New circuit breaker state
            triggered_by: Event that triggered the state change
        """
        state_map = {'closed': 0, 'open': 1, 'half-open': 2}
        
        if self.config.enable_metrics:
            circuit_breaker_state.labels(service=self.service_name).set(
                state_map.get(new_state, 0)
            )
        
        logger.info(
            "Circuit breaker state changed",
            service=self.service_name,
            previous_state=previous_state,
            new_state=new_state,
            triggered_by=str(triggered_by)
        )
        
        # Emit circuit breaker error when opening
        if new_state == 'open':
            raise CircuitBreakerError(
                message=f"Circuit breaker opened for service {self.service_name}",
                service_name=self.service_name,
                circuit_state=new_state
            )
    
    def _create_retry_decorator(self, method: str):
        """
        Create retry decorator with exponential backoff for transient failures.
        
        Args:
            method: HTTP method for logging purposes
            
        Returns:
            Configured retry decorator
        """
        return retry(
            stop=stop_after_attempt(self.config.max_retries),
            wait=wait_exponential(
                multiplier=self.config.retry_multiplier,
                min=self.config.retry_delay_min,
                max=self.config.retry_delay_max
            ),
            retry=retry_if_exception_type((
                requests.exceptions.ConnectTimeout,
                requests.exceptions.ReadTimeout,
                requests.exceptions.ConnectionError,
                httpx.ConnectTimeout,
                httpx.ReadTimeout,
                httpx.ConnectError,
                ExternalServiceError
            )),
            before_sleep=before_sleep_log(logger, logging.INFO),
            after=after_log(logger, logging.INFO)
        )
    
    def _log_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        correlation_id: Optional[str] = None
    ):
        """
        Log HTTP request with structured logging.
        
        Args:
            method: HTTP method
            url: Request URL
            headers: Request headers
            correlation_id: Request correlation ID
        """
        if not self.config.log_requests:
            return
        
        logger.info(
            "HTTP request initiated",
            method=method,
            url=url,
            service=self.service_name,
            correlation_id=correlation_id,
            headers=safe_str(headers) if headers else None
        )
    
    def _log_response(
        self,
        method: str,
        url: str,
        status_code: int,
        response_time: float,
        correlation_id: Optional[str] = None,
        error: Optional[str] = None
    ):
        """
        Log HTTP response with structured logging.
        
        Args:
            method: HTTP method
            url: Request URL
            status_code: HTTP status code
            response_time: Response time in seconds
            correlation_id: Request correlation ID
            error: Error message if applicable
        """
        log_data = {
            'method': method,
            'url': url,
            'service': self.service_name,
            'status_code': status_code,
            'response_time': response_time,
            'correlation_id': correlation_id
        }
        
        if error:
            logger.error("HTTP request failed", error=error, **log_data)
        else:
            logger.info("HTTP request completed", **log_data)
    
    def _update_metrics(
        self,
        method: str,
        status_code: int,
        response_time: float,
        client_type: str
    ):
        """
        Update Prometheus metrics for HTTP requests.
        
        Args:
            method: HTTP method
            status_code: HTTP status code
            response_time: Response time in seconds
            client_type: Type of HTTP client (sync/async)
        """
        if not self.config.enable_metrics:
            return
        
        http_requests_total.labels(
            method=method,
            service=self.service_name,
            status_code=str(status_code),
            client_type=client_type
        ).inc()
        
        http_request_duration_seconds.labels(
            method=method,
            service=self.service_name,
            client_type=client_type
        ).observe(response_time)
    
    def _handle_request_error(
        self,
        error: Exception,
        method: str,
        url: str,
        correlation_id: Optional[str] = None
    ) -> ExternalServiceError:
        """
        Handle and convert request errors to application exceptions.
        
        Args:
            error: Original exception
            method: HTTP method
            url: Request URL
            correlation_id: Request correlation ID
            
        Returns:
            Converted ExternalServiceError
        """
        error_context = create_error_context(
            operation=f"{method} {url}",
            details={
                'service': self.service_name,
                'original_error': str(error),
                'error_type': error.__class__.__name__
            },
            correlation_id=correlation_id
        )
        
        # Determine status code and message based on error type
        if isinstance(error, (requests.exceptions.ConnectTimeout, httpx.ConnectTimeout)):
            status_code = 408
            message = f"Connection timeout to {self.service_name}"
        elif isinstance(error, (requests.exceptions.ReadTimeout, httpx.ReadTimeout)):
            status_code = 408
            message = f"Read timeout from {self.service_name}"
        elif isinstance(error, (requests.exceptions.ConnectionError, httpx.ConnectError)):
            status_code = 503
            message = f"Connection error to {self.service_name}"
        elif isinstance(error, PyBreakerError):
            status_code = 503
            message = f"Circuit breaker open for {self.service_name}"
        else:
            status_code = 502
            message = f"External service error from {self.service_name}"
        
        return ExternalServiceError(
            message=message,
            service_name=self.service_name,
            status_code=status_code,
            details=error_context,
            correlation_id=correlation_id
        )


class SyncHTTPClient(HTTPClientBase):
    """
    Synchronous HTTP client using requests 2.31+ with enterprise-grade features.
    
    Provides circuit breaker protection, retry logic with exponential backoff,
    connection pooling, and comprehensive monitoring for external service communication
    per Section 0.1.2 external integration components.
    """
    
    def __init__(self, service_name: str, config: Optional[HTTPClientConfig] = None):
        super().__init__(service_name, config)
        self._setup_session()
    
    def _setup_session(self):
        """Setup requests session with connection pooling and adapter configuration."""
        self._session = requests.Session()
        
        # Configure connection pooling adapter
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=self.config.max_connections_per_host,
            pool_maxsize=self.config.max_connections,
            pool_block=False,
            max_retries=0  # We handle retries manually with Tenacity
        )
        
        self._session.mount('http://', adapter)
        self._session.mount('https://', adapter)
        
        # Set default headers
        self._session.headers.update(self.config.default_headers)
        
        # Configure SSL verification
        self._session.verify = self.config.verify_ssl
        
        # Configure timeouts
        self._session.timeout = (self.config.connect_timeout, self.config.read_timeout)
    
    @contextmanager
    def _connection_monitoring(self):
        """Context manager for monitoring active connections."""
        if self.config.enable_metrics:
            active_connections.labels(
                service=self.service_name,
                client_type='sync'
            ).inc()
        
        try:
            yield
        finally:
            if self.config.enable_metrics:
                active_connections.labels(
                    service=self.service_name,
                    client_type='sync'
                ).dec()
    
    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        data: Optional[Union[str, bytes, Dict[str, Any]]] = None,
        timeout: Optional[float] = None,
        correlation_id: Optional[str] = None,
        **kwargs
    ) -> requests.Response:
        """
        Make HTTP request with circuit breaker protection and retry logic.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE, PATCH)
            url: Request URL
            headers: Additional headers to send
            params: URL parameters
            json_data: JSON data to send in request body
            data: Form data or raw data to send
            timeout: Request timeout override
            correlation_id: Request correlation ID for tracking
            **kwargs: Additional arguments passed to requests
            
        Returns:
            HTTP response object
            
        Raises:
            ExternalServiceError: On request failure
            CircuitBreakerError: When circuit breaker is open
        """
        start_time = time.time()
        
        # Prepare request parameters
        request_headers = self.config.default_headers.copy()
        if headers:
            request_headers.update(headers)
        
        if correlation_id:
            request_headers['X-Correlation-ID'] = correlation_id
            self.correlation_ids[correlation_id] = correlation_id
        
        request_timeout = timeout or self.config.total_timeout
        
        # Log request
        self._log_request(method, url, request_headers, correlation_id)
        
        @self._create_retry_decorator(method)
        def _make_request():
            """Internal request function with retry logic."""
            with self._connection_monitoring():
                try:
                    # Use circuit breaker for external service protection
                    response = self._circuit_breaker(self._session.request)(
                        method=method.upper(),
                        url=url,
                        headers=request_headers,
                        params=params,
                        json=json_data,
                        data=data,
                        timeout=request_timeout,
                        **kwargs
                    )
                    
                    # Check for HTTP error status codes
                    if response.status_code >= 400:
                        if response.status_code >= 500:
                            # Server errors are retryable
                            raise ExternalServiceError(
                                message=f"Server error from {self.service_name}",
                                service_name=self.service_name,
                                status_code=response.status_code,
                                correlation_id=correlation_id
                            )
                        else:
                            # Client errors are not retryable
                            logger.warning(
                                "HTTP client error",
                                method=method,
                                url=url,
                                status_code=response.status_code,
                                service=self.service_name,
                                correlation_id=correlation_id
                            )
                    
                    return response
                
                except PyBreakerError as e:
                    raise CircuitBreakerError(
                        message=f"Circuit breaker open for {self.service_name}",
                        service_name=self.service_name,
                        circuit_state="open",
                        correlation_id=correlation_id
                    ) from e
                
                except requests.exceptions.RequestException as e:
                    raise self._handle_request_error(e, method, url, correlation_id) from e
        
        try:
            response = _make_request()
            response_time = time.time() - start_time
            
            # Log successful response
            self._log_response(method, url, response.status_code, response_time, correlation_id)
            
            # Update metrics
            self._update_metrics(method, response.status_code, response_time, 'sync')
            
            return response
        
        except Exception as e:
            response_time = time.time() - start_time
            error_message = str(e)
            
            # Log failed response
            self._log_response(method, url, 0, response_time, correlation_id, error_message)
            
            # Update retry metrics if it was a retry attempt
            if hasattr(e, '__context__') and e.__context__:
                http_retry_attempts_total.labels(
                    method=method,
                    service=self.service_name,
                    retry_reason=e.__class__.__name__
                ).inc()
            
            raise
    
    def get(self, url: str, **kwargs) -> requests.Response:
        """Make GET request."""
        return self.request('GET', url, **kwargs)
    
    def post(self, url: str, **kwargs) -> requests.Response:
        """Make POST request."""
        return self.request('POST', url, **kwargs)
    
    def put(self, url: str, **kwargs) -> requests.Response:
        """Make PUT request."""
        return self.request('PUT', url, **kwargs)
    
    def delete(self, url: str, **kwargs) -> requests.Response:
        """Make DELETE request."""
        return self.request('DELETE', url, **kwargs)
    
    def patch(self, url: str, **kwargs) -> requests.Response:
        """Make PATCH request."""
        return self.request('PATCH', url, **kwargs)
    
    def close(self):
        """Close the HTTP session and clean up resources."""
        if self._session:
            self._session.close()
            self._session = None


class AsyncHTTPClient(HTTPClientBase):
    """
    Asynchronous HTTP client using httpx 0.24+ with enterprise-grade features.
    
    Provides async circuit breaker protection, retry logic with exponential backoff,
    connection pooling, and comprehensive monitoring for high-performance external API calls
    per Section 3.2.3 HTTP client libraries.
    """
    
    def __init__(self, service_name: str, config: Optional[HTTPClientConfig] = None):
        super().__init__(service_name, config)
        self._client = None
        self._client_limits = None
    
    def _setup_client(self):
        """Setup httpx async client with connection pooling and configuration."""
        if self._client is not None:
            return
        
        # Configure connection limits for optimal performance
        self._client_limits = httpx.Limits(
            max_keepalive_connections=self.config.keepalive_connections,
            max_connections=self.config.max_connections,
            keepalive_expiry=self.config.keepalive_expiry
        )
        
        # Configure timeouts
        timeout = httpx.Timeout(
            connect=self.config.connect_timeout,
            read=self.config.read_timeout,
            write=self.config.connect_timeout,
            pool=self.config.total_timeout
        )
        
        self._client = httpx.AsyncClient(
            limits=self._client_limits,
            timeout=timeout,
            verify=self.config.verify_ssl,
            headers=self.config.default_headers
        )
    
    @asynccontextmanager
    async def _connection_monitoring(self):
        """Async context manager for monitoring active connections."""
        if self.config.enable_metrics:
            active_connections.labels(
                service=self.service_name,
                client_type='async'
            ).inc()
        
        try:
            yield
        finally:
            if self.config.enable_metrics:
                active_connections.labels(
                    service=self.service_name,
                    client_type='async'
                ).dec()
    
    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        data: Optional[Union[str, bytes, Dict[str, Any]]] = None,
        timeout: Optional[float] = None,
        correlation_id: Optional[str] = None,
        **kwargs
    ) -> httpx.Response:
        """
        Make async HTTP request with circuit breaker protection and retry logic.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE, PATCH)
            url: Request URL
            headers: Additional headers to send
            params: URL parameters
            json_data: JSON data to send in request body
            data: Form data or raw data to send
            timeout: Request timeout override
            correlation_id: Request correlation ID for tracking
            **kwargs: Additional arguments passed to httpx
            
        Returns:
            HTTP response object
            
        Raises:
            ExternalServiceError: On request failure
            CircuitBreakerError: When circuit breaker is open
        """
        await self._setup_client_async()
        start_time = time.time()
        
        # Prepare request parameters
        request_headers = self.config.default_headers.copy()
        if headers:
            request_headers.update(headers)
        
        if correlation_id:
            request_headers['X-Correlation-ID'] = correlation_id
            self.correlation_ids[correlation_id] = correlation_id
        
        request_timeout = timeout or self.config.total_timeout
        
        # Log request
        self._log_request(method, url, request_headers, correlation_id)
        
        # Create async retry decorator
        async_retry = retry(
            stop=stop_after_attempt(self.config.max_retries),
            wait=wait_exponential(
                multiplier=self.config.retry_multiplier,
                min=self.config.retry_delay_min,
                max=self.config.retry_delay_max
            ),
            retry=retry_if_exception_type((
                httpx.ConnectTimeout,
                httpx.ReadTimeout,
                httpx.ConnectError,
                ExternalServiceError
            )),
            before_sleep=before_sleep_log(logger, logging.INFO),
            after=after_log(logger, logging.INFO)
        )
        
        @async_retry
        async def _make_request():
            """Internal async request function with retry logic."""
            async with self._connection_monitoring():
                try:
                    # Note: Circuit breaker pattern adapted for async context
                    if self._circuit_breaker.current_state == 'open':
                        raise CircuitBreakerError(
                            message=f"Circuit breaker open for {self.service_name}",
                            service_name=self.service_name,
                            circuit_state="open",
                            correlation_id=correlation_id
                        )
                    
                    response = await self._client.request(
                        method=method.upper(),
                        url=url,
                        headers=request_headers,
                        params=params,
                        json=json_data,
                        data=data,
                        timeout=request_timeout,
                        **kwargs
                    )
                    
                    # Update circuit breaker on successful request
                    self._circuit_breaker._state_storage['successful_requests'] = 0
                    
                    # Check for HTTP error status codes
                    if response.status_code >= 400:
                        if response.status_code >= 500:
                            # Server errors are retryable
                            raise ExternalServiceError(
                                message=f"Server error from {self.service_name}",
                                service_name=self.service_name,
                                status_code=response.status_code,
                                correlation_id=correlation_id
                            )
                        else:
                            # Client errors are not retryable
                            logger.warning(
                                "HTTP client error",
                                method=method,
                                url=url,
                                status_code=response.status_code,
                                service=self.service_name,
                                correlation_id=correlation_id
                            )
                    
                    return response
                
                except httpx.HTTPError as e:
                    # Update circuit breaker failure count
                    self._circuit_breaker._state_storage.setdefault('failure_count', 0)
                    self._circuit_breaker._state_storage['failure_count'] += 1
                    
                    raise self._handle_request_error(e, method, url, correlation_id) from e
        
        try:
            response = await _make_request()
            response_time = time.time() - start_time
            
            # Log successful response
            self._log_response(method, url, response.status_code, response_time, correlation_id)
            
            # Update metrics
            self._update_metrics(method, response.status_code, response_time, 'async')
            
            return response
        
        except Exception as e:
            response_time = time.time() - start_time
            error_message = str(e)
            
            # Log failed response
            self._log_response(method, url, 0, response_time, correlation_id, error_message)
            
            # Update retry metrics if it was a retry attempt
            if hasattr(e, '__context__') and e.__context__:
                http_retry_attempts_total.labels(
                    method=method,
                    service=self.service_name,
                    retry_reason=e.__class__.__name__
                ).inc()
            
            raise
    
    async def _setup_client_async(self):
        """Async setup of httpx client if not already initialized."""
        if self._client is None:
            self._setup_client()
    
    async def get(self, url: str, **kwargs) -> httpx.Response:
        """Make async GET request."""
        return await self.request('GET', url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> httpx.Response:
        """Make async POST request."""
        return await self.request('POST', url, **kwargs)
    
    async def put(self, url: str, **kwargs) -> httpx.Response:
        """Make async PUT request."""
        return await self.request('PUT', url, **kwargs)
    
    async def delete(self, url: str, **kwargs) -> httpx.Response:
        """Make async DELETE request."""
        return await self.request('DELETE', url, **kwargs)
    
    async def patch(self, url: str, **kwargs) -> httpx.Response:
        """Make async PATCH request."""
        return await self.request('PATCH', url, **kwargs)
    
    async def close(self):
        """Close the async HTTP client and clean up resources."""
        if self._client:
            await self._client.aclose()
            self._client = None


class HTTPClientFactory:
    """
    Factory class for creating configured HTTP clients with service-specific settings.
    
    Provides centralized client creation and management for external service integration
    per Section 0.1.4 service communication patterns.
    """
    
    _sync_clients: Dict[str, SyncHTTPClient] = {}
    _async_clients: Dict[str, AsyncHTTPClient] = {}
    _default_config = HTTPClientConfig()
    
    @classmethod
    def create_sync_client(
        cls,
        service_name: str,
        config: Optional[HTTPClientConfig] = None
    ) -> SyncHTTPClient:
        """
        Create or retrieve sync HTTP client for a service.
        
        Args:
            service_name: Name of the external service
            config: Optional client configuration
            
        Returns:
            Configured sync HTTP client
        """
        client_key = f"{service_name}_sync"
        
        if client_key not in cls._sync_clients:
            cls._sync_clients[client_key] = SyncHTTPClient(
                service_name=service_name,
                config=config or cls._default_config
            )
        
        return cls._sync_clients[client_key]
    
    @classmethod
    def create_async_client(
        cls,
        service_name: str,
        config: Optional[HTTPClientConfig] = None
    ) -> AsyncHTTPClient:
        """
        Create or retrieve async HTTP client for a service.
        
        Args:
            service_name: Name of the external service
            config: Optional client configuration
            
        Returns:
            Configured async HTTP client
        """
        client_key = f"{service_name}_async"
        
        if client_key not in cls._async_clients:
            cls._async_clients[client_key] = AsyncHTTPClient(
                service_name=service_name,
                config=config or cls._default_config
            )
        
        return cls._async_clients[client_key]
    
    @classmethod
    def set_default_config(cls, config: HTTPClientConfig):
        """
        Set default configuration for all new HTTP clients.
        
        Args:
            config: Default HTTP client configuration
        """
        cls._default_config = config
    
    @classmethod
    def close_all_clients(cls):
        """Close all HTTP clients and clean up resources."""
        # Close sync clients
        for client in cls._sync_clients.values():
            client.close()
        cls._sync_clients.clear()
        
        # Close async clients (requires async context)
        for client in cls._async_clients.values():
            if hasattr(client, '_client') and client._client:
                # Note: This should be called from an async context
                asyncio.create_task(client.close())
        cls._async_clients.clear()


# Convenience functions for common use cases
def create_sync_client(
    service_name: str,
    base_url: Optional[str] = None,
    config: Optional[HTTPClientConfig] = None
) -> SyncHTTPClient:
    """
    Create a configured sync HTTP client for external service communication.
    
    Args:
        service_name: Name of the external service
        base_url: Base URL for the service (optional)
        config: Optional client configuration
        
    Returns:
        Configured sync HTTP client
    """
    client = HTTPClientFactory.create_sync_client(service_name, config)
    if base_url:
        client.base_url = base_url
    return client


def create_async_client(
    service_name: str,
    base_url: Optional[str] = None,
    config: Optional[HTTPClientConfig] = None
) -> AsyncHTTPClient:
    """
    Create a configured async HTTP client for high-performance external API calls.
    
    Args:
        service_name: Name of the external service
        base_url: Base URL for the service (optional)
        config: Optional client configuration
        
    Returns:
        Configured async HTTP client
    """
    client = HTTPClientFactory.create_async_client(service_name, config)
    if base_url:
        client.base_url = base_url
    return client


# Export public interface
__all__ = [
    'HTTPClientConfig',
    'SyncHTTPClient',
    'AsyncHTTPClient',
    'HTTPClientFactory',
    'create_sync_client',
    'create_async_client',
    'ExternalServiceError',
    'CircuitBreakerError'
]