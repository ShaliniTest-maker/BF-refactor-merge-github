"""
HTTP client management implementing requests 2.31+ for synchronous operations 
and httpx 0.24+ for asynchronous external API communication.

This module provides enterprise-grade HTTP client patterns with optimized connection pooling,
timeout management, comprehensive error handling, and monitoring integration. It serves as
the foundation for all external service communications in the Flask application.

Aligned with:
- Section 0.1.2: HTTP client libraries replacing Node.js HTTP clients
- Section 3.2.3: External service integration with connection pooling
- Section 6.3.5: Performance optimization and connection pool tuning
- Section 4.2.3: Error handling and recovery patterns
- Section 6.3.3: External systems integration architecture
"""

import asyncio
import json
import logging
import time
from contextlib import asynccontextmanager, contextmanager
from typing import Any, Dict, List, Optional, Union, Callable, Tuple
from urllib.parse import urljoin, urlparse

import httpx
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from urllib3.poolmanager import PoolManager

from .exceptions import (
    HTTPClientError,
    RequestsHTTPError,
    HttpxHTTPError,
    ConnectionError,
    TimeoutError,
    HTTPResponseError,
    IntegrationExceptionFactory
)


# Module-level logger with structured logging
logger = logging.getLogger(__name__)


class OptimizedHTTPAdapter(HTTPAdapter):
    """
    Custom HTTPAdapter with optimized connection pooling and retry strategies.
    
    Implements enterprise-grade connection pool management with tuned parameters
    for external service integration performance optimization per Section 6.3.5.
    """
    
    def __init__(
        self,
        pool_connections: int = 20,
        pool_maxsize: int = 50,
        max_retries: int = 3,
        pool_block: bool = False,
        *args,
        **kwargs
    ):
        """
        Initialize HTTP adapter with optimized pool settings.
        
        Args:
            pool_connections: Number of connection pools to cache
            pool_maxsize: Maximum number of connections per pool
            max_retries: Maximum retry attempts for failed requests
            pool_block: Whether to block when pool is exhausted
        """
        self.pool_connections = pool_connections
        self.pool_maxsize = pool_maxsize
        self.pool_block = pool_block
        
        # Configure retry strategy with exponential backoff
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE"]
        )
        
        super().__init__(max_retries=retry_strategy, *args, **kwargs)
    
    def init_poolmanager(self, *args, **kwargs):
        """Initialize connection pool manager with optimized settings."""
        kwargs['maxsize'] = self.pool_maxsize
        kwargs['block'] = self.pool_block
        return super().init_poolmanager(*args, **kwargs)


class SynchronousHTTPClient:
    """
    Synchronous HTTP client using requests 2.31+ with enterprise-grade patterns.
    
    Provides optimized connection pooling, comprehensive error handling, and
    monitoring integration for external service communication per Section 3.2.3.
    """
    
    def __init__(
        self,
        base_url: Optional[str] = None,
        timeout: Union[float, Tuple[float, float]] = 30.0,
        headers: Optional[Dict[str, str]] = None,
        pool_connections: int = 20,
        pool_maxsize: int = 50,
        max_retries: int = 3,
        verify_ssl: bool = True,
        **kwargs
    ):
        """
        Initialize synchronous HTTP client with optimized configuration.
        
        Args:
            base_url: Base URL for all requests
            timeout: Request timeout (connect, read) or single value
            headers: Default headers for all requests
            pool_connections: Number of connection pools
            pool_maxsize: Maximum connections per pool
            max_retries: Maximum retry attempts
            verify_ssl: SSL certificate verification
            **kwargs: Additional session configuration
        """
        self.base_url = base_url.rstrip('/') if base_url else None
        self.timeout = timeout
        self.default_headers = headers or {}
        self.verify_ssl = verify_ssl
        
        # Initialize requests session with optimized adapter
        self.session = requests.Session()
        
        # Configure optimized HTTP adapter
        adapter = OptimizedHTTPAdapter(
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
            max_retries=max_retries
        )
        
        # Mount adapter for both HTTP and HTTPS
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        
        # Configure session defaults
        self.session.headers.update(self.default_headers)
        self.session.verify = verify_ssl
        
        # Apply additional session configuration
        for key, value in kwargs.items():
            if hasattr(self.session, key):
                setattr(self.session, key, value)
        
        # Request/response interceptors
        self._request_interceptors: List[Callable] = []
        self._response_interceptors: List[Callable] = []
        
        logger.info(
            "Initialized synchronous HTTP client",
            extra={
                'client_type': 'requests',
                'base_url': self.base_url,
                'timeout': self.timeout,
                'pool_connections': pool_connections,
                'pool_maxsize': pool_maxsize,
                'max_retries': max_retries
            }
        )
    
    def add_request_interceptor(self, interceptor: Callable):
        """
        Add request interceptor for preprocessing requests.
        
        Args:
            interceptor: Function to modify requests before sending
        """
        self._request_interceptors.append(interceptor)
    
    def add_response_interceptor(self, interceptor: Callable):
        """
        Add response interceptor for postprocessing responses.
        
        Args:
            interceptor: Function to modify responses after receiving
        """
        self._response_interceptors.append(interceptor)
    
    def _build_url(self, path: str) -> str:
        """
        Build complete URL from base URL and path.
        
        Args:
            path: Request path or complete URL
            
        Returns:
            Complete URL for the request
        """
        if self.base_url and not path.startswith(('http://', 'https://')):
            return urljoin(self.base_url + '/', path.lstrip('/'))
        return path
    
    def _apply_request_interceptors(self, **kwargs) -> Dict[str, Any]:
        """
        Apply all registered request interceptors.
        
        Args:
            **kwargs: Request parameters
            
        Returns:
            Modified request parameters
        """
        for interceptor in self._request_interceptors:
            kwargs = interceptor(**kwargs) or kwargs
        return kwargs
    
    def _apply_response_interceptors(self, response: requests.Response) -> requests.Response:
        """
        Apply all registered response interceptors.
        
        Args:
            response: Response object to process
            
        Returns:
            Processed response object
        """
        for interceptor in self._response_interceptors:
            response = interceptor(response) or response
        return response
    
    def _handle_request_exception(
        self,
        exception: Exception,
        method: str,
        url: str,
        **kwargs
    ) -> None:
        """
        Convert requests exceptions to integration exceptions.
        
        Args:
            exception: Original exception from requests
            method: HTTP method
            url: Request URL
            **kwargs: Request parameters
        """
        service_name = urlparse(url).netloc or 'unknown_service'
        operation = f"{method.upper()}_{urlparse(url).path}"
        
        if isinstance(exception, requests.exceptions.ConnectionError):
            raise ConnectionError(
                message=f"Connection failed to {service_name}",
                service_name=service_name,
                operation=operation,
                url=url,
                method=method
            ) from exception
        elif isinstance(exception, requests.exceptions.Timeout):
            raise TimeoutError(
                message=f"Request timeout to {service_name}",
                service_name=service_name,
                operation=operation,
                url=url,
                method=method,
                timeout=kwargs.get('timeout', self.timeout)
            ) from exception
        elif isinstance(exception, requests.exceptions.HTTPError):
            response = getattr(exception, 'response', None)
            status_code = response.status_code if response else None
            raise HTTPResponseError(
                message=f"HTTP error {status_code} from {service_name}",
                service_name=service_name,
                operation=operation,
                url=url,
                method=method,
                status_code=status_code,
                response_text=response.text if response else None
            ) from exception
        else:
            raise RequestsHTTPError(
                message=f"HTTP client error: {str(exception)}",
                service_name=service_name,
                operation=operation,
                url=url,
                method=method,
                error_context={'original_exception': str(exception)}
            ) from exception
    
    def request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        data: Optional[Union[Dict[str, Any], str, bytes]] = None,
        timeout: Optional[Union[float, Tuple[float, float]]] = None,
        **kwargs
    ) -> requests.Response:
        """
        Make HTTP request with comprehensive error handling and monitoring.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            path: Request path or complete URL
            params: Query parameters
            headers: Request headers
            json_data: JSON payload for request body
            data: Raw data for request body
            timeout: Request timeout override
            **kwargs: Additional request parameters
            
        Returns:
            Response object
            
        Raises:
            HTTPClientError: For various HTTP client failures
        """
        start_time = time.time()
        url = self._build_url(path)
        request_timeout = timeout or self.timeout
        
        # Merge headers
        request_headers = self.default_headers.copy()
        if headers:
            request_headers.update(headers)
        
        # Prepare request parameters
        request_kwargs = {
            'method': method.upper(),
            'url': url,
            'params': params,
            'headers': request_headers,
            'timeout': request_timeout,
            **kwargs
        }
        
        # Add JSON or data payload
        if json_data is not None:
            request_kwargs['json'] = json_data
        elif data is not None:
            request_kwargs['data'] = data
        
        # Apply request interceptors
        request_kwargs = self._apply_request_interceptors(**request_kwargs)
        
        try:
            logger.debug(
                "Making HTTP request",
                extra={
                    'method': method.upper(),
                    'url': url,
                    'timeout': request_timeout,
                    'has_json': json_data is not None,
                    'has_data': data is not None
                }
            )
            
            # Make the request
            response = self.session.request(**request_kwargs)
            
            # Apply response interceptors
            response = self._apply_response_interceptors(response)
            
            # Log successful request
            duration = time.time() - start_time
            logger.info(
                "HTTP request completed",
                extra={
                    'method': method.upper(),
                    'url': url,
                    'status_code': response.status_code,
                    'duration_ms': round(duration * 1000, 2),
                    'response_size': len(response.content) if response.content else 0
                }
            )
            
            return response
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                "HTTP request failed",
                extra={
                    'method': method.upper(),
                    'url': url,
                    'duration_ms': round(duration * 1000, 2),
                    'error': str(e),
                    'error_type': type(e).__name__
                }
            )
            self._handle_request_exception(e, method, url, **request_kwargs)
    
    def get(self, path: str, **kwargs) -> requests.Response:
        """Make GET request."""
        return self.request('GET', path, **kwargs)
    
    def post(self, path: str, **kwargs) -> requests.Response:
        """Make POST request."""
        return self.request('POST', path, **kwargs)
    
    def put(self, path: str, **kwargs) -> requests.Response:
        """Make PUT request."""
        return self.request('PUT', path, **kwargs)
    
    def patch(self, path: str, **kwargs) -> requests.Response:
        """Make PATCH request."""
        return self.request('PATCH', path, **kwargs)
    
    def delete(self, path: str, **kwargs) -> requests.Response:
        """Make DELETE request."""
        return self.request('DELETE', path, **kwargs)
    
    def head(self, path: str, **kwargs) -> requests.Response:
        """Make HEAD request."""
        return self.request('HEAD', path, **kwargs)
    
    def options(self, path: str, **kwargs) -> requests.Response:
        """Make OPTIONS request."""
        return self.request('OPTIONS', path, **kwargs)
    
    @contextmanager
    def session_context(self):
        """Context manager for session lifecycle management."""
        try:
            yield self.session
        finally:
            # Session cleanup is handled by the session itself
            pass
    
    def close(self):
        """Close the HTTP session and cleanup resources."""
        if hasattr(self, 'session'):
            self.session.close()
            logger.info("Closed synchronous HTTP client session")


class AsynchronousHTTPClient:
    """
    Asynchronous HTTP client using httpx 0.24+ with high-performance patterns.
    
    Provides optimized async connection pooling, comprehensive error handling,
    and monitoring integration for high-performance external API calls per Section 3.2.3.
    """
    
    def __init__(
        self,
        base_url: Optional[str] = None,
        timeout: Union[float, httpx.Timeout] = 30.0,
        headers: Optional[Dict[str, str]] = None,
        max_connections: int = 100,
        max_keepalive_connections: int = 50,
        keepalive_expiry: float = 30.0,
        verify_ssl: bool = True,
        http2: bool = True,
        **kwargs
    ):
        """
        Initialize asynchronous HTTP client with optimized configuration.
        
        Args:
            base_url: Base URL for all requests
            timeout: Request timeout configuration
            headers: Default headers for all requests
            max_connections: Maximum total connections
            max_keepalive_connections: Maximum keepalive connections
            keepalive_expiry: Keepalive connection expiry time
            verify_ssl: SSL certificate verification
            http2: Enable HTTP/2 support
            **kwargs: Additional client configuration
        """
        self.base_url = base_url.rstrip('/') if base_url else None
        self.default_headers = headers or {}
        self.verify_ssl = verify_ssl
        self.http2 = http2
        
        # Configure timeout
        if isinstance(timeout, (int, float)):
            self.timeout = httpx.Timeout(timeout)
        else:
            self.timeout = timeout
        
        # Configure connection limits per Section 6.3.5
        self.limits = httpx.Limits(
            max_connections=max_connections,
            max_keepalive_connections=max_keepalive_connections,
            keepalive_expiry=keepalive_expiry
        )
        
        # Client configuration
        self.client_config = {
            'base_url': self.base_url,
            'headers': self.default_headers,
            'timeout': self.timeout,
            'limits': self.limits,
            'verify': self.verify_ssl,
            'http2': self.http2,
            **kwargs
        }
        
        # Client instance (created on demand)
        self._client: Optional[httpx.AsyncClient] = None
        
        # Request/response interceptors
        self._request_interceptors: List[Callable] = []
        self._response_interceptors: List[Callable] = []
        
        logger.info(
            "Initialized asynchronous HTTP client",
            extra={
                'client_type': 'httpx',
                'base_url': self.base_url,
                'timeout': str(self.timeout),
                'max_connections': max_connections,
                'max_keepalive_connections': max_keepalive_connections,
                'http2': http2
            }
        )
    
    @property
    def client(self) -> httpx.AsyncClient:
        """
        Get or create async client instance.
        
        Returns:
            Configured httpx AsyncClient instance
        """
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(**self.client_config)
        return self._client
    
    def add_request_interceptor(self, interceptor: Callable):
        """
        Add request interceptor for preprocessing requests.
        
        Args:
            interceptor: Async function to modify requests before sending
        """
        self._request_interceptors.append(interceptor)
    
    def add_response_interceptor(self, interceptor: Callable):
        """
        Add response interceptor for postprocessing responses.
        
        Args:
            interceptor: Async function to modify responses after receiving
        """
        self._response_interceptors.append(interceptor)
    
    def _build_url(self, path: str) -> str:
        """
        Build complete URL from base URL and path.
        
        Args:
            path: Request path or complete URL
            
        Returns:
            Complete URL for the request
        """
        if self.base_url and not path.startswith(('http://', 'https://')):
            return urljoin(self.base_url + '/', path.lstrip('/'))
        return path
    
    async def _apply_request_interceptors(self, **kwargs) -> Dict[str, Any]:
        """
        Apply all registered request interceptors.
        
        Args:
            **kwargs: Request parameters
            
        Returns:
            Modified request parameters
        """
        for interceptor in self._request_interceptors:
            if asyncio.iscoroutinefunction(interceptor):
                kwargs = await interceptor(**kwargs) or kwargs
            else:
                kwargs = interceptor(**kwargs) or kwargs
        return kwargs
    
    async def _apply_response_interceptors(self, response: httpx.Response) -> httpx.Response:
        """
        Apply all registered response interceptors.
        
        Args:
            response: Response object to process
            
        Returns:
            Processed response object
        """
        for interceptor in self._response_interceptors:
            if asyncio.iscoroutinefunction(interceptor):
                response = await interceptor(response) or response
            else:
                response = interceptor(response) or response
        return response
    
    def _handle_request_exception(
        self,
        exception: Exception,
        method: str,
        url: str,
        **kwargs
    ) -> None:
        """
        Convert httpx exceptions to integration exceptions.
        
        Args:
            exception: Original exception from httpx
            method: HTTP method
            url: Request URL
            **kwargs: Request parameters
        """
        service_name = urlparse(url).netloc or 'unknown_service'
        operation = f"{method.upper()}_{urlparse(url).path}"
        
        if isinstance(exception, httpx.ConnectError):
            raise ConnectionError(
                message=f"Connection failed to {service_name}",
                service_name=service_name,
                operation=operation,
                url=url,
                method=method
            ) from exception
        elif isinstance(exception, httpx.TimeoutException):
            raise TimeoutError(
                message=f"Request timeout to {service_name}",
                service_name=service_name,
                operation=operation,
                url=url,
                method=method,
                timeout=kwargs.get('timeout', self.timeout)
            ) from exception
        elif isinstance(exception, httpx.HTTPStatusError):
            raise HTTPResponseError(
                message=f"HTTP error {exception.response.status_code} from {service_name}",
                service_name=service_name,
                operation=operation,
                url=url,
                method=method,
                status_code=exception.response.status_code,
                response_text=exception.response.text
            ) from exception
        else:
            raise HttpxHTTPError(
                message=f"HTTP client error: {str(exception)}",
                service_name=service_name,
                operation=operation,
                url=url,
                method=method,
                error_context={'original_exception': str(exception)}
            ) from exception
    
    async def request(
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
        Make async HTTP request with comprehensive error handling and monitoring.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            path: Request path or complete URL
            params: Query parameters
            headers: Request headers
            json_data: JSON payload for request body
            data: Raw data for request body
            timeout: Request timeout override
            **kwargs: Additional request parameters
            
        Returns:
            Response object
            
        Raises:
            HTTPClientError: For various HTTP client failures
        """
        start_time = time.time()
        url = self._build_url(path)
        request_timeout = timeout or self.timeout
        
        # Merge headers
        request_headers = self.default_headers.copy()
        if headers:
            request_headers.update(headers)
        
        # Prepare request parameters
        request_kwargs = {
            'method': method.upper(),
            'url': url,
            'params': params,
            'headers': request_headers,
            'timeout': request_timeout,
            **kwargs
        }
        
        # Add JSON or data payload
        if json_data is not None:
            request_kwargs['json'] = json_data
        elif data is not None:
            request_kwargs['data'] = data
        
        # Apply request interceptors
        request_kwargs = await self._apply_request_interceptors(**request_kwargs)
        
        try:
            logger.debug(
                "Making async HTTP request",
                extra={
                    'method': method.upper(),
                    'url': url,
                    'timeout': str(request_timeout),
                    'has_json': json_data is not None,
                    'has_data': data is not None
                }
            )
            
            # Make the request
            response = await self.client.request(**request_kwargs)
            
            # Apply response interceptors
            response = await self._apply_response_interceptors(response)
            
            # Log successful request
            duration = time.time() - start_time
            logger.info(
                "Async HTTP request completed",
                extra={
                    'method': method.upper(),
                    'url': url,
                    'status_code': response.status_code,
                    'duration_ms': round(duration * 1000, 2),
                    'response_size': len(response.content) if response.content else 0
                }
            )
            
            return response
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                "Async HTTP request failed",
                extra={
                    'method': method.upper(),
                    'url': url,
                    'duration_ms': round(duration * 1000, 2),
                    'error': str(e),
                    'error_type': type(e).__name__
                }
            )
            self._handle_request_exception(e, method, url, **request_kwargs)
    
    async def get(self, path: str, **kwargs) -> httpx.Response:
        """Make async GET request."""
        return await self.request('GET', path, **kwargs)
    
    async def post(self, path: str, **kwargs) -> httpx.Response:
        """Make async POST request."""
        return await self.request('POST', path, **kwargs)
    
    async def put(self, path: str, **kwargs) -> httpx.Response:
        """Make async PUT request."""
        return await self.request('PUT', path, **kwargs)
    
    async def patch(self, path: str, **kwargs) -> httpx.Response:
        """Make async PATCH request."""
        return await self.request('PATCH', path, **kwargs)
    
    async def delete(self, path: str, **kwargs) -> httpx.Response:
        """Make async DELETE request."""
        return await self.request('DELETE', path, **kwargs)
    
    async def head(self, path: str, **kwargs) -> httpx.Response:
        """Make async HEAD request."""
        return await self.request('HEAD', path, **kwargs)
    
    async def options(self, path: str, **kwargs) -> httpx.Response:
        """Make async OPTIONS request."""
        return await self.request('OPTIONS', path, **kwargs)
    
    @asynccontextmanager
    async def client_context(self):
        """Async context manager for client lifecycle management."""
        try:
            yield self.client
        finally:
            # Client cleanup is handled automatically
            pass
    
    async def close(self):
        """Close the async HTTP client and cleanup resources."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            logger.info("Closed asynchronous HTTP client")


class HTTPClientManager:
    """
    Unified HTTP client manager providing both synchronous and asynchronous clients.
    
    Implements enterprise-grade HTTP client patterns with optimized connection pooling,
    comprehensive error handling, and monitoring integration for external service
    communication per Section 6.3.5 performance characteristics.
    """
    
    def __init__(
        self,
        base_url: Optional[str] = None,
        timeout: Union[float, Tuple[float, float]] = 30.0,
        headers: Optional[Dict[str, str]] = None,
        sync_pool_connections: int = 20,
        sync_pool_maxsize: int = 50,
        async_max_connections: int = 100,
        async_max_keepalive_connections: int = 50,
        verify_ssl: bool = True,
        enable_http2: bool = True,
        **kwargs
    ):
        """
        Initialize unified HTTP client manager.
        
        Args:
            base_url: Base URL for all clients
            timeout: Default timeout for requests
            headers: Default headers for all requests
            sync_pool_connections: Sync client pool connections
            sync_pool_maxsize: Sync client pool max size
            async_max_connections: Async client max connections
            async_max_keepalive_connections: Async client max keepalive connections
            verify_ssl: SSL certificate verification
            enable_http2: Enable HTTP/2 for async client
            **kwargs: Additional configuration
        """
        self.base_url = base_url
        self.timeout = timeout
        self.default_headers = headers or {}
        self.verify_ssl = verify_ssl
        self.enable_http2 = enable_http2
        
        # Initialize synchronous client
        self.sync_client = SynchronousHTTPClient(
            base_url=base_url,
            timeout=timeout,
            headers=headers,
            pool_connections=sync_pool_connections,
            pool_maxsize=sync_pool_maxsize,
            verify_ssl=verify_ssl,
            **kwargs
        )
        
        # Initialize asynchronous client
        self.async_client = AsynchronousHTTPClient(
            base_url=base_url,
            timeout=timeout,
            headers=headers,
            max_connections=async_max_connections,
            max_keepalive_connections=async_max_keepalive_connections,
            verify_ssl=verify_ssl,
            http2=enable_http2,
            **kwargs
        )
        
        logger.info(
            "Initialized unified HTTP client manager",
            extra={
                'base_url': base_url,
                'timeout': timeout,
                'sync_pool_maxsize': sync_pool_maxsize,
                'async_max_connections': async_max_connections,
                'http2_enabled': enable_http2
            }
        )
    
    def get_sync_client(self) -> SynchronousHTTPClient:
        """
        Get synchronous HTTP client for blocking operations.
        
        Returns:
            Configured synchronous HTTP client
        """
        return self.sync_client
    
    def get_async_client(self) -> AsynchronousHTTPClient:
        """
        Get asynchronous HTTP client for non-blocking operations.
        
        Returns:
            Configured asynchronous HTTP client
        """
        return self.async_client
    
    def add_request_interceptor(self, interceptor: Callable, client_type: str = 'both'):
        """
        Add request interceptor to specified client type.
        
        Args:
            interceptor: Interceptor function
            client_type: 'sync', 'async', or 'both'
        """
        if client_type in ('sync', 'both'):
            self.sync_client.add_request_interceptor(interceptor)
        if client_type in ('async', 'both'):
            self.async_client.add_request_interceptor(interceptor)
    
    def add_response_interceptor(self, interceptor: Callable, client_type: str = 'both'):
        """
        Add response interceptor to specified client type.
        
        Args:
            interceptor: Interceptor function
            client_type: 'sync', 'async', or 'both'
        """
        if client_type in ('sync', 'both'):
            self.sync_client.add_response_interceptor(interceptor)
        if client_type in ('async', 'both'):
            self.async_client.add_response_interceptor(interceptor)
    
    async def close_all(self):
        """Close both synchronous and asynchronous clients."""
        self.sync_client.close()
        await self.async_client.close()
        logger.info("Closed all HTTP clients")


# Factory functions for convenient client creation

def create_sync_client(
    base_url: Optional[str] = None,
    timeout: Union[float, Tuple[float, float]] = 30.0,
    **kwargs
) -> SynchronousHTTPClient:
    """
    Factory function to create optimized synchronous HTTP client.
    
    Args:
        base_url: Base URL for all requests
        timeout: Request timeout configuration
        **kwargs: Additional client configuration
        
    Returns:
        Configured synchronous HTTP client
    """
    return SynchronousHTTPClient(
        base_url=base_url,
        timeout=timeout,
        **kwargs
    )


def create_async_client(
    base_url: Optional[str] = None,
    timeout: Union[float, httpx.Timeout] = 30.0,
    **kwargs
) -> AsynchronousHTTPClient:
    """
    Factory function to create optimized asynchronous HTTP client.
    
    Args:
        base_url: Base URL for all requests
        timeout: Request timeout configuration
        **kwargs: Additional client configuration
        
    Returns:
        Configured asynchronous HTTP client
    """
    return AsynchronousHTTPClient(
        base_url=base_url,
        timeout=timeout,
        **kwargs
    )


def create_client_manager(
    base_url: Optional[str] = None,
    timeout: Union[float, Tuple[float, float]] = 30.0,
    **kwargs
) -> HTTPClientManager:
    """
    Factory function to create unified HTTP client manager.
    
    Args:
        base_url: Base URL for all clients
        timeout: Request timeout configuration
        **kwargs: Additional client configuration
        
    Returns:
        Configured HTTP client manager
    """
    return HTTPClientManager(
        base_url=base_url,
        timeout=timeout,
        **kwargs
    )


# Default client instances for application-wide use
_default_sync_client: Optional[SynchronousHTTPClient] = None
_default_async_client: Optional[AsynchronousHTTPClient] = None
_default_client_manager: Optional[HTTPClientManager] = None


def get_default_sync_client() -> SynchronousHTTPClient:
    """
    Get or create default synchronous HTTP client.
    
    Returns:
        Default synchronous HTTP client instance
    """
    global _default_sync_client
    if _default_sync_client is None:
        _default_sync_client = create_sync_client()
    return _default_sync_client


def get_default_async_client() -> AsynchronousHTTPClient:
    """
    Get or create default asynchronous HTTP client.
    
    Returns:
        Default asynchronous HTTP client instance
    """
    global _default_async_client
    if _default_async_client is None:
        _default_async_client = create_async_client()
    return _default_async_client


def get_default_client_manager() -> HTTPClientManager:
    """
    Get or create default HTTP client manager.
    
    Returns:
        Default HTTP client manager instance
    """
    global _default_client_manager
    if _default_client_manager is None:
        _default_client_manager = create_client_manager()
    return _default_client_manager


async def cleanup_default_clients():
    """Cleanup all default client instances."""
    global _default_sync_client, _default_async_client, _default_client_manager
    
    if _default_sync_client:
        _default_sync_client.close()
        _default_sync_client = None
    
    if _default_async_client:
        await _default_async_client.close()
        _default_async_client = None
    
    if _default_client_manager:
        await _default_client_manager.close_all()
        _default_client_manager = None
    
    logger.info("Cleaned up all default HTTP clients")


# Module-level convenience functions

def request_sync(method: str, url: str, **kwargs) -> requests.Response:
    """
    Make synchronous HTTP request using default client.
    
    Args:
        method: HTTP method
        url: Request URL
        **kwargs: Request parameters
        
    Returns:
        Response object
    """
    client = get_default_sync_client()
    return client.request(method, url, **kwargs)


async def request_async(method: str, url: str, **kwargs) -> httpx.Response:
    """
    Make asynchronous HTTP request using default client.
    
    Args:
        method: HTTP method
        url: Request URL
        **kwargs: Request parameters
        
    Returns:
        Response object
    """
    client = get_default_async_client()
    return await client.request(method, url, **kwargs)


# Export public interface
__all__ = [
    # Main classes
    'SynchronousHTTPClient',
    'AsynchronousHTTPClient',
    'HTTPClientManager',
    'OptimizedHTTPAdapter',
    
    # Factory functions
    'create_sync_client',
    'create_async_client',
    'create_client_manager',
    
    # Default client functions
    'get_default_sync_client',
    'get_default_async_client',
    'get_default_client_manager',
    'cleanup_default_clients',
    
    # Convenience functions
    'request_sync',
    'request_async',
]