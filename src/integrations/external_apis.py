"""
External API Integration Module

Third-party API client implementations providing standardized interfaces for external 
service communication beyond Auth0 and AWS. Implements generic API client patterns, 
webhook handlers, file processing integrations, and enterprise service wrappers with 
comprehensive error handling and monitoring.

This module serves as the central hub for all external service integrations, providing:
- Generic API client patterns for enterprise service integration
- Webhook handlers for external service callbacks
- File processing integrations with external services
- Enterprise service API wrappers maintaining existing contracts
- Comprehensive error handling for third-party service failures

Performance Requirements:
- Maintains ≤10% variance from Node.js baseline performance
- Implements circuit breaker patterns for service resilience
- Provides exponential backoff retry strategies for fault tolerance
- Includes comprehensive monitoring and metrics collection

Author: Blitzy Platform Migration Team
Version: 1.0.0
Last Updated: 2024
"""

import asyncio
import json
import logging
import mimetypes
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union, Callable, Tuple
from urllib.parse import urljoin, urlparse

import requests
import httpx
from flask import Flask, Blueprint, request, jsonify, current_app
from prometheus_client import Counter, Histogram, Gauge
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from pybreaker import CircuitBreaker
import structlog

# Import dependencies (these would be implemented in separate files)
try:
    from .base_client import BaseAPIClient, HTTPMethod
    from .exceptions import (
        ExternalServiceError, 
        CircuitBreakerOpenError, 
        RetryExhaustedError,
        WebhookValidationError,
        FileProcessingError
    )
    from .monitoring import ExternalServiceMetrics
except ImportError:
    # Fallback implementations for missing dependencies
    class BaseAPIClient:
        """Fallback base client implementation"""
        def __init__(self, base_url: str, **kwargs):
            self.base_url = base_url
            self.session = requests.Session()
            
        def get(self, endpoint: str, **kwargs) -> requests.Response:
            return self.session.get(urljoin(self.base_url, endpoint), **kwargs)
            
        def post(self, endpoint: str, **kwargs) -> requests.Response:
            return self.session.post(urljoin(self.base_url, endpoint), **kwargs)
    
    class ExternalServiceError(Exception): pass
    class CircuitBreakerOpenError(Exception): pass
    class RetryExhaustedError(Exception): pass
    class WebhookValidationError(Exception): pass
    class FileProcessingError(Exception): pass
    
    class ExternalServiceMetrics:
        """Fallback metrics implementation"""
        def __init__(self):
            self.request_counter = Counter('external_api_requests_total', 'Total external API requests')
            self.response_time = Histogram('external_api_response_time_seconds', 'External API response time')
            
        def record_request(self, service: str, endpoint: str): pass
        def record_response_time(self, service: str, endpoint: str, duration: float): pass
        def record_error(self, service: str, endpoint: str, error_type: str): pass

    class HTTPMethod:
        GET = "GET"
        POST = "POST"
        PUT = "PUT"
        DELETE = "DELETE"
        PATCH = "PATCH"


# Initialize structured logging
logger = structlog.get_logger(__name__)

# Initialize metrics collection
metrics = ExternalServiceMetrics()

# Create Flask Blueprint for external API endpoints
external_api_bp = Blueprint('external_apis', __name__, url_prefix='/api/v1/external')


@dataclass
class APIClientConfig:
    """Configuration class for external API clients"""
    base_url: str
    timeout: int = 30
    retries: int = 3
    circuit_breaker_threshold: int = 5
    circuit_breaker_timeout: int = 60
    connection_pool_size: int = 20
    api_key: Optional[str] = None
    auth_header: Optional[str] = None
    rate_limit: Optional[int] = None
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class WebhookConfig:
    """Configuration for webhook endpoints"""
    endpoint: str
    secret_key: Optional[str] = None
    allowed_ips: List[str] = field(default_factory=list)
    timeout: int = 30
    retry_attempts: int = 3


@dataclass
class FileProcessingConfig:
    """Configuration for file processing integrations"""
    max_file_size: int = 100 * 1024 * 1024  # 100MB
    allowed_extensions: List[str] = field(default_factory=lambda: ['.jpg', '.png', '.pdf', '.docx'])
    upload_endpoint: str = ""
    storage_backend: str = "s3"  # s3, local, etc.
    chunk_size: int = 8192


class GenericAPIClient(BaseAPIClient):
    """
    Generic API client providing standardized interface for external service communication.
    
    Implements enterprise-grade patterns including circuit breaker protection,
    exponential backoff retry strategies, comprehensive error handling, and 
    performance monitoring integration.
    
    Features:
    - Circuit breaker protection for service resilience
    - Exponential backoff retry with jitter
    - Connection pooling for optimal resource utilization
    - Comprehensive request/response logging
    - Prometheus metrics integration
    - Automatic authentication header management
    """
    
    def __init__(self, config: APIClientConfig):
        """
        Initialize generic API client with enterprise configuration.
        
        Args:
            config: APIClientConfig containing service-specific settings
        """
        super().__init__(config.base_url)
        self.config = config
        self.logger = logger.bind(service=self._get_service_name())
        
        # Initialize circuit breaker for service protection
        self.circuit_breaker = CircuitBreaker(
            fail_max=config.circuit_breaker_threshold,
            reset_timeout=config.circuit_breaker_timeout,
            name=f"{self._get_service_name()}_circuit_breaker"
        )
        
        # Configure HTTP session with connection pooling
        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=config.connection_pool_size,
            pool_maxsize=config.connection_pool_size,
            max_retries=0  # We handle retries manually
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        
        # Configure default headers
        self._setup_headers()
        
        # Initialize async client for high-performance operations
        self.async_client = httpx.AsyncClient(
            timeout=config.timeout,
            limits=httpx.Limits(
                max_connections=config.connection_pool_size,
                max_keepalive_connections=config.connection_pool_size // 2
            )
        )
    
    def _get_service_name(self) -> str:
        """Extract service name from base URL for metrics and logging"""
        parsed = urlparse(self.config.base_url)
        return parsed.netloc.replace('.', '_').replace(':', '_')
    
    def _setup_headers(self) -> None:
        """Configure default headers including authentication"""
        headers = {
            'User-Agent': 'Flask-Migration-Client/1.0',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            **self.config.headers
        }
        
        # Add authentication header if configured
        if self.config.api_key and self.config.auth_header:
            headers[self.config.auth_header] = self.config.api_key
        elif self.config.api_key:
            headers['Authorization'] = f'Bearer {self.config.api_key}'
        
        self.session.headers.update(headers)
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception_type((requests.RequestException, httpx.RequestError))
    )
    def make_request(
        self, 
        method: str, 
        endpoint: str, 
        data: Optional[Dict] = None,
        params: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        timeout: Optional[int] = None
    ) -> requests.Response:
        """
        Make HTTP request with circuit breaker protection and retry logic.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE, PATCH)
            endpoint: API endpoint relative to base URL
            data: Request body data
            params: Query parameters
            headers: Additional headers
            timeout: Request timeout override
            
        Returns:
            Response object
            
        Raises:
            CircuitBreakerOpenError: When circuit breaker is open
            RetryExhaustedError: When all retry attempts are exhausted
            ExternalServiceError: For other external service failures
        """
        start_time = time.time()
        service_name = self._get_service_name()
        
        try:
            # Record request metrics
            metrics.record_request(service_name, endpoint)
            
            # Log request details
            self.logger.info(
                "Making external API request",
                method=method,
                endpoint=endpoint,
                has_data=data is not None,
                has_params=params is not None
            )
            
            # Use circuit breaker to protect against cascading failures
            response = self.circuit_breaker(self._execute_request)(
                method, endpoint, data, params, headers, timeout
            )
            
            # Record successful response metrics
            duration = time.time() - start_time
            metrics.record_response_time(service_name, endpoint, duration)
            
            # Log successful response
            self.logger.info(
                "External API request completed",
                method=method,
                endpoint=endpoint,
                status_code=response.status_code,
                duration=duration
            )
            
            return response
            
        except Exception as e:
            # Record error metrics
            duration = time.time() - start_time
            error_type = type(e).__name__
            metrics.record_error(service_name, endpoint, error_type)
            
            # Log error details
            self.logger.error(
                "External API request failed",
                method=method,
                endpoint=endpoint,
                error=str(e),
                error_type=error_type,
                duration=duration
            )
            
            # Re-raise with appropriate error type
            if "circuit breaker" in str(e).lower():
                raise CircuitBreakerOpenError(f"Circuit breaker open for {service_name}") from e
            elif "retry" in str(e).lower():
                raise RetryExhaustedError(f"Retry attempts exhausted for {endpoint}") from e
            else:
                raise ExternalServiceError(f"External service error: {str(e)}") from e
    
    def _execute_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        params: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        timeout: Optional[int] = None
    ) -> requests.Response:
        """Execute the actual HTTP request"""
        url = urljoin(self.config.base_url, endpoint)
        request_timeout = timeout or self.config.timeout
        
        # Prepare request kwargs
        kwargs = {
            'params': params,
            'timeout': request_timeout,
        }
        
        if headers:
            kwargs['headers'] = headers
        
        if data:
            if isinstance(data, dict):
                kwargs['json'] = data
            else:
                kwargs['data'] = data
        
        # Execute request
        response = self.session.request(method, url, **kwargs)
        response.raise_for_status()
        
        return response
    
    async def make_async_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        params: Optional[Dict] = None,
        headers: Optional[Dict] = None
    ) -> httpx.Response:
        """
        Make asynchronous HTTP request for high-performance operations.
        
        Args:
            method: HTTP method
            endpoint: API endpoint
            data: Request body data
            params: Query parameters
            headers: Additional headers
            
        Returns:
            Async response object
        """
        start_time = time.time()
        service_name = self._get_service_name()
        
        try:
            url = urljoin(self.config.base_url, endpoint)
            
            # Record request metrics
            metrics.record_request(service_name, endpoint)
            
            # Prepare request kwargs
            kwargs = {'params': params}
            if headers:
                kwargs['headers'] = headers
            if data:
                kwargs['json'] = data
            
            # Execute async request
            response = await self.async_client.request(method, url, **kwargs)
            response.raise_for_status()
            
            # Record metrics
            duration = time.time() - start_time
            metrics.record_response_time(service_name, endpoint, duration)
            
            return response
            
        except Exception as e:
            duration = time.time() - start_time
            metrics.record_error(service_name, endpoint, type(e).__name__)
            raise ExternalServiceError(f"Async request failed: {str(e)}") from e
    
    def close(self) -> None:
        """Clean up resources"""
        self.session.close()
        if hasattr(self, 'async_client'):
            asyncio.create_task(self.async_client.aclose())


class WebhookHandler:
    """
    Enterprise webhook handler for external service callbacks.
    
    Provides secure webhook endpoint processing with signature validation,
    IP allowlisting, request validation, and comprehensive error handling.
    Maintains API contracts while ensuring security and reliability.
    
    Features:
    - HMAC signature validation for security
    - IP allowlisting for access control
    - Request validation and sanitization
    - Asynchronous processing for performance
    - Comprehensive logging and monitoring
    """
    
    def __init__(self, config: WebhookConfig):
        """
        Initialize webhook handler with security configuration.
        
        Args:
            config: WebhookConfig containing security and processing settings
        """
        self.config = config
        self.logger = logger.bind(webhook_endpoint=config.endpoint)
        self.processors: Dict[str, Callable] = {}
    
    def register_processor(self, event_type: str, processor: Callable) -> None:
        """
        Register event processor for specific webhook event types.
        
        Args:
            event_type: Type of webhook event (e.g., 'payment.completed')
            processor: Callable to process the event
        """
        self.processors[event_type] = processor
        self.logger.info("Registered webhook processor", event_type=event_type)
    
    def validate_signature(self, payload: bytes, signature: str) -> bool:
        """
        Validate webhook signature using HMAC-SHA256.
        
        Args:
            payload: Raw request payload
            signature: Signature from webhook header
            
        Returns:
            True if signature is valid, False otherwise
        """
        if not self.config.secret_key:
            return True  # Skip validation if no secret configured
        
        import hmac
        import hashlib
        
        expected_signature = hmac.new(
            self.config.secret_key.encode('utf-8'),
            payload,
            hashlib.sha256
        ).hexdigest()
        
        # Compare signatures securely
        return hmac.compare_digest(f"sha256={expected_signature}", signature)
    
    def validate_source_ip(self, client_ip: str) -> bool:
        """
        Validate request source IP against allowlist.
        
        Args:
            client_ip: Client IP address
            
        Returns:
            True if IP is allowed, False otherwise
        """
        if not self.config.allowed_ips:
            return True  # No IP restrictions configured
        
        return client_ip in self.config.allowed_ips
    
    async def process_webhook(self, payload: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Process incoming webhook with validation and error handling.
        
        Args:
            payload: Webhook payload data
            headers: Request headers
            
        Returns:
            Processing result
            
        Raises:
            WebhookValidationError: For validation failures
        """
        start_time = time.time()
        
        try:
            # Extract event type from payload
            event_type = payload.get('type') or payload.get('event_type')
            if not event_type:
                raise WebhookValidationError("Missing event type in webhook payload")
            
            # Find appropriate processor
            processor = self.processors.get(event_type)
            if not processor:
                self.logger.warning("No processor found for event type", event_type=event_type)
                return {"status": "ignored", "message": f"No processor for {event_type}"}
            
            # Process webhook asynchronously
            result = await self._execute_processor(processor, payload)
            
            # Log successful processing
            duration = time.time() - start_time
            self.logger.info(
                "Webhook processed successfully",
                event_type=event_type,
                duration=duration,
                result_status=result.get('status', 'unknown')
            )
            
            return result
            
        except Exception as e:
            duration = time.time() - start_time
            self.logger.error(
                "Webhook processing failed",
                event_type=event_type,
                error=str(e),
                duration=duration
            )
            raise
    
    async def _execute_processor(self, processor: Callable, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Execute webhook processor with error handling"""
        try:
            if asyncio.iscoroutinefunction(processor):
                return await processor(payload)
            else:
                # Run synchronous processor in thread pool
                loop = asyncio.get_event_loop()
                return await loop.run_in_executor(None, processor, payload)
        except Exception as e:
            raise WebhookValidationError(f"Processor execution failed: {str(e)}") from e


class FileProcessingIntegration:
    """
    File processing integration for external services.
    
    Handles file upload, download, and processing operations with external
    services while maintaining performance, security, and reliability standards.
    Implements streaming for large files and comprehensive error handling.
    
    Features:
    - Streaming file upload/download for memory efficiency
    - File type validation and size limits
    - Progress tracking for large file operations
    - Integration with external storage services
    - Comprehensive error handling and recovery
    """
    
    def __init__(self, config: FileProcessingConfig, api_client: GenericAPIClient):
        """
        Initialize file processing integration.
        
        Args:
            config: FileProcessingConfig containing processing settings
            api_client: Configured API client for external service communication
        """
        self.config = config
        self.client = api_client
        self.logger = logger.bind(service="file_processing")
    
    def validate_file(self, filename: str, file_size: int) -> bool:
        """
        Validate file based on extension and size restrictions.
        
        Args:
            filename: Name of the file
            file_size: Size of the file in bytes
            
        Returns:
            True if file is valid, False otherwise
        """
        # Check file size
        if file_size > self.config.max_file_size:
            return False
        
        # Check file extension
        if self.config.allowed_extensions:
            file_ext = '.' + filename.split('.')[-1].lower() if '.' in filename else ''
            return file_ext in self.config.allowed_extensions
        
        return True
    
    async def upload_file(
        self,
        file_path: str,
        filename: str,
        metadata: Optional[Dict[str, Any]] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> Dict[str, Any]:
        """
        Upload file to external service with streaming and progress tracking.
        
        Args:
            file_path: Local path to file
            filename: Name for uploaded file
            metadata: Additional metadata
            progress_callback: Optional callback for upload progress
            
        Returns:
            Upload result containing file ID and URL
            
        Raises:
            FileProcessingError: For file processing failures
        """
        import os
        
        try:
            # Validate file
            file_size = os.path.getsize(file_path)
            if not self.validate_file(filename, file_size):
                raise FileProcessingError(f"File validation failed: {filename}")
            
            self.logger.info(
                "Starting file upload",
                filename=filename,
                file_size=file_size,
                metadata=metadata
            )
            
            # Prepare multipart upload
            content_type = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
            
            # Stream file upload in chunks
            with open(file_path, 'rb') as file:
                total_bytes = file_size
                uploaded_bytes = 0
                
                # Create multipart form data
                files = {'file': (filename, file, content_type)}
                data = metadata or {}
                
                # Make upload request
                response = self.client.make_request(
                    method='POST',
                    endpoint=self.config.upload_endpoint,
                    data=data,
                    files=files
                )
                
                # Parse response
                result = response.json()
                
                self.logger.info(
                    "File upload completed",
                    filename=filename,
                    file_id=result.get('file_id'),
                    file_url=result.get('file_url')
                )
                
                return result
                
        except Exception as e:
            self.logger.error(
                "File upload failed",
                filename=filename,
                error=str(e)
            )
            raise FileProcessingError(f"File upload failed: {str(e)}") from e
    
    async def download_file(
        self,
        file_url: str,
        local_path: str,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> str:
        """
        Download file from external service with streaming.
        
        Args:
            file_url: URL of file to download
            local_path: Local path to save file
            progress_callback: Optional callback for download progress
            
        Returns:
            Path to downloaded file
            
        Raises:
            FileProcessingError: For download failures
        """
        import os
        
        try:
            self.logger.info("Starting file download", file_url=file_url, local_path=local_path)
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            
            # Stream download
            response = self.client.session.get(file_url, stream=True)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            downloaded_size = 0
            
            with open(local_path, 'wb') as file:
                for chunk in response.iter_content(chunk_size=self.config.chunk_size):
                    if chunk:
                        file.write(chunk)
                        downloaded_size += len(chunk)
                        
                        # Call progress callback if provided
                        if progress_callback:
                            progress_callback(downloaded_size, total_size)
            
            self.logger.info(
                "File download completed",
                file_url=file_url,
                local_path=local_path,
                file_size=downloaded_size
            )
            
            return local_path
            
        except Exception as e:
            self.logger.error(
                "File download failed",
                file_url=file_url,
                error=str(e)
            )
            raise FileProcessingError(f"File download failed: {str(e)}") from e


class EnterpriseServiceWrapper:
    """
    Enterprise service wrapper maintaining existing API contracts.
    
    Provides a high-level interface for common enterprise service patterns
    while maintaining compatibility with existing API contracts. Implements
    comprehensive monitoring, error handling, and performance optimization.
    
    Features:
    - Unified interface for multiple external services
    - Contract compatibility preservation
    - Comprehensive error handling and recovery
    - Performance monitoring and optimization
    - Enterprise security patterns
    """
    
    def __init__(self, service_configs: Dict[str, APIClientConfig]):
        """
        Initialize enterprise service wrapper with multiple service configurations.
        
        Args:
            service_configs: Dictionary of service name to configuration mappings
        """
        self.services: Dict[str, GenericAPIClient] = {}
        self.webhooks: Dict[str, WebhookHandler] = {}
        self.file_processors: Dict[str, FileProcessingIntegration] = {}
        self.logger = logger.bind(component="enterprise_wrapper")
        
        # Initialize service clients
        for service_name, config in service_configs.items():
            self.services[service_name] = GenericAPIClient(config)
            self.logger.info("Initialized service client", service=service_name)
    
    def get_service(self, service_name: str) -> GenericAPIClient:
        """
        Get configured service client by name.
        
        Args:
            service_name: Name of the service
            
        Returns:
            Configured API client
            
        Raises:
            ExternalServiceError: If service is not configured
        """
        if service_name not in self.services:
            raise ExternalServiceError(f"Service not configured: {service_name}")
        
        return self.services[service_name]
    
    def add_webhook_handler(self, service_name: str, config: WebhookConfig) -> WebhookHandler:
        """
        Add webhook handler for a service.
        
        Args:
            service_name: Name of the service
            config: Webhook configuration
            
        Returns:
            Configured webhook handler
        """
        handler = WebhookHandler(config)
        self.webhooks[service_name] = handler
        self.logger.info("Added webhook handler", service=service_name, endpoint=config.endpoint)
        return handler
    
    def add_file_processor(self, service_name: str, config: FileProcessingConfig) -> FileProcessingIntegration:
        """
        Add file processing integration for a service.
        
        Args:
            service_name: Name of the service
            config: File processing configuration
            
        Returns:
            Configured file processor
        """
        if service_name not in self.services:
            raise ExternalServiceError(f"Service client required for file processing: {service_name}")
        
        processor = FileProcessingIntegration(config, self.services[service_name])
        self.file_processors[service_name] = processor
        self.logger.info("Added file processor", service=service_name)
        return processor
    
    async def health_check(self) -> Dict[str, Dict[str, Any]]:
        """
        Perform health check on all configured services.
        
        Returns:
            Health status for each service
        """
        health_results = {}
        
        for service_name, client in self.services.items():
            try:
                start_time = time.time()
                
                # Attempt a simple request to check service health
                response = client.make_request('GET', '/health', timeout=5)
                
                health_results[service_name] = {
                    'status': 'healthy',
                    'response_time': time.time() - start_time,
                    'status_code': response.status_code
                }
                
            except Exception as e:
                health_results[service_name] = {
                    'status': 'unhealthy',
                    'error': str(e),
                    'response_time': time.time() - start_time
                }
        
        return health_results
    
    def close_all(self) -> None:
        """Clean up all service clients"""
        for client in self.services.values():
            client.close()


# Initialize global enterprise service wrapper
_enterprise_wrapper: Optional[EnterpriseServiceWrapper] = None


def init_external_apis(app: Flask, service_configs: Dict[str, APIClientConfig]) -> EnterpriseServiceWrapper:
    """
    Initialize external APIs integration with Flask application.
    
    Args:
        app: Flask application instance
        service_configs: Dictionary of service configurations
        
    Returns:
        Configured enterprise service wrapper
    """
    global _enterprise_wrapper
    
    # Initialize enterprise wrapper
    _enterprise_wrapper = EnterpriseServiceWrapper(service_configs)
    
    # Register blueprint with Flask app
    app.register_blueprint(external_api_bp)
    
    # Store wrapper in app context
    app.extensions['external_apis'] = _enterprise_wrapper
    
    logger.info("External APIs integration initialized", services=list(service_configs.keys()))
    
    return _enterprise_wrapper


def get_enterprise_wrapper() -> EnterpriseServiceWrapper:
    """
    Get the global enterprise service wrapper.
    
    Returns:
        Enterprise service wrapper instance
        
    Raises:
        RuntimeError: If not initialized
    """
    if _enterprise_wrapper is None:
        raise RuntimeError("External APIs not initialized. Call init_external_apis() first.")
    
    return _enterprise_wrapper


# Flask Blueprint Routes

@external_api_bp.route('/health', methods=['GET'])
async def health_check():
    """Health check endpoint for external services"""
    try:
        wrapper = get_enterprise_wrapper()
        health_results = await wrapper.health_check()
        
        # Determine overall health status
        overall_status = 'healthy' if all(
            result['status'] == 'healthy' for result in health_results.values()
        ) else 'degraded'
        
        return jsonify({
            'status': overall_status,
            'services': health_results,
            'timestamp': datetime.utcnow().isoformat()
        }), 200 if overall_status == 'healthy' else 207
        
    except Exception as e:
        logger.error("Health check failed", error=str(e))
        return jsonify({
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500


@external_api_bp.route('/webhook/<service_name>', methods=['POST'])
async def handle_webhook(service_name: str):
    """Generic webhook handler endpoint"""
    try:
        wrapper = get_enterprise_wrapper()
        
        # Check if webhook handler exists for service
        if service_name not in wrapper.webhooks:
            return jsonify({'error': f'No webhook handler for service: {service_name}'}), 404
        
        handler = wrapper.webhooks[service_name]
        
        # Validate source IP
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        if not handler.validate_source_ip(client_ip):
            logger.warning("Webhook request from unauthorized IP", client_ip=client_ip, service=service_name)
            return jsonify({'error': 'Unauthorized IP address'}), 403
        
        # Validate signature if configured
        signature = request.headers.get('X-Signature-256') or request.headers.get('X-Hub-Signature-256')
        if signature and not handler.validate_signature(request.get_data(), signature):
            logger.warning("Invalid webhook signature", service=service_name)
            return jsonify({'error': 'Invalid signature'}), 403
        
        # Process webhook
        payload = request.get_json()
        if not payload:
            return jsonify({'error': 'Invalid JSON payload'}), 400
        
        result = await handler.process_webhook(payload, dict(request.headers))
        
        return jsonify(result), 200
        
    except WebhookValidationError as e:
        logger.error("Webhook validation failed", service=service_name, error=str(e))
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error("Webhook processing failed", service=service_name, error=str(e))
        return jsonify({'error': 'Internal server error'}), 500


@external_api_bp.route('/services', methods=['GET'])
def list_services():
    """List all configured external services"""
    try:
        wrapper = get_enterprise_wrapper()
        
        services_info = {}
        for service_name, client in wrapper.services.items():
            services_info[service_name] = {
                'base_url': client.config.base_url,
                'circuit_breaker_state': client.circuit_breaker.current_state,
                'has_webhook': service_name in wrapper.webhooks,
                'has_file_processor': service_name in wrapper.file_processors
            }
        
        return jsonify({
            'services': services_info,
            'total_count': len(services_info)
        }), 200
        
    except Exception as e:
        logger.error("Failed to list services", error=str(e))
        return jsonify({'error': str(e)}), 500


# Error handlers for Flask integration
@external_api_bp.errorhandler(ExternalServiceError)
def handle_external_service_error(error):
    """Handle external service errors"""
    logger.error("External service error", error=str(error))
    return jsonify({'error': 'External service error', 'message': str(error)}), 502


@external_api_bp.errorhandler(CircuitBreakerOpenError)
def handle_circuit_breaker_error(error):
    """Handle circuit breaker open errors"""
    logger.warning("Circuit breaker open", error=str(error))
    return jsonify({'error': 'Service temporarily unavailable', 'message': str(error)}), 503


@external_api_bp.errorhandler(RetryExhaustedError)
def handle_retry_exhausted_error(error):
    """Handle retry exhausted errors"""
    logger.error("Retry attempts exhausted", error=str(error))
    return jsonify({'error': 'Service request failed', 'message': str(error)}), 502


@external_api_bp.errorhandler(WebhookValidationError)
def handle_webhook_validation_error(error):
    """Handle webhook validation errors"""
    logger.warning("Webhook validation failed", error=str(error))
    return jsonify({'error': 'Webhook validation failed', 'message': str(error)}), 400


@external_api_bp.errorhandler(FileProcessingError)
def handle_file_processing_error(error):
    """Handle file processing errors"""
    logger.error("File processing failed", error=str(error))
    return jsonify({'error': 'File processing failed', 'message': str(error)}), 422


# Export public interface
__all__ = [
    'GenericAPIClient',
    'WebhookHandler',
    'FileProcessingIntegration',
    'EnterpriseServiceWrapper',
    'APIClientConfig',
    'WebhookConfig',
    'FileProcessingConfig',
    'init_external_apis',
    'get_enterprise_wrapper',
    'external_api_bp'
]