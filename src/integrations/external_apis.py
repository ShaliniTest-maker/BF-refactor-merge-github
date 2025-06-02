"""
External API Client Implementations for Third-Party Service Integration

This module provides comprehensive third-party API client implementations with standardized
interfaces for external service communication beyond Auth0 and AWS. Implements generic API
client patterns, webhook handlers, file processing integrations, and enterprise service
wrappers with comprehensive error handling and monitoring aligned with Section 0.1.2, 6.3.3,
and migration performance requirements.

Key Features:
- Generic API client patterns for enterprise service integration per Section 6.3.3
- Webhook handlers for external service callbacks per Section 6.3.3
- File processing integrations with streaming support per Section 6.3.2
- Enterprise service API wrappers maintaining existing contracts per Section 0.1.4
- Third-party API clients converted to Python HTTP client implementations per Section 0.1.2
- Comprehensive error handling for third-party service failures per Section 4.2.3
- Circuit breaker protection and retry logic with exponential backoff
- Performance monitoring with prometheus-client integration per Section 6.3.5

Performance Requirements:
- Maintains ≤10% variance from Node.js baseline per Section 0.3.2
- Enterprise-grade monitoring integration per Section 6.5.1.1
- Optimized connection pooling for external service calls per Section 6.3.5
"""

import asyncio
import hashlib
import hmac
import json
import logging
import time
import uuid
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union, Callable, Iterator, AsyncIterator
from urllib.parse import urljoin, urlparse, parse_qs
from functools import wraps

import structlog
from flask import Request, Response, jsonify, request as flask_request

# Core integration dependencies
from .base_client import (
    BaseExternalServiceClient,
    BaseClientConfiguration,
    create_api_service_client,
    create_auth_service_client
)
from .exceptions import (
    IntegrationError,
    HTTPClientError,
    HTTPResponseError,
    ConnectionError,
    TimeoutError,
    CircuitBreakerOpenError,
    RetryExhaustedError,
    ValidationError,
    IntegrationExceptionFactory
)
from .monitoring import (
    external_service_monitor,
    ServiceType,
    CircuitBreakerState,
    HealthStatus,
    track_external_service_call,
    update_service_health
)

# Initialize structured logger for enterprise integration
logger = structlog.get_logger(__name__)


class WebhookValidationError(ValidationError):
    """Exception for webhook signature validation failures."""
    
    def __init__(
        self,
        message: str,
        webhook_source: str,
        signature_header: Optional[str] = None,
        **kwargs
    ):
        super().__init__(
            message=message,
            operation="webhook_validation",
            validation_errors={'signature_validation': [message]},
            **kwargs
        )
        self.webhook_source = webhook_source
        self.signature_header = signature_header


class FileProcessingError(IntegrationError):
    """Exception for file processing integration failures."""
    
    def __init__(
        self,
        message: str,
        operation: str,
        file_path: Optional[str] = None,
        file_size: Optional[int] = None,
        processing_stage: Optional[str] = None,
        **kwargs
    ):
        super().__init__(
            message=message,
            service_name="file_processing",
            operation=operation,
            **kwargs
        )
        self.file_path = file_path
        self.file_size = file_size
        self.processing_stage = processing_stage
        
        self.error_context.update({
            'file_path': file_path,
            'file_size': file_size,
            'processing_stage': processing_stage
        })


class GenericAPIClient(BaseExternalServiceClient):
    """
    Generic external API client implementing standardized patterns for third-party integrations.
    
    Provides comprehensive foundation for external service communication with enterprise-grade
    resilience patterns, monitoring, and error handling. Supports both synchronous and
    asynchronous operations with circuit breaker protection and retry logic.
    
    Implements requirements from Section 0.1.2, 6.3.3, and 4.2.3 specifications.
    """
    
    def __init__(
        self,
        service_name: str,
        base_url: str,
        api_key: Optional[str] = None,
        api_version: Optional[str] = None,
        timeout: Union[float, tuple] = 30.0,
        **kwargs
    ):
        """
        Initialize generic API client with comprehensive configuration.
        
        Args:
            service_name: Unique service identifier for monitoring
            base_url: Base URL for API service
            api_key: Optional API key for authentication
            api_version: Optional API version for versioned endpoints
            timeout: Request timeout configuration
            **kwargs: Additional configuration parameters
        """
        # Configure service-specific settings
        default_headers = kwargs.get('default_headers', {})
        if api_key:
            default_headers['Authorization'] = f'Bearer {api_key}'
        if api_version:
            default_headers['Accept'] = f'application/vnd.api+json;version={api_version}'
        
        # Create configuration with API-specific defaults
        config = create_api_service_client(
            service_name=service_name,
            base_url=base_url,
            timeout=timeout,
            default_headers=default_headers,
            health_check_endpoint='/health',
            **kwargs
        )
        
        super().__init__(config)
        
        self.api_key = api_key
        self.api_version = api_version
        
        logger.info(
            "generic_api_client_initialized",
            service_name=service_name,
            base_url=base_url,
            api_version=api_version,
            has_api_key=bool(api_key),
            component="integrations.external_apis"
        )
    
    def authenticate(self, credentials: Dict[str, Any]) -> Dict[str, Any]:
        """
        Authenticate with the external API service.
        
        Args:
            credentials: Authentication credentials (api_key, oauth_token, etc.)
            
        Returns:
            Authentication result with token and expiration info
        """
        auth_result = {
            'authenticated': False,
            'token': None,
            'expires_at': None,
            'token_type': 'bearer'
        }
        
        try:
            if 'api_key' in credentials:
                # API key authentication
                self.api_key = credentials['api_key']
                self.config.default_headers['Authorization'] = f'Bearer {self.api_key}'
                auth_result['authenticated'] = True
                auth_result['token'] = self.api_key
                
            elif 'oauth_token' in credentials:
                # OAuth token authentication
                oauth_token = credentials['oauth_token']
                self.config.default_headers['Authorization'] = f'Bearer {oauth_token}'
                auth_result['authenticated'] = True
                auth_result['token'] = oauth_token
                auth_result['expires_at'] = credentials.get('expires_at')
                
            else:
                # Try basic authentication if username/password provided
                if 'username' in credentials and 'password' in credentials:
                    auth_response = self.post(
                        '/auth/login',
                        json_data={
                            'username': credentials['username'],
                            'password': credentials['password']
                        }
                    )
                    
                    if auth_response.status_code == 200:
                        auth_data = auth_response.json()
                        auth_result['authenticated'] = True
                        auth_result['token'] = auth_data.get('access_token')
                        auth_result['expires_at'] = auth_data.get('expires_at')
                        
                        # Update headers with new token
                        if auth_result['token']:
                            self.config.default_headers['Authorization'] = f'Bearer {auth_result["token"]}'
            
            logger.info(
                "api_authentication_completed",
                service_name=self.service_name,
                authenticated=auth_result['authenticated'],
                token_type=auth_result['token_type'],
                component="integrations.external_apis"
            )
            
            return auth_result
            
        except Exception as e:
            logger.error(
                "api_authentication_failed",
                service_name=self.service_name,
                error=str(e),
                component="integrations.external_apis",
                exc_info=e
            )
            raise IntegrationError(
                message=f"Authentication failed for {self.service_name}: {str(e)}",
                service_name=self.service_name,
                operation="authenticate",
                error_context={'credentials_type': list(credentials.keys())}
            ) from e
    
    def validate_response(self, response: Any) -> bool:
        """
        Validate external API response format and content.
        
        Args:
            response: Response object from external service
            
        Returns:
            True if response is valid, False otherwise
        """
        try:
            # Check HTTP status code
            if not hasattr(response, 'status_code'):
                return False
            
            if response.status_code < 200 or response.status_code >= 400:
                return False
            
            # Check content type for JSON APIs
            content_type = response.headers.get('content-type', '')
            if 'application/json' in content_type:
                try:
                    response.json()
                except (ValueError, json.JSONDecodeError):
                    return False
            
            # Check for required headers
            required_headers = ['content-length', 'date']
            for header in required_headers:
                if header not in response.headers:
                    logger.warning(
                        "response_missing_required_header",
                        service_name=self.service_name,
                        header=header,
                        component="integrations.external_apis"
                    )
            
            return True
            
        except Exception as e:
            logger.error(
                "response_validation_error",
                service_name=self.service_name,
                error=str(e),
                component="integrations.external_apis"
            )
            return False
    
    def get_service_endpoints(self) -> List[str]:
        """
        Get list of available service endpoints.
        
        Returns:
            List of endpoint paths for the external service
        """
        try:
            # Try to get endpoints from API discovery
            response = self.get('/endpoints')
            if response.status_code == 200:
                endpoints_data = response.json()
                return endpoints_data.get('endpoints', [])
                
        except Exception as e:
            logger.warning(
                "endpoints_discovery_failed",
                service_name=self.service_name,
                error=str(e),
                component="integrations.external_apis"
            )
        
        # Return common endpoints as fallback
        return [
            '/health',
            '/version',
            '/status',
            '/endpoints'
        ]
    
    def paginated_request(
        self,
        endpoint: str,
        method: str = 'GET',
        page_size: int = 100,
        max_pages: Optional[int] = None,
        **kwargs
    ) -> Iterator[Dict[str, Any]]:
        """
        Handle paginated API requests with automatic page iteration.
        
        Args:
            endpoint: API endpoint path
            method: HTTP method
            page_size: Number of items per page
            max_pages: Maximum number of pages to fetch
            **kwargs: Additional request parameters
            
        Yields:
            Individual items from paginated response
        """
        page = 1
        pages_fetched = 0
        
        while True:
            # Add pagination parameters
            params = kwargs.get('params', {})
            params.update({
                'page': page,
                'limit': page_size
            })
            kwargs['params'] = params
            
            try:
                response = self.make_request(method, endpoint, **kwargs)
                
                if not self.validate_response(response):
                    logger.error(
                        "paginated_request_invalid_response",
                        service_name=self.service_name,
                        endpoint=endpoint,
                        page=page,
                        status_code=response.status_code,
                        component="integrations.external_apis"
                    )
                    break
                
                data = response.json()
                items = data.get('items', data.get('data', []))
                
                # Yield individual items
                for item in items:
                    yield item
                
                # Check if there are more pages
                has_more = data.get('has_more', False)
                total_pages = data.get('total_pages')
                
                if not has_more or (total_pages and page >= total_pages):
                    break
                
                pages_fetched += 1
                if max_pages and pages_fetched >= max_pages:
                    break
                
                page += 1
                
            except Exception as e:
                logger.error(
                    "paginated_request_failed",
                    service_name=self.service_name,
                    endpoint=endpoint,
                    page=page,
                    error=str(e),
                    component="integrations.external_apis",
                    exc_info=e
                )
                break
    
    async def paginated_request_async(
        self,
        endpoint: str,
        method: str = 'GET',
        page_size: int = 100,
        max_pages: Optional[int] = None,
        **kwargs
    ) -> AsyncIterator[Dict[str, Any]]:
        """
        Handle paginated API requests asynchronously with automatic page iteration.
        
        Args:
            endpoint: API endpoint path
            method: HTTP method
            page_size: Number of items per page
            max_pages: Maximum number of pages to fetch
            **kwargs: Additional request parameters
            
        Yields:
            Individual items from paginated response
        """
        page = 1
        pages_fetched = 0
        
        while True:
            # Add pagination parameters
            params = kwargs.get('params', {})
            params.update({
                'page': page,
                'limit': page_size
            })
            kwargs['params'] = params
            
            try:
                response = await self.make_request_async(method, endpoint, **kwargs)
                
                if not self.validate_response(response):
                    logger.error(
                        "async_paginated_request_invalid_response",
                        service_name=self.service_name,
                        endpoint=endpoint,
                        page=page,
                        status_code=response.status_code,
                        component="integrations.external_apis"
                    )
                    break
                
                data = response.json()
                items = data.get('items', data.get('data', []))
                
                # Yield individual items
                for item in items:
                    yield item
                
                # Check if there are more pages
                has_more = data.get('has_more', False)
                total_pages = data.get('total_pages')
                
                if not has_more or (total_pages and page >= total_pages):
                    break
                
                pages_fetched += 1
                if max_pages and pages_fetched >= max_pages:
                    break
                
                page += 1
                
            except Exception as e:
                logger.error(
                    "async_paginated_request_failed",
                    service_name=self.service_name,
                    endpoint=endpoint,
                    page=page,
                    error=str(e),
                    component="integrations.external_apis",
                    exc_info=e
                )
                break


class WebhookHandler:
    """
    Generic webhook handler for external service callbacks with comprehensive validation.
    
    Implements secure webhook processing with signature verification, payload validation,
    and event routing. Supports multiple signature algorithms and provides enterprise-grade
    security patterns for webhook endpoint protection.
    
    Aligned with Section 6.3.3 external service integration requirements.
    """
    
    def __init__(
        self,
        service_name: str,
        secret_key: str,
        signature_header: str = 'X-Signature',
        signature_algorithm: str = 'sha256',
        timestamp_header: str = 'X-Timestamp',
        timestamp_tolerance: int = 300,  # 5 minutes
        payload_size_limit: int = 1024 * 1024  # 1MB
    ):
        """
        Initialize webhook handler with security configuration.
        
        Args:
            service_name: Service identifier for monitoring
            secret_key: Secret key for signature verification
            signature_header: Header containing webhook signature
            signature_algorithm: Algorithm for signature computation (sha256, sha1, md5)
            timestamp_header: Header containing timestamp for replay protection
            timestamp_tolerance: Maximum age of webhook in seconds
            payload_size_limit: Maximum payload size in bytes
        """
        self.service_name = service_name
        self.secret_key = secret_key.encode('utf-8')
        self.signature_header = signature_header
        self.signature_algorithm = signature_algorithm
        self.timestamp_header = timestamp_header
        self.timestamp_tolerance = timestamp_tolerance
        self.payload_size_limit = payload_size_limit
        
        # Initialize monitoring
        external_service_monitor.register_service(
            service_name=f"{service_name}_webhook",
            service_type=ServiceType.WEBHOOK,
            endpoint_url="webhook_handler",
            metadata={
                'signature_algorithm': signature_algorithm,
                'timestamp_tolerance': timestamp_tolerance,
                'payload_size_limit': payload_size_limit
            }
        )
        
        logger.info(
            "webhook_handler_initialized",
            service_name=service_name,
            signature_algorithm=signature_algorithm,
            timestamp_tolerance=timestamp_tolerance,
            payload_size_limit=payload_size_limit,
            component="integrations.external_apis"
        )
    
    def verify_signature(self, payload: bytes, signature: str, timestamp: Optional[str] = None) -> bool:
        """
        Verify webhook signature using HMAC.
        
        Args:
            payload: Raw webhook payload
            signature: Signature from webhook headers
            timestamp: Optional timestamp for replay protection
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Check timestamp if provided
            if timestamp and self.timestamp_tolerance > 0:
                try:
                    webhook_time = int(timestamp)
                    current_time = int(time.time())
                    
                    if abs(current_time - webhook_time) > self.timestamp_tolerance:
                        logger.warning(
                            "webhook_timestamp_expired",
                            service_name=self.service_name,
                            webhook_time=webhook_time,
                            current_time=current_time,
                            tolerance=self.timestamp_tolerance,
                            component="integrations.external_apis"
                        )
                        return False
                        
                except (ValueError, TypeError):
                    logger.warning(
                        "webhook_invalid_timestamp",
                        service_name=self.service_name,
                        timestamp=timestamp,
                        component="integrations.external_apis"
                    )
                    return False
            
            # Compute expected signature
            if self.signature_algorithm == 'sha256':
                expected_signature = hmac.new(
                    self.secret_key,
                    payload,
                    hashlib.sha256
                ).hexdigest()
            elif self.signature_algorithm == 'sha1':
                expected_signature = hmac.new(
                    self.secret_key,
                    payload,
                    hashlib.sha1
                ).hexdigest()
            elif self.signature_algorithm == 'md5':
                expected_signature = hmac.new(
                    self.secret_key,
                    payload,
                    hashlib.md5
                ).hexdigest()
            else:
                logger.error(
                    "webhook_unsupported_signature_algorithm",
                    service_name=self.service_name,
                    algorithm=self.signature_algorithm,
                    component="integrations.external_apis"
                )
                return False
            
            # Remove algorithm prefix if present (e.g., "sha256=...")
            if '=' in signature:
                algorithm_prefix, signature_value = signature.split('=', 1)
                signature = signature_value
            
            # Constant-time comparison to prevent timing attacks
            return hmac.compare_digest(expected_signature, signature)
            
        except Exception as e:
            logger.error(
                "webhook_signature_verification_failed",
                service_name=self.service_name,
                error=str(e),
                component="integrations.external_apis",
                exc_info=e
            )
            return False
    
    @track_external_service_call(
        service_name="webhook_handler",
        service_type=ServiceType.WEBHOOK
    )
    def process_webhook(
        self,
        request: Request,
        event_handlers: Dict[str, Callable]
    ) -> Response:
        """
        Process incoming webhook with comprehensive validation and event routing.
        
        Args:
            request: Flask request object
            event_handlers: Dictionary mapping event types to handler functions
            
        Returns:
            Flask response object
        """
        start_time = time.time()
        
        try:
            # Check payload size
            content_length = request.content_length or 0
            if content_length > self.payload_size_limit:
                logger.warning(
                    "webhook_payload_too_large",
                    service_name=self.service_name,
                    content_length=content_length,
                    limit=self.payload_size_limit,
                    component="integrations.external_apis"
                )
                return jsonify({'error': 'Payload too large'}), 413
            
            # Get payload and headers
            payload = request.get_data()
            signature = request.headers.get(self.signature_header)
            timestamp = request.headers.get(self.timestamp_header)
            
            if not signature:
                logger.warning(
                    "webhook_missing_signature",
                    service_name=self.service_name,
                    headers=dict(request.headers),
                    component="integrations.external_apis"
                )
                return jsonify({'error': 'Missing signature'}), 400
            
            # Verify signature
            if not self.verify_signature(payload, signature, timestamp):
                logger.warning(
                    "webhook_invalid_signature",
                    service_name=self.service_name,
                    signature_header=self.signature_header,
                    component="integrations.external_apis"
                )
                return jsonify({'error': 'Invalid signature'}), 401
            
            # Parse JSON payload
            try:
                webhook_data = json.loads(payload.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                logger.warning(
                    "webhook_invalid_json",
                    service_name=self.service_name,
                    error=str(e),
                    component="integrations.external_apis"
                )
                return jsonify({'error': 'Invalid JSON payload'}), 400
            
            # Extract event type
            event_type = webhook_data.get('type') or webhook_data.get('event_type')
            if not event_type:
                logger.warning(
                    "webhook_missing_event_type",
                    service_name=self.service_name,
                    payload_keys=list(webhook_data.keys()),
                    component="integrations.external_apis"
                )
                return jsonify({'error': 'Missing event type'}), 400
            
            # Route to appropriate handler
            handler = event_handlers.get(event_type)
            if not handler:
                logger.warning(
                    "webhook_unhandled_event_type",
                    service_name=self.service_name,
                    event_type=event_type,
                    available_handlers=list(event_handlers.keys()),
                    component="integrations.external_apis"
                )
                return jsonify({'error': f'Unhandled event type: {event_type}'}), 400
            
            # Process event
            try:
                result = handler(webhook_data)
                
                duration = time.time() - start_time
                logger.info(
                    "webhook_processed_successfully",
                    service_name=self.service_name,
                    event_type=event_type,
                    duration_ms=round(duration * 1000, 2),
                    component="integrations.external_apis"
                )
                
                # Update monitoring
                update_service_health(
                    service_name=f"{self.service_name}_webhook",
                    service_type=ServiceType.WEBHOOK,
                    status=HealthStatus.HEALTHY,
                    duration=duration
                )
                
                if isinstance(result, Response):
                    return result
                else:
                    return jsonify({'status': 'success', 'result': result}), 200
                    
            except Exception as e:
                logger.error(
                    "webhook_handler_failed",
                    service_name=self.service_name,
                    event_type=event_type,
                    error=str(e),
                    component="integrations.external_apis",
                    exc_info=e
                )
                
                # Update monitoring
                update_service_health(
                    service_name=f"{self.service_name}_webhook",
                    service_type=ServiceType.WEBHOOK,
                    status=HealthStatus.UNHEALTHY,
                    duration=time.time() - start_time
                )
                
                return jsonify({'error': 'Handler failed'}), 500
                
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                "webhook_processing_failed",
                service_name=self.service_name,
                error=str(e),
                duration_ms=round(duration * 1000, 2),
                component="integrations.external_apis",
                exc_info=e
            )
            
            # Update monitoring
            update_service_health(
                service_name=f"{self.service_name}_webhook",
                service_type=ServiceType.WEBHOOK,
                status=HealthStatus.UNHEALTHY,
                duration=duration
            )
            
            return jsonify({'error': 'Processing failed'}), 500


class FileProcessingIntegration:
    """
    File processing integration for external services with streaming support.
    
    Implements enterprise-grade file processing patterns with streaming upload/download,
    progress tracking, and comprehensive error handling. Supports multiple file formats
    and provides integration with external file processing services.
    
    Aligned with Section 6.3.2 stream processing requirements.
    """
    
    def __init__(
        self,
        service_name: str,
        api_client: GenericAPIClient,
        chunk_size: int = 8192,
        max_file_size: int = 100 * 1024 * 1024,  # 100MB
        allowed_extensions: Optional[List[str]] = None,
        temp_directory: str = '/tmp'
    ):
        """
        Initialize file processing integration.
        
        Args:
            service_name: Service identifier for monitoring
            api_client: Configured API client for service communication
            chunk_size: Chunk size for streaming operations
            max_file_size: Maximum file size in bytes
            allowed_extensions: List of allowed file extensions
            temp_directory: Temporary directory for file processing
        """
        self.service_name = service_name
        self.api_client = api_client
        self.chunk_size = chunk_size
        self.max_file_size = max_file_size
        self.allowed_extensions = allowed_extensions or []
        self.temp_directory = temp_directory
        
        # Initialize monitoring
        external_service_monitor.register_service(
            service_name=f"{service_name}_files",
            service_type=ServiceType.FILE_STORAGE,
            endpoint_url=api_client.base_url,
            metadata={
                'chunk_size': chunk_size,
                'max_file_size': max_file_size,
                'allowed_extensions': allowed_extensions
            }
        )
        
        logger.info(
            "file_processing_integration_initialized",
            service_name=service_name,
            chunk_size=chunk_size,
            max_file_size=max_file_size,
            allowed_extensions=allowed_extensions,
            component="integrations.external_apis"
        )
    
    def validate_file(self, file_path: str, file_size: int) -> bool:
        """
        Validate file before processing.
        
        Args:
            file_path: Path to file
            file_size: File size in bytes
            
        Returns:
            True if file is valid, False otherwise
        """
        try:
            # Check file size
            if file_size > self.max_file_size:
                logger.warning(
                    "file_too_large",
                    service_name=self.service_name,
                    file_path=file_path,
                    file_size=file_size,
                    max_size=self.max_file_size,
                    component="integrations.external_apis"
                )
                return False
            
            # Check file extension if restrictions are configured
            if self.allowed_extensions:
                file_extension = file_path.split('.')[-1].lower()
                if file_extension not in self.allowed_extensions:
                    logger.warning(
                        "file_extension_not_allowed",
                        service_name=self.service_name,
                        file_path=file_path,
                        extension=file_extension,
                        allowed_extensions=self.allowed_extensions,
                        component="integrations.external_apis"
                    )
                    return False
            
            return True
            
        except Exception as e:
            logger.error(
                "file_validation_failed",
                service_name=self.service_name,
                file_path=file_path,
                error=str(e),
                component="integrations.external_apis",
                exc_info=e
            )
            return False
    
    @track_external_service_call(
        service_name="file_processing",
        service_type=ServiceType.FILE_STORAGE
    )
    def upload_file(
        self,
        file_path: str,
        file_data: bytes,
        metadata: Optional[Dict[str, Any]] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> Dict[str, Any]:
        """
        Upload file to external service with streaming support.
        
        Args:
            file_path: Target file path in external service
            file_data: File content as bytes
            metadata: Optional file metadata
            progress_callback: Optional progress callback function
            
        Returns:
            Upload result with file ID and metadata
        """
        start_time = time.time()
        file_size = len(file_data)
        
        try:
            # Validate file
            if not self.validate_file(file_path, file_size):
                raise FileProcessingError(
                    message=f"File validation failed: {file_path}",
                    operation="upload_file",
                    file_path=file_path,
                    file_size=file_size,
                    processing_stage="validation"
                )
            
            # Prepare multipart upload
            files = {
                'file': (file_path, file_data, 'application/octet-stream')
            }
            
            data = {
                'path': file_path,
                'metadata': json.dumps(metadata or {})
            }
            
            # Upload with progress tracking
            uploaded_bytes = 0
            
            def upload_progress_wrapper(monitor):
                nonlocal uploaded_bytes
                uploaded_bytes = monitor.bytes_read
                if progress_callback:
                    progress_callback(uploaded_bytes, file_size)
            
            response = self.api_client.post(
                '/files/upload',
                files=files,
                data=data,
                timeout=(30, 300)  # 30s connect, 5min read timeout
            )
            
            if not self.api_client.validate_response(response):
                raise FileProcessingError(
                    message=f"Upload failed with status {response.status_code}",
                    operation="upload_file",
                    file_path=file_path,
                    file_size=file_size,
                    processing_stage="upload",
                    error_code=response.status_code
                )
            
            result = response.json()
            duration = time.time() - start_time
            
            logger.info(
                "file_upload_completed",
                service_name=self.service_name,
                file_path=file_path,
                file_size=file_size,
                file_id=result.get('file_id'),
                duration_ms=round(duration * 1000, 2),
                component="integrations.external_apis"
            )
            
            # Update monitoring
            update_service_health(
                service_name=f"{self.service_name}_files",
                service_type=ServiceType.FILE_STORAGE,
                status=HealthStatus.HEALTHY,
                duration=duration,
                metadata={'operation': 'upload', 'file_size': file_size}
            )
            
            return result
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                "file_upload_failed",
                service_name=self.service_name,
                file_path=file_path,
                file_size=file_size,
                error=str(e),
                duration_ms=round(duration * 1000, 2),
                component="integrations.external_apis",
                exc_info=e
            )
            
            # Update monitoring
            update_service_health(
                service_name=f"{self.service_name}_files",
                service_type=ServiceType.FILE_STORAGE,
                status=HealthStatus.UNHEALTHY,
                duration=duration,
                metadata={'operation': 'upload', 'error': str(e)}
            )
            
            if isinstance(e, FileProcessingError):
                raise
            else:
                raise FileProcessingError(
                    message=f"File upload failed: {str(e)}",
                    operation="upload_file",
                    file_path=file_path,
                    file_size=file_size,
                    processing_stage="upload"
                ) from e
    
    @track_external_service_call(
        service_name="file_processing",
        service_type=ServiceType.FILE_STORAGE
    )
    def download_file(
        self,
        file_id: str,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> bytes:
        """
        Download file from external service with streaming support.
        
        Args:
            file_id: File identifier in external service
            progress_callback: Optional progress callback function
            
        Returns:
            File content as bytes
        """
        start_time = time.time()
        
        try:
            response = self.api_client.get(
                f'/files/{file_id}/download',
                stream=True,
                timeout=(30, 300)  # 30s connect, 5min read timeout
            )
            
            if not self.api_client.validate_response(response):
                raise FileProcessingError(
                    message=f"Download failed with status {response.status_code}",
                    operation="download_file",
                    processing_stage="download",
                    error_code=response.status_code,
                    error_context={'file_id': file_id}
                )
            
            # Get file size from headers
            content_length = response.headers.get('content-length')
            total_size = int(content_length) if content_length else 0
            
            # Stream download with progress tracking
            downloaded_data = b''
            downloaded_bytes = 0
            
            for chunk in response.iter_content(chunk_size=self.chunk_size):
                if chunk:
                    downloaded_data += chunk
                    downloaded_bytes += len(chunk)
                    
                    if progress_callback and total_size > 0:
                        progress_callback(downloaded_bytes, total_size)
            
            duration = time.time() - start_time
            
            logger.info(
                "file_download_completed",
                service_name=self.service_name,
                file_id=file_id,
                file_size=len(downloaded_data),
                duration_ms=round(duration * 1000, 2),
                component="integrations.external_apis"
            )
            
            # Update monitoring
            update_service_health(
                service_name=f"{self.service_name}_files",
                service_type=ServiceType.FILE_STORAGE,
                status=HealthStatus.HEALTHY,
                duration=duration,
                metadata={'operation': 'download', 'file_size': len(downloaded_data)}
            )
            
            return downloaded_data
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                "file_download_failed",
                service_name=self.service_name,
                file_id=file_id,
                error=str(e),
                duration_ms=round(duration * 1000, 2),
                component="integrations.external_apis",
                exc_info=e
            )
            
            # Update monitoring
            update_service_health(
                service_name=f"{self.service_name}_files",
                service_type=ServiceType.FILE_STORAGE,
                status=HealthStatus.UNHEALTHY,
                duration=duration,
                metadata={'operation': 'download', 'error': str(e)}
            )
            
            if isinstance(e, FileProcessingError):
                raise
            else:
                raise FileProcessingError(
                    message=f"File download failed: {str(e)}",
                    operation="download_file",
                    processing_stage="download",
                    error_context={'file_id': file_id}
                ) from e
    
    async def upload_file_async(
        self,
        file_path: str,
        file_data: bytes,
        metadata: Optional[Dict[str, Any]] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> Dict[str, Any]:
        """
        Upload file to external service asynchronously with streaming support.
        
        Args:
            file_path: Target file path in external service
            file_data: File content as bytes
            metadata: Optional file metadata
            progress_callback: Optional progress callback function
            
        Returns:
            Upload result with file ID and metadata
        """
        start_time = time.time()
        file_size = len(file_data)
        
        try:
            # Validate file
            if not self.validate_file(file_path, file_size):
                raise FileProcessingError(
                    message=f"File validation failed: {file_path}",
                    operation="upload_file_async",
                    file_path=file_path,
                    file_size=file_size,
                    processing_stage="validation"
                )
            
            # Prepare multipart upload
            files = {
                'file': (file_path, file_data, 'application/octet-stream')
            }
            
            data = {
                'path': file_path,
                'metadata': json.dumps(metadata or {})
            }
            
            response = await self.api_client.post_async(
                '/files/upload',
                files=files,
                data=data,
                timeout=(30, 300)  # 30s connect, 5min read timeout
            )
            
            if not self.api_client.validate_response(response):
                raise FileProcessingError(
                    message=f"Async upload failed with status {response.status_code}",
                    operation="upload_file_async",
                    file_path=file_path,
                    file_size=file_size,
                    processing_stage="upload",
                    error_code=response.status_code
                )
            
            result = response.json()
            duration = time.time() - start_time
            
            logger.info(
                "async_file_upload_completed",
                service_name=self.service_name,
                file_path=file_path,
                file_size=file_size,
                file_id=result.get('file_id'),
                duration_ms=round(duration * 1000, 2),
                component="integrations.external_apis"
            )
            
            return result
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                "async_file_upload_failed",
                service_name=self.service_name,
                file_path=file_path,
                file_size=file_size,
                error=str(e),
                duration_ms=round(duration * 1000, 2),
                component="integrations.external_apis",
                exc_info=e
            )
            
            if isinstance(e, FileProcessingError):
                raise
            else:
                raise FileProcessingError(
                    message=f"Async file upload failed: {str(e)}",
                    operation="upload_file_async",
                    file_path=file_path,
                    file_size=file_size,
                    processing_stage="upload"
                ) from e


class EnterpriseServiceWrapper:
    """
    Enterprise service wrapper maintaining existing API contracts.
    
    Provides standardized interface for enterprise service integration with
    comprehensive error handling, monitoring, and contract preservation.
    Implements patterns required by Section 0.1.4 for maintaining API contracts.
    """
    
    def __init__(
        self,
        service_name: str,
        service_config: Dict[str, Any],
        contract_version: str = "1.0"
    ):
        """
        Initialize enterprise service wrapper.
        
        Args:
            service_name: Enterprise service identifier
            service_config: Service configuration including endpoints and auth
            contract_version: API contract version for compatibility tracking
        """
        self.service_name = service_name
        self.service_config = service_config
        self.contract_version = contract_version
        
        # Initialize API client
        self.api_client = GenericAPIClient(
            service_name=service_name,
            base_url=service_config['base_url'],
            api_key=service_config.get('api_key'),
            api_version=contract_version,
            timeout=service_config.get('timeout', 30),
            **service_config.get('client_config', {})
        )
        
        # Initialize webhook handler if configured
        self.webhook_handler = None
        if 'webhook_config' in service_config:
            webhook_config = service_config['webhook_config']
            self.webhook_handler = WebhookHandler(
                service_name=service_name,
                secret_key=webhook_config['secret_key'],
                signature_header=webhook_config.get('signature_header', 'X-Signature'),
                signature_algorithm=webhook_config.get('signature_algorithm', 'sha256')
            )
        
        # Initialize file processing if configured
        self.file_processor = None
        if 'file_processing_config' in service_config:
            file_config = service_config['file_processing_config']
            self.file_processor = FileProcessingIntegration(
                service_name=service_name,
                api_client=self.api_client,
                **file_config
            )
        
        logger.info(
            "enterprise_service_wrapper_initialized",
            service_name=service_name,
            contract_version=contract_version,
            has_webhook_handler=bool(self.webhook_handler),
            has_file_processor=bool(self.file_processor),
            component="integrations.external_apis"
        )
    
    def get_service_info(self) -> Dict[str, Any]:
        """
        Get comprehensive service information.
        
        Returns:
            Service information including status and capabilities
        """
        try:
            # Get basic service status
            health_result = self.api_client.health_check()
            
            # Get available endpoints
            endpoints = self.api_client.get_service_endpoints()
            
            # Compile service information
            service_info = {
                'service_name': self.service_name,
                'contract_version': self.contract_version,
                'base_url': self.api_client.base_url,
                'health_status': health_result,
                'available_endpoints': endpoints,
                'capabilities': {
                    'webhook_support': bool(self.webhook_handler),
                    'file_processing': bool(self.file_processor),
                    'pagination_support': True,
                    'async_support': True
                },
                'last_updated': datetime.utcnow().isoformat()
            }
            
            return service_info
            
        except Exception as e:
            logger.error(
                "service_info_retrieval_failed",
                service_name=self.service_name,
                error=str(e),
                component="integrations.external_apis",
                exc_info=e
            )
            
            return {
                'service_name': self.service_name,
                'contract_version': self.contract_version,
                'error': str(e),
                'last_updated': datetime.utcnow().isoformat()
            }
    
    async def get_service_info_async(self) -> Dict[str, Any]:
        """
        Get comprehensive service information asynchronously.
        
        Returns:
            Service information including status and capabilities
        """
        try:
            # Get basic service status
            health_result = await self.api_client.health_check_async()
            
            # Get available endpoints
            endpoints = self.api_client.get_service_endpoints()
            
            # Compile service information
            service_info = {
                'service_name': self.service_name,
                'contract_version': self.contract_version,
                'base_url': self.api_client.base_url,
                'health_status': health_result,
                'available_endpoints': endpoints,
                'capabilities': {
                    'webhook_support': bool(self.webhook_handler),
                    'file_processing': bool(self.file_processor),
                    'pagination_support': True,
                    'async_support': True
                },
                'last_updated': datetime.utcnow().isoformat()
            }
            
            return service_info
            
        except Exception as e:
            logger.error(
                "async_service_info_retrieval_failed",
                service_name=self.service_name,
                error=str(e),
                component="integrations.external_apis",
                exc_info=e
            )
            
            return {
                'service_name': self.service_name,
                'contract_version': self.contract_version,
                'error': str(e),
                'last_updated': datetime.utcnow().isoformat()
            }


# Factory functions for common service types

def create_analytics_service_client(
    service_name: str,
    base_url: str,
    api_key: str,
    **kwargs
) -> GenericAPIClient:
    """
    Factory function for creating analytics service clients.
    
    Args:
        service_name: Service identifier
        base_url: Analytics service base URL
        api_key: API key for authentication
        **kwargs: Additional configuration parameters
        
    Returns:
        Configured GenericAPIClient for analytics services
    """
    return GenericAPIClient(
        service_name=service_name,
        base_url=base_url,
        api_key=api_key,
        timeout=(10, 60),  # Analytics may need longer read timeout
        **kwargs
    )


def create_notification_service_client(
    service_name: str,
    base_url: str,
    api_key: str,
    **kwargs
) -> GenericAPIClient:
    """
    Factory function for creating notification service clients.
    
    Args:
        service_name: Service identifier
        base_url: Notification service base URL
        api_key: API key for authentication
        **kwargs: Additional configuration parameters
        
    Returns:
        Configured GenericAPIClient for notification services
    """
    return GenericAPIClient(
        service_name=service_name,
        base_url=base_url,
        api_key=api_key,
        timeout=(5, 30),  # Notifications should be fast
        **kwargs
    )


def create_document_processing_service(
    service_name: str,
    base_url: str,
    api_key: str,
    **kwargs
) -> EnterpriseServiceWrapper:
    """
    Factory function for creating document processing service wrappers.
    
    Args:
        service_name: Service identifier
        base_url: Document processing service base URL
        api_key: API key for authentication
        **kwargs: Additional configuration parameters
        
    Returns:
        Configured EnterpriseServiceWrapper for document processing
    """
    service_config = {
        'base_url': base_url,
        'api_key': api_key,
        'timeout': 120,  # Document processing may be slow
        'file_processing_config': {
            'chunk_size': 16384,  # 16KB chunks for documents
            'max_file_size': 50 * 1024 * 1024,  # 50MB for documents
            'allowed_extensions': ['pdf', 'doc', 'docx', 'txt', 'rtf']
        }
    }
    service_config.update(kwargs)
    
    return EnterpriseServiceWrapper(
        service_name=service_name,
        service_config=service_config,
        contract_version="1.0"
    )


# Real-world service integration examples

class SlackIntegration(GenericAPIClient):
    """
    Slack API integration example implementing enterprise messaging capabilities.
    
    Demonstrates real-world third-party API integration patterns with webhook
    support and comprehensive error handling.
    """
    
    def __init__(self, bot_token: str, **kwargs):
        """Initialize Slack integration with bot token."""
        super().__init__(
            service_name="slack",
            base_url="https://slack.com/api",
            api_key=bot_token,
            timeout=(10, 30),
            **kwargs
        )
        
        # Configure Slack-specific headers
        self.config.default_headers.update({
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {bot_token}'
        })
    
    def send_message(self, channel: str, text: str, **kwargs) -> Dict[str, Any]:
        """
        Send message to Slack channel.
        
        Args:
            channel: Channel ID or name
            text: Message text
            **kwargs: Additional message parameters
            
        Returns:
            Slack API response
        """
        payload = {
            'channel': channel,
            'text': text,
            **kwargs
        }
        
        response = self.post('/chat.postMessage', json_data=payload)
        return response.json()
    
    def get_service_endpoints(self) -> List[str]:
        """Get Slack API endpoints."""
        return [
            '/api.test',
            '/auth.test',
            '/chat.postMessage',
            '/channels.list',
            '/users.list'
        ]


class SendGridIntegration(GenericAPIClient):
    """
    SendGrid email service integration example.
    
    Demonstrates email service integration with comprehensive error handling
    and monitoring capabilities.
    """
    
    def __init__(self, api_key: str, **kwargs):
        """Initialize SendGrid integration with API key."""
        super().__init__(
            service_name="sendgrid",
            base_url="https://api.sendgrid.com/v3",
            api_key=api_key,
            timeout=(10, 30),
            **kwargs
        )
        
        # Configure SendGrid-specific headers
        self.config.default_headers.update({
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {api_key}'
        })
    
    def send_email(
        self,
        to_email: str,
        from_email: str,
        subject: str,
        content: str,
        content_type: str = 'text/plain'
    ) -> Dict[str, Any]:
        """
        Send email via SendGrid.
        
        Args:
            to_email: Recipient email address
            from_email: Sender email address
            subject: Email subject
            content: Email content
            content_type: Content type (text/plain or text/html)
            
        Returns:
            SendGrid API response
        """
        payload = {
            'personalizations': [{
                'to': [{'email': to_email}]
            }],
            'from': {'email': from_email},
            'subject': subject,
            'content': [{
                'type': content_type,
                'value': content
            }]
        }
        
        response = self.post('/mail/send', json_data=payload)
        return {'message_id': response.headers.get('X-Message-Id'), 'status': 'sent'}
    
    def get_service_endpoints(self) -> List[str]:
        """Get SendGrid API endpoints."""
        return [
            '/mail/send',
            '/templates',
            '/suppression/bounces',
            '/stats'
        ]


# Global service registry for managing multiple external services
class ExternalServiceRegistry:
    """
    Global registry for managing multiple external service integrations.
    
    Provides centralized management of external services with health monitoring,
    configuration management, and unified access patterns.
    """
    
    def __init__(self):
        """Initialize the service registry."""
        self._services: Dict[str, Union[GenericAPIClient, EnterpriseServiceWrapper]] = {}
        self._configurations: Dict[str, Dict[str, Any]] = {}
        
        logger.info(
            "external_service_registry_initialized",
            component="integrations.external_apis"
        )
    
    def register_service(
        self,
        service_name: str,
        service_instance: Union[GenericAPIClient, EnterpriseServiceWrapper],
        configuration: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Register external service in the registry.
        
        Args:
            service_name: Unique service identifier
            service_instance: Configured service instance
            configuration: Optional service configuration
        """
        self._services[service_name] = service_instance
        self._configurations[service_name] = configuration or {}
        
        logger.info(
            "service_registered",
            service_name=service_name,
            service_type=type(service_instance).__name__,
            component="integrations.external_apis"
        )
    
    def get_service(self, service_name: str) -> Optional[Union[GenericAPIClient, EnterpriseServiceWrapper]]:
        """
        Get registered service by name.
        
        Args:
            service_name: Service identifier
            
        Returns:
            Service instance or None if not found
        """
        return self._services.get(service_name)
    
    def get_all_services(self) -> Dict[str, Union[GenericAPIClient, EnterpriseServiceWrapper]]:
        """
        Get all registered services.
        
        Returns:
            Dictionary of all registered services
        """
        return dict(self._services)
    
    def health_check_all(self) -> Dict[str, Dict[str, Any]]:
        """
        Perform health check on all registered services.
        
        Returns:
            Health check results for all services
        """
        health_results = {}
        
        for service_name, service_instance in self._services.items():
            try:
                if isinstance(service_instance, GenericAPIClient):
                    health_result = service_instance.health_check()
                elif isinstance(service_instance, EnterpriseServiceWrapper):
                    health_result = service_instance.get_service_info()
                else:
                    health_result = {'status': 'unknown', 'error': 'Unsupported service type'}
                
                health_results[service_name] = health_result
                
            except Exception as e:
                logger.error(
                    "service_health_check_failed",
                    service_name=service_name,
                    error=str(e),
                    component="integrations.external_apis",
                    exc_info=e
                )
                
                health_results[service_name] = {
                    'status': 'unhealthy',
                    'error': str(e),
                    'timestamp': datetime.utcnow().isoformat()
                }
        
        return health_results
    
    async def health_check_all_async(self) -> Dict[str, Dict[str, Any]]:
        """
        Perform asynchronous health check on all registered services.
        
        Returns:
            Health check results for all services
        """
        health_results = {}
        
        # Create tasks for all health checks
        health_check_tasks = []
        service_names = []
        
        for service_name, service_instance in self._services.items():
            service_names.append(service_name)
            
            if isinstance(service_instance, GenericAPIClient):
                task = service_instance.health_check_async()
            elif isinstance(service_instance, EnterpriseServiceWrapper):
                task = service_instance.get_service_info_async()
            else:
                # Create a simple coroutine for unsupported types
                async def unsupported_health_check():
                    return {'status': 'unknown', 'error': 'Unsupported service type'}
                task = unsupported_health_check()
            
            health_check_tasks.append(task)
        
        # Execute all health checks concurrently
        try:
            results = await asyncio.gather(*health_check_tasks, return_exceptions=True)
            
            for service_name, result in zip(service_names, results):
                if isinstance(result, Exception):
                    logger.error(
                        "async_service_health_check_failed",
                        service_name=service_name,
                        error=str(result),
                        component="integrations.external_apis",
                        exc_info=result
                    )
                    
                    health_results[service_name] = {
                        'status': 'unhealthy',
                        'error': str(result),
                        'timestamp': datetime.utcnow().isoformat()
                    }
                else:
                    health_results[service_name] = result
                    
        except Exception as e:
            logger.error(
                "async_health_check_batch_failed",
                error=str(e),
                component="integrations.external_apis",
                exc_info=e
            )
        
        return health_results


# Global service registry instance
external_service_registry = ExternalServiceRegistry()


# Export public interface
__all__ = [
    # Main classes
    'GenericAPIClient',
    'WebhookHandler',
    'FileProcessingIntegration',
    'EnterpriseServiceWrapper',
    'ExternalServiceRegistry',
    
    # Exception classes
    'WebhookValidationError',
    'FileProcessingError',
    
    # Factory functions
    'create_analytics_service_client',
    'create_notification_service_client',
    'create_document_processing_service',
    
    # Example integrations
    'SlackIntegration',
    'SendGridIntegration',
    
    # Global instances
    'external_service_registry',
    
    # Monitoring functions from dependencies
    'track_external_service_call',
    'ServiceType',
    'HealthStatus',
]


# Module initialization logging
logger.info(
    "external_apis_module_loaded",
    component="integrations.external_apis",
    features=[
        "generic_api_client",
        "webhook_handler",
        "file_processing_integration",
        "enterprise_service_wrapper",
        "service_registry",
        "real_world_integrations"
    ]
)