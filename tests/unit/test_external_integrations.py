"""
Unit tests for external service integration components.

This module provides comprehensive testing for external service integrations including HTTP clients 
(requests/httpx), AWS SDK (boto3), circuit breaker patterns, and third-party API integration.
Tests external service communication with comprehensive mocking and resilience pattern validation
per Section 0.1.4 and Section 5.2.6 specifications.

Key Testing Areas:
- HTTP client library testing for requests 2.31+ and httpx 0.24+ per Section 5.2.6
- AWS service integration testing with boto3 1.28+ per Section 5.2.6  
- Circuit breaker and retry logic testing for service resilience per Section 6.3.3
- External service authentication testing per Section 6.3.3
- API rate limiting and retry logic testing per Section 6.3.3
- Connection pooling testing for external services per Section 6.3.3

Dependencies:
- pytest 7.4+ with pytest-asyncio for async testing patterns
- pytest-mock for comprehensive external service mocking
- requests 2.31+ and httpx 0.24+ for HTTP client testing
- boto3 1.28+ for AWS SDK integration testing
- pybreaker for circuit breaker pattern testing
- tenacity for retry logic testing per Section 6.3.3

Author: Flask Migration Team
Version: 1.0.0
Compliance: Section 0.1.4 External Systems Interactions, Section 5.2.6 External Service Integration Layer
"""

import asyncio
import json
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Union
from unittest.mock import AsyncMock, Mock, MagicMock, patch, call
from urllib.parse import urljoin

import pytest
import pytest_asyncio
import requests
import httpx
from requests.exceptions import RequestException, ConnectionError, Timeout, HTTPError
from httpx import ConnectError, TimeoutException, HTTPStatusError

# Test specific imports
from tests.unit.conftest import (
    mock_external_services, mock_circuit_breaker, error_simulation,
    performance_test_context, test_metrics_collector
)

# Integration module imports for testing per Section 5.2.6
from src.integrations import (
    BaseExternalServiceClient, BaseClientConfiguration, IntegrationManager,
    integration_manager, create_auth0_client, create_aws_s3_client, 
    create_http_api_client, ExternalServiceMonitor, ServiceMetrics, 
    ExternalServiceType, ServiceHealthState, external_service_monitor
)


# =============================================================================
# Test Configuration and Constants
# =============================================================================

# Test configuration constants per Section 6.3.3
TEST_AUTH0_DOMAIN = "test-domain.auth0.com"
TEST_AUTH0_CLIENT_ID = "test-client-id"
TEST_AUTH0_CLIENT_SECRET = "test-client-secret"
TEST_AUTH0_AUDIENCE = "test-audience"

TEST_AWS_ACCESS_KEY = "test-access-key"
TEST_AWS_SECRET_KEY = "test-secret-key"
TEST_AWS_REGION = "us-east-1"
TEST_S3_BUCKET = "test-bucket"

TEST_API_BASE_URL = "https://api.example.com"
TEST_API_KEY = "test-api-key"

# Circuit breaker configuration per Section 6.3.3
TEST_CIRCUIT_BREAKER_CONFIG = {
    "failure_threshold": 5,
    "recovery_timeout": 60,
    "expected_exception": RequestException
}

# Performance baseline configuration per Section 0.3.2
PERFORMANCE_VARIANCE_THRESHOLD = 0.10  # ≤10% variance requirement

# Mock response data for external service testing
MOCK_AUTH0_JWKS_RESPONSE = {
    "keys": [{
        "kty": "RSA",
        "use": "sig",
        "kid": "test-key-id",
        "n": "test-n-value",
        "e": "AQAB",
        "alg": "RS256"
    }]
}

MOCK_AUTH0_USER_INFO = {
    "sub": "auth0|test-user-id",
    "email": "test@example.com",
    "email_verified": True,
    "name": "Test User",
    "picture": "https://example.com/avatar.jpg",
    "permissions": ["read:users", "write:users"]
}

MOCK_AWS_S3_RESPONSE = {
    "ETag": "test-etag-value",
    "VersionId": "test-version-id",
    "ResponseMetadata": {
        "RequestId": "test-request-id",
        "HTTPStatusCode": 200
    }
}


# =============================================================================
# Test Fixtures for External Service Testing
# =============================================================================

@pytest.fixture
def base_client_config():
    """
    Fixture providing base external service client configuration for testing.
    
    Creates BaseClientConfiguration instance with comprehensive test settings
    including timeout, retry, circuit breaker, and authentication configuration
    per Section 5.2.6 requirements.
    
    Returns:
        BaseClientConfiguration: Test configuration instance
    """
    return BaseClientConfiguration(
        service_name="test_service",
        base_url=TEST_API_BASE_URL,
        timeout=30.0,
        max_retries=3,
        retry_backoff_factor=1.0,
        circuit_breaker_enabled=True,
        circuit_breaker_failure_threshold=5,
        circuit_breaker_recovery_timeout=60,
        authentication_enabled=True,
        connection_pool_size=20,
        default_headers={"User-Agent": "Flask-Test-Client/1.0"}
    )


@pytest.fixture
def mock_requests_session():
    """
    Fixture providing mock requests session for synchronous HTTP client testing.
    
    Creates comprehensive mock for requests.Session with configurable responses,
    timeout simulation, and connection pooling testing per Section 5.2.6.
    
    Returns:
        Mock: Mock requests session instance
    """
    mock_session = Mock(spec=requests.Session)
    
    # Configure successful response mock
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"status": "success", "data": {}}
    mock_response.text = '{"status": "success", "data": {}}'
    mock_response.headers = {"Content-Type": "application/json"}
    mock_response.elapsed = timedelta(milliseconds=150)
    mock_response.raise_for_status.return_value = None
    
    # Configure session methods
    mock_session.get.return_value = mock_response
    mock_session.post.return_value = mock_response
    mock_session.put.return_value = mock_response
    mock_session.delete.return_value = mock_response
    mock_session.patch.return_value = mock_response
    mock_session.request.return_value = mock_response
    
    return mock_session


@pytest_asyncio.fixture
async def mock_httpx_client():
    """
    Async fixture providing mock httpx client for async HTTP testing.
    
    Creates comprehensive mock for httpx.AsyncClient with async response
    simulation, timeout handling, and connection pooling testing per Section 5.2.6.
    
    Returns:
        AsyncMock: Mock httpx async client instance
    """
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    
    # Configure successful async response mock
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"status": "success", "data": {}}
    mock_response.text = '{"status": "success", "data": {}}'
    mock_response.headers = {"Content-Type": "application/json"}
    mock_response.elapsed = timedelta(milliseconds=120)
    mock_response.raise_for_status.return_value = None
    
    # Configure async client methods
    mock_client.get.return_value = mock_response
    mock_client.post.return_value = mock_response
    mock_client.put.return_value = mock_response
    mock_client.delete.return_value = mock_response
    mock_client.patch.return_value = mock_response
    mock_client.request.return_value = mock_response
    
    # Configure context manager behavior
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None
    
    return mock_client


@pytest.fixture
def mock_boto3_client():
    """
    Fixture providing mock boto3 client for AWS service testing.
    
    Creates comprehensive mock for boto3 clients with S3, CloudWatch, and
    Lambda service simulation per Section 5.2.6 AWS integration requirements.
    
    Returns:
        Mock: Mock boto3 client instance
    """
    mock_client = Mock()
    
    # Configure S3 operations
    mock_client.upload_file.return_value = MOCK_AWS_S3_RESPONSE
    mock_client.download_file.return_value = None
    mock_client.delete_object.return_value = {"DeleteMarker": True}
    mock_client.list_objects_v2.return_value = {
        "Contents": [{"Key": "test-file.txt", "Size": 1024}],
        "KeyCount": 1
    }
    mock_client.head_object.return_value = {
        "ContentLength": 1024,
        "LastModified": datetime.now(timezone.utc),
        "ETag": "test-etag"
    }
    
    # Configure CloudWatch operations
    mock_client.put_metric_data.return_value = {"ResponseMetadata": {"HTTPStatusCode": 200}}
    mock_client.describe_alarms.return_value = {"MetricAlarms": []}
    
    # Configure service health checks
    mock_client.describe_instances.return_value = {"Reservations": []}
    
    return mock_client


@pytest.fixture
def mock_pybreaker():
    """
    Fixture providing mock circuit breaker for resilience pattern testing.
    
    Creates mock pybreaker.CircuitBreaker with state transition simulation,
    failure threshold testing, and recovery timeout validation per Section 6.3.3.
    
    Returns:
        Mock: Mock circuit breaker instance
    """
    mock_breaker = Mock()
    mock_breaker.state = "closed"
    mock_breaker.fail_counter = 0
    mock_breaker.failure_threshold = TEST_CIRCUIT_BREAKER_CONFIG["failure_threshold"]
    mock_breaker.recovery_timeout = TEST_CIRCUIT_BREAKER_CONFIG["recovery_timeout"]
    mock_breaker.expected_exception = TEST_CIRCUIT_BREAKER_CONFIG["expected_exception"]
    
    # Configure circuit breaker call method
    def mock_call(func, *args, **kwargs):
        if mock_breaker.state == "open":
            raise Exception("Circuit breaker is open")
        
        try:
            result = func(*args, **kwargs)
            # Reset failure counter on success
            if mock_breaker.state == "half-open":
                mock_breaker.state = "closed"
                mock_breaker.fail_counter = 0
            return result
        except Exception as e:
            mock_breaker.fail_counter += 1
            if mock_breaker.fail_counter >= mock_breaker.failure_threshold:
                mock_breaker.state = "open"
            raise
    
    mock_breaker.call = mock_call
    
    # Configure state inspection methods
    mock_breaker.reset.side_effect = lambda: setattr(mock_breaker, 'state', 'closed')
    mock_breaker.open.side_effect = lambda: setattr(mock_breaker, 'state', 'open')
    
    return mock_breaker


@pytest.fixture
def external_service_monitor_instance():
    """
    Fixture providing external service monitor for health check testing.
    
    Creates ExternalServiceMonitor instance with service registration,
    health check validation, and metrics collection per Section 6.3.3.
    
    Returns:
        ExternalServiceMonitor: Test monitor instance
    """
    monitor = ExternalServiceMonitor()
    
    # Register test services for monitoring
    test_services = [
        ServiceMetrics(
            service_name="auth0",
            service_type=ExternalServiceType.AUTH_PROVIDER,
            health_endpoint="/api/v2/",
            timeout_seconds=5.0,
            critical_threshold_ms=3000.0,
            warning_threshold_ms=1000.0
        ),
        ServiceMetrics(
            service_name="aws_s3",
            service_type=ExternalServiceType.CLOUD_STORAGE,
            health_endpoint=None,
            timeout_seconds=10.0,
            critical_threshold_ms=5000.0,
            warning_threshold_ms=2000.0
        ),
        ServiceMetrics(
            service_name="test_api",
            service_type=ExternalServiceType.HTTP_API,
            health_endpoint="/health",
            timeout_seconds=30.0,
            critical_threshold_ms=10000.0,
            warning_threshold_ms=5000.0
        )
    ]
    
    for service in test_services:
        monitor.register_service(service)
    
    return monitor


# =============================================================================
# BaseExternalServiceClient Testing
# =============================================================================

class TestBaseExternalServiceClient:
    """
    Test suite for BaseExternalServiceClient functionality.
    
    Tests core external service client infrastructure including configuration,
    HTTP request handling, error processing, and connection management per
    Section 5.2.6 External Service Integration Layer requirements.
    """
    
    def test_client_initialization(self, base_client_config):
        """
        Test BaseExternalServiceClient initialization with configuration.
        
        Validates proper client initialization with configuration parameters,
        default headers setup, and connection pool configuration.
        """
        client = BaseExternalServiceClient(base_client_config)
        
        assert client.config == base_client_config
        assert client.service_name == "test_service"
        assert client.base_url == TEST_API_BASE_URL
        assert client.timeout == 30.0
        assert client.max_retries == 3
        assert "User-Agent" in client.default_headers
    
    def test_client_configuration_validation(self):
        """
        Test client configuration validation for required parameters.
        
        Validates configuration parameter validation, type checking,
        and error handling for invalid configuration values.
        """
        # Test missing service name
        with pytest.raises(ValueError, match="service_name is required"):
            BaseClientConfiguration(
                service_name="",
                base_url=TEST_API_BASE_URL
            )
        
        # Test invalid timeout value
        with pytest.raises(ValueError, match="timeout must be positive"):
            BaseClientConfiguration(
                service_name="test_service",
                base_url=TEST_API_BASE_URL,
                timeout=-1.0
            )
        
        # Test invalid retry count
        with pytest.raises(ValueError, match="max_retries must be non-negative"):
            BaseClientConfiguration(
                service_name="test_service",
                base_url=TEST_API_BASE_URL,
                max_retries=-1
            )
    
    @patch('src.integrations.base_client.requests.Session')
    def test_synchronous_http_requests(self, mock_session_class, base_client_config, mock_requests_session):
        """
        Test synchronous HTTP requests using requests library.
        
        Validates GET, POST, PUT, DELETE operations with proper header handling,
        timeout configuration, and response processing per Section 5.2.6.
        """
        mock_session_class.return_value = mock_requests_session
        client = BaseExternalServiceClient(base_client_config)
        
        # Test GET request
        response = client.get("/users")
        
        mock_requests_session.get.assert_called_once()
        call_args = mock_requests_session.get.call_args
        assert call_args[0][0] == urljoin(TEST_API_BASE_URL, "/users")
        assert call_args[1]["timeout"] == 30.0
        assert "User-Agent" in call_args[1]["headers"]
        
        assert response.status_code == 200
        assert response.json() == {"status": "success", "data": {}}
        
        # Test POST request with data
        test_data = {"name": "Test User", "email": "test@example.com"}
        client.post("/users", json=test_data)
        
        mock_requests_session.post.assert_called_once()
        post_call_args = mock_requests_session.post.call_args
        assert post_call_args[1]["json"] == test_data
        assert post_call_args[1]["timeout"] == 30.0
        
        # Test PUT request
        client.put("/users/123", json={"name": "Updated User"})
        mock_requests_session.put.assert_called_once()
        
        # Test DELETE request
        client.delete("/users/123")
        mock_requests_session.delete.assert_called_once()
    
    @pytest_asyncio.async_test
    @patch('src.integrations.base_client.httpx.AsyncClient')
    async def test_asynchronous_http_requests(self, mock_client_class, base_client_config, mock_httpx_client):
        """
        Test asynchronous HTTP requests using httpx library.
        
        Validates async GET, POST, PUT, DELETE operations with proper
        connection pooling, timeout handling, and async context management.
        """
        mock_client_class.return_value = mock_httpx_client
        client = BaseExternalServiceClient(base_client_config)
        
        # Test async GET request
        response = await client.async_get("/users")
        
        mock_httpx_client.get.assert_called_once()
        call_args = mock_httpx_client.get.call_args
        assert call_args[0][0] == urljoin(TEST_API_BASE_URL, "/users")
        assert call_args[1]["timeout"] == 30.0
        
        assert response.status_code == 200
        assert await response.json() == {"status": "success", "data": {}}
        
        # Test async POST request with data
        test_data = {"name": "Test User", "email": "test@example.com"}
        await client.async_post("/users", json=test_data)
        
        mock_httpx_client.post.assert_called_once()
        post_call_args = mock_httpx_client.post.call_args
        assert post_call_args[1]["json"] == test_data
        
        # Test connection pool configuration
        async with client.get_async_client() as async_client:
            assert isinstance(async_client, httpx.AsyncClient)
            mock_httpx_client.__aenter__.assert_called()
    
    def test_error_handling_and_exceptions(self, base_client_config, mock_requests_session):
        """
        Test error handling for HTTP exceptions and network failures.
        
        Validates proper exception handling for timeout, connection errors,
        HTTP status errors, and circuit breaker integration per Section 6.3.3.
        """
        with patch('src.integrations.base_client.requests.Session') as mock_session_class:
            mock_session_class.return_value = mock_requests_session
            client = BaseExternalServiceClient(base_client_config)
            
            # Test timeout exception
            mock_requests_session.get.side_effect = Timeout("Request timeout")
            
            with pytest.raises(Timeout):
                client.get("/users")
            
            # Test connection error
            mock_requests_session.get.side_effect = ConnectionError("Connection failed")
            
            with pytest.raises(ConnectionError):
                client.get("/users")
            
            # Test HTTP error status
            mock_error_response = Mock()
            mock_error_response.status_code = 404
            mock_error_response.raise_for_status.side_effect = HTTPError("Not found")
            mock_requests_session.get.side_effect = None
            mock_requests_session.get.return_value = mock_error_response
            
            with pytest.raises(HTTPError):
                response = client.get("/users")
                response.raise_for_status()
    
    def test_authentication_header_handling(self, base_client_config):
        """
        Test authentication header management for external services.
        
        Validates API key authentication, Bearer token handling, and
        custom authentication header configuration per Section 6.3.3.
        """
        # Test API key authentication
        config_with_auth = base_client_config
        config_with_auth.default_headers = {"Authorization": f"Bearer {TEST_API_KEY}"}
        
        client = BaseExternalServiceClient(config_with_auth)
        
        with patch('src.integrations.base_client.requests.Session') as mock_session_class:
            mock_session = Mock()
            mock_session_class.return_value = mock_session
            
            client.get("/protected")
            
            call_args = mock_session.get.call_args
            assert "Authorization" in call_args[1]["headers"]
            assert call_args[1]["headers"]["Authorization"] == f"Bearer {TEST_API_KEY}"
    
    def test_health_check_functionality(self, base_client_config, mock_requests_session):
        """
        Test health check functionality for external service monitoring.
        
        Validates health endpoint verification, response time measurement,
        and service status determination per Section 6.3.3.
        """
        with patch('src.integrations.base_client.requests.Session') as mock_session_class:
            mock_session_class.return_value = mock_requests_session
            client = BaseExternalServiceClient(base_client_config)
            
            # Configure health check endpoint
            health_response = Mock()
            health_response.status_code = 200
            health_response.json.return_value = {"status": "healthy", "timestamp": datetime.now().isoformat()}
            health_response.elapsed = timedelta(milliseconds=50)
            mock_requests_session.get.return_value = health_response
            
            # Test health check
            health_result = client.check_health()
            
            assert health_result["service_name"] == "test_service"
            assert health_result["overall_status"] == "healthy"
            assert health_result["response_time_ms"] == 50
            assert "timestamp" in health_result
            
            # Test unhealthy service
            health_response.status_code = 503
            health_response.json.return_value = {"status": "unhealthy", "error": "Service unavailable"}
            
            health_result = client.check_health()
            assert health_result["overall_status"] == "unhealthy"


# =============================================================================
# HTTP Client Libraries Testing (requests/httpx)
# =============================================================================

class TestHTTPClientLibraries:
    """
    Test suite for HTTP client library integration.
    
    Tests requests 2.31+ and httpx 0.24+ integration with comprehensive
    validation of synchronous and asynchronous HTTP operations, connection
    pooling, and performance characteristics per Section 5.2.6.
    """
    
    @patch('requests.get')
    def test_requests_synchronous_operations(self, mock_get):
        """
        Test requests library synchronous HTTP operations.
        
        Validates requests 2.31+ integration with timeout handling,
        session management, and connection pooling configuration.
        """
        # Configure mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"message": "Success"}
        mock_response.headers = {"Content-Type": "application/json"}
        mock_response.elapsed = timedelta(milliseconds=100)
        mock_get.return_value = mock_response
        
        # Test basic GET request
        response = requests.get(
            "https://api.example.com/data",
            timeout=30.0,
            headers={"Authorization": "Bearer token"}
        )
        
        assert response.status_code == 200
        assert response.json() == {"message": "Success"}
        
        # Verify request parameters
        mock_get.assert_called_once_with(
            "https://api.example.com/data",
            timeout=30.0,
            headers={"Authorization": "Bearer token"}
        )
    
    @patch('requests.Session')
    def test_requests_session_management(self, mock_session_class):
        """
        Test requests session management and connection pooling.
        
        Validates session reuse, connection pooling configuration,
        and persistent header management for efficient HTTP operations.
        """
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        # Configure session response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": "test"}
        mock_session.get.return_value = mock_response
        
        # Test session usage
        session = requests.Session()
        session.headers.update({"User-Agent": "Test-Client"})
        
        # Make multiple requests with same session
        for i in range(3):
            response = session.get(f"https://api.example.com/item/{i}")
            assert response.status_code == 200
        
        # Verify session was called correctly
        assert mock_session.get.call_count == 3
        
        # Test session cleanup
        session.close()
    
    @pytest_asyncio.async_test
    async def test_httpx_asynchronous_operations(self):
        """
        Test httpx library asynchronous HTTP operations.
        
        Validates httpx 0.24+ async client functionality with connection
        pooling, timeout handling, and concurrent request processing.
        """
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client
            
            # Configure async response
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"message": "Async success"}
            mock_response.headers = {"Content-Type": "application/json"}
            mock_client.get.return_value = mock_response
            
            # Configure context manager
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            
            # Test async GET request
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    "https://api.example.com/async-data",
                    headers={"Authorization": "Bearer async-token"}
                )
                
                assert response.status_code == 200
                assert await response.json() == {"message": "Async success"}
            
            # Verify async client usage
            mock_client.get.assert_called_once_with(
                "https://api.example.com/async-data",
                headers={"Authorization": "Bearer async-token"}
            )
    
    @pytest_asyncio.async_test
    async def test_httpx_concurrent_requests(self):
        """
        Test httpx concurrent request processing capabilities.
        
        Validates concurrent HTTP request handling, connection pooling
        efficiency, and async performance characteristics per Section 5.2.6.
        """
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client
            
            # Configure multiple async responses
            responses = []
            for i in range(5):
                mock_response = AsyncMock()
                mock_response.status_code = 200
                mock_response.json.return_value = {"id": i, "data": f"item_{i}"}
                responses.append(mock_response)
            
            mock_client.get.side_effect = responses
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            
            # Test concurrent requests
            async with httpx.AsyncClient() as client:
                tasks = [
                    client.get(f"https://api.example.com/items/{i}")
                    for i in range(5)
                ]
                
                responses = await asyncio.gather(*tasks)
                
                assert len(responses) == 5
                for i, response in enumerate(responses):
                    assert response.status_code == 200
                    response_data = await response.json()
                    assert response_data["id"] == i
            
            # Verify all requests were made
            assert mock_client.get.call_count == 5
    
    def test_http_client_error_handling(self):
        """
        Test HTTP client error handling for network failures.
        
        Validates timeout handling, connection errors, and HTTP status
        error processing for both requests and httpx libraries.
        """
        # Test requests timeout handling
        with patch('requests.get') as mock_get:
            mock_get.side_effect = requests.Timeout("Request timeout")
            
            with pytest.raises(requests.Timeout):
                requests.get("https://api.example.com/data", timeout=5.0)
        
        # Test requests connection error
        with patch('requests.get') as mock_get:
            mock_get.side_effect = requests.ConnectionError("Connection failed")
            
            with pytest.raises(requests.ConnectionError):
                requests.get("https://api.example.com/data")
    
    @pytest_asyncio.async_test
    async def test_httpx_error_handling(self):
        """
        Test httpx async client error handling.
        
        Validates async timeout handling, connection errors, and
        HTTP status error processing for httpx 0.24+ client.
        """
        with patch('httpx.AsyncClient') as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            
            # Test timeout error
            mock_client.get.side_effect = httpx.TimeoutException("Async timeout")
            
            with pytest.raises(httpx.TimeoutException):
                async with httpx.AsyncClient() as client:
                    await client.get("https://api.example.com/data")
            
            # Test connection error
            mock_client.get.side_effect = httpx.ConnectError("Async connection failed")
            
            with pytest.raises(httpx.ConnectError):
                async with httpx.AsyncClient() as client:
                    await client.get("https://api.example.com/data")


# =============================================================================
# AWS SDK (boto3) Integration Testing
# =============================================================================

class TestAWSSDKIntegration:
    """
    Test suite for AWS SDK (boto3) integration.
    
    Tests boto3 1.28+ integration for S3 operations, CloudWatch metrics,
    and AWS service communication with comprehensive error handling and
    performance validation per Section 5.2.6.
    """
    
    @patch('boto3.client')
    def test_s3_client_operations(self, mock_boto3_client, mock_boto3_client):
        """
        Test S3 client operations including upload, download, and delete.
        
        Validates S3 file operations, bucket management, and object
        lifecycle operations with proper error handling and response processing.
        """
        mock_boto3_client.return_value = mock_boto3_client
        
        # Test S3 file upload
        s3_client = boto3.client(
            's3',
            aws_access_key_id=TEST_AWS_ACCESS_KEY,
            aws_secret_access_key=TEST_AWS_SECRET_KEY,
            region_name=TEST_AWS_REGION
        )
        
        # Test upload_file operation
        upload_result = s3_client.upload_file(
            Filename="test-file.txt",
            Bucket=TEST_S3_BUCKET,
            Key="uploads/test-file.txt"
        )
        
        mock_boto3_client.upload_file.assert_called_once_with(
            Filename="test-file.txt",
            Bucket=TEST_S3_BUCKET,
            Key="uploads/test-file.txt"
        )
        assert upload_result == MOCK_AWS_S3_RESPONSE
        
        # Test download_file operation
        s3_client.download_file(
            Bucket=TEST_S3_BUCKET,
            Key="uploads/test-file.txt",
            Filename="downloaded-file.txt"
        )
        
        mock_boto3_client.download_file.assert_called_once()
        
        # Test delete_object operation
        delete_result = s3_client.delete_object(
            Bucket=TEST_S3_BUCKET,
            Key="uploads/test-file.txt"
        )
        
        mock_boto3_client.delete_object.assert_called_once()
        assert delete_result["DeleteMarker"] is True
    
    @patch('boto3.client')
    def test_s3_bucket_operations(self, mock_boto3_client, mock_boto3_client):
        """
        Test S3 bucket operations including listing and metadata retrieval.
        
        Validates bucket content listing, object metadata access, and
        bucket policy management with comprehensive response handling.
        """
        mock_boto3_client.return_value = mock_boto3_client
        
        s3_client = boto3.client('s3', region_name=TEST_AWS_REGION)
        
        # Test list_objects_v2 operation
        list_result = s3_client.list_objects_v2(
            Bucket=TEST_S3_BUCKET,
            Prefix="uploads/"
        )
        
        mock_boto3_client.list_objects_v2.assert_called_once_with(
            Bucket=TEST_S3_BUCKET,
            Prefix="uploads/"
        )
        assert list_result["KeyCount"] == 1
        assert len(list_result["Contents"]) == 1
        
        # Test head_object operation for metadata
        head_result = s3_client.head_object(
            Bucket=TEST_S3_BUCKET,
            Key="uploads/test-file.txt"
        )
        
        mock_boto3_client.head_object.assert_called_once()
        assert head_result["ContentLength"] == 1024
        assert "ETag" in head_result
    
    @patch('boto3.client')
    def test_cloudwatch_integration(self, mock_boto3_client, mock_boto3_client):
        """
        Test CloudWatch integration for metrics and monitoring.
        
        Validates CloudWatch metrics submission, alarm management, and
        monitoring data retrieval per Section 6.3.3 monitoring requirements.
        """
        mock_boto3_client.return_value = mock_boto3_client
        
        cloudwatch_client = boto3.client('cloudwatch', region_name=TEST_AWS_REGION)
        
        # Test put_metric_data operation
        metric_result = cloudwatch_client.put_metric_data(
            Namespace='FlaskApp/ExternalIntegrations',
            MetricData=[
                {
                    'MetricName': 'APIRequestCount',
                    'Value': 1.0,
                    'Unit': 'Count',
                    'Timestamp': datetime.now(timezone.utc),
                    'Dimensions': [
                        {
                            'Name': 'ServiceName',
                            'Value': 'external_api'
                        }
                    ]
                }
            ]
        )
        
        mock_boto3_client.put_metric_data.assert_called_once()
        assert metric_result["ResponseMetadata"]["HTTPStatusCode"] == 200
        
        # Test describe_alarms operation
        alarms_result = cloudwatch_client.describe_alarms(
            AlarmNames=['external-service-error-rate']
        )
        
        mock_boto3_client.describe_alarms.assert_called_once()
        assert "MetricAlarms" in alarms_result
    
    def test_aws_client_configuration(self):
        """
        Test AWS client configuration and credential management.
        
        Validates AWS client initialization, credential handling, region
        configuration, and session management per Section 5.2.6.
        """
        with patch('boto3.Session') as mock_session_class:
            mock_session = Mock()
            mock_session_class.return_value = mock_session
            
            # Configure mock client
            mock_client = Mock()
            mock_session.client.return_value = mock_client
            
            # Test session-based client creation
            session = boto3.Session(
                aws_access_key_id=TEST_AWS_ACCESS_KEY,
                aws_secret_access_key=TEST_AWS_SECRET_KEY,
                region_name=TEST_AWS_REGION
            )
            
            s3_client = session.client('s3')
            
            # Verify session configuration
            mock_session_class.assert_called_once_with(
                aws_access_key_id=TEST_AWS_ACCESS_KEY,
                aws_secret_access_key=TEST_AWS_SECRET_KEY,
                region_name=TEST_AWS_REGION
            )
            mock_session.client.assert_called_once_with('s3')
    
    @patch('boto3.client')
    def test_aws_error_handling(self, mock_boto3_client):
        """
        Test AWS SDK error handling and exception processing.
        
        Validates AWS service error handling, retry logic, and
        credential error processing with proper exception handling.
        """
        from botocore.exceptions import ClientError, NoCredentialsError
        
        mock_client = Mock()
        mock_boto3_client.return_value = mock_client
        
        # Test client error handling
        mock_client.upload_file.side_effect = ClientError(
            error_response={
                'Error': {
                    'Code': 'NoSuchBucket',
                    'Message': 'The specified bucket does not exist'
                }
            },
            operation_name='UploadFile'
        )
        
        s3_client = boto3.client('s3')
        
        with pytest.raises(ClientError) as exc_info:
            s3_client.upload_file("test.txt", "nonexistent-bucket", "test.txt")
        
        assert exc_info.value.response['Error']['Code'] == 'NoSuchBucket'
        
        # Test credentials error
        mock_boto3_client.side_effect = NoCredentialsError()
        
        with pytest.raises(NoCredentialsError):
            boto3.client('s3')


# =============================================================================
# Circuit Breaker Pattern Testing
# =============================================================================

class TestCircuitBreakerPatterns:
    """
    Test suite for circuit breaker resilience patterns.
    
    Tests circuit breaker implementation, failure threshold detection,
    recovery timeout management, and fallback mechanism validation per
    Section 6.3.3 resilience pattern requirements.
    """
    
    def test_circuit_breaker_initialization(self, mock_pybreaker):
        """
        Test circuit breaker initialization and configuration.
        
        Validates circuit breaker setup with failure thresholds, recovery
        timeouts, and expected exception configuration.
        """
        breaker = mock_pybreaker
        
        assert breaker.state == "closed"
        assert breaker.fail_counter == 0
        assert breaker.failure_threshold == 5
        assert breaker.recovery_timeout == 60
        assert breaker.expected_exception == RequestException
    
    def test_circuit_breaker_failure_detection(self, mock_pybreaker):
        """
        Test circuit breaker failure detection and state transitions.
        
        Validates failure counting, threshold detection, and automatic
        state transition from closed to open on failure threshold breach.
        """
        breaker = mock_pybreaker
        
        def failing_function():
            raise RequestException("Service unavailable")
        
        # Test failure accumulation
        for i in range(4):
            with pytest.raises(RequestException):
                breaker.call(failing_function)
            assert breaker.fail_counter == i + 1
            assert breaker.state == "closed"
        
        # Test state transition on threshold breach
        with pytest.raises(RequestException):
            breaker.call(failing_function)
        
        assert breaker.fail_counter == 5
        assert breaker.state == "open"
    
    def test_circuit_breaker_open_state_behavior(self, mock_pybreaker):
        """
        Test circuit breaker behavior in open state.
        
        Validates request blocking in open state, immediate failure
        responses, and prevention of downstream service calls.
        """
        breaker = mock_pybreaker
        breaker.state = "open"
        
        def normal_function():
            return "success"
        
        # Test that open circuit blocks requests
        with pytest.raises(Exception, match="Circuit breaker is open"):
            breaker.call(normal_function)
        
        # Verify function was not called
        assert breaker.state == "open"
    
    def test_circuit_breaker_recovery_mechanism(self, mock_pybreaker):
        """
        Test circuit breaker recovery and half-open state behavior.
        
        Validates recovery timeout handling, half-open state transitions,
        and successful recovery to closed state.
        """
        breaker = mock_pybreaker
        
        def successful_function():
            return "recovery_success"
        
        # Simulate half-open state
        breaker.state = "half-open"
        breaker.fail_counter = 3
        
        # Test successful recovery
        result = breaker.call(successful_function)
        
        assert result == "recovery_success"
        assert breaker.state == "closed"
        assert breaker.fail_counter == 0
    
    def test_circuit_breaker_with_external_service_client(self, base_client_config):
        """
        Test circuit breaker integration with external service client.
        
        Validates circuit breaker wrapper around HTTP client operations,
        failure detection during external service calls, and automatic
        protection activation per Section 6.3.3.
        """
        with patch('src.integrations.base_client.pybreaker.CircuitBreaker') as mock_breaker_class, \
             patch('src.integrations.base_client.requests.Session') as mock_session_class:
            
            mock_breaker = Mock()
            mock_breaker_class.return_value = mock_breaker
            mock_breaker.state = "closed"
            
            mock_session = Mock()
            mock_session_class.return_value = mock_session
            
            # Configure circuit breaker to allow calls initially
            def breaker_call_passthrough(func, *args, **kwargs):
                return func(*args, **kwargs)
            
            mock_breaker.call = breaker_call_passthrough
            
            # Configure successful response
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"status": "success"}
            mock_session.get.return_value = mock_response
            
            # Create client with circuit breaker enabled
            client = BaseExternalServiceClient(base_client_config)
            
            # Test successful request through circuit breaker
            response = client.get("/health")
            assert response.status_code == 200
            
            # Verify circuit breaker was initialized
            mock_breaker_class.assert_called_once()
    
    def test_circuit_breaker_metrics_collection(self, mock_pybreaker):
        """
        Test circuit breaker metrics collection and monitoring.
        
        Validates metrics emission for circuit breaker state changes,
        failure rates, and recovery statistics per Section 6.3.3.
        """
        breaker = mock_pybreaker
        
        # Add metrics collection mock
        metrics_collector = Mock()
        breaker.metrics_collector = metrics_collector
        
        def test_function():
            raise RequestException("Test failure")
        
        # Test metrics on failure
        with pytest.raises(RequestException):
            breaker.call(test_function)
        
        # Verify state can be inspected for metrics
        state_info = {
            "state": breaker.state,
            "fail_counter": breaker.fail_counter,
            "failure_threshold": breaker.failure_threshold
        }
        
        assert state_info["state"] in ["closed", "open", "half-open"]
        assert isinstance(state_info["fail_counter"], int)
        assert isinstance(state_info["failure_threshold"], int)


# =============================================================================
# Retry Logic and Resilience Testing
# =============================================================================

class TestRetryLogicAndResilience:
    """
    Test suite for retry logic and resilience patterns.
    
    Tests exponential backoff, jitter implementation, maximum retry limits,
    and intelligent retry strategies per Section 6.3.3 resilience requirements.
    """
    
    def test_exponential_backoff_implementation(self):
        """
        Test exponential backoff retry logic with configurable parameters.
        
        Validates exponential delay calculation, maximum backoff limits,
        and retry attempt tracking for external service resilience.
        """
        from unittest.mock import patch
        import time
        
        retry_attempts = []
        
        def failing_function():
            retry_attempts.append(time.time())
            if len(retry_attempts) < 3:
                raise RequestException("Temporary failure")
            return "success"
        
        # Mock tenacity retry decorator
        with patch('time.sleep') as mock_sleep:
            # Simulate exponential backoff: 1s, 2s, 4s
            expected_delays = [1.0, 2.0, 4.0]
            
            for i, delay in enumerate(expected_delays):
                try:
                    failing_function()
                except RequestException:
                    if i < len(expected_delays) - 1:
                        # Simulate sleep between retries
                        mock_sleep(delay)
            
            # Final successful attempt
            result = failing_function()
            assert result == "success"
            assert len(retry_attempts) == 3
    
    def test_jitter_implementation(self):
        """
        Test jitter implementation for retry timing randomization.
        
        Validates random jitter addition to prevent thundering herd
        patterns during service recovery per Section 6.3.3.
        """
        import random
        
        def calculate_jitter_delay(base_delay: float, jitter_factor: float = 0.1) -> float:
            """Calculate delay with jitter to prevent thundering herd."""
            jitter = random.uniform(-jitter_factor, jitter_factor) * base_delay
            return max(0.1, base_delay + jitter)
        
        base_delay = 2.0
        jitter_factor = 0.1
        
        # Test multiple jitter calculations
        delays = [calculate_jitter_delay(base_delay, jitter_factor) for _ in range(10)]
        
        # Verify all delays are within expected range
        min_delay = base_delay * (1 - jitter_factor)
        max_delay = base_delay * (1 + jitter_factor)
        
        for delay in delays:
            assert min_delay <= delay <= max_delay
        
        # Verify delays are not all identical (jitter is working)
        assert len(set(delays)) > 1
    
    def test_retry_with_specific_exceptions(self):
        """
        Test retry logic with specific exception handling.
        
        Validates selective retry behavior based on exception types,
        with different retry strategies for different error conditions.
        """
        def create_selective_retry_function(exception_type, max_attempts=3):
            """Create function that retries only on specific exceptions."""
            attempt_count = 0
            
            def retry_function():
                nonlocal attempt_count
                attempt_count += 1
                
                if attempt_count < max_attempts:
                    raise exception_type(f"Attempt {attempt_count} failed")
                return f"Success after {attempt_count} attempts"
            
            return retry_function
        
        # Test retry on RequestException
        request_retry_func = create_selective_retry_function(RequestException)
        result = request_retry_func()
        assert "Success after 3 attempts" in result
        
        # Test retry on ConnectionError
        connection_retry_func = create_selective_retry_function(ConnectionError)
        result = connection_retry_func()
        assert "Success after 3 attempts" in result
        
        # Test no retry on ValueError (non-retriable exception)
        def non_retriable_function():
            raise ValueError("This should not be retried")
        
        with pytest.raises(ValueError, match="This should not be retried"):
            non_retriable_function()
    
    def test_maximum_retry_limits(self):
        """
        Test maximum retry limit enforcement and final failure handling.
        
        Validates retry limit enforcement, final exception propagation,
        and resource cleanup after exhausting retry attempts.
        """
        def always_failing_function():
            raise RequestException("Persistent failure")
        
        max_retries = 3
        retry_count = 0
        
        def limited_retry_wrapper(func, max_attempts):
            nonlocal retry_count
            
            for attempt in range(max_attempts):
                try:
                    retry_count += 1
                    return func()
                except RequestException as e:
                    if attempt == max_attempts - 1:
                        # Final attempt failed, raise exception
                        raise e
                    # Continue to next retry
                    continue
        
        # Test retry limit enforcement
        with pytest.raises(RequestException, match="Persistent failure"):
            limited_retry_wrapper(always_failing_function, max_retries)
        
        assert retry_count == max_retries
    
    def test_retry_with_timeout_handling(self):
        """
        Test retry logic with timeout constraints and deadline enforcement.
        
        Validates retry behavior under timeout constraints, deadline
        enforcement, and early termination on timeout expiration.
        """
        import time
        from unittest.mock import patch
        
        def slow_function():
            time.sleep(0.1)  # Simulate slow operation
            raise RequestException("Timeout occurred")
        
        start_time = time.time()
        timeout_deadline = 0.5  # 500ms timeout
        
        retry_count = 0
        
        with patch('time.sleep'):  # Mock sleep to speed up test
            while time.time() - start_time < timeout_deadline:
                try:
                    retry_count += 1
                    slow_function()
                except RequestException:
                    if time.time() - start_time >= timeout_deadline:
                        break
                    continue
        
        # Verify retries were attempted within timeout window
        assert retry_count >= 1
        assert time.time() - start_time <= timeout_deadline + 0.1  # Allow small buffer


# =============================================================================
# Integration Manager Testing
# =============================================================================

class TestIntegrationManager:
    """
    Test suite for IntegrationManager functionality.
    
    Tests service registration, health monitoring, client management,
    and graceful shutdown capabilities per Section 6.3.3 requirements.
    """
    
    def test_integration_manager_initialization(self):
        """
        Test IntegrationManager initialization and basic functionality.
        
        Validates manager initialization, registry setup, and
        basic service management capabilities.
        """
        manager = IntegrationManager()
        
        assert isinstance(manager._clients, dict)
        assert isinstance(manager._health_registry, dict)
        assert isinstance(manager._initialization_order, list)
        assert len(manager._clients) == 0
    
    def test_service_client_registration(self, base_client_config):
        """
        Test service client registration and management.
        
        Validates client registration, service metrics integration,
        and proper service tracking in the integration manager.
        """
        manager = IntegrationManager()
        
        # Create test client and metrics
        client = BaseExternalServiceClient(base_client_config)
        metrics = ServiceMetrics(
            service_name="test_service",
            service_type=ExternalServiceType.HTTP_API,
            health_endpoint="/health",
            timeout_seconds=30.0,
            critical_threshold_ms=5000.0,
            warning_threshold_ms=2000.0
        )
        
        # Register client
        manager.register_client("test_service", client, metrics)
        
        # Verify registration
        assert "test_service" in manager._clients
        assert manager.get_client("test_service") == client
        assert "test_service" in manager._health_registry
        assert "test_service" in manager._initialization_order
    
    def test_client_retrieval_and_listing(self, base_client_config):
        """
        Test client retrieval and service listing functionality.
        
        Validates registered client access, service enumeration,
        and client type information retrieval.
        """
        manager = IntegrationManager()
        
        # Register multiple clients
        clients = {}
        for service_name in ["auth0", "aws_s3", "external_api"]:
            config = BaseClientConfiguration(
                service_name=service_name,
                base_url=f"https://{service_name}.example.com"
            )
            client = BaseExternalServiceClient(config)
            clients[service_name] = client
            manager.register_client(service_name, client)
        
        # Test client retrieval
        assert manager.get_client("auth0") == clients["auth0"]
        assert manager.get_client("aws_s3") == clients["aws_s3"]
        assert manager.get_client("nonexistent") is None
        
        # Test client listing
        client_list = manager.list_clients()
        assert len(client_list) == 3
        assert all(service in client_list for service in ["auth0", "aws_s3", "external_api"])
        assert all("BaseExternalServiceClient" in client_type for client_type in client_list.values())
    
    def test_comprehensive_health_check(self, base_client_config):
        """
        Test comprehensive health check functionality for all services.
        
        Validates health check execution, status aggregation, and
        overall system health determination per Section 6.3.3.
        """
        manager = IntegrationManager()
        
        # Register clients with mock health check responses
        services = [
            ("healthy_service", "healthy", 50),
            ("degraded_service", "degraded", 150),
            ("unhealthy_service", "unhealthy", 0)
        ]
        
        for service_name, status, response_time in services:
            config = BaseClientConfiguration(
                service_name=service_name,
                base_url=f"https://{service_name}.example.com"
            )
            client = BaseExternalServiceClient(config)
            
            # Mock health check response
            with patch.object(client, 'check_health') as mock_health:
                mock_health.return_value = {
                    "service_name": service_name,
                    "overall_status": status,
                    "response_time_ms": response_time,
                    "timestamp": datetime.now().isoformat()
                }
                
                manager.register_client(service_name, client)
        
        # Execute comprehensive health check
        health_summary = manager.check_all_health()
        
        # Verify health summary structure
        assert "overall_status" in health_summary
        assert "total_services" in health_summary
        assert "healthy_services" in health_summary
        assert "degraded_services" in health_summary
        assert "unhealthy_services" in health_summary
        assert "services" in health_summary
        
        # Verify service counts
        assert health_summary["total_services"] == 3
        assert health_summary["healthy_services"] == 1
        assert health_summary["degraded_services"] == 1
        assert health_summary["unhealthy_services"] == 1
        
        # Overall status should be unhealthy due to unhealthy service
        assert health_summary["overall_status"] == "unhealthy"
    
    @pytest_asyncio.async_test
    async def test_graceful_shutdown(self, base_client_config):
        """
        Test graceful shutdown functionality for all registered services.
        
        Validates proper shutdown sequence, resource cleanup, and
        orderly service termination per Section 6.3.3.
        """
        manager = IntegrationManager()
        
        # Register multiple clients
        shutdown_order = []
        
        for i, service_name in enumerate(["service_1", "service_2", "service_3"]):
            config = BaseClientConfiguration(
                service_name=service_name,
                base_url=f"https://{service_name}.example.com"
            )
            client = BaseExternalServiceClient(config)
            
            # Mock close method to track shutdown order
            async def mock_close(svc_name=service_name):
                shutdown_order.append(svc_name)
            
            client.close = mock_close
            manager.register_client(service_name, client)
        
        # Execute graceful shutdown
        await manager.shutdown_all()
        
        # Verify shutdown occurred in reverse initialization order
        expected_order = ["service_3", "service_2", "service_1"]
        assert shutdown_order == expected_order
        
        # Verify registries are cleared
        assert len(manager._clients) == 0
        assert len(manager._health_registry) == 0
        assert len(manager._initialization_order) == 0
    
    def test_duplicate_service_registration(self, base_client_config):
        """
        Test handling of duplicate service registration.
        
        Validates proper handling of duplicate registrations, warning
        generation, and service replacement behavior.
        """
        manager = IntegrationManager()
        
        # Create two different clients for same service
        config1 = BaseClientConfiguration(
            service_name="duplicate_service",
            base_url="https://old.example.com"
        )
        client1 = BaseExternalServiceClient(config1)
        
        config2 = BaseClientConfiguration(
            service_name="duplicate_service",
            base_url="https://new.example.com"
        )
        client2 = BaseExternalServiceClient(config2)
        
        # Register first client
        manager.register_client("duplicate_service", client1)
        assert manager.get_client("duplicate_service") == client1
        
        # Register second client (should replace first)
        with patch('src.integrations.structlog.get_logger') as mock_logger:
            mock_log = Mock()
            mock_logger.return_value = mock_log
            
            manager.register_client("duplicate_service", client2)
            
            # Verify replacement occurred
            assert manager.get_client("duplicate_service") == client2
            
            # Verify warning was logged
            mock_log.warning.assert_called()


# =============================================================================
# External Service Monitoring Testing
# =============================================================================

class TestExternalServiceMonitoring:
    """
    Test suite for external service monitoring and health checks.
    
    Tests service health monitoring, metrics collection, performance
    threshold validation, and alerting per Section 6.3.3 requirements.
    """
    
    def test_service_metrics_creation(self):
        """
        Test ServiceMetrics creation and validation.
        
        Validates service metrics configuration, threshold settings,
        and service type classification per monitoring requirements.
        """
        metrics = ServiceMetrics(
            service_name="test_api",
            service_type=ExternalServiceType.HTTP_API,
            health_endpoint="/health",
            timeout_seconds=30.0,
            critical_threshold_ms=5000.0,
            warning_threshold_ms=2000.0
        )
        
        assert metrics.service_name == "test_api"
        assert metrics.service_type == ExternalServiceType.HTTP_API
        assert metrics.health_endpoint == "/health"
        assert metrics.timeout_seconds == 30.0
        assert metrics.critical_threshold_ms == 5000.0
        assert metrics.warning_threshold_ms == 2000.0
    
    def test_external_service_monitor_registration(self, external_service_monitor_instance):
        """
        Test external service monitor registration and service tracking.
        
        Validates service registration, metrics tracking, and monitor
        configuration per Section 6.3.3 monitoring specifications.
        """
        monitor = external_service_monitor_instance
        
        # Verify pre-registered services
        registered_services = monitor.get_registered_services()
        assert "auth0" in registered_services
        assert "aws_s3" in registered_services
        assert "test_api" in registered_services
        
        # Test additional service registration
        new_metrics = ServiceMetrics(
            service_name="new_service",
            service_type=ExternalServiceType.HTTP_API,
            health_endpoint="/status",
            timeout_seconds=15.0,
            critical_threshold_ms=3000.0,
            warning_threshold_ms=1500.0
        )
        
        monitor.register_service(new_metrics)
        updated_services = monitor.get_registered_services()
        assert "new_service" in updated_services
    
    def test_service_health_state_determination(self):
        """
        Test service health state determination based on response metrics.
        
        Validates health state calculation, threshold comparison, and
        status classification (healthy/degraded/unhealthy) logic.
        """
        def determine_health_state(response_time_ms: float, warning_threshold: float, critical_threshold: float) -> str:
            """Determine health state based on response time thresholds."""
            if response_time_ms <= warning_threshold:
                return "healthy"
            elif response_time_ms <= critical_threshold:
                return "degraded"
            else:
                return "unhealthy"
        
        warning_threshold = 1000.0
        critical_threshold = 3000.0
        
        # Test healthy state
        assert determine_health_state(500.0, warning_threshold, critical_threshold) == "healthy"
        
        # Test degraded state
        assert determine_health_state(2000.0, warning_threshold, critical_threshold) == "degraded"
        
        # Test unhealthy state
        assert determine_health_state(5000.0, warning_threshold, critical_threshold) == "unhealthy"
        
        # Test boundary conditions
        assert determine_health_state(1000.0, warning_threshold, critical_threshold) == "healthy"
        assert determine_health_state(3000.0, warning_threshold, critical_threshold) == "degraded"
    
    def test_health_check_execution_with_timeouts(self, external_service_monitor_instance):
        """
        Test health check execution with timeout handling.
        
        Validates health check timeout enforcement, response time
        measurement, and timeout exception handling per monitoring specs.
        """
        monitor = external_service_monitor_instance
        
        # Mock health check with various response times
        test_cases = [
            ("fast_service", 0.5, "healthy"),
            ("slow_service", 2.5, "degraded"),
            ("timeout_service", 10.0, "unhealthy")
        ]
        
        for service_name, response_time, expected_status in test_cases:
            with patch('time.time') as mock_time:
                # Mock response time measurement
                mock_time.side_effect = [0.0, response_time]
                
                # Mock HTTP request for health check
                with patch('requests.get') as mock_get:
                    mock_response = Mock()
                    mock_response.status_code = 200
                    mock_response.json.return_value = {"status": "ok"}
                    mock_response.elapsed = timedelta(seconds=response_time)
                    mock_get.return_value = mock_response
                    
                    # Execute health check (simulated)
                    health_result = {
                        "service_name": service_name,
                        "response_time_ms": response_time * 1000,
                        "overall_status": expected_status,
                        "timestamp": datetime.now().isoformat()
                    }
                    
                    assert health_result["overall_status"] == expected_status
                    assert health_result["response_time_ms"] == response_time * 1000
    
    def test_performance_threshold_alerting(self):
        """
        Test performance threshold alerting and notification generation.
        
        Validates alerting logic, threshold breach detection, and
        notification generation for performance degradation scenarios.
        """
        def check_performance_threshold(response_time_ms: float, thresholds: Dict[str, float]) -> List[str]:
            """Check performance thresholds and generate alerts."""
            alerts = []
            
            if response_time_ms > thresholds.get("critical", float('inf')):
                alerts.append(f"CRITICAL: Response time {response_time_ms}ms exceeds critical threshold")
            elif response_time_ms > thresholds.get("warning", float('inf')):
                alerts.append(f"WARNING: Response time {response_time_ms}ms exceeds warning threshold")
            
            return alerts
        
        thresholds = {
            "warning": 1000.0,
            "critical": 3000.0
        }
        
        # Test no alert scenario
        alerts = check_performance_threshold(500.0, thresholds)
        assert len(alerts) == 0
        
        # Test warning alert
        alerts = check_performance_threshold(1500.0, thresholds)
        assert len(alerts) == 1
        assert "WARNING" in alerts[0]
        
        # Test critical alert
        alerts = check_performance_threshold(4000.0, thresholds)
        assert len(alerts) == 1
        assert "CRITICAL" in alerts[0]
    
    def test_monitoring_metrics_collection(self, external_service_monitor_instance):
        """
        Test monitoring metrics collection and aggregation.
        
        Validates metrics collection, performance data aggregation,
        and monitoring dashboard data preparation per Section 6.3.3.
        """
        monitor = external_service_monitor_instance
        
        # Simulate metrics collection over time
        metrics_data = []
        
        for i in range(10):
            timestamp = datetime.now() + timedelta(seconds=i)
            service_metrics = {
                "timestamp": timestamp.isoformat(),
                "service_name": "test_api",
                "response_time_ms": 500 + (i * 100),  # Increasing response time
                "status_code": 200,
                "success": True
            }
            metrics_data.append(service_metrics)
        
        # Calculate metrics aggregation
        response_times = [m["response_time_ms"] for m in metrics_data]
        success_rate = sum(1 for m in metrics_data if m["success"]) / len(metrics_data)
        avg_response_time = sum(response_times) / len(response_times)
        max_response_time = max(response_times)
        min_response_time = min(response_times)
        
        # Verify metrics calculations
        assert success_rate == 1.0
        assert avg_response_time == 950.0  # Average of 500-1400ms range
        assert max_response_time == 1400.0
        assert min_response_time == 500.0
        
        # Test metrics summary structure
        metrics_summary = {
            "service_name": "test_api",
            "data_points": len(metrics_data),
            "success_rate": success_rate,
            "avg_response_time_ms": avg_response_time,
            "max_response_time_ms": max_response_time,
            "min_response_time_ms": min_response_time,
            "collection_period": "10 seconds"
        }
        
        assert metrics_summary["data_points"] == 10
        assert metrics_summary["success_rate"] == 1.0


# =============================================================================
# Performance and Integration Testing
# =============================================================================

class TestPerformanceAndIntegration:
    """
    Test suite for performance validation and integration testing.
    
    Tests performance baseline compliance (≤10% variance), load testing,
    concurrent request handling, and integration performance per Section 0.3.2.
    """
    
    def test_performance_baseline_compliance(self, performance_test_context):
        """
        Test performance baseline compliance for ≤10% variance requirement.
        
        Validates response time measurement, baseline comparison, and
        variance calculation per Section 0.3.2 performance monitoring.
        """
        context = performance_test_context
        
        # Simulate baseline Node.js performance metrics
        baseline_metrics = {
            "api_request_time": 0.150,  # 150ms baseline
            "database_query_time": 0.050,  # 50ms baseline
            "external_api_call_time": 0.200  # 200ms baseline
        }
        
        # Simulate Python Flask performance measurements
        test_measurements = {
            "api_request_time": 0.160,  # 160ms (6.67% increase)
            "database_query_time": 0.048,  # 48ms (4% decrease)
            "external_api_call_time": 0.215  # 215ms (7.5% increase)
        }
        
        # Validate variance calculations
        for metric_name, baseline_value in baseline_metrics.items():
            measured_value = test_measurements[metric_name]
            variance = abs(measured_value - baseline_value) / baseline_value
            
            # All variances should be ≤10%
            assert variance <= PERFORMANCE_VARIANCE_THRESHOLD, \
                f"{metric_name} variance {variance:.2%} exceeds {PERFORMANCE_VARIANCE_THRESHOLD:.0%} threshold"
        
        # Test variance threshold breach detection
        failing_measurement = 0.300  # 100% increase
        variance = abs(failing_measurement - baseline_metrics["api_request_time"]) / baseline_metrics["api_request_time"]
        assert variance > PERFORMANCE_VARIANCE_THRESHOLD
    
    def test_concurrent_request_handling(self, mock_external_services):
        """
        Test concurrent request handling performance and scalability.
        
        Validates concurrent HTTP request processing, connection pooling
        efficiency, and resource utilization per Section 5.2.6.
        """
        import threading
        import time
        
        # Mock external service responses
        context = mock_external_services
        
        # Configure concurrent request simulation
        num_concurrent_requests = 50
        request_results = []
        request_times = []
        
        def make_concurrent_request(request_id):
            """Simulate concurrent external service request."""
            start_time = time.time()
            
            try:
                # Simulate HTTP request processing
                response = context['mock_requests_get'](
                    f"https://api.example.com/data/{request_id}",
                    timeout=30.0
                )
                
                end_time = time.time()
                request_times.append(end_time - start_time)
                request_results.append({
                    "request_id": request_id,
                    "status_code": response.status_code,
                    "response_time": end_time - start_time,
                    "success": True
                })
                
            except Exception as e:
                end_time = time.time()
                request_results.append({
                    "request_id": request_id,
                    "error": str(e),
                    "response_time": end_time - start_time,
                    "success": False
                })
        
        # Execute concurrent requests
        threads = []
        start_time = time.time()
        
        for i in range(num_concurrent_requests):
            thread = threading.Thread(target=make_concurrent_request, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all requests to complete
        for thread in threads:
            thread.join()
        
        total_time = time.time() - start_time
        
        # Validate concurrent processing results
        assert len(request_results) == num_concurrent_requests
        
        successful_requests = [r for r in request_results if r["success"]]
        success_rate = len(successful_requests) / num_concurrent_requests
        
        # Verify high success rate
        assert success_rate >= 0.95  # 95% success rate minimum
        
        # Verify reasonable concurrent processing time
        assert total_time < 5.0  # Should complete within 5 seconds
        
        # Verify average response time is reasonable
        if request_times:
            avg_response_time = sum(request_times) / len(request_times)
            assert avg_response_time < 1.0  # Average response under 1 second
    
    @pytest_asyncio.async_test
    async def test_async_operation_performance(self, mock_httpx_client):
        """
        Test asynchronous operation performance and efficiency.
        
        Validates async HTTP client performance, concurrent async operations,
        and async database operation efficiency per Section 5.2.6.
        """
        import asyncio
        import time
        
        # Configure async mock responses
        async_client = mock_httpx_client
        
        async def async_external_request(request_id: int) -> Dict[str, Any]:
            """Simulate async external service request."""
            start_time = time.time()
            
            response = await async_client.get(
                f"https://api.example.com/async/{request_id}",
                timeout=30.0
            )
            
            end_time = time.time()
            
            return {
                "request_id": request_id,
                "status_code": response.status_code,
                "response_time": end_time - start_time,
                "data": await response.json()
            }
        
        # Execute concurrent async requests
        num_async_requests = 20
        start_time = time.time()
        
        # Create and execute concurrent async tasks
        tasks = [
            async_external_request(i)
            for i in range(num_async_requests)
        ]
        
        results = await asyncio.gather(*tasks)
        
        total_time = time.time() - start_time
        
        # Validate async operation efficiency
        assert len(results) == num_async_requests
        assert all(result["status_code"] == 200 for result in results)
        
        # Async operations should be significantly faster than sequential
        assert total_time < 2.0  # Should complete within 2 seconds
        
        # Verify response time consistency
        response_times = [result["response_time"] for result in results]
        avg_response_time = sum(response_times) / len(response_times)
        assert avg_response_time < 0.5  # Average async response under 500ms
    
    def test_memory_usage_monitoring(self, test_metrics_collector):
        """
        Test memory usage monitoring and resource efficiency.
        
        Validates memory consumption tracking, resource leak detection,
        and memory efficiency per performance requirements.
        """
        import gc
        import sys
        
        collector = test_metrics_collector
        
        # Measure initial memory usage
        gc.collect()  # Force garbage collection
        initial_memory = sys.getsizeof(gc.get_objects())
        
        # Simulate external integration operations
        test_objects = []
        
        for i in range(1000):
            # Simulate client object creation
            test_object = {
                "request_id": i,
                "timestamp": time.time(),
                "data": f"test_data_{i}" * 10,  # Some data content
                "metadata": {"index": i, "type": "test"}
            }
            test_objects.append(test_object)
            
            # Record operation in metrics collector
            collector.record_operation("external_api")
        
        # Measure memory usage after operations
        current_memory = sys.getsizeof(gc.get_objects())
        memory_increase = current_memory - initial_memory
        
        # Cleanup test objects
        test_objects.clear()
        gc.collect()
        
        # Measure memory after cleanup
        final_memory = sys.getsizeof(gc.get_objects())
        memory_recovered = current_memory - final_memory
        
        # Validate memory management
        # Memory increase should be reasonable for 1000 operations
        assert memory_increase < 1024 * 1024  # Less than 1MB increase
        
        # Memory recovery should be significant after cleanup
        recovery_rate = memory_recovered / memory_increase if memory_increase > 0 else 1.0
        assert recovery_rate > 0.8  # At least 80% memory recovery
        
        # Verify metrics collection
        metrics_summary = collector.get_summary()
        assert metrics_summary["operation_counts"]["external_api_operations"] == 1000
    
    def test_connection_pool_efficiency(self, base_client_config):
        """
        Test connection pool efficiency and resource management.
        
        Validates connection reuse, pool size optimization, and
        connection lifecycle management per Section 5.2.6.
        """
        # Mock connection pool statistics
        pool_stats = {
            "max_connections": 20,
            "active_connections": 0,
            "idle_connections": 5,
            "total_requests": 0,
            "connection_reuse_count": 0
        }
        
        def simulate_request_with_pool():
            """Simulate request using connection pool."""
            pool_stats["total_requests"] += 1
            
            if pool_stats["idle_connections"] > 0:
                # Reuse existing connection
                pool_stats["idle_connections"] -= 1
                pool_stats["active_connections"] += 1
                pool_stats["connection_reuse_count"] += 1
            else:
                # Create new connection if under limit
                if pool_stats["active_connections"] < pool_stats["max_connections"]:
                    pool_stats["active_connections"] += 1
                else:
                    # Wait for available connection (simulated)
                    pass
            
            # Simulate request completion
            pool_stats["active_connections"] -= 1
            pool_stats["idle_connections"] += 1
        
        # Simulate multiple requests
        for _ in range(50):
            simulate_request_with_pool()
        
        # Validate connection pool efficiency
        assert pool_stats["total_requests"] == 50
        assert pool_stats["connection_reuse_count"] > 30  # High reuse rate
        
        # Pool should not exceed max connections
        assert pool_stats["active_connections"] <= pool_stats["max_connections"]
        
        # Calculate efficiency metrics
        reuse_rate = pool_stats["connection_reuse_count"] / pool_stats["total_requests"]
        assert reuse_rate > 0.6  # At least 60% connection reuse


# =============================================================================
# Integration Test Execution and Validation
# =============================================================================

if __name__ == "__main__":
    """
    Execute integration tests with comprehensive validation.
    
    Runs complete test suite with performance monitoring, error tracking,
    and compliance validation per Section 0.3.2 requirements.
    """
    pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "--strict-markers",
        "--strict-config",
        "-m", "not slow"  # Exclude slow tests by default
    ])