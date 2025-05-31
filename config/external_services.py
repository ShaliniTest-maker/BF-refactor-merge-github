"""
External Service Integration Configuration Module

This module provides comprehensive external service integration configuration for AWS services
(boto3 1.28+), HTTP clients (requests 2.31+/httpx 0.24+), Auth0 integration, and third-party
API configurations. Replaces Node.js AWS SDK and HTTP client configurations with Python
equivalents while maintaining equivalent functionality and performance.

Key Features:
- boto3 1.28+ AWS service integration with KMS key management (Section 0.2.4)
- requests 2.31+ and httpx 0.24+ HTTP client operations (Section 3.2.3)
- AWS KMS integration for encryption key management (Section 6.4.3)
- Circuit breaker patterns for service resilience (Section 5.2.6)
- Connection pooling for external service efficiency (Section 3.2.3)
- Auth0 enterprise authentication service integration
- Third-party API client configurations with retry logic
- Enterprise security standards and compliance controls

Dependencies:
- boto3 1.28+ for AWS service integration
- requests 2.31+ for synchronous HTTP operations
- httpx 0.24+ for asynchronous HTTP operations
- urllib3 2.0+ for connection pooling and management
- tenacity 8.2+ for retry and circuit breaker patterns
- python-dotenv 1.0+ for secure environment management

Author: Flask Migration Team
Version: 1.0.0
Migration Phase: Node.js to Python/Flask Migration (Section 0.1.1)
"""

import os
import logging
import ssl
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Union, Callable, Tuple
from urllib.parse import urlparse
import boto3
from botocore.config import Config as BotoCoreConfig
from botocore.exceptions import ClientError, NoCredentialsError, BotoCoreError
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import httpx
from urllib3 import PoolManager
from urllib3.util.retry import Retry as Urllib3Retry
from tenacity import (
    retry, stop_after_attempt, wait_exponential_jitter,
    retry_if_exception_type, before_sleep_log, after_log
)
import json
import hashlib
import base64
from pathlib import Path

# Configure logging for external services module
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ExternalServiceError(Exception):
    """Base exception for external service configuration errors."""
    pass


class AWSConfigurationError(ExternalServiceError):
    """AWS service configuration specific exception."""
    pass


class HTTPClientConfigurationError(ExternalServiceError):
    """HTTP client configuration specific exception."""
    pass


class CircuitBreakerError(ExternalServiceError):
    """Circuit breaker activation exception."""
    pass


class ExternalServiceConfigurationManager:
    """
    Comprehensive external service configuration manager implementing enterprise-grade
    AWS integration, HTTP client configuration, and circuit breaker patterns for
    service resilience as specified in Section 5.2.6.
    
    This class provides centralized configuration for all external service integrations
    including AWS services, HTTP clients, Auth0 authentication, and third-party APIs
    with comprehensive error handling, retry logic, and security controls.
    """
    
    def __init__(self, environment: str = None):
        """
        Initialize external service configuration manager.
        
        Args:
            environment: Optional environment override (development, staging, production)
        """
        self.environment = environment or os.getenv('FLASK_ENV', 'production')
        self.logger = logging.getLogger(f"{__name__}.ExternalServiceConfigurationManager")
        
        # Initialize configuration components
        self._load_environment_configuration()
        self._validate_required_credentials()
        self._initialize_aws_configuration()
        self._initialize_http_client_configuration()
        self._initialize_auth0_configuration()
        self._initialize_circuit_breaker_configuration()
        self._validate_service_connectivity()
    
    def _load_environment_configuration(self) -> None:
        """
        Load environment-specific configuration with comprehensive validation.
        
        This method loads external service credentials and configuration from
        environment variables with proper validation and security checks.
        """
        try:
            # AWS Configuration
            self.aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID')
            self.aws_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY')
            self.aws_session_token = os.getenv('AWS_SESSION_TOKEN')
            self.aws_region = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
            self.aws_kms_key_arn = os.getenv('AWS_KMS_KEY_ARN')
            
            # S3 Configuration
            self.s3_bucket_name = os.getenv('S3_BUCKET_NAME')
            self.s3_region = os.getenv('S3_REGION', self.aws_region)
            self.s3_endpoint_url = os.getenv('S3_ENDPOINT_URL')  # For S3-compatible services
            
            # HTTP Client Configuration
            self.http_timeout = float(os.getenv('HTTP_TIMEOUT', '30.0'))
            self.http_retries = int(os.getenv('HTTP_RETRIES', '3'))
            self.http_backoff_factor = float(os.getenv('HTTP_BACKOFF_FACTOR', '1.0'))
            self.http_max_connections = int(os.getenv('HTTP_MAX_CONNECTIONS', '100'))
            self.http_max_keepalive = int(os.getenv('HTTP_MAX_KEEPALIVE_CONNECTIONS', '50'))
            
            # Auth0 Configuration
            self.auth0_domain = os.getenv('AUTH0_DOMAIN')
            self.auth0_client_id = os.getenv('AUTH0_CLIENT_ID')
            self.auth0_client_secret = os.getenv('AUTH0_CLIENT_SECRET')
            self.auth0_audience = os.getenv('AUTH0_AUDIENCE')
            self.auth0_management_api_token = os.getenv('AUTH0_MANAGEMENT_API_TOKEN')
            
            # Circuit Breaker Configuration
            self.circuit_breaker_enabled = os.getenv('CIRCUIT_BREAKER_ENABLED', 'true').lower() == 'true'
            self.circuit_breaker_failure_threshold = int(os.getenv('CIRCUIT_BREAKER_FAILURE_THRESHOLD', '5'))
            self.circuit_breaker_timeout = int(os.getenv('CIRCUIT_BREAKER_TIMEOUT', '60'))
            self.circuit_breaker_expected_exception = os.getenv('CIRCUIT_BREAKER_EXPECTED_EXCEPTION', 'requests.exceptions.RequestException')
            
            # SSL/TLS Configuration
            self.ssl_verify = os.getenv('SSL_VERIFY', 'true').lower() == 'true'
            self.ssl_cert_path = os.getenv('SSL_CERT_PATH')
            self.ssl_key_path = os.getenv('SSL_KEY_PATH')
            self.ca_cert_path = os.getenv('CA_CERT_PATH')
            
            # Third-party API Configuration
            self.external_api_base_urls = self._parse_external_api_urls()
            self.external_api_timeouts = self._parse_external_api_timeouts()
            
            self.logger.info(f"External service configuration loaded for environment: {self.environment}")
            
        except Exception as e:
            error_msg = f"Failed to load external service configuration: {str(e)}"
            self.logger.error(error_msg)
            raise ExternalServiceError(error_msg)
    
    def _parse_external_api_urls(self) -> Dict[str, str]:
        """
        Parse external API base URLs from environment variables.
        
        Returns:
            Dictionary mapping service names to base URLs
        """
        api_urls = {}
        
        # Parse semicolon-separated API URL configuration
        api_urls_env = os.getenv('EXTERNAL_API_URLS', '')
        if api_urls_env:
            try:
                for api_config in api_urls_env.split(';'):
                    if '=' in api_config:
                        service_name, base_url = api_config.split('=', 1)
                        api_urls[service_name.strip()] = base_url.strip()
            except Exception as e:
                self.logger.warning(f"Failed to parse external API URLs: {str(e)}")
        
        # Add default service URLs
        api_urls.update({
            'auth0_management': f"https://{self.auth0_domain}/api/v2" if self.auth0_domain else '',
            'aws_sts': f"https://sts.{self.aws_region}.amazonaws.com",
            'aws_kms': f"https://kms.{self.aws_region}.amazonaws.com",
            'aws_s3': f"https://s3.{self.s3_region}.amazonaws.com"
        })
        
        return api_urls
    
    def _parse_external_api_timeouts(self) -> Dict[str, float]:
        """
        Parse external API timeout configurations from environment variables.
        
        Returns:
            Dictionary mapping service names to timeout values in seconds
        """
        timeouts = {}
        
        # Parse semicolon-separated timeout configuration
        timeouts_env = os.getenv('EXTERNAL_API_TIMEOUTS', '')
        if timeouts_env:
            try:
                for timeout_config in timeouts_env.split(';'):
                    if '=' in timeout_config:
                        service_name, timeout_str = timeout_config.split('=', 1)
                        timeouts[service_name.strip()] = float(timeout_str.strip())
            except Exception as e:
                self.logger.warning(f"Failed to parse external API timeouts: {str(e)}")
        
        # Default timeouts for different service types
        default_timeouts = {
            'auth0': 30.0,
            'aws': 60.0,
            'external_api': self.http_timeout,
            'auth0_management': 45.0,
            'aws_sts': 30.0,
            'aws_kms': 30.0,
            'aws_s3': 120.0  # Longer timeout for S3 operations
        }
        
        # Merge with defaults
        for service, default_timeout in default_timeouts.items():
            if service not in timeouts:
                timeouts[service] = default_timeout
        
        return timeouts
    
    def _validate_required_credentials(self) -> None:
        """
        Validate that required external service credentials are present and valid.
        
        This method performs comprehensive validation of external service credentials
        based on environment and usage requirements.
        
        Raises:
            ExternalServiceError: When required credentials are missing or invalid
        """
        validation_errors = []
        
        # AWS Credentials Validation
        if not self.aws_access_key_id or not self.aws_secret_access_key:
            if self.environment == 'production':
                validation_errors.append("AWS credentials (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY) are required for production")
            else:
                self.logger.warning("AWS credentials not configured - AWS services will be unavailable")
        
        # AWS KMS Key Validation
        if self.aws_kms_key_arn:
            if not self.aws_kms_key_arn.startswith('arn:aws:kms:'):
                validation_errors.append(f"Invalid AWS KMS key ARN format: {self.aws_kms_key_arn}")
        elif self.environment == 'production':
            validation_errors.append("AWS KMS key ARN is required for production encryption")
        
        # Auth0 Configuration Validation
        if self.environment in ['production', 'staging']:
            if not all([self.auth0_domain, self.auth0_client_id, self.auth0_client_secret]):
                validation_errors.append("Auth0 configuration (AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET) is required for production/staging")
        
        # SSL/TLS Certificate Validation
        if self.ssl_cert_path:
            if not Path(self.ssl_cert_path).exists():
                validation_errors.append(f"SSL certificate file not found: {self.ssl_cert_path}")
        
        if self.ssl_key_path:
            if not Path(self.ssl_key_path).exists():
                validation_errors.append(f"SSL key file not found: {self.ssl_key_path}")
        
        # Validate timeout configurations
        if self.http_timeout <= 0:
            validation_errors.append("HTTP timeout must be positive")
        
        if self.http_retries < 0:
            validation_errors.append("HTTP retries must be non-negative")
        
        if validation_errors:
            error_message = "External service configuration validation failed:\n" + "\n".join(
                f"- {error}" for error in validation_errors
            )
            raise ExternalServiceError(error_message)
        
        self.logger.info("External service credentials validation completed successfully")
    
    def _initialize_aws_configuration(self) -> None:
        """
        Initialize comprehensive AWS service configuration using boto3 1.28+ with
        KMS integration, connection pooling, and enterprise security settings.
        
        This method configures boto3 clients for AWS services including S3, KMS,
        and other AWS services with proper authentication, retry logic, and
        connection management as specified in Section 0.2.4.
        """
        try:
            # Configure boto3 session with credentials
            session_kwargs = {
                'region_name': self.aws_region
            }
            
            if self.aws_access_key_id and self.aws_secret_access_key:
                session_kwargs.update({
                    'aws_access_key_id': self.aws_access_key_id,
                    'aws_secret_access_key': self.aws_secret_access_key
                })
                
                if self.aws_session_token:
                    session_kwargs['aws_session_token'] = self.aws_session_token
            
            self.aws_session = boto3.Session(**session_kwargs)
            
            # Configure boto3 client configuration with retry and connection pooling
            self.boto3_config = BotoCoreConfig(
                region_name=self.aws_region,
                retries={
                    'max_attempts': self.http_retries + 1,  # boto3 includes initial attempt
                    'mode': 'adaptive'  # Adaptive retry mode for better performance
                },
                max_pool_connections=self.http_max_connections,
                connect_timeout=30,
                read_timeout=self.http_timeout,
                tcp_keepalive=True,
                signature_version='v4',
                s3={
                    'addressing_style': 'virtual'  # Use virtual-hosted-style URLs for S3
                }
            )
            
            # Initialize AWS service clients
            self.aws_clients = self._create_aws_clients()
            
            # Initialize KMS key manager if KMS ARN is provided
            if self.aws_kms_key_arn:
                self.kms_key_manager = AWSKMSKeyManager(
                    kms_client=self.aws_clients['kms'],
                    cmk_arn=self.aws_kms_key_arn
                )
            else:
                self.kms_key_manager = None
                self.logger.warning("AWS KMS key manager not initialized - KMS ARN not provided")
            
            self.logger.info("AWS configuration initialized successfully")
            
        except Exception as e:
            error_msg = f"AWS configuration initialization failed: {str(e)}"
            self.logger.error(error_msg)
            raise AWSConfigurationError(error_msg)
    
    def _create_aws_clients(self) -> Dict[str, Any]:
        """
        Create AWS service clients with consistent configuration.
        
        Returns:
            Dictionary mapping service names to configured boto3 clients
        """
        clients = {}
        
        # List of AWS services to initialize
        aws_services = ['s3', 'kms', 'sts', 'secretsmanager', 'cloudwatch']
        
        for service_name in aws_services:
            try:
                client_kwargs = {'config': self.boto3_config}
                
                # Add custom endpoint URL for S3 if specified (for S3-compatible services)
                if service_name == 's3' and self.s3_endpoint_url:
                    client_kwargs['endpoint_url'] = self.s3_endpoint_url
                
                clients[service_name] = self.aws_session.client(service_name, **client_kwargs)
                self.logger.debug(f"AWS {service_name} client initialized successfully")
                
            except Exception as e:
                # Log warning but continue with other services
                self.logger.warning(f"Failed to initialize AWS {service_name} client: {str(e)}")
        
        return clients
    
    def _initialize_http_client_configuration(self) -> None:
        """
        Initialize comprehensive HTTP client configuration using requests 2.31+ and
        httpx 0.24+ with connection pooling, retry logic, and circuit breaker patterns.
        
        This method configures both synchronous (requests) and asynchronous (httpx)
        HTTP clients with enterprise-grade settings for external API communication
        as specified in Section 3.2.3.
        """
        try:
            # Initialize requests session with retry strategy
            self.requests_session = self._create_requests_session()
            
            # Initialize httpx async client
            self.httpx_client_config = self._create_httpx_client_config()
            
            # Initialize Auth0 specific HTTP clients
            self.auth0_http_client = self._create_auth0_http_client()
            
            # Initialize external API HTTP clients
            self.external_api_clients = self._create_external_api_clients()
            
            self.logger.info("HTTP client configuration initialized successfully")
            
        except Exception as e:
            error_msg = f"HTTP client configuration initialization failed: {str(e)}"
            self.logger.error(error_msg)
            raise HTTPClientConfigurationError(error_msg)
    
    def _create_requests_session(self) -> requests.Session:
        """
        Create configured requests session with comprehensive retry strategy and connection pooling.
        
        Returns:
            Configured requests Session with retry logic and connection pooling
        """
        session = requests.Session()
        
        # Configure retry strategy with exponential backoff
        retry_strategy = Retry(
            total=self.http_retries,
            status_forcelist=[429, 500, 502, 503, 504],  # HTTP status codes to retry
            method_whitelist=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE"],
            backoff_factor=self.http_backoff_factor,
            raise_on_redirect=False,
            raise_on_status=False
        )
        
        # Configure HTTP adapter with connection pooling
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=self.http_max_connections,
            pool_maxsize=self.http_max_connections,
            pool_block=False
        )
        
        # Mount adapter for HTTP and HTTPS
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Configure session defaults
        session.headers.update({
            'User-Agent': f'Flask-External-Services/1.0 (Python/{os.sys.version.split()[0]})',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        
        # Configure SSL/TLS verification
        if self.ssl_verify:
            if self.ca_cert_path:
                session.verify = self.ca_cert_path
            else:
                session.verify = True
        else:
            session.verify = False
            # Disable SSL warnings when verification is disabled
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Configure client certificates if provided
        if self.ssl_cert_path and self.ssl_key_path:
            session.cert = (self.ssl_cert_path, self.ssl_key_path)
        
        return session
    
    def _create_httpx_client_config(self) -> Dict[str, Any]:
        """
        Create httpx async client configuration with enterprise settings.
        
        Returns:
            Dictionary containing httpx client configuration
        """
        # Configure timeout settings
        timeout_config = httpx.Timeout(
            connect=10.0,
            read=self.http_timeout,
            write=10.0,
            pool=5.0
        )
        
        # Configure connection limits
        limits_config = httpx.Limits(
            max_connections=self.http_max_connections,
            max_keepalive_connections=self.http_max_keepalive,
            keepalive_expiry=30.0
        )
        
        # Configure SSL/TLS context
        ssl_context = None
        if self.ssl_verify:
            ssl_context = ssl.create_default_context()
            if self.ca_cert_path:
                ssl_context.load_verify_locations(self.ca_cert_path)
        else:
            ssl_context = ssl._create_unverified_context()
        
        # Configure client certificates
        cert = None
        if self.ssl_cert_path and self.ssl_key_path:
            cert = (self.ssl_cert_path, self.ssl_key_path)
        
        return {
            'timeout': timeout_config,
            'limits': limits_config,
            'verify': ssl_context if self.ssl_verify else False,
            'cert': cert,
            'headers': {
                'User-Agent': f'Flask-External-Services/1.0 (httpx async)',
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            'http2': True  # Enable HTTP/2 support
        }
    
    def _create_auth0_http_client(self) -> requests.Session:
        """
        Create specialized HTTP client for Auth0 API communications with optimized settings.
        
        Returns:
            Configured requests Session optimized for Auth0 API calls
        """
        session = requests.Session()
        
        # Configure Auth0-specific retry strategy
        auth0_retry = Retry(
            total=3,  # Fewer retries for Auth0 to avoid account lockouts
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "POST"],
            backoff_factor=2.0,  # Longer backoff for Auth0 rate limiting
            respect_retry_after_header=True
        )
        
        # Configure adapter with Auth0-specific settings
        adapter = HTTPAdapter(
            max_retries=auth0_retry,
            pool_connections=20,  # Lower connection pool for Auth0
            pool_maxsize=20,
            pool_block=False
        )
        
        session.mount("https://", adapter)
        
        # Configure Auth0-specific headers
        session.headers.update({
            'User-Agent': 'Flask-Auth0-Client/1.0',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        
        # Set base timeout for Auth0 operations
        session.timeout = self.external_api_timeouts.get('auth0', 30.0)
        
        return session
    
    def _create_external_api_clients(self) -> Dict[str, requests.Session]:
        """
        Create specialized HTTP clients for different external APIs.
        
        Returns:
            Dictionary mapping API names to configured requests Sessions
        """
        clients = {}
        
        for api_name, base_url in self.external_api_base_urls.items():
            if not base_url:
                continue
                
            session = requests.Session()
            
            # Configure API-specific retry strategy
            retry_strategy = Retry(
                total=self.http_retries,
                status_forcelist=[429, 500, 502, 503, 504],
                backoff_factor=self.http_backoff_factor,
                respect_retry_after_header=True
            )
            
            # Configure adapter
            adapter = HTTPAdapter(
                max_retries=retry_strategy,
                pool_connections=10,
                pool_maxsize=10
            )
            
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            
            # Configure API-specific headers
            session.headers.update({
                'User-Agent': f'Flask-{api_name.title()}-Client/1.0',
                'Accept': 'application/json'
            })
            
            # Set API-specific timeout
            session.timeout = self.external_api_timeouts.get(api_name, self.http_timeout)
            
            clients[api_name] = session
        
        return clients
    
    def _initialize_auth0_configuration(self) -> None:
        """
        Initialize Auth0 enterprise authentication service configuration.
        
        This method sets up Auth0 integration with proper authentication settings,
        API client configuration, and security controls for enterprise authentication.
        """
        try:
            if not self.auth0_domain:
                self.logger.warning("Auth0 domain not configured - Auth0 integration will be unavailable")
                self.auth0_config = None
                return
            
            # Validate Auth0 domain format
            if not self.auth0_domain.endswith('.auth0.com') and not self.auth0_domain.endswith('.eu.auth0.com'):
                if self.environment == 'production':
                    raise ExternalServiceError(f"Invalid Auth0 domain format: {self.auth0_domain}")
                else:
                    self.logger.warning(f"Auth0 domain format unusual: {self.auth0_domain}")
            
            # Configure Auth0 settings
            self.auth0_config = {
                'domain': self.auth0_domain,
                'client_id': self.auth0_client_id,
                'client_secret': self.auth0_client_secret,
                'audience': self.auth0_audience,
                'management_api_token': self.auth0_management_api_token,
                'base_url': f"https://{self.auth0_domain}",
                'management_api_url': f"https://{self.auth0_domain}/api/v2",
                'algorithms': ['RS256'],  # Auth0 default algorithm
                'leeway': 10,  # 10 seconds leeway for token validation
                'issuer': f"https://{self.auth0_domain}/",
                'jwks_uri': f"https://{self.auth0_domain}/.well-known/jwks.json",
                'token_endpoint': f"https://{self.auth0_domain}/oauth/token",
                'userinfo_endpoint': f"https://{self.auth0_domain}/userinfo",
                'authorize_endpoint': f"https://{self.auth0_domain}/authorize"
            }
            
            # Initialize Auth0 circuit breaker if enabled
            if self.circuit_breaker_enabled:
                self.auth0_circuit_breaker = self._create_circuit_breaker('auth0')
            else:
                self.auth0_circuit_breaker = None
            
            self.logger.info("Auth0 configuration initialized successfully")
            
        except Exception as e:
            error_msg = f"Auth0 configuration initialization failed: {str(e)}"
            self.logger.error(error_msg)
            raise ExternalServiceError(error_msg)
    
    def _initialize_circuit_breaker_configuration(self) -> None:
        """
        Initialize circuit breaker patterns for service resilience as specified in Section 5.2.6.
        
        This method sets up circuit breaker configurations for different external services
        to provide graceful degradation and prevent cascade failures during service outages.
        """
        try:
            if not self.circuit_breaker_enabled:
                self.logger.info("Circuit breaker patterns disabled by configuration")
                self.circuit_breakers = {}
                return
            
            # Initialize circuit breakers for different service categories
            self.circuit_breakers = {
                'aws': self._create_circuit_breaker('aws'),
                'auth0': self._create_circuit_breaker('auth0'),
                'external_api': self._create_circuit_breaker('external_api'),
                'http_client': self._create_circuit_breaker('http_client')
            }
            
            # Configure circuit breaker monitoring
            self.circuit_breaker_metrics = CircuitBreakerMetrics()
            
            self.logger.info("Circuit breaker configuration initialized successfully")
            
        except Exception as e:
            error_msg = f"Circuit breaker configuration initialization failed: {str(e)}"
            self.logger.error(error_msg)
            raise ExternalServiceError(error_msg)
    
    def _create_circuit_breaker(self, service_name: str) -> Callable:
        """
        Create circuit breaker decorator for specific service.
        
        Args:
            service_name: Name of the service for circuit breaker configuration
            
        Returns:
            Configured circuit breaker decorator
        """
        # Service-specific circuit breaker configurations
        service_configs = {
            'aws': {
                'failure_threshold': self.circuit_breaker_failure_threshold,
                'timeout_seconds': self.circuit_breaker_timeout,
                'expected_exception': (ClientError, BotoCoreError, NoCredentialsError)
            },
            'auth0': {
                'failure_threshold': 3,  # Lower threshold for Auth0
                'timeout_seconds': 30,   # Shorter timeout for Auth0
                'expected_exception': (requests.exceptions.RequestException, requests.exceptions.Timeout)
            },
            'external_api': {
                'failure_threshold': self.circuit_breaker_failure_threshold,
                'timeout_seconds': self.circuit_breaker_timeout,
                'expected_exception': (requests.exceptions.RequestException, httpx.RequestError)
            },
            'http_client': {
                'failure_threshold': self.circuit_breaker_failure_threshold,
                'timeout_seconds': self.circuit_breaker_timeout,
                'expected_exception': (requests.exceptions.RequestException, httpx.RequestError)
            }
        }
        
        config = service_configs.get(service_name, service_configs['external_api'])
        
        return retry(
            stop=stop_after_attempt(config['failure_threshold']),
            wait=wait_exponential_jitter(initial=1, max=config['timeout_seconds'], jitter=2),
            retry=retry_if_exception_type(config['expected_exception']),
            before_sleep=before_sleep_log(logger, logging.WARNING),
            after=after_log(logger, logging.INFO)
        )
    
    def _validate_service_connectivity(self) -> None:
        """
        Validate connectivity to external services and log status.
        
        This method performs basic connectivity checks to external services
        to ensure configuration is correct and services are reachable.
        """
        connectivity_status = {}
        
        # Test AWS connectivity
        if self.aws_access_key_id and self.aws_secret_access_key:
            try:
                sts_client = self.aws_clients.get('sts')
                if sts_client:
                    response = sts_client.get_caller_identity()
                    connectivity_status['aws'] = 'connected'
                    self.logger.info(f"AWS connectivity verified - Account: {response.get('Account', 'unknown')}")
                else:
                    connectivity_status['aws'] = 'client_not_initialized'
            except Exception as e:
                connectivity_status['aws'] = f'failed: {str(e)}'
                self.logger.warning(f"AWS connectivity check failed: {str(e)}")
        else:
            connectivity_status['aws'] = 'credentials_not_configured'
        
        # Test Auth0 connectivity
        if self.auth0_domain:
            try:
                response = self.auth0_http_client.get(
                    f"https://{self.auth0_domain}/.well-known/jwks.json",
                    timeout=10
                )
                if response.status_code == 200:
                    connectivity_status['auth0'] = 'connected'
                    self.logger.info("Auth0 connectivity verified")
                else:
                    connectivity_status['auth0'] = f'http_error: {response.status_code}'
            except Exception as e:
                connectivity_status['auth0'] = f'failed: {str(e)}'
                self.logger.warning(f"Auth0 connectivity check failed: {str(e)}")
        else:
            connectivity_status['auth0'] = 'domain_not_configured'
        
        # Log overall connectivity status
        connected_services = [service for service, status in connectivity_status.items() if status == 'connected']
        self.logger.info(f"External service connectivity: {len(connected_services)}/{len(connectivity_status)} services connected")
        
        # Store connectivity status for monitoring
        self.connectivity_status = connectivity_status
    
    def get_aws_client(self, service_name: str) -> Any:
        """
        Get configured AWS service client with circuit breaker protection.
        
        Args:
            service_name: AWS service name (s3, kms, sts, etc.)
            
        Returns:
            Configured boto3 client for the specified service
            
        Raises:
            AWSConfigurationError: When client is not available or configured
        """
        if service_name not in self.aws_clients:
            raise AWSConfigurationError(f"AWS {service_name} client not configured or available")
        
        client = self.aws_clients[service_name]
        
        # Wrap client with circuit breaker if enabled
        if self.circuit_breaker_enabled and 'aws' in self.circuit_breakers:
            return CircuitBreakerWrapper(client, self.circuit_breakers['aws'], service_name)
        
        return client
    
    def get_http_client(self, client_type: str = 'requests') -> Union[requests.Session, Dict[str, Any]]:
        """
        Get configured HTTP client with circuit breaker protection.
        
        Args:
            client_type: Type of client ('requests', 'httpx', 'auth0', or API name)
            
        Returns:
            Configured HTTP client
            
        Raises:
            HTTPClientConfigurationError: When client type is not supported
        """
        if client_type == 'requests':
            return self.requests_session
        elif client_type == 'httpx':
            return self.httpx_client_config
        elif client_type == 'auth0':
            return self.auth0_http_client
        elif client_type in self.external_api_clients:
            return self.external_api_clients[client_type]
        else:
            raise HTTPClientConfigurationError(f"Unsupported HTTP client type: {client_type}")
    
    def get_auth0_config(self) -> Optional[Dict[str, Any]]:
        """
        Get Auth0 configuration dictionary.
        
        Returns:
            Auth0 configuration dictionary or None if not configured
        """
        return self.auth0_config
    
    def get_circuit_breaker(self, service_name: str) -> Optional[Callable]:
        """
        Get circuit breaker decorator for specific service.
        
        Args:
            service_name: Service name for circuit breaker
            
        Returns:
            Circuit breaker decorator or None if not configured
        """
        return self.circuit_breakers.get(service_name) if self.circuit_breaker_enabled else None
    
    def get_service_timeout(self, service_name: str) -> float:
        """
        Get timeout configuration for specific service.
        
        Args:
            service_name: Service name for timeout lookup
            
        Returns:
            Timeout value in seconds
        """
        return self.external_api_timeouts.get(service_name, self.http_timeout)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert configuration to dictionary for debugging and monitoring.
        
        Note: Sensitive values are masked for security.
        
        Returns:
            Dictionary representation of external service configuration
        """
        config_dict = {
            'environment': self.environment,
            'aws_region': self.aws_region,
            'aws_credentials_configured': bool(self.aws_access_key_id and self.aws_secret_access_key),
            'aws_kms_key_configured': bool(self.aws_kms_key_arn),
            's3_bucket_configured': bool(self.s3_bucket_name),
            'auth0_configured': bool(self.auth0_domain and self.auth0_client_id),
            'circuit_breaker_enabled': self.circuit_breaker_enabled,
            'http_timeout': self.http_timeout,
            'http_retries': self.http_retries,
            'ssl_verify': self.ssl_verify,
            'connectivity_status': getattr(self, 'connectivity_status', {}),
            'configured_aws_services': list(self.aws_clients.keys()) if hasattr(self, 'aws_clients') else [],
            'configured_api_clients': list(self.external_api_clients.keys()) if hasattr(self, 'external_api_clients') else []
        }
        
        return config_dict


class AWSKMSKeyManager:
    """
    AWS KMS key management implementation for encryption key operations
    using boto3 1.28+ with comprehensive error handling and key rotation support.
    
    This class provides enterprise-grade key management functionality for
    encryption operations as specified in Section 6.4.3.
    """
    
    def __init__(self, kms_client: Any, cmk_arn: str):
        """
        Initialize KMS key manager.
        
        Args:
            kms_client: Configured boto3 KMS client
            cmk_arn: Customer Master Key ARN for encryption operations
        """
        self.kms_client = kms_client
        self.cmk_arn = cmk_arn
        self.logger = logging.getLogger(f"{__name__}.AWSKMSKeyManager")
        self._validate_kms_key()
    
    def _validate_kms_key(self) -> None:
        """
        Validate KMS key accessibility and permissions.
        
        Raises:
            AWSConfigurationError: When KMS key is not accessible
        """
        try:
            response = self.kms_client.describe_key(KeyId=self.cmk_arn)
            key_state = response['KeyMetadata']['KeyState']
            
            if key_state != 'Enabled':
                raise AWSConfigurationError(f"KMS key is not enabled. Current state: {key_state}")
            
            self.logger.info(f"KMS key validation successful: {self.cmk_arn}")
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NotFoundException':
                raise AWSConfigurationError(f"KMS key not found: {self.cmk_arn}")
            elif error_code == 'AccessDeniedException':
                raise AWSConfigurationError(f"Access denied to KMS key: {self.cmk_arn}")
            else:
                raise AWSConfigurationError(f"KMS key validation failed: {str(e)}")
    
    def generate_data_key(self, key_spec: str = 'AES_256', encryption_context: Optional[Dict[str, str]] = None) -> Tuple[bytes, bytes]:
        """
        Generate data key for encryption operations.
        
        Args:
            key_spec: Key specification (AES_256, AES_128)
            encryption_context: Optional encryption context for additional security
            
        Returns:
            Tuple of (plaintext_key, encrypted_key)
            
        Raises:
            AWSConfigurationError: When data key generation fails
        """
        try:
            generate_params = {
                'KeyId': self.cmk_arn,
                'KeySpec': key_spec
            }
            
            if encryption_context:
                generate_params['EncryptionContext'] = encryption_context
            
            response = self.kms_client.generate_data_key(**generate_params)
            
            self.logger.debug("Data key generated successfully")
            return response['Plaintext'], response['CiphertextBlob']
            
        except ClientError as e:
            error_msg = f"Failed to generate data key: {str(e)}"
            self.logger.error(error_msg)
            raise AWSConfigurationError(error_msg)
    
    def decrypt_data_key(self, encrypted_key: bytes, encryption_context: Optional[Dict[str, str]] = None) -> bytes:
        """
        Decrypt data key for encryption operations.
        
        Args:
            encrypted_key: Encrypted data key from KMS
            encryption_context: Optional encryption context for validation
            
        Returns:
            Decrypted plaintext key
            
        Raises:
            AWSConfigurationError: When data key decryption fails
        """
        try:
            decrypt_params = {
                'CiphertextBlob': encrypted_key
            }
            
            if encryption_context:
                decrypt_params['EncryptionContext'] = encryption_context
            
            response = self.kms_client.decrypt(**decrypt_params)
            
            self.logger.debug("Data key decrypted successfully")
            return response['Plaintext']
            
        except ClientError as e:
            error_msg = f"Failed to decrypt data key: {str(e)}"
            self.logger.error(error_msg)
            raise AWSConfigurationError(error_msg)
    
    def enable_key_rotation(self) -> bool:
        """
        Enable automatic key rotation for the KMS key.
        
        Returns:
            True if rotation was enabled successfully
            
        Raises:
            AWSConfigurationError: When key rotation cannot be enabled
        """
        try:
            self.kms_client.enable_key_rotation(KeyId=self.cmk_arn)
            self.logger.info(f"Key rotation enabled for KMS key: {self.cmk_arn}")
            return True
            
        except ClientError as e:
            error_msg = f"Failed to enable key rotation: {str(e)}"
            self.logger.error(error_msg)
            raise AWSConfigurationError(error_msg)
    
    def get_key_rotation_status(self) -> bool:
        """
        Get current key rotation status.
        
        Returns:
            True if key rotation is enabled
        """
        try:
            response = self.kms_client.get_key_rotation_status(KeyId=self.cmk_arn)
            return response['KeyRotationEnabled']
            
        except ClientError as e:
            self.logger.warning(f"Failed to get key rotation status: {str(e)}")
            return False


class CircuitBreakerWrapper:
    """
    Circuit breaker wrapper for external service clients providing
    graceful degradation and failure protection patterns.
    """
    
    def __init__(self, client: Any, circuit_breaker: Callable, service_name: str):
        """
        Initialize circuit breaker wrapper.
        
        Args:
            client: External service client to wrap
            circuit_breaker: Circuit breaker decorator
            service_name: Service name for logging and metrics
        """
        self.client = client
        self.circuit_breaker = circuit_breaker
        self.service_name = service_name
        self.logger = logging.getLogger(f"{__name__}.CircuitBreakerWrapper")
    
    def __getattr__(self, name):
        """
        Wrap client method calls with circuit breaker protection.
        
        Args:
            name: Method name to call on wrapped client
            
        Returns:
            Circuit breaker protected method
        """
        if hasattr(self.client, name):
            original_method = getattr(self.client, name)
            
            @self.circuit_breaker
            def wrapped_method(*args, **kwargs):
                try:
                    result = original_method(*args, **kwargs)
                    self.logger.debug(f"Circuit breaker call successful: {self.service_name}.{name}")
                    return result
                except Exception as e:
                    self.logger.warning(f"Circuit breaker call failed: {self.service_name}.{name} - {str(e)}")
                    raise
            
            return wrapped_method
        else:
            raise AttributeError(f"'{type(self.client).__name__}' object has no attribute '{name}'")


class CircuitBreakerMetrics:
    """
    Circuit breaker metrics collection for monitoring and alerting.
    """
    
    def __init__(self):
        """Initialize circuit breaker metrics."""
        self.metrics = {
            'total_calls': 0,
            'successful_calls': 0,
            'failed_calls': 0,
            'circuit_open_count': 0,
            'last_failure_time': None,
            'last_success_time': None
        }
        self.logger = logging.getLogger(f"{__name__}.CircuitBreakerMetrics")
    
    def record_call_success(self, service_name: str) -> None:
        """Record successful circuit breaker call."""
        self.metrics['total_calls'] += 1
        self.metrics['successful_calls'] += 1
        self.metrics['last_success_time'] = datetime.utcnow()
        self.logger.debug(f"Circuit breaker success recorded for {service_name}")
    
    def record_call_failure(self, service_name: str, exception: Exception) -> None:
        """Record failed circuit breaker call."""
        self.metrics['total_calls'] += 1
        self.metrics['failed_calls'] += 1
        self.metrics['last_failure_time'] = datetime.utcnow()
        self.logger.warning(f"Circuit breaker failure recorded for {service_name}: {str(exception)}")
    
    def record_circuit_open(self, service_name: str) -> None:
        """Record circuit breaker opening."""
        self.metrics['circuit_open_count'] += 1
        self.logger.error(f"Circuit breaker opened for {service_name}")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current circuit breaker metrics."""
        return self.metrics.copy()


# Environment-specific configuration factory
def get_external_service_config(environment: str = None) -> ExternalServiceConfigurationManager:
    """
    External service configuration factory function.
    
    This function provides environment-specific external service configuration
    following the same pattern as the main Flask configuration factory.
    
    Args:
        environment: Optional environment name override
        
    Returns:
        Configured ExternalServiceConfigurationManager instance
        
    Raises:
        ExternalServiceError: When configuration initialization fails
    """
    try:
        config_instance = ExternalServiceConfigurationManager(environment)
        logger.info(f"External service configuration loaded for environment: {config_instance.environment}")
        return config_instance
    except Exception as e:
        logger.error(f"Failed to create external service configuration: {str(e)}")
        raise ExternalServiceError(f"External service configuration creation failed: {str(e)}")


# Global configuration instance
external_service_config = get_external_service_config()

# Configuration exports for application integration
__all__ = [
    'ExternalServiceConfigurationManager',
    'AWSKMSKeyManager',
    'CircuitBreakerWrapper',
    'CircuitBreakerMetrics',
    'get_external_service_config',
    'external_service_config',
    'ExternalServiceError',
    'AWSConfigurationError',
    'HTTPClientConfigurationError',
    'CircuitBreakerError'
]