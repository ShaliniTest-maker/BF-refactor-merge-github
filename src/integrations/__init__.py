"""
Integration module initialization for external service client management and monitoring.

This module provides comprehensive initialization and organization for all third-party API integrations
with enterprise-grade resilience patterns, monitoring instrumentation, and centralized configuration
management. It serves as the primary external service communication layer per Section 0.1.2 and
Section 6.3.3 specifications.

Key Features:
- Flask Blueprint registration for integration health endpoints per Section 6.3.3
- Centralized imports for external service clients per Section 0.1.2
- Circuit breaker patterns for external service resilience per Section 6.3.3
- Integration monitoring endpoints for external service health verification per Section 6.3.3
- Package-level configuration for HTTP client management per Section 4.2.1
- Blueprint registration pattern for Flask application factory integration per Section 4.2.1
- Namespace organization for Auth0, AWS S3, and HTTP API integrations per Section 6.1.1

Aligned with:
- Section 0.1.2: External Integration Components - HTTP client library replacement
- Section 6.3.3: External Systems - Third-party integration patterns and monitoring
- Section 6.1.1: Flask Blueprint Architecture - Modular route organization
- Section 4.2.1: Flask Application Initialization - Blueprint registration patterns
"""

import logging
from typing import Dict, List, Optional, Any

import structlog

# Core base client infrastructure per Section 0.1.2
from .base_client import (
    BaseExternalServiceClient,
    BaseClientConfiguration,
    create_base_client_config,
    create_auth0_config,
    create_aws_s3_config,
    create_external_api_config
)

# Monitoring and health check infrastructure per Section 6.3.3
from .monitoring import (
    ExternalServiceMonitor,
    ServiceHealthState,
    ExternalServiceType,
    ServiceMetrics,
    external_service_monitor,
    monitoring_bp,
    register_auth0_monitoring,
    register_aws_s3_monitoring,
    register_mongodb_monitoring,
    register_redis_monitoring
)

# Initialize structured logger for integration module operations
logger = structlog.get_logger(__name__)

# Package version and metadata
__version__ = "1.0.0"
__author__ = "Flask Migration Team"
__description__ = "External service integration module with enterprise-grade resilience patterns"

# Global integration registry for tracking active integrations per Section 6.3.3
_integration_registry: Dict[str, BaseExternalServiceClient] = {}
_registered_services: List[str] = []
_monitoring_initialized: bool = False


class IntegrationManager:
    """
    Centralized manager for external service integrations implementing enterprise-grade
    service lifecycle management, monitoring registration, and health verification.
    
    Provides comprehensive integration management with circuit breaker patterns,
    monitoring instrumentation, and graceful shutdown capabilities per Section 6.3.3.
    """
    
    def __init__(self):
        """Initialize integration manager with monitoring and registry capabilities."""
        self._clients: Dict[str, BaseExternalServiceClient] = {}
        self._health_registry: Dict[str, ServiceMetrics] = {}
        self._initialization_order: List[str] = []
        
        logger.info("Integration manager initialized", 
                   registry_enabled=True,
                   monitoring_enabled=True)
    
    def register_client(
        self,
        service_name: str,
        client: BaseExternalServiceClient,
        service_metrics: Optional[ServiceMetrics] = None
    ) -> None:
        """
        Register external service client with monitoring integration.
        
        Args:
            service_name: Unique identifier for the external service
            client: Configured external service client instance
            service_metrics: Service metrics configuration for monitoring
        """
        if service_name in self._clients:
            logger.warning(
                "Service client already registered, replacing existing",
                service_name=service_name,
                existing_client=type(self._clients[service_name]).__name__
            )
        
        self._clients[service_name] = client
        self._initialization_order.append(service_name)
        
        # Register with global registry
        _integration_registry[service_name] = client
        if service_name not in _registered_services:
            _registered_services.append(service_name)
        
        # Register monitoring if metrics provided
        if service_metrics:
            self._health_registry[service_name] = service_metrics
            external_service_monitor.register_service(service_metrics)
        
        logger.info(
            "External service client registered",
            service_name=service_name,
            client_type=type(client).__name__,
            monitoring_enabled=service_metrics is not None,
            total_clients=len(self._clients)
        )
    
    def get_client(self, service_name: str) -> Optional[BaseExternalServiceClient]:
        """
        Retrieve registered external service client.
        
        Args:
            service_name: Service identifier
            
        Returns:
            External service client instance or None if not found
        """
        return self._clients.get(service_name)
    
    def list_clients(self) -> Dict[str, str]:
        """
        List all registered clients with their types.
        
        Returns:
            Dictionary mapping service names to client types
        """
        return {
            name: type(client).__name__ 
            for name, client in self._clients.items()
        }
    
    def check_all_health(self) -> Dict[str, Any]:
        """
        Perform comprehensive health check for all registered services.
        
        Returns:
            Dictionary containing health status for all registered services
        """
        health_summary = {
            'overall_status': 'healthy',
            'total_services': len(self._clients),
            'healthy_services': 0,
            'degraded_services': 0,
            'unhealthy_services': 0,
            'services': {}
        }
        
        for service_name, client in self._clients.items():
            try:
                health_status = client.check_health()
                health_summary['services'][service_name] = health_status
                
                # Update counters based on health status
                status = health_status.get('overall_status', 'unhealthy')
                if status == 'healthy':
                    health_summary['healthy_services'] += 1
                elif status == 'degraded':
                    health_summary['degraded_services'] += 1
                    if health_summary['overall_status'] == 'healthy':
                        health_summary['overall_status'] = 'degraded'
                else:
                    health_summary['unhealthy_services'] += 1
                    health_summary['overall_status'] = 'unhealthy'
                    
            except Exception as e:
                health_summary['services'][service_name] = {
                    'service_name': service_name,
                    'overall_status': 'error',
                    'error': str(e)
                }
                health_summary['unhealthy_services'] += 1
                health_summary['overall_status'] = 'unhealthy'
                
                logger.error(
                    "Health check failed for service",
                    service_name=service_name,
                    error=str(e)
                )
        
        return health_summary
    
    async def shutdown_all(self) -> None:
        """
        Gracefully shutdown all registered clients.
        
        Performs orderly shutdown in reverse initialization order to prevent
        dependency conflicts during resource cleanup.
        """
        logger.info("Initiating shutdown for all external service clients")
        
        # Shutdown in reverse order to handle dependencies
        shutdown_order = list(reversed(self._initialization_order))
        
        for service_name in shutdown_order:
            if service_name in self._clients:
                try:
                    client = self._clients[service_name]
                    await client.close()
                    
                    logger.info(
                        "External service client shutdown completed",
                        service_name=service_name
                    )
                    
                except Exception as e:
                    logger.error(
                        "Error during client shutdown",
                        service_name=service_name,
                        error=str(e)
                    )
        
        # Clear registries
        self._clients.clear()
        self._health_registry.clear()
        self._initialization_order.clear()
        
        logger.info("All external service clients shutdown completed")


# Global integration manager instance
integration_manager = IntegrationManager()


def configure_integration_monitoring() -> None:
    """
    Configure comprehensive integration monitoring per Section 6.3.3.
    
    Initializes monitoring for common external services including Auth0,
    AWS S3, MongoDB, and Redis with enterprise-grade health verification.
    """
    global _monitoring_initialized
    
    if _monitoring_initialized:
        logger.debug("Integration monitoring already configured")
        return
    
    try:
        # Register monitoring for common external services
        register_auth0_monitoring()
        register_aws_s3_monitoring()
        register_mongodb_monitoring()
        register_redis_monitoring()
        
        _monitoring_initialized = True
        
        logger.info(
            "Integration monitoring configured successfully",
            auth0_monitoring=True,
            aws_s3_monitoring=True,
            mongodb_monitoring=True,
            redis_monitoring=True
        )
        
    except Exception as e:
        logger.error(
            "Failed to configure integration monitoring",
            error=str(e)
        )
        raise


def register_integration_blueprints(app) -> None:
    """
    Register integration-related Flask Blueprints with the application.
    
    Implements Blueprint registration pattern for Flask application factory
    integration per Section 4.2.1 and Section 6.1.1 requirements.
    
    Args:
        app: Flask application instance
    """
    try:
        # Register monitoring Blueprint for health endpoints per Section 6.3.3
        app.register_blueprint(monitoring_bp)
        
        logger.info(
            "Integration Blueprints registered successfully",
            monitoring_blueprint=True,
            blueprint_prefix="/monitoring"
        )
        
    except Exception as e:
        logger.error(
            "Failed to register integration Blueprints",
            error=str(e)
        )
        raise


def create_auth0_client(
    domain: str,
    client_id: str,
    client_secret: str,
    **kwargs
) -> BaseExternalServiceClient:
    """
    Factory function to create Auth0 integration client with optimized configuration.
    
    Creates Auth0 client with enterprise-grade authentication patterns,
    circuit breaker protection, and comprehensive monitoring per Section 6.3.3.
    
    Args:
        domain: Auth0 domain (e.g., 'your-tenant.auth0.com')
        client_id: Auth0 application client ID
        client_secret: Auth0 application client secret
        **kwargs: Additional configuration parameters
        
    Returns:
        Configured Auth0 external service client
    """
    # Create Auth0-specific configuration
    config = create_auth0_config(
        base_url=f"https://{domain}",
        **kwargs
    )
    
    # Create base client with Auth0 configuration
    client = BaseExternalServiceClient(config)
    
    # Register with integration manager
    auth0_metrics = ServiceMetrics(
        service_name="auth0",
        service_type=ExternalServiceType.AUTH_PROVIDER,
        health_endpoint="/api/v2/",
        timeout_seconds=5.0,
        critical_threshold_ms=3000.0,
        warning_threshold_ms=1000.0
    )
    
    integration_manager.register_client("auth0", client, auth0_metrics)
    
    logger.info(
        "Auth0 client created and registered",
        domain=domain,
        monitoring_enabled=True
    )
    
    return client


def create_aws_s3_client(
    aws_access_key_id: str,
    aws_secret_access_key: str,
    region: str = 'us-east-1',
    **kwargs
) -> BaseExternalServiceClient:
    """
    Factory function to create AWS S3 integration client with optimized configuration.
    
    Creates AWS S3 client with enterprise-grade file storage patterns,
    circuit breaker protection, and comprehensive monitoring per Section 6.3.3.
    
    Args:
        aws_access_key_id: AWS access key ID
        aws_secret_access_key: AWS secret access key
        region: AWS region for S3 operations
        **kwargs: Additional configuration parameters
        
    Returns:
        Configured AWS S3 external service client
    """
    # Create AWS S3-specific configuration
    config = create_aws_s3_config(
        region=region,
        **kwargs
    )
    
    # Create base client with AWS S3 configuration
    client = BaseExternalServiceClient(config)
    
    # Register with integration manager
    s3_metrics = ServiceMetrics(
        service_name="aws_s3",
        service_type=ExternalServiceType.CLOUD_STORAGE,
        health_endpoint=None,  # S3 doesn't have a standard health endpoint
        timeout_seconds=10.0,
        critical_threshold_ms=5000.0,
        warning_threshold_ms=2000.0
    )
    
    integration_manager.register_client("aws_s3", client, s3_metrics)
    
    logger.info(
        "AWS S3 client created and registered",
        region=region,
        monitoring_enabled=True
    )
    
    return client


def create_http_api_client(
    service_name: str,
    base_url: str,
    api_key: Optional[str] = None,
    **kwargs
) -> BaseExternalServiceClient:
    """
    Factory function to create generic HTTP API integration client.
    
    Creates HTTP API client with enterprise-grade communication patterns,
    circuit breaker protection, and comprehensive monitoring per Section 6.3.3.
    
    Args:
        service_name: Unique identifier for the external API
        base_url: Base URL for the external API
        api_key: Optional API key for authentication
        **kwargs: Additional configuration parameters
        
    Returns:
        Configured HTTP API external service client
    """
    # Create external API-specific configuration
    config = create_external_api_config(
        service_name=service_name,
        base_url=base_url,
        **kwargs
    )
    
    # Add API key to default headers if provided
    if api_key:
        if not config.default_headers:
            config.default_headers = {}
        config.default_headers['Authorization'] = f"Bearer {api_key}"
    
    # Create base client with API configuration
    client = BaseExternalServiceClient(config)
    
    # Register with integration manager
    api_metrics = ServiceMetrics(
        service_name=service_name,
        service_type=ExternalServiceType.HTTP_API,
        health_endpoint="/health",  # Common health endpoint
        timeout_seconds=30.0,
        critical_threshold_ms=10000.0,
        warning_threshold_ms=5000.0
    )
    
    integration_manager.register_client(service_name, client, api_metrics)
    
    logger.info(
        "HTTP API client created and registered",
        service_name=service_name,
        base_url=base_url,
        monitoring_enabled=True
    )
    
    return client


def get_integration_summary() -> Dict[str, Any]:
    """
    Get comprehensive summary of all registered integrations.
    
    Provides enterprise-grade integration visibility with health status,
    performance metrics, and monitoring information per Section 6.3.3.
    
    Returns:
        Dictionary containing integration summary and health information
    """
    return {
        'total_integrations': len(_registered_services),
        'registered_services': _registered_services.copy(),
        'monitoring_initialized': _monitoring_initialized,
        'client_types': integration_manager.list_clients(),
        'health_summary': integration_manager.check_all_health()
    }


async def shutdown_integrations() -> None:
    """
    Gracefully shutdown all registered integrations.
    
    Implements comprehensive resource cleanup and connection management
    for enterprise-grade application lifecycle management.
    """
    logger.info("Initiating integration shutdown sequence")
    
    try:
        await integration_manager.shutdown_all()
        
        # Clear global registry
        _integration_registry.clear()
        _registered_services.clear()
        
        logger.info("Integration shutdown completed successfully")
        
    except Exception as e:
        logger.error(
            "Error during integration shutdown",
            error=str(e)
        )
        raise


# Package-level exports for external service integration per Section 6.3.3
__all__ = [
    # Core base client infrastructure
    'BaseExternalServiceClient',
    'BaseClientConfiguration',
    'create_base_client_config',
    'create_auth0_config',
    'create_aws_s3_config',
    'create_external_api_config',
    
    # Monitoring and health check infrastructure
    'ExternalServiceMonitor',
    'ServiceHealthState',
    'ExternalServiceType',
    'ServiceMetrics',
    'external_service_monitor',
    'monitoring_bp',
    
    # Integration management
    'IntegrationManager',
    'integration_manager',
    
    # Configuration and setup functions
    'configure_integration_monitoring',
    'register_integration_blueprints',
    
    # Factory functions for common integrations
    'create_auth0_client',
    'create_aws_s3_client',
    'create_http_api_client',
    
    # Utility functions
    'get_integration_summary',
    'shutdown_integrations',
    
    # Service registration functions
    'register_auth0_monitoring',
    'register_aws_s3_monitoring',
    'register_mongodb_monitoring',
    'register_redis_monitoring'
]

# Initialize integration monitoring on module import
try:
    configure_integration_monitoring()
    logger.info(
        "Integration module initialized successfully",
        version=__version__,
        monitoring_enabled=True,
        blueprint_registration_ready=True
    )
except Exception as e:
    logger.error(
        "Failed to initialize integration module",
        error=str(e)
    )
    # Don't raise here to allow module import to succeed