"""
Business Logic Package Initialization for Flask Application

This module serves as the centralized access point for all business logic components,
providing Flask Blueprint integration and seamless namespace organization for the core
application functionality engine. Establishes the business logic module as the primary
processing layer per Section 5.2.4 Business Logic Engine requirements.

The business package implements:
- Business logic engine for core application functionality per Section 5.2.4
- Flask Blueprint integration for modular business logic organization per Section 6.1.1
- Package organization providing centralized access point per Section 5.2.4
- Business logic module supporting integration orchestration per Section 5.2.4
- Performance monitoring maintaining ≤10% variance from Node.js baseline per Section 0.1.1

Package Structure:
    services.py: Business service layer for operation orchestration and external integration
    processors.py: Core data processing and transformation engine with business rules
    validators.py: Business rule validation engine using marshmallow schemas
    models.py: Pydantic data models for validation, type checking, and serialization
    exceptions.py: Business-specific exception classes and error handling patterns
    utils.py: Business utility functions for data processing and transformation

Flask Integration:
- Blueprint registration for modular business logic routes per Section 6.1.1
- Application factory pattern integration per Section 6.1.1
- Service layer initialization for dependency injection patterns
- Performance monitoring and metrics collection per Section 0.1.1
- Circuit breaker patterns for external service resilience per Section 6.1.3

Author: Business Logic Migration Team
Version: 1.0.0
License: Enterprise
"""

import logging
from typing import Dict, Any, Optional, List, Type, Union, Callable
from datetime import datetime, timezone

# Flask framework imports for Blueprint integration
from flask import Blueprint, current_app, g, request
import structlog

# Configure structured logging for business package
logger = structlog.get_logger("business")

# ============================================================================
# CORE BUSINESS LOGIC IMPORTS
# ============================================================================

# Service Layer - Business operation orchestration and external integration
from .services import (
    # Base service infrastructure
    BaseBusinessService,
    ServiceContext,
    ServiceMetrics,
    ServiceOperationType,
    ServicePriority,
    ServiceInterface,
    service_operation,
    
    # Specialized business services
    UserManagementService,
    DataProcessingService,
    IntegrationOrchestrationService,
    TransactionService,
    WorkflowService,
    
    # Service management and factory
    ServiceFactory,
    get_user_service,
    get_data_processing_service,
    get_integration_service,
    get_transaction_service,
    get_workflow_service,
    create_service_context,
    get_service_health_summary,
    get_service_metrics_summary
)

# Processing Engine - Core data processing and transformation
from .processors import (
    # Core processing classes
    ProcessingWorkflow,
    DataTransformer,
    BusinessRuleEngine,
    DateTimeProcessor,
    ProcessingMetrics,
    
    # Processing functions
    get_business_processor,
    process_business_data,
    validate_business_rules,
    monitor_performance,
    create_processing_context,
    execute_transformation_pipeline
)

# Validation Engine - Business rule validation and schema enforcement
from .validators import (
    # Validation base classes
    BaseValidator,
    BusinessRuleValidator,
    DataModelValidator,
    InputValidator,
    OutputValidator,
    ValidationContext,
    ValidationType,
    ValidationMode,
    
    # Validation functions
    validate_business_data,
    validate_request_data,
    validate_response_data,
    create_validation_schema,
    format_validation_errors
)

# Data Models - Pydantic models for validation and serialization
from .models import (
    # Core business data models
    ProcessingRequest,
    ProcessingResult,
    BusinessData,
    ValidationResult,
    TransformationRule,
    ProcessingContext,
    AuditRecord,
    
    # Request/Response models
    BaseRequest,
    BaseResponse,
    PaginatedResponse,
    ErrorResponse,
    
    # Business entity models
    User,
    Organization,
    Product,
    Order,
    Payment,
    Address,
    Contact
)

# Exception Handling - Business-specific exceptions and error management
from .exceptions import (
    # Base exception classes
    BaseBusinessException,
    BusinessRuleViolationError,
    DataValidationError,
    DataProcessingError,
    IntegrationError,
    PerformanceError,
    
    # Error classification
    ErrorSeverity,
    ErrorCategory,
    
    # Error handling utilities
    handle_business_exception,
    format_business_error,
    create_error_response
)

# Business Utilities - Helper functions for data processing and transformation
try:
    from .utils import (
        # Data validation utilities
        validate_email,
        validate_phone,
        validate_postal_code,
        
        # Data transformation utilities
        sanitize_input,
        safe_int,
        safe_float,
        safe_str,
        normalize_boolean,
        
        # Date/time utilities
        parse_date,
        format_date,
        convert_timezone,
        
        # Business calculation utilities
        round_currency,
        validate_currency,
        calculate_percentage,
        format_currency,
        
        # Data processing utilities
        deep_merge,
        hash_data,
        generate_id,
        normalize_string
    )
except ImportError as import_error:
    # Log warning for missing utilities module
    logger.warning(
        "Business utilities module not available",
        error=str(import_error),
        module="business.utils"
    )
    
    # Define minimal fallback utilities to prevent import failures
    def validate_email(email: str) -> bool:
        """Fallback email validation."""
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    def safe_str(value: Any, default: str = '') -> str:
        """Fallback safe string conversion."""
        try:
            return str(value) if value is not None else default
        except Exception:
            return default

# ============================================================================
# FLASK BLUEPRINT INTEGRATION
# ============================================================================

class BusinessLogicBlueprint:
    """
    Flask Blueprint wrapper for business logic integration.
    
    Provides centralized business logic blueprint registration and configuration
    for seamless integration with Flask application factory pattern per Section 6.1.1.
    Enables modular business logic organization with proper route handling and
    service integration patterns.
    """
    
    def __init__(self, name: str = 'business', url_prefix: str = '/api/business'):
        """
        Initialize business logic blueprint with configuration.
        
        Args:
            name: Blueprint name for Flask registration
            url_prefix: URL prefix for business logic routes
        """
        self.name = name
        self.url_prefix = url_prefix
        self.blueprint = Blueprint(name, __name__, url_prefix=url_prefix)
        self._service_registry: Dict[str, BaseBusinessService] = {}
        self._initialized = False
        
        # Configure blueprint with business logic patterns
        self._configure_blueprint()
        
        logger.info(
            "Business logic blueprint initialized",
            blueprint_name=name,
            url_prefix=url_prefix
        )
    
    def _configure_blueprint(self) -> None:
        """Configure blueprint with business logic patterns and middleware."""
        
        @self.blueprint.before_request
        def setup_business_context():
            """Set up business context for request processing."""
            try:
                # Create service context for business operations
                g.business_context = create_service_context(
                    operation_type=ServiceOperationType.PROCESS,
                    user_id=getattr(g, 'user_id', None),
                    session_id=getattr(g, 'session_id', None),
                    priority=ServicePriority.NORMAL,
                    metadata={
                        'endpoint': request.endpoint,
                        'method': request.method,
                        'path': request.path
                    }
                )
                
                # Initialize performance monitoring for business operations
                g.business_start_time = datetime.now(timezone.utc)
                
                logger.debug(
                    "Business context established",
                    operation_id=g.business_context.operation_id,
                    endpoint=request.endpoint,
                    method=request.method
                )
                
            except Exception as context_error:
                logger.error(
                    "Failed to establish business context",
                    error=str(context_error),
                    endpoint=request.endpoint
                )
                # Continue processing with minimal context
                g.business_context = create_service_context()
        
        @self.blueprint.after_request
        def finalize_business_context(response):
            """Finalize business context and collect metrics."""
            try:
                if hasattr(g, 'business_context') and hasattr(g, 'business_start_time'):
                    execution_time = (datetime.now(timezone.utc) - g.business_start_time).total_seconds()
                    
                    logger.info(
                        "Business request completed",
                        operation_id=g.business_context.operation_id,
                        execution_time=execution_time,
                        status_code=response.status_code,
                        endpoint=request.endpoint
                    )
                    
                    # Monitor performance against ≤10% variance requirement
                    monitor_performance(
                        operation_name=request.endpoint or 'unknown',
                        execution_time=execution_time,
                        context=g.business_context.to_dict()
                    )
                
            except Exception as finalize_error:
                logger.warning(
                    "Failed to finalize business context",
                    error=str(finalize_error)
                )
            
            return response
        
        @self.blueprint.errorhandler(BaseBusinessException)
        def handle_business_exception(error: BaseBusinessException):
            """Handle business-specific exceptions with proper error formatting."""
            try:
                error_response = create_error_response(error)
                
                logger.error(
                    "Business exception handled",
                    error_code=error.error_code,
                    error_message=error.message,
                    severity=error.severity.value if error.severity else 'unknown',
                    operation_id=getattr(g, 'business_context', {}).get('operation_id')
                )
                
                return error_response
                
            except Exception as handler_error:
                logger.error(
                    "Failed to handle business exception",
                    original_error=str(error),
                    handler_error=str(handler_error)
                )
                
                # Return generic error response as fallback
                return {
                    'error': 'Internal business logic error',
                    'error_code': 'BUSINESS_LOGIC_ERROR',
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }, 500
        
        # Add health check endpoint for business logic monitoring
        @self.blueprint.route('/health', methods=['GET'])
        def business_health():
            """Business logic health check endpoint."""
            try:
                health_summary = get_service_health_summary()
                
                status_code = 200 if health_summary['overall_status'] == 'healthy' else 503
                
                return health_summary, status_code
                
            except Exception as health_error:
                logger.error(
                    "Business health check failed",
                    error=str(health_error)
                )
                
                return {
                    'overall_status': 'error',
                    'error': str(health_error),
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }, 500
        
        # Add metrics endpoint for business logic performance monitoring
        @self.blueprint.route('/metrics', methods=['GET'])
        def business_metrics():
            """Business logic metrics endpoint for performance monitoring."""
            try:
                metrics_summary = get_service_metrics_summary()
                
                return metrics_summary, 200
                
            except Exception as metrics_error:
                logger.error(
                    "Business metrics collection failed",
                    error=str(metrics_error)
                )
                
                return {
                    'error': 'Metrics collection failed',
                    'error_code': 'METRICS_ERROR',
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }, 500
    
    def register_service(self, service_name: str, service_instance: BaseBusinessService) -> None:
        """
        Register business service with blueprint for dependency injection.
        
        Args:
            service_name: Unique service name for registration
            service_instance: Business service instance to register
        """
        self._service_registry[service_name] = service_instance
        
        logger.debug(
            "Business service registered",
            service_name=service_name,
            service_class=service_instance.__class__.__name__
        )
    
    def get_service(self, service_name: str) -> Optional[BaseBusinessService]:
        """
        Get registered business service by name.
        
        Args:
            service_name: Name of service to retrieve
            
        Returns:
            Business service instance or None if not found
        """
        return self._service_registry.get(service_name)
    
    def get_blueprint(self) -> Blueprint:
        """
        Get Flask blueprint for application registration.
        
        Returns:
            Configured Flask blueprint instance
        """
        return self.blueprint
    
    def initialize_services(self) -> None:
        """Initialize all business services for application startup."""
        if self._initialized:
            return
        
        try:
            # Register default business services
            default_services = {
                'user_management': get_user_service(),
                'data_processing': get_data_processing_service(),
                'integration_orchestration': get_integration_service(),
                'transaction_management': get_transaction_service(),
                'workflow_orchestration': get_workflow_service()
            }
            
            for service_name, service_instance in default_services.items():
                self.register_service(service_name, service_instance)
            
            self._initialized = True
            
            logger.info(
                "Business services initialized",
                service_count=len(self._service_registry),
                services=list(self._service_registry.keys())
            )
            
        except Exception as init_error:
            logger.error(
                "Failed to initialize business services",
                error=str(init_error)
            )
            raise
    
    def get_service_registry(self) -> Dict[str, BaseBusinessService]:
        """
        Get all registered business services.
        
        Returns:
            Dictionary of registered business services
        """
        return self._service_registry.copy()


# ============================================================================
# PACKAGE INITIALIZATION AND CONFIGURATION
# ============================================================================

# Create default business logic blueprint instance
business_blueprint = BusinessLogicBlueprint()

def init_business_logic(app=None) -> None:
    """
    Initialize business logic package with Flask application.
    
    Provides centralized initialization for business logic components including
    service registration, blueprint configuration, and performance monitoring
    setup per Section 6.1.1 Flask application factory pattern.
    
    Args:
        app: Flask application instance (optional, uses current_app if not provided)
    """
    try:
        if app is None:
            app = current_app
        
        # Initialize business services
        business_blueprint.initialize_services()
        
        # Register blueprint with application
        if not any(bp.name == business_blueprint.name for bp in app.blueprints.values()):
            app.register_blueprint(business_blueprint.get_blueprint())
            
            logger.info(
                "Business logic blueprint registered with Flask application",
                blueprint_name=business_blueprint.name,
                url_prefix=business_blueprint.url_prefix
            )
        
        # Configure business logic specific settings
        app.config.setdefault('BUSINESS_LOGIC_CACHE_TTL', 3600)
        app.config.setdefault('BUSINESS_LOGIC_TIMEOUT', 30.0)
        app.config.setdefault('BUSINESS_LOGIC_PERFORMANCE_MONITORING', True)
        app.config.setdefault('BUSINESS_LOGIC_CIRCUIT_BREAKER_ENABLED', True)
        
        logger.info(
            "Business logic package initialized successfully",
            app_name=getattr(app, 'name', 'unknown'),
            business_services=len(business_blueprint.get_service_registry()),
            performance_monitoring=app.config.get('BUSINESS_LOGIC_PERFORMANCE_MONITORING', False)
        )
        
    except Exception as init_error:
        logger.error(
            "Failed to initialize business logic package",
            error=str(init_error)
        )
        raise


def get_business_blueprint() -> BusinessLogicBlueprint:
    """
    Get business logic blueprint instance for application integration.
    
    Returns:
        BusinessLogicBlueprint instance for Flask application registration
    """
    return business_blueprint


def register_business_service(service_name: str, service_instance: BaseBusinessService) -> None:
    """
    Register custom business service with the business logic package.
    
    Args:
        service_name: Unique service name for registration
        service_instance: Business service instance to register
    """
    business_blueprint.register_service(service_name, service_instance)
    
    logger.info(
        "Custom business service registered",
        service_name=service_name,
        service_class=service_instance.__class__.__name__
    )


def get_business_service(service_name: str) -> Optional[BaseBusinessService]:
    """
    Get business service by name from the service registry.
    
    Args:
        service_name: Name of service to retrieve
        
    Returns:
        Business service instance or None if not found
    """
    return business_blueprint.get_service(service_name)


# ============================================================================
# PACKAGE EXPORTS AND PUBLIC API
# ============================================================================

# Export main service classes for external use
__all__ = [
    # Core service infrastructure
    'BaseBusinessService',
    'ServiceContext',
    'ServiceMetrics',
    'ServiceOperationType',
    'ServicePriority',
    'ServiceInterface',
    'service_operation',
    
    # Specialized business services
    'UserManagementService',
    'DataProcessingService',
    'IntegrationOrchestrationService',
    'TransactionService',
    'WorkflowService',
    
    # Service management and utilities
    'ServiceFactory',
    'get_user_service',
    'get_data_processing_service',
    'get_integration_service',
    'get_transaction_service',
    'get_workflow_service',
    'create_service_context',
    'get_service_health_summary',
    'get_service_metrics_summary',
    
    # Processing engine components
    'ProcessingWorkflow',
    'DataTransformer',
    'BusinessRuleEngine',
    'DateTimeProcessor',
    'ProcessingMetrics',
    'get_business_processor',
    'process_business_data',
    'validate_business_rules',
    'monitor_performance',
    
    # Validation engine components
    'BaseValidator',
    'BusinessRuleValidator',
    'DataModelValidator',
    'InputValidator',
    'OutputValidator',
    'ValidationContext',
    'ValidationType',
    'ValidationMode',
    'validate_business_data',
    'validate_request_data',
    'validate_response_data',
    'format_validation_errors',
    
    # Data models
    'ProcessingRequest',
    'ProcessingResult',
    'BusinessData',
    'ValidationResult',
    'TransformationRule',
    'ProcessingContext',
    'AuditRecord',
    'BaseRequest',
    'BaseResponse',
    'PaginatedResponse',
    'ErrorResponse',
    'User',
    'Organization',
    'Product',
    'Order',
    'Payment',
    'Address',
    'Contact',
    
    # Exception handling
    'BaseBusinessException',
    'BusinessRuleViolationError',
    'DataValidationError',
    'DataProcessingError',
    'IntegrationError',
    'PerformanceError',
    'ErrorSeverity',
    'ErrorCategory',
    'handle_business_exception',
    'format_business_error',
    'create_error_response',
    
    # Flask integration
    'BusinessLogicBlueprint',
    'business_blueprint',
    'init_business_logic',
    'get_business_blueprint',
    'register_business_service',
    'get_business_service',
    
    # Utility functions (with fallbacks)
    'validate_email',
    'safe_str'
]

# Package metadata and version information
__version__ = "1.0.0"
__author__ = "Business Logic Migration Team"
__license__ = "Enterprise"
__description__ = "Business logic package for Flask application factory integration"

# Package initialization logging
logger.info(
    "Business logic package loaded successfully",
    package_version=__version__,
    exported_symbols=len(__all__),
    blueprint_name=business_blueprint.name,
    features=[
        "business_operation_orchestration",
        "flask_blueprint_integration",
        "service_layer_architecture", 
        "performance_monitoring",
        "circuit_breaker_patterns",
        "comprehensive_validation",
        "data_processing_engine",
        "external_service_integration",
        "transaction_management",
        "workflow_orchestration"
    ]
)