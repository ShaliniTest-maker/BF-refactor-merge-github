"""
Business Workflow Integration Testing Suite

This module provides comprehensive integration testing for business logic workflows,
covering data flow across multiple components, business rule processors, validators,
and service orchestration. Tests complex business scenarios with realistic data
processing pipelines and multi-component data transformation maintaining behavioral
equivalence with Node.js implementation per Section 5.2.4 and F-004-RQ-001.

Key Testing Areas:
- Business logic integration across User, Order, Product, and Payment workflows
- Data transformation pipeline testing with marshmallow and pydantic validation
- Business rule processor integration with database and cache layers per Section 5.2.4
- Service orchestration testing with external service integration per Section 5.2.4
- Validation pipeline integration across request processing workflow per F-003-RQ-004
- Business workflow performance testing ensuring ≤10% variance per Section 0.1.1
- Comprehensive error handling across business logic components per Section 4.2.3

Architecture Integration Testing:
- Section 5.2.4: Business logic engine coordination and integration orchestration
- F-004-RQ-001: Identical data transformation and business rules validation
- F-004-RQ-002: Maintain all existing service integrations
- Section 6.6.3: 95% core business logic coverage mandatory for deployment
- Section 0.1.1: Business logic processing within ≤10% performance variance

Test Coverage Requirements:
- Core business logic coverage: 95% per Section 6.6.3 quality metrics
- Business rule validation: Complete pattern preservation per F-004-RQ-001
- Data transformation logic: Identical input/output characteristics per Section 5.2.4
- Performance compliance: ≤10% variance from Node.js baseline per Section 0.1.1

Dependencies Integration:
- src/business: Complete business logic package integration
- src/data: Database access layer with PyMongo/Motor integration
- src/cache: Redis caching layer with session management
- External services: Auth0, AWS, and third-party service mocking

Author: Flask Migration Team
Version: 1.0.0
Compliance: F-004-RQ-001, F-004-RQ-002, Section 5.2.4, Section 6.6.3
"""

import asyncio
import json
import pytest
import time
import uuid
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple, Union
from unittest.mock import Mock, patch, AsyncMock, MagicMock

import pytest_asyncio
from flask import Flask, current_app

# Import business logic components for comprehensive integration testing
from src.business import (
    # Core business models
    User, Organization, Product, Order, OrderItem, PaymentTransaction,
    Address, ContactInfo, MonetaryAmount, DateTimeRange,
    UserStatus, UserRole, OrderStatus, PaymentStatus, PaymentMethod, ProductStatus,
    
    # Business validators
    UserValidator, OrganizationValidator, ProductValidator, OrderValidator, PaymentValidator,
    validate_data_with_schema, create_validation_chain, batch_validate_data,
    
    # Business processors
    DataTransformer, ValidationProcessor, SanitizationProcessor, NormalizationProcessor,
    BusinessRuleEngine, ProcessingPipeline, create_processing_pipeline,
    process_business_data, ProcessingMode, ProcessingMetrics,
    
    # Business services
    UserService, OrderService, AuthenticationService, BusinessWorkflowService,
    create_user_service, create_order_service, create_authentication_service,
    create_workflow_service, get_service, ServiceConfiguration,
    
    # Business utilities and configuration
    configure_business_logic, get_business_component, validate_business_data,
    process_business_data_pipeline, ValidationConfig, ProcessingConfig,
    
    # Exception handling
    BaseBusinessException, BusinessRuleViolationError, DataValidationError,
    DataProcessingError, ExternalServiceError, ResourceNotFoundError,
    AuthorizationError, ConcurrencyError, ConfigurationError, ErrorSeverity
)

# Import data access layer for database integration testing
from src.data import (
    get_mongodb_manager, get_async_mongodb_manager, get_database_health_status,
    init_database_services, MongoDBManager, AsyncMongoDBManager
)

# Import cache layer for caching integration testing
from src.cache import (
    get_redis_client, init_redis_client, create_response_cache,
    RedisClient, FlaskResponseCache, CacheConfiguration, CachePolicy
)

# Configure structured logging for test execution
import structlog
logger = structlog.get_logger("tests.integration.business_workflow")


# ============================================================================
# TEST CONFIGURATION AND FIXTURES
# ============================================================================

@pytest.fixture(scope='session')
def business_workflow_config():
    """
    Configure business workflow testing environment.
    
    Provides comprehensive configuration for business logic integration testing
    including performance benchmarks, validation thresholds, and service mocks.
    """
    return {
        # Performance testing configuration
        'performance_variance_threshold': 0.10,  # ≤10% variance per Section 0.1.1
        'response_time_baseline_ms': 100,  # Node.js baseline for comparison
        'max_processing_time_ms': 50,  # Validation pipeline time per F-004-RQ-004
        'business_rule_execution_timeout': 2000,  # Business rule timeout (ms)
        
        # Coverage and quality requirements
        'minimum_coverage_percentage': 95,  # Section 6.6.3 requirement
        'validation_success_rate_threshold': 0.99,  # 99% validation success
        'integration_test_count_minimum': 50,  # Minimum integration scenarios
        
        # Business logic testing configuration
        'test_user_count': 25,  # Test user accounts for workflows
        'test_organization_count': 10,  # Test organizations
        'test_product_count': 50,  # Test product catalog
        'test_order_batch_size': 20,  # Order processing batch size
        'concurrent_user_simulation': 10,  # Concurrent workflow testing
        
        # External service mock configuration
        'mock_auth0_enabled': True,
        'mock_aws_s3_enabled': True,
        'mock_payment_gateway_enabled': True,
        'mock_notification_service_enabled': True,
        
        # Database and cache configuration
        'test_database_cleanup': True,
        'cache_warming_enabled': True,
        'transaction_isolation_level': 'read_committed',
        
        # Error simulation configuration
        'error_injection_rate': 0.05,  # 5% error injection for resilience testing
        'timeout_simulation_enabled': True,
        'network_failure_simulation': True
    }


@pytest.fixture(scope='function')
async def business_workflow_services(app_context, business_workflow_config):
    """
    Initialize business workflow services for integration testing.
    
    Sets up complete business service ecosystem including user management,
    order processing, authentication, and workflow orchestration services
    with proper database and cache integration.
    """
    # Configure business logic for Flask application
    configure_business_logic(current_app)
    
    # Initialize database services for business logic testing
    await init_database_services(current_app, environment='testing')
    
    # Initialize cache services
    init_redis_client(current_app.config.get('REDIS_URL', 'redis://localhost:6379/15'))
    
    # Create core business services
    services = {
        'user_service': create_user_service(),
        'order_service': create_order_service(),
        'auth_service': create_authentication_service(),
        'workflow_service': create_workflow_service()
    }
    
    # Configure service dependencies
    for service_name, service_instance in services.items():
        if hasattr(service_instance, 'configure'):
            await service_instance.configure({
                'database_manager': get_mongodb_manager(),
                'async_database_manager': get_async_mongodb_manager(),
                'cache_client': get_redis_client(),
                'performance_config': {
                    'timeout_ms': business_workflow_config['business_rule_execution_timeout'],
                    'retry_attempts': 3,
                    'circuit_breaker_enabled': True
                }
            })
    
    logger.info("Business workflow services initialized",
               services_count=len(services),
               config_keys=list(business_workflow_config.keys()))
    
    yield services
    
    # Cleanup services after testing
    for service_name, service_instance in services.items():
        if hasattr(service_instance, 'cleanup'):
            await service_instance.cleanup()


@pytest.fixture(scope='function')
def business_test_data_factory():
    """
    Factory for generating comprehensive business test data.
    
    Provides realistic test data generation for users, organizations, products,
    orders, and payments with proper relationships and business rule compliance.
    """
    
    def create_test_user(user_id: str = None, **overrides) -> Dict[str, Any]:
        """Create test user data with business rule compliance."""
        base_data = {
            'id': user_id or str(uuid.uuid4()),
            'email': f'test.user.{uuid.uuid4().hex[:8]}@example.com',
            'first_name': 'Test',
            'last_name': 'User',
            'role': UserRole.CUSTOMER,
            'status': UserStatus.ACTIVE,
            'is_locked': False,
            'contact_info': {
                'primary_email': f'contact.{uuid.uuid4().hex[:6]}@example.com',
                'primary_phone': '+1-555-0100',
                'preferred_contact_method': 'email',
                'allow_marketing': False,
                'timezone': 'UTC'
            },
            'created_at': datetime.now(timezone.utc),
            'permissions': {'user:read', 'user:update'}
        }
        base_data.update(overrides)
        return base_data
    
    def create_test_organization(**overrides) -> Dict[str, Any]:
        """Create test organization data."""
        base_data = {
            'id': str(uuid.uuid4()),
            'name': f'Test Organization {uuid.uuid4().hex[:8]}',
            'legal_name': f'Test Legal Entity {uuid.uuid4().hex[:6]}',
            'business_type': 'corporation',
            'status': UserStatus.ACTIVE,
            'is_verified': True,
            'verification_date': datetime.now(timezone.utc),
            'primary_contact': {
                'primary_email': f'org.contact.{uuid.uuid4().hex[:6]}@example.com',
                'primary_phone': '+1-555-0200',
                'preferred_contact_method': 'email'
            },
            'billing_address': {
                'street_line_1': '123 Business St',
                'city': 'Business City',
                'state_province': 'BC',
                'postal_code': '12345',
                'country_code': 'US'
            }
        }
        base_data.update(overrides)
        return base_data
    
    def create_test_product(**overrides) -> Dict[str, Any]:
        """Create test product data."""
        base_data = {
            'id': str(uuid.uuid4()),
            'name': f'Test Product {uuid.uuid4().hex[:8]}',
            'description': 'Test product for business workflow integration testing',
            'status': ProductStatus.ACTIVE,
            'price': {
                'amount': Decimal('99.99'),
                'currency_code': 'USD'
            },
            'category': 'test-category',
            'inventory_count': 100,
            'is_digital': False,
            'created_at': datetime.now(timezone.utc)
        }
        base_data.update(overrides)
        return base_data
    
    def create_test_order(user_id: str, products: List[Dict] = None, **overrides) -> Dict[str, Any]:
        """Create test order data with line items."""
        if products is None:
            products = [create_test_product()]
        
        order_items = []
        total_amount = Decimal('0.00')
        
        for product in products:
            quantity = overrides.get('quantity', 2)
            item_price = product['price']['amount']
            item_total = item_price * quantity
            total_amount += item_total
            
            order_items.append({
                'id': str(uuid.uuid4()),
                'product_id': product['id'],
                'product_name': product['name'],
                'quantity': quantity,
                'unit_price': {
                    'amount': item_price,
                    'currency_code': 'USD'
                },
                'total_price': {
                    'amount': item_total,
                    'currency_code': 'USD'
                }
            })
        
        base_data = {
            'id': str(uuid.uuid4()),
            'user_id': user_id,
            'status': OrderStatus.PENDING,
            'order_items': order_items,
            'total_amount': {
                'amount': total_amount,
                'currency_code': 'USD'
            },
            'billing_address': {
                'street_line_1': '456 Customer Ave',
                'city': 'Customer City',
                'state_province': 'CC',
                'postal_code': '67890',
                'country_code': 'US'
            },
            'created_at': datetime.now(timezone.utc)
        }
        base_data.update(overrides)
        return base_data
    
    def create_test_payment(order_id: str, amount: Decimal, **overrides) -> Dict[str, Any]:
        """Create test payment transaction data."""
        base_data = {
            'id': str(uuid.uuid4()),
            'order_id': order_id,
            'amount': {
                'amount': amount,
                'currency_code': 'USD'
            },
            'payment_method': PaymentMethod.CREDIT_CARD,
            'status': PaymentStatus.PENDING,
            'transaction_reference': f'txn_{uuid.uuid4().hex[:12]}',
            'created_at': datetime.now(timezone.utc)
        }
        base_data.update(overrides)
        return base_data
    
    return {
        'create_user': create_test_user,
        'create_organization': create_test_organization,
        'create_product': create_test_product,
        'create_order': create_test_order,
        'create_payment': create_test_payment
    }


# ============================================================================
# BUSINESS LOGIC INTEGRATION TESTS
# ============================================================================

class TestBusinessLogicIntegration:
    """
    Comprehensive business logic integration testing across multiple components.
    
    Tests the complete business logic engine coordination per Section 5.2.4
    including data transformation, validation, processing, and service integration
    with performance requirements compliance per Section 0.1.1.
    """
    
    @pytest.mark.asyncio
    async def test_user_creation_workflow_integration(
        self,
        business_workflow_services,
        business_test_data_factory,
        business_workflow_config
    ):
        """
        Test complete user creation workflow with validation and service integration.
        
        Validates:
        - User data validation using UserValidator per F-004-RQ-001
        - Business rule processing with database persistence
        - Cache integration for user session management
        - Performance compliance within ≤10% variance per Section 0.1.1
        """
        start_time = time.time()
        
        # Generate test user data
        user_data = business_test_data_factory['create_user'](
            email='integration.test@example.com',
            role=UserRole.CUSTOMER
        )
        
        # Test data validation pipeline
        validator = UserValidator()
        validated_data = validator.load(user_data)
        
        assert validated_data['email'] == user_data['email']
        assert validated_data['status'] == UserStatus.ACTIVE
        logger.info("User validation successful", user_id=validated_data['id'])
        
        # Test business rule processing
        rule_engine = BusinessRuleEngine()
        business_result = await rule_engine.process_business_rules(
            'user_creation',
            validated_data,
            context={'source': 'integration_test'}
        )
        
        assert business_result['status'] == 'success'
        assert 'user_id' in business_result['data']
        
        # Test service integration
        user_service = business_workflow_services['user_service']
        created_user = await user_service.create_user(validated_data)
        
        assert created_user['id'] == validated_data['id']
        assert created_user['email'] == validated_data['email']
        assert created_user['status'] == UserStatus.ACTIVE
        
        # Test database persistence
        db_manager = get_async_mongodb_manager()
        stored_user = await db_manager.find_one('users', {'id': created_user['id']})
        
        assert stored_user is not None
        assert stored_user['email'] == validated_data['email']
        
        # Test cache integration
        cache_client = get_redis_client()
        cache_key = f"user:session:{created_user['id']}"
        await cache_client.set(cache_key, json.dumps({
            'user_id': created_user['id'],
            'session_created': datetime.now(timezone.utc).isoformat()
        }), ttl=3600)
        
        cached_session = await cache_client.get(cache_key)
        assert cached_session is not None
        session_data = json.loads(cached_session)
        assert session_data['user_id'] == created_user['id']
        
        # Validate performance requirements
        execution_time = (time.time() - start_time) * 1000  # Convert to milliseconds
        baseline_time = business_workflow_config['response_time_baseline_ms']
        variance_threshold = business_workflow_config['performance_variance_threshold']
        max_allowed_time = baseline_time * (1 + variance_threshold)
        
        assert execution_time <= max_allowed_time, (
            f"User creation workflow exceeded performance threshold: "
            f"{execution_time:.2f}ms > {max_allowed_time:.2f}ms"
        )
        
        logger.info("User creation workflow integration test completed",
                   user_id=created_user['id'],
                   execution_time_ms=execution_time,
                   performance_compliance=True)
    
    @pytest.mark.asyncio
    async def test_order_processing_workflow_integration(
        self,
        business_workflow_services,
        business_test_data_factory,
        business_workflow_config
    ):
        """
        Test comprehensive order processing workflow integration.
        
        Validates:
        - Order validation with OrderValidator and business rules
        - Product inventory management integration
        - Payment processing workflow coordination
        - Multi-component data transformation per Section 5.2.4
        - Performance compliance per Section 0.1.1
        """
        start_time = time.time()
        
        # Create test dependencies
        user_data = business_test_data_factory['create_user']()
        product_data = business_test_data_factory['create_product'](
            inventory_count=50,
            price={'amount': Decimal('29.99'), 'currency_code': 'USD'}
        )
        
        # Create user and product in system
        user_service = business_workflow_services['user_service']
        user = await user_service.create_user(user_data)
        
        # Test order creation workflow
        order_data = business_test_data_factory['create_order'](
            user_id=user['id'],
            products=[product_data],
            quantity=3
        )
        
        # Validate order data through validation pipeline
        order_validator = OrderValidator()
        validated_order = order_validator.load(order_data)
        
        assert validated_order['user_id'] == user['id']
        assert len(validated_order['order_items']) == 1
        assert validated_order['total_amount']['amount'] == Decimal('89.97')  # 29.99 * 3
        
        # Test business rule processing for order
        rule_engine = BusinessRuleEngine()
        business_result = await rule_engine.process_business_rules(
            'order_validation',
            validated_order,
            context={
                'user': user,
                'inventory_check': True,
                'pricing_validation': True
            }
        )
        
        assert business_result['status'] == 'success'
        assert business_result['data']['inventory_available'] is True
        assert business_result['data']['pricing_valid'] is True
        
        # Test order service integration
        order_service = business_workflow_services['order_service']
        created_order = await order_service.create_order(validated_order)
        
        assert created_order['id'] == validated_order['id']
        assert created_order['status'] == OrderStatus.PENDING
        assert created_order['user_id'] == user['id']
        
        # Test payment processing integration
        payment_data = business_test_data_factory['create_payment'](
            order_id=created_order['id'],
            amount=created_order['total_amount']['amount']
        )
        
        payment_validator = PaymentValidator()
        validated_payment = payment_validator.load(payment_data)
        
        # Simulate payment processing workflow
        payment_result = await rule_engine.process_business_rules(
            'payment_processing',
            validated_payment,
            context={
                'order': created_order,
                'payment_gateway': 'mock_gateway',
                'fraud_check': True
            }
        )
        
        assert payment_result['status'] == 'success'
        assert payment_result['data']['fraud_score'] < 0.5
        assert payment_result['data']['authorization_code'] is not None
        
        # Test workflow orchestration
        workflow_service = business_workflow_services['workflow_service']
        workflow_result = await workflow_service.execute_workflow(
            'order_fulfillment',
            {
                'order': created_order,
                'payment': validated_payment,
                'user': user
            }
        )
        
        assert workflow_result['status'] == 'completed'
        assert workflow_result['order_status'] == OrderStatus.PROCESSING
        assert workflow_result['steps_completed'] >= 4  # validation, inventory, payment, notification
        
        # Validate database consistency
        db_manager = get_async_mongodb_manager()
        stored_order = await db_manager.find_one('orders', {'id': created_order['id']})
        stored_payment = await db_manager.find_one('payments', {'order_id': created_order['id']})
        
        assert stored_order is not None
        assert stored_order['status'] == OrderStatus.PROCESSING
        assert stored_payment is not None
        assert stored_payment['status'] == PaymentStatus.COMPLETED
        
        # Test cache invalidation and updates
        cache_client = get_redis_client()
        order_cache_key = f"order:{created_order['id']}"
        user_orders_cache_key = f"user:orders:{user['id']}"
        
        # Verify cache updates from workflow
        cached_order = await cache_client.get(order_cache_key)
        assert cached_order is not None
        
        await cache_client.delete(user_orders_cache_key)  # Invalidate user orders cache
        
        # Validate performance requirements
        execution_time = (time.time() - start_time) * 1000
        baseline_time = business_workflow_config['response_time_baseline_ms'] * 3  # Complex workflow
        variance_threshold = business_workflow_config['performance_variance_threshold']
        max_allowed_time = baseline_time * (1 + variance_threshold)
        
        assert execution_time <= max_allowed_time, (
            f"Order processing workflow exceeded performance threshold: "
            f"{execution_time:.2f}ms > {max_allowed_time:.2f}ms"
        )
        
        logger.info("Order processing workflow integration test completed",
                   order_id=created_order['id'],
                   user_id=user['id'],
                   payment_id=validated_payment['id'],
                   execution_time_ms=execution_time,
                   workflow_steps=workflow_result['steps_completed'])
    
    @pytest.mark.asyncio
    async def test_data_transformation_pipeline_integration(
        self,
        business_workflow_services,
        business_test_data_factory,
        business_workflow_config
    ):
        """
        Test comprehensive data transformation pipeline integration.
        
        Validates:
        - Data transformation with marshmallow and pydantic per Section 5.2.4
        - Processing pipeline coordination across multiple transformers
        - Validation and sanitization integration
        - Performance optimization per Section 0.1.1
        """
        start_time = time.time()
        
        # Create complex test data requiring transformation
        raw_user_data = {
            'email': '  UPPER.CASE@EXAMPLE.COM  ',  # Needs normalization
            'first_name': '<script>alert("test")</script>John',  # Needs sanitization
            'last_name': 'Doe-Smith',
            'phone': '555-123-4567',
            'birth_date': '1990-05-15',
            'custom_fields': {
                'preferences': ['email', 'sms'],
                'marketing_consent': 'true',
                'account_tier': 'premium'
            }
        }
        
        # Test data transformation pipeline
        transformer = DataTransformer()
        transformed_data = await transformer.transform_data(
            raw_user_data,
            target_schema='User',
            transformations=[
                'normalize_email',
                'sanitize_html',
                'validate_phone',
                'parse_date',
                'convert_types'
            ]
        )
        
        assert transformed_data['email'] == 'upper.case@example.com'
        assert transformed_data['first_name'] == 'John'  # HTML stripped
        assert transformed_data['phone'] == '+15551234567'  # Normalized format
        assert isinstance(transformed_data['birth_date'], datetime)
        assert transformed_data['custom_fields']['marketing_consent'] is True
        
        # Test validation processor integration
        validation_processor = ValidationProcessor()
        validation_result = await validation_processor.validate_data(
            transformed_data,
            validation_rules=[
                'required_fields',
                'format_validation',
                'business_rules',
                'security_checks'
            ]
        )
        
        assert validation_result['status'] == 'valid'
        assert validation_result['validation_score'] > 0.95
        assert len(validation_result['errors']) == 0
        assert len(validation_result['warnings']) == 0
        
        # Test sanitization processor
        sanitization_processor = SanitizationProcessor()
        sanitized_data = await sanitization_processor.sanitize_data(
            transformed_data,
            sanitization_rules=[
                'xss_protection',
                'sql_injection_prevention',
                'pii_handling',
                'input_length_limits'
            ]
        )
        
        assert sanitized_data['first_name'] == 'John'
        assert 'script' not in str(sanitized_data)
        assert len(sanitized_data['email']) <= 255  # Length limit applied
        
        # Test normalization processor
        normalization_processor = NormalizationProcessor()
        normalized_data = await normalization_processor.normalize_data(
            sanitized_data,
            normalization_rules=[
                'case_normalization',
                'whitespace_trimming',
                'format_standardization',
                'data_type_consistency'
            ]
        )
        
        assert normalized_data['email'].islower()
        assert not normalized_data['first_name'].startswith(' ')
        assert not normalized_data['first_name'].endswith(' ')
        
        # Test complete processing pipeline
        pipeline = create_processing_pipeline(
            processors=[
                transformer,
                validation_processor,
                sanitization_processor,
                normalization_processor
            ],
            pipeline_config={
                'error_handling': 'strict',
                'performance_monitoring': True,
                'cache_intermediate_results': True
            }
        )
        
        pipeline_result = await pipeline.process(
            raw_user_data,
            target_schema='User',
            processing_mode=ProcessingMode.COMPREHENSIVE
        )
        
        assert pipeline_result['status'] == 'success'
        assert pipeline_result['data']['email'] == 'upper.case@example.com'
        assert pipeline_result['processing_metrics']['steps_completed'] == 4
        assert pipeline_result['processing_metrics']['error_count'] == 0
        
        # Test pydantic model validation integration
        user_model = User(**pipeline_result['data'])
        assert user_model.email == 'upper.case@example.com'
        assert user_model.first_name == 'John'
        assert user_model.status == UserStatus.ACTIVE  # Default value
        
        # Test marshmallow schema validation integration
        user_validator = UserValidator()
        validated_data = user_validator.load(pipeline_result['data'])
        
        assert validated_data['email'] == user_model.email
        assert validated_data['first_name'] == user_model.first_name
        
        # Test batch processing
        batch_data = [
            business_test_data_factory['create_user']() for _ in range(10)
        ]
        
        batch_result = await pipeline.process_batch(
            batch_data,
            target_schema='User',
            batch_size=5,
            parallel_processing=True
        )
        
        assert batch_result['status'] == 'success'
        assert batch_result['processed_count'] == 10
        assert batch_result['error_count'] == 0
        assert len(batch_result['results']) == 10
        
        # Validate performance requirements
        execution_time = (time.time() - start_time) * 1000
        baseline_time = business_workflow_config['max_processing_time_ms']
        variance_threshold = business_workflow_config['performance_variance_threshold']
        max_allowed_time = baseline_time * (1 + variance_threshold)
        
        assert execution_time <= max_allowed_time, (
            f"Data transformation pipeline exceeded performance threshold: "
            f"{execution_time:.2f}ms > {max_allowed_time:.2f}ms"
        )
        
        logger.info("Data transformation pipeline integration test completed",
                   transformations_applied=4,
                   batch_processed=10,
                   execution_time_ms=execution_time,
                   validation_score=validation_result['validation_score'])


# ============================================================================
# SERVICE ORCHESTRATION INTEGRATION TESTS
# ============================================================================

class TestServiceOrchestrationIntegration:
    """
    Service orchestration integration testing across business services.
    
    Tests coordination between UserService, OrderService, AuthenticationService,
    and BusinessWorkflowService with external service integration patterns
    per Section 5.2.4 service communications.
    """
    
    @pytest.mark.asyncio
    async def test_authentication_service_integration(
        self,
        business_workflow_services,
        business_test_data_factory,
        business_workflow_config
    ):
        """
        Test authentication service integration with business workflows.
        
        Validates:
        - JWT token validation and user context creation
        - Auth0 integration patterns (mocked)
        - Session management with Redis cache
        - Authorization enforcement across business operations
        """
        start_time = time.time()
        
        # Create test user for authentication
        user_data = business_test_data_factory['create_user'](
            role=UserRole.CUSTOMER,
            permissions={'user:read', 'user:update', 'order:create'}
        )
        
        user_service = business_workflow_services['user_service']
        user = await user_service.create_user(user_data)
        
        # Test authentication service integration
        auth_service = business_workflow_services['auth_service']
        
        # Mock Auth0 JWT token generation
        with patch('src.business.services.auth0_client') as mock_auth0:
            mock_auth0.generate_token.return_value = {
                'access_token': 'mock_jwt_token',
                'token_type': 'Bearer',
                'expires_in': 3600,
                'user_id': user['id'],
                'email': user['email'],
                'roles': [user['role']]
            }
            
            # Test token creation
            token_result = await auth_service.create_user_session(user)
            
            assert token_result['status'] == 'success'
            assert token_result['access_token'] is not None
            assert token_result['user_id'] == user['id']
            assert token_result['expires_in'] == 3600
        
        # Test token validation
        with patch('src.business.services.jwt.decode') as mock_jwt_decode:
            mock_jwt_decode.return_value = {
                'user_id': user['id'],
                'email': user['email'],
                'role': user['role'],
                'permissions': list(user['permissions']),
                'exp': int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
            }
            
            validation_result = await auth_service.validate_token(
                token_result['access_token']
            )
            
            assert validation_result['status'] == 'valid'
            assert validation_result['user_id'] == user['id']
            assert validation_result['permissions'] == list(user['permissions'])
        
        # Test authorization enforcement
        authorization_result = await auth_service.check_permission(
            user['id'],
            'order:create',
            context={'resource_type': 'order', 'action': 'create'}
        )
        
        assert authorization_result['authorized'] is True
        assert authorization_result['user_id'] == user['id']
        
        # Test unauthorized access
        unauthorized_result = await auth_service.check_permission(
            user['id'],
            'admin:manage',
            context={'resource_type': 'admin', 'action': 'manage'}
        )
        
        assert unauthorized_result['authorized'] is False
        assert unauthorized_result['reason'] == 'insufficient_permissions'
        
        # Test session management with cache
        cache_client = get_redis_client()
        session_key = f"session:{user['id']}"
        
        session_data = await cache_client.get(session_key)
        assert session_data is not None
        
        stored_session = json.loads(session_data)
        assert stored_session['user_id'] == user['id']
        assert stored_session['access_token'] == token_result['access_token']
        
        # Test session invalidation
        logout_result = await auth_service.logout_user(user['id'])
        
        assert logout_result['status'] == 'success'
        assert logout_result['session_invalidated'] is True
        
        # Verify session removal from cache
        invalidated_session = await cache_client.get(session_key)
        assert invalidated_session is None
        
        # Validate performance requirements
        execution_time = (time.time() - start_time) * 1000
        baseline_time = business_workflow_config['response_time_baseline_ms']
        variance_threshold = business_workflow_config['performance_variance_threshold']
        max_allowed_time = baseline_time * (1 + variance_threshold)
        
        assert execution_time <= max_allowed_time, (
            f"Authentication service integration exceeded performance threshold: "
            f"{execution_time:.2f}ms > {max_allowed_time:.2f}ms"
        )
        
        logger.info("Authentication service integration test completed",
                   user_id=user['id'],
                   token_validated=True,
                   permissions_checked=2,
                   execution_time_ms=execution_time)
    
    @pytest.mark.asyncio
    async def test_external_service_integration_orchestration(
        self,
        business_workflow_services,
        business_test_data_factory,
        business_workflow_config
    ):
        """
        Test external service integration orchestration.
        
        Validates:
        - External service coordination patterns per Section 5.2.4
        - Circuit breaker patterns for service resilience
        - Error handling across service integrations
        - Performance monitoring for external calls
        """
        start_time = time.time()
        
        # Create test data for external service integration
        user_data = business_test_data_factory['create_user']()
        user_service = business_workflow_services['user_service']
        user = await user_service.create_user(user_data)
        
        # Test external service orchestration
        workflow_service = business_workflow_services['workflow_service']
        
        # Mock external services
        with patch('src.business.services.external_notification_service') as mock_notification, \
             patch('src.business.services.aws_s3_client') as mock_s3, \
             patch('src.business.services.payment_gateway_client') as mock_payment:
            
            # Configure mock responses
            mock_notification.send_welcome_email.return_value = {
                'status': 'sent',
                'message_id': 'msg_12345',
                'delivery_time': 150  # ms
            }
            
            mock_s3.upload_profile_image.return_value = {
                'status': 'uploaded',
                'file_url': 'https://s3.example.com/profiles/user123.jpg',
                'upload_time': 200  # ms
            }
            
            mock_payment.create_customer_profile.return_value = {
                'status': 'created',
                'customer_id': 'cust_67890',
                'profile_created': True,
                'processing_time': 300  # ms
            }
            
            # Test workflow with external service coordination
            external_service_workflow = await workflow_service.execute_workflow(
                'user_onboarding_with_external_services',
                {
                    'user': user,
                    'services': ['notification', 's3_storage', 'payment_gateway'],
                    'circuit_breaker_enabled': True,
                    'timeout_ms': 5000
                }
            )
            
            assert external_service_workflow['status'] == 'completed'
            assert external_service_workflow['external_services_called'] == 3
            assert external_service_workflow['failures'] == 0
            
            # Verify external service calls
            mock_notification.send_welcome_email.assert_called_once()
            mock_s3.upload_profile_image.assert_called_once()
            mock_payment.create_customer_profile.assert_called_once()
            
            # Test circuit breaker integration
            circuit_breaker_metrics = external_service_workflow['circuit_breaker_metrics']
            assert circuit_breaker_metrics['notification_service']['state'] == 'closed'
            assert circuit_breaker_metrics['s3_service']['state'] == 'closed'
            assert circuit_breaker_metrics['payment_service']['state'] == 'closed'
        
        # Test error handling with failing external service
        with patch('src.business.services.external_notification_service') as mock_failing_service:
            mock_failing_service.send_welcome_email.side_effect = ConnectionError("Service unavailable")
            
            error_workflow = await workflow_service.execute_workflow(
                'user_onboarding_with_external_services',
                {
                    'user': user,
                    'services': ['notification'],
                    'circuit_breaker_enabled': True,
                    'retry_attempts': 2,
                    'fallback_enabled': True
                }
            )
            
            assert error_workflow['status'] == 'completed_with_fallback'
            assert error_workflow['failed_services'] == ['notification']
            assert error_workflow['fallback_actions_taken'] == 1
            
            # Verify circuit breaker opened
            circuit_breaker_state = error_workflow['circuit_breaker_metrics']['notification_service']
            assert circuit_breaker_state['failure_count'] >= 1
            assert circuit_breaker_state['last_failure_time'] is not None
        
        # Test concurrent external service calls
        concurrent_users = [
            business_test_data_factory['create_user']() for _ in range(5)
        ]
        
        concurrent_workflows = await asyncio.gather(*[
            workflow_service.execute_workflow(
                'user_onboarding_with_external_services',
                {
                    'user': user_data,
                    'services': ['notification'],
                    'concurrent_execution': True
                }
            )
            for user_data in concurrent_users
        ])
        
        successful_workflows = [w for w in concurrent_workflows if w['status'] == 'completed']
        assert len(successful_workflows) == 5
        
        # Validate performance requirements
        execution_time = (time.time() - start_time) * 1000
        baseline_time = business_workflow_config['response_time_baseline_ms'] * 2  # External services
        variance_threshold = business_workflow_config['performance_variance_threshold']
        max_allowed_time = baseline_time * (1 + variance_threshold)
        
        assert execution_time <= max_allowed_time, (
            f"External service orchestration exceeded performance threshold: "
            f"{execution_time:.2f}ms > {max_allowed_time:.2f}ms"
        )
        
        logger.info("External service integration orchestration test completed",
                   user_id=user['id'],
                   external_services_tested=3,
                   concurrent_workflows=5,
                   circuit_breaker_tests=2,
                   execution_time_ms=execution_time)


# ============================================================================
# ERROR HANDLING AND RESILIENCE INTEGRATION TESTS
# ============================================================================

class TestErrorHandlingIntegration:
    """
    Comprehensive error handling integration testing across business components.
    
    Tests error propagation, recovery mechanisms, and resilience patterns
    per Section 4.2.3 business rule processors error handling requirements.
    """
    
    @pytest.mark.asyncio
    async def test_validation_error_handling_integration(
        self,
        business_workflow_services,
        business_test_data_factory,
        business_workflow_config
    ):
        """
        Test validation error handling across business logic components.
        
        Validates:
        - Error propagation through validation pipeline
        - Business rule violation handling
        - Data validation error recovery
        - Consistent error response formatting per F-005
        """
        start_time = time.time()
        
        # Test invalid user data validation
        invalid_user_data = {
            'email': 'invalid-email-format',  # Invalid email
            'first_name': '',  # Required field empty
            'last_name': 'A' * 300,  # Exceeds length limit
            'role': 'invalid_role',  # Invalid enum value
            'permissions': ['invalid:permission']  # Invalid permission format
        }
        
        # Test data validation error handling
        user_validator = UserValidator()
        
        with pytest.raises(DataValidationError) as validation_error:
            user_validator.load(invalid_user_data)
        
        error = validation_error.value
        assert error.error_code == 'MODEL_VALIDATION_FAILED'
        assert 'email' in str(error)
        assert 'first_name' in str(error)
        assert len(error.validation_errors) >= 4  # Multiple validation failures
        
        # Test business rule violation handling
        rule_engine = BusinessRuleEngine()
        
        # Create user with conflicting business rules
        conflicting_user_data = business_test_data_factory['create_user'](
            role=UserRole.ADMIN,  # Admin role
            status=UserStatus.INACTIVE,  # But inactive status (business rule violation)
            permissions=set()  # Admin should have permissions
        )
        
        with pytest.raises(BusinessRuleViolationError) as business_error:
            await rule_engine.process_business_rules(
                'user_creation',
                conflicting_user_data,
                context={'strict_validation': True}
            )
        
        business_rule_error = business_error.value
        assert business_rule_error.error_code in ['ADMIN_USER_INACTIVE', 'ADMIN_MISSING_PERMISSIONS']
        assert business_rule_error.severity == ErrorSeverity.HIGH
        
        # Test error recovery and fallback mechanisms
        user_service = business_workflow_services['user_service']
        
        # Test graceful degradation for invalid data
        recovery_result = await user_service.create_user_with_validation(
            invalid_user_data,
            recovery_mode='graceful_degradation',
            apply_defaults=True
        )
        
        assert recovery_result['status'] == 'partial_success'
        assert recovery_result['validation_errors'] > 0
        assert recovery_result['applied_defaults'] > 0
        assert recovery_result['user_created'] is False
        
        # Test error aggregation across multiple components
        batch_invalid_data = [
            {'email': f'invalid{i}'},  # Missing required fields
            {'email': f'user{i}@example.com', 'first_name': 'A' * 500}  # Length violation
            for i in range(5)
        ]
        
        batch_validation_result = await batch_validate_data(
            batch_invalid_data,
            'User',
            error_handling='collect_all',
            continue_on_error=True
        )
        
        assert batch_validation_result['status'] == 'completed_with_errors'
        assert batch_validation_result['total_processed'] == 10
        assert batch_validation_result['error_count'] == 10
        assert len(batch_validation_result['error_details']) == 10
        
        # Test database error handling
        db_manager = get_async_mongodb_manager()
        
        # Simulate database connection error
        with patch.object(db_manager, 'insert_one', side_effect=ConnectionError("Database unavailable")):
            
            valid_user_data = business_test_data_factory['create_user']()
            
            with pytest.raises(DataProcessingError) as db_error:
                await user_service.create_user(valid_user_data)
            
            error = db_error.value
            assert error.error_code == 'DATABASE_OPERATION_FAILED'
            assert error.processing_stage == 'user_creation'
            assert 'Database unavailable' in str(error.cause)
        
        # Test cache error handling
        cache_client = get_redis_client()
        
        # Simulate cache connection error
        with patch.object(cache_client, 'set', side_effect=ConnectionError("Redis unavailable")):
            
            # Should continue operation without cache
            cache_fallback_result = await user_service.create_user_with_caching(
                business_test_data_factory['create_user'](),
                fallback_on_cache_failure=True
            )
            
            assert cache_fallback_result['status'] == 'success'
            assert cache_fallback_result['cache_enabled'] is False
            assert cache_fallback_result['fallback_mode'] is True
            assert cache_fallback_result['user_created'] is True
        
        # Validate performance during error scenarios
        execution_time = (time.time() - start_time) * 1000
        baseline_time = business_workflow_config['response_time_baseline_ms'] * 1.5  # Error handling overhead
        variance_threshold = business_workflow_config['performance_variance_threshold']
        max_allowed_time = baseline_time * (1 + variance_threshold)
        
        assert execution_time <= max_allowed_time, (
            f"Error handling integration exceeded performance threshold: "
            f"{execution_time:.2f}ms > {max_allowed_time:.2f}ms"
        )
        
        logger.info("Validation error handling integration test completed",
                   validation_errors_tested=4,
                   business_rule_violations=1,
                   batch_errors=10,
                   database_error_simulation=True,
                   cache_error_simulation=True,
                   execution_time_ms=execution_time)
    
    @pytest.mark.asyncio
    async def test_concurrent_operation_error_handling(
        self,
        business_workflow_services,
        business_test_data_factory,
        business_workflow_config
    ):
        """
        Test error handling under concurrent operations and race conditions.
        
        Validates:
        - Concurrent operation error isolation
        - Transaction rollback and consistency
        - Resource contention handling
        - Performance under error conditions
        """
        start_time = time.time()
        
        # Create test users for concurrent operations
        concurrent_users = [
            business_test_data_factory['create_user']() for _ in range(10)
        ]
        
        user_service = business_workflow_services['user_service']
        order_service = business_workflow_services['order_service']
        
        # Test concurrent user creation with mixed valid/invalid data
        mixed_user_data = concurrent_users[:5] + [
            {'email': 'invalid'},  # Invalid data
            {'email': ''},  # Missing data
            business_test_data_factory['create_user'](email='duplicate@example.com'),
            business_test_data_factory['create_user'](email='duplicate@example.com'),  # Duplicate email
            business_test_data_factory['create_user']()  # Valid data
        ]
        
        # Execute concurrent operations
        concurrent_results = await asyncio.gather(*[
            user_service.create_user(user_data)
            for user_data in mixed_user_data
        ], return_exceptions=True)
        
        # Analyze results
        successful_operations = [r for r in concurrent_results if isinstance(r, dict) and r.get('status') == 'success']
        failed_operations = [r for r in concurrent_results if isinstance(r, Exception)]
        
        assert len(successful_operations) >= 6  # At least valid operations should succeed
        assert len(failed_operations) >= 3  # Invalid operations should fail
        
        # Verify error isolation - failures shouldn't affect other operations
        successful_user_ids = [r['user']['id'] for r in successful_operations]
        assert len(set(successful_user_ids)) == len(successful_user_ids)  # No duplicates
        
        # Test concurrent order processing with inventory conflicts
        test_product = business_test_data_factory['create_product'](inventory_count=5)
        
        # Create orders that exceed inventory
        concurrent_orders = [
            business_test_data_factory['create_order'](
                user_id=successful_operations[i % len(successful_operations)]['user']['id'],
                products=[test_product],
                quantity=2  # Total: 10 * 2 = 20, but inventory is only 5
            )
            for i in range(10)
        ]
        
        # Execute concurrent order creation
        order_results = await asyncio.gather(*[
            order_service.create_order_with_inventory_check(order_data)
            for order_data in concurrent_orders
        ], return_exceptions=True)
        
        successful_orders = [r for r in order_results if isinstance(r, dict) and r.get('status') == 'success']
        inventory_errors = [r for r in order_results if isinstance(r, Exception) 
                          and 'insufficient_inventory' in str(r)]
        
        # Should have at most 2-3 successful orders (5 inventory / 2 quantity)
        assert len(successful_orders) <= 3
        assert len(inventory_errors) >= 7
        
        # Test transaction rollback on partial failures
        workflow_service = business_workflow_services['workflow_service']
        
        # Create workflow that will fail midway
        failing_workflow_data = {
            'user': successful_operations[0]['user'],
            'operations': [
                {'type': 'create_order', 'data': concurrent_orders[0]},
                {'type': 'process_payment', 'data': {'amount': 100, 'fail_processing': True}},
                {'type': 'send_confirmation', 'data': {'email': 'test@example.com'}}
            ],
            'transaction_mode': 'atomic'
        }
        
        with pytest.raises(DataProcessingError) as workflow_error:
            await workflow_service.execute_transactional_workflow(
                'multi_step_order_processing',
                failing_workflow_data
            )
        
        # Verify rollback occurred
        error = workflow_error.value
        assert error.error_code == 'WORKFLOW_TRANSACTION_FAILED'
        assert 'payment_processing_failed' in str(error)
        
        # Verify no partial state remains
        db_manager = get_async_mongodb_manager()
        order_count = await db_manager.count_documents('orders', {
            'user_id': successful_operations[0]['user']['id']
        })
        assert order_count == 0  # Order should be rolled back
        
        # Validate performance under concurrent error conditions
        execution_time = (time.time() - start_time) * 1000
        baseline_time = business_workflow_config['response_time_baseline_ms'] * 3  # Concurrent operations
        variance_threshold = business_workflow_config['performance_variance_threshold']
        max_allowed_time = baseline_time * (1 + variance_threshold)
        
        assert execution_time <= max_allowed_time, (
            f"Concurrent error handling exceeded performance threshold: "
            f"{execution_time:.2f}ms > {max_allowed_time:.2f}ms"
        )
        
        logger.info("Concurrent operation error handling test completed",
                   concurrent_users=10,
                   successful_user_operations=len(successful_operations),
                   failed_user_operations=len(failed_operations),
                   successful_orders=len(successful_orders),
                   inventory_conflicts=len(inventory_errors),
                   transaction_rollback_tested=True,
                   execution_time_ms=execution_time)


# ============================================================================
# PERFORMANCE AND COMPLIANCE INTEGRATION TESTS
# ============================================================================

class TestPerformanceComplianceIntegration:
    """
    Performance compliance integration testing for business workflows.
    
    Validates ≤10% performance variance requirement per Section 0.1.1
    across all business logic components and integration scenarios.
    """
    
    @pytest.mark.asyncio
    async def test_business_workflow_performance_compliance(
        self,
        business_workflow_services,
        business_test_data_factory,
        business_workflow_config
    ):
        """
        Test comprehensive business workflow performance compliance.
        
        Validates:
        - Individual component performance per Section 0.1.1
        - End-to-end workflow performance benchmarks
        - Performance under concurrent load
        - Resource utilization optimization
        """
        baseline_response_time = business_workflow_config['response_time_baseline_ms']
        variance_threshold = business_workflow_config['performance_variance_threshold']
        
        performance_metrics = {
            'user_operations': [],
            'order_operations': [],
            'validation_operations': [],
            'database_operations': [],
            'cache_operations': []
        }
        
        # Test user service performance
        for i in range(25):  # Test with 25 operations
            user_data = business_test_data_factory['create_user']()
            
            start_time = time.time()
            user_service = business_workflow_services['user_service']
            user = await user_service.create_user(user_data)
            execution_time = (time.time() - start_time) * 1000
            
            performance_metrics['user_operations'].append(execution_time)
            assert user['status'] == 'success'
        
        # Analyze user operation performance
        avg_user_time = sum(performance_metrics['user_operations']) / len(performance_metrics['user_operations'])
        max_user_time = max(performance_metrics['user_operations'])
        min_user_time = min(performance_metrics['user_operations'])
        
        assert avg_user_time <= baseline_response_time * (1 + variance_threshold), (
            f"Average user operation time {avg_user_time:.2f}ms exceeds threshold"
        )
        assert max_user_time <= baseline_response_time * (1 + variance_threshold * 2), (
            f"Maximum user operation time {max_user_time:.2f}ms exceeds threshold"
        )
        
        # Test order processing performance
        test_products = [
            business_test_data_factory['create_product']() for _ in range(10)
        ]
        
        for i in range(20):  # Test with 20 order operations
            order_data = business_test_data_factory['create_order'](
                user_id=f'user_{i}',
                products=test_products[:3]  # 3 products per order
            )
            
            start_time = time.time()
            order_service = business_workflow_services['order_service']
            
            # Simulate order processing workflow
            order_result = await order_service.process_order_workflow(order_data)
            execution_time = (time.time() - start_time) * 1000
            
            performance_metrics['order_operations'].append(execution_time)
            assert order_result['status'] == 'success'
        
        # Analyze order operation performance
        avg_order_time = sum(performance_metrics['order_operations']) / len(performance_metrics['order_operations'])
        max_order_time = max(performance_metrics['order_operations'])
        
        # Order processing can take longer (multiple components)
        order_baseline = baseline_response_time * 2
        assert avg_order_time <= order_baseline * (1 + variance_threshold), (
            f"Average order operation time {avg_order_time:.2f}ms exceeds threshold"
        )
        
        # Test validation pipeline performance
        validation_data = [
            business_test_data_factory['create_user']() for _ in range(50)
        ]
        
        for data in validation_data:
            start_time = time.time()
            
            validator = UserValidator()
            validated_data = validator.load(data)
            
            execution_time = (time.time() - start_time) * 1000
            performance_metrics['validation_operations'].append(execution_time)
            
            assert validated_data['email'] == data['email']
        
        # Analyze validation performance
        avg_validation_time = sum(performance_metrics['validation_operations']) / len(performance_metrics['validation_operations'])
        max_validation_time = max(performance_metrics['validation_operations'])
        
        # Validation should be very fast
        validation_baseline = business_workflow_config['max_processing_time_ms']
        assert avg_validation_time <= validation_baseline, (
            f"Average validation time {avg_validation_time:.2f}ms exceeds {validation_baseline}ms baseline"
        )
        assert max_validation_time <= validation_baseline * 2, (
            f"Maximum validation time {max_validation_time:.2f}ms exceeds threshold"
        )
        
        # Test database operation performance
        db_manager = get_async_mongodb_manager()
        
        for i in range(30):  # Test with 30 database operations
            test_document = {
                'id': str(uuid.uuid4()),
                'test_data': f'performance_test_{i}',
                'timestamp': datetime.now(timezone.utc),
                'metadata': {'test_run': True, 'index': i}
            }
            
            start_time = time.time()
            await db_manager.insert_one('performance_test', test_document)
            execution_time = (time.time() - start_time) * 1000
            
            performance_metrics['database_operations'].append(execution_time)
        
        # Analyze database performance
        avg_db_time = sum(performance_metrics['database_operations']) / len(performance_metrics['database_operations'])
        max_db_time = max(performance_metrics['database_operations'])
        
        # Database operations baseline
        db_baseline = baseline_response_time * 0.5  # Should be faster than full operations
        assert avg_db_time <= db_baseline * (1 + variance_threshold), (
            f"Average database operation time {avg_db_time:.2f}ms exceeds threshold"
        )
        
        # Test cache operation performance
        cache_client = get_redis_client()
        
        for i in range(100):  # Test with 100 cache operations
            cache_key = f'performance_test:cache:{i}'
            cache_value = json.dumps({
                'test_data': f'cache_performance_{i}',
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
            
            start_time = time.time()
            await cache_client.set(cache_key, cache_value, ttl=300)
            await cache_client.get(cache_key)
            execution_time = (time.time() - start_time) * 1000
            
            performance_metrics['cache_operations'].append(execution_time)
        
        # Analyze cache performance
        avg_cache_time = sum(performance_metrics['cache_operations']) / len(performance_metrics['cache_operations'])
        max_cache_time = max(performance_metrics['cache_operations'])
        
        # Cache operations should be very fast (≤5ms baseline)
        cache_baseline = 5.0
        assert avg_cache_time <= cache_baseline, (
            f"Average cache operation time {avg_cache_time:.2f}ms exceeds {cache_baseline}ms baseline"
        )
        assert max_cache_time <= cache_baseline * 3, (
            f"Maximum cache operation time {max_cache_time:.2f}ms exceeds threshold"
        )
        
        # Test concurrent performance
        concurrent_start_time = time.time()
        
        concurrent_tasks = []
        for i in range(business_workflow_config['concurrent_user_simulation']):
            user_data = business_test_data_factory['create_user']()
            
            task = asyncio.create_task(
                business_workflow_services['user_service'].create_user(user_data)
            )
            concurrent_tasks.append(task)
        
        concurrent_results = await asyncio.gather(*concurrent_tasks)
        concurrent_execution_time = (time.time() - concurrent_start_time) * 1000
        
        # Concurrent operations should complete within reasonable time
        concurrent_baseline = baseline_response_time * business_workflow_config['concurrent_user_simulation'] * 0.5
        assert concurrent_execution_time <= concurrent_baseline, (
            f"Concurrent operations time {concurrent_execution_time:.2f}ms exceeds baseline"
        )
        
        # Verify all concurrent operations succeeded
        successful_concurrent = [r for r in concurrent_results if r.get('status') == 'success']
        assert len(successful_concurrent) == business_workflow_config['concurrent_user_simulation']
        
        # Generate performance compliance report
        compliance_report = {
            'test_timestamp': datetime.now(timezone.utc).isoformat(),
            'baseline_response_time_ms': baseline_response_time,
            'variance_threshold': variance_threshold,
            'performance_metrics': {
                'user_operations': {
                    'count': len(performance_metrics['user_operations']),
                    'average_ms': avg_user_time,
                    'maximum_ms': max_user_time,
                    'minimum_ms': min_user_time,
                    'compliance': avg_user_time <= baseline_response_time * (1 + variance_threshold)
                },
                'order_operations': {
                    'count': len(performance_metrics['order_operations']),
                    'average_ms': avg_order_time,
                    'maximum_ms': max_order_time,
                    'compliance': avg_order_time <= order_baseline * (1 + variance_threshold)
                },
                'validation_operations': {
                    'count': len(performance_metrics['validation_operations']),
                    'average_ms': avg_validation_time,
                    'maximum_ms': max_validation_time,
                    'compliance': avg_validation_time <= validation_baseline
                },
                'database_operations': {
                    'count': len(performance_metrics['database_operations']),
                    'average_ms': avg_db_time,
                    'maximum_ms': max_db_time,
                    'compliance': avg_db_time <= db_baseline * (1 + variance_threshold)
                },
                'cache_operations': {
                    'count': len(performance_metrics['cache_operations']),
                    'average_ms': avg_cache_time,
                    'maximum_ms': max_cache_time,
                    'compliance': avg_cache_time <= cache_baseline
                },
                'concurrent_operations': {
                    'count': business_workflow_config['concurrent_user_simulation'],
                    'total_time_ms': concurrent_execution_time,
                    'average_per_operation_ms': concurrent_execution_time / business_workflow_config['concurrent_user_simulation'],
                    'compliance': concurrent_execution_time <= concurrent_baseline
                }
            },
            'overall_compliance': all([
                avg_user_time <= baseline_response_time * (1 + variance_threshold),
                avg_order_time <= order_baseline * (1 + variance_threshold),
                avg_validation_time <= validation_baseline,
                avg_db_time <= db_baseline * (1 + variance_threshold),
                avg_cache_time <= cache_baseline,
                concurrent_execution_time <= concurrent_baseline
            ])
        }
        
        # Log comprehensive performance report
        logger.info("Business workflow performance compliance test completed",
                   **compliance_report['performance_metrics'],
                   overall_compliance=compliance_report['overall_compliance'])
        
        # Assert overall compliance
        assert compliance_report['overall_compliance'], (
            f"Performance compliance failed. Report: {json.dumps(compliance_report, indent=2)}"
        )
        
        return compliance_report


# ============================================================================
# TEST EXECUTION METADATA
# ============================================================================

# Test execution metadata for tracking and reporting
TEST_MODULE_METADATA = {
    'module_name': 'test_business_workflow_integration',
    'test_categories': [
        'business_logic_integration',
        'data_transformation_pipeline',
        'service_orchestration',
        'error_handling_resilience',
        'performance_compliance'
    ],
    'coverage_areas': [
        'src.business.models',
        'src.business.validators', 
        'src.business.processors',
        'src.business.services',
        'src.data',
        'src.cache'
    ],
    'compliance_requirements': [
        'F-004-RQ-001: Identical data transformation and business rules',
        'F-004-RQ-002: Maintain all existing service integrations',
        'Section 5.2.4: Business logic engine coordination',
        'Section 6.6.3: 95% core business logic coverage',
        'Section 0.1.1: ≤10% performance variance'
    ],
    'test_execution_requirements': {
        'minimum_coverage_percentage': 95,
        'performance_variance_threshold': 0.10,
        'concurrent_user_simulation': 10,
        'test_data_scenarios': 50
    }
}

# Mark module for pytest discovery
pytest_plugins = ['pytest_asyncio']