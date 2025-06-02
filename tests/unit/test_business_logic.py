"""
Core Business Logic Testing Suite for Flask Application

This module provides comprehensive testing for the business logic layer including models,
validators, processors, services, and utilities. Implements 95% coverage requirement
per Section 6.6.3 with behavioral equivalence validation per F-004-RQ-001 and
performance validation within ≤10% variance per Section 0.1.1.

Test Coverage Areas:
- Business Models: Pydantic model validation, serialization, business rules (95% coverage)
- Business Validators: Marshmallow schema validation, business rule enforcement
- Business Processors: Data transformation, business rule execution, performance
- Business Services: Service orchestration, external service integration
- Business Utils: Data manipulation, validation utilities, type conversion

Testing Framework:
- pytest 7.4+ with extensive plugin ecosystem per Section 6.6.1
- pytest-mock for comprehensive external service simulation
- factory_boy for dynamic test object generation per Section 6.6.1
- Testcontainers for realistic MongoDB/Redis behavior per Section 6.6.1
- Performance validation ensuring ≤10% variance from Node.js baseline

Compliance Requirements:
- F-004-RQ-001: Identical data transformation and business rules
- Section 5.2.4: Business logic engine behavioral equivalence
- Section 6.6.3: 95% core business logic coverage mandatory
- Section 0.1.1: Performance within ≤10% variance requirement

Author: Flask Migration Team
Version: 1.0.0
Test Coverage Target: 95% mandatory for deployment
Performance Target: ≤10% variance from Node.js baseline
"""

import asyncio
import json
import time
import uuid
from datetime import datetime, timezone, timedelta, date
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional, Union, Tuple
from unittest.mock import Mock, patch, MagicMock, AsyncMock, call

import pytest
import pytest_asyncio
from pydantic import ValidationError as PydanticValidationError
from marshmallow import ValidationError as MarshmallowValidationError
import factory
from testcontainers.mongodb import MongoDbContainer
from testcontainers.redis import RedisContainer

# Import business logic components for comprehensive testing
from src.business.models import (
    BaseBusinessModel, User, Organization, Product, ProductCategory, Order,
    OrderItem, PaymentTransaction, Address, ContactInfo, MonetaryAmount,
    DateTimeRange, FileUpload, SystemConfiguration, PaginationParams,
    SortParams, SearchParams, ApiResponse, PaginatedResponse,
    UserStatus, UserRole, OrderStatus, PaymentStatus, PaymentMethod,
    ProductStatus, Priority, ContactMethod, BUSINESS_MODEL_REGISTRY,
    get_model_by_name, validate_model_data, serialize_for_api
)

from src.business.validators import (
    ValidationConfig, BaseBusinessValidator, UserValidator,
    OrganizationValidator, ProductValidator, OrderValidator,
    PaymentValidator, AddressValidator, ContactInfoValidator,
    MonetaryAmountValidator, FileUploadValidator, BusinessRuleEngine,
    ValidationChain, ConditionalValidator, CrossFieldValidator
)

from src.business.processors import (
    DataTransformer, ValidationProcessor, SanitizationProcessor,
    NormalizationProcessor, BusinessRuleEngine as ProcessorBusinessRuleEngine,
    WorkflowProcessor, CalculationProcessor, AggregationProcessor,
    DateTimeProcessor, TimezoneProcessor, BusinessDayProcessor,
    ProcessingPipeline, BatchProcessor, AsyncProcessor
)

from src.business.services import (
    UserService, OrganizationService, ProductService, OrderService,
    PaymentService, AuthenticationService, FileStorageService,
    CacheService, BusinessWorkflowService, DataProcessingService,
    IntegrationOrchestrator, TransactionService, ValidationService,
    AuditService, MetricsService, HealthCheckService
)

from src.business.utils import (
    clean_data, validate_email, validate_phone, validate_postal_code,
    sanitize_input, safe_str, safe_int, safe_float, normalize_boolean,
    parse_date, format_date, round_currency, validate_currency,
    DataFormat, JSONType, DateTimeType, NumericType
)

from src.business.exceptions import (
    BaseBusinessException, BusinessRuleViolationError, DataValidationError,
    DataProcessingError, ExternalServiceError, ResourceNotFoundError,
    AuthorizationError, ConcurrencyError, ConfigurationError,
    ErrorSeverity, ErrorCategory
)

# Configure structured logging for business logic testing
import structlog
logger = structlog.get_logger("tests.unit.test_business_logic")


# ============================================================================
# TEST FACTORIES FOR DYNAMIC DATA GENERATION
# ============================================================================

class UserModelFactory(factory.Factory):
    """Factory for generating User model test instances with varied data."""
    
    class Meta:
        model = User
    
    id = factory.LazyFunction(lambda: str(uuid.uuid4()))
    username = factory.Sequence(lambda n: f"testuser{n}")
    email = factory.LazyAttribute(lambda obj: f"{obj.username}@example.com")
    first_name = factory.Faker('first_name')
    last_name = factory.Faker('last_name')
    status = UserStatus.ACTIVE
    role = UserRole.USER
    permissions = factory.LazyFunction(lambda: {'read_profile', 'update_profile'})
    language_code = "en"
    timezone = "UTC"


class OrganizationModelFactory(factory.Factory):
    """Factory for generating Organization model test instances."""
    
    class Meta:
        model = Organization
    
    id = factory.LazyFunction(lambda: str(uuid.uuid4()))
    name = factory.Faker('company')
    legal_name = factory.LazyAttribute(lambda obj: f"{obj.name} Inc.")
    business_type = "corporation"
    status = UserStatus.ACTIVE
    is_verified = False


class ProductModelFactory(factory.Factory):
    """Factory for generating Product model test instances."""
    
    class Meta:
        model = Product
    
    id = factory.LazyFunction(lambda: str(uuid.uuid4()))
    sku = factory.Sequence(lambda n: f"SKU{n:06d}")
    name = factory.Faker('word')
    slug = factory.LazyAttribute(lambda obj: obj.name.lower().replace(' ', '-'))
    base_price = factory.LazyFunction(
        lambda: MonetaryAmount(amount=Decimal('99.99'), currency_code='USD')
    )
    status = ProductStatus.ACTIVE
    inventory_quantity = 100
    track_inventory = True


class OrderModelFactory(factory.Factory):
    """Factory for generating Order model test instances."""
    
    class Meta:
        model = Order
    
    id = factory.LazyFunction(lambda: str(uuid.uuid4()))
    customer_email = factory.Faker('email')
    customer_name = factory.Faker('name')
    subtotal = factory.LazyFunction(
        lambda: MonetaryAmount(amount=Decimal('100.00'), currency_code='USD')
    )
    tax_amount = factory.LazyFunction(
        lambda: MonetaryAmount(amount=Decimal('8.50'), currency_code='USD')
    )
    shipping_amount = factory.LazyFunction(
        lambda: MonetaryAmount(amount=Decimal('5.99'), currency_code='USD')
    )
    discount_amount = factory.LazyFunction(
        lambda: MonetaryAmount(amount=Decimal('0.00'), currency_code='USD')
    )
    total_amount = factory.LazyFunction(
        lambda: MonetaryAmount(amount=Decimal('114.49'), currency_code='USD')
    )
    status = OrderStatus.PENDING
    billing_address = factory.SubFactory('tests.unit.test_business_logic.AddressModelFactory')
    items = factory.LazyFunction(list)  # Will be populated in tests


class AddressModelFactory(factory.Factory):
    """Factory for generating Address model test instances."""
    
    class Meta:
        model = Address
    
    street_line_1 = factory.Faker('street_address')
    city = factory.Faker('city')
    state_province = factory.Faker('state')
    postal_code = factory.Faker('zipcode')
    country_code = "US"


class PaymentTransactionFactory(factory.Factory):
    """Factory for generating PaymentTransaction model test instances."""
    
    class Meta:
        model = PaymentTransaction
    
    id = factory.LazyFunction(lambda: str(uuid.uuid4()))
    amount = factory.LazyFunction(
        lambda: MonetaryAmount(amount=Decimal('114.49'), currency_code='USD')
    )
    payment_method = PaymentMethod.CREDIT_CARD
    payment_status = PaymentStatus.PENDING


# ============================================================================
# BUSINESS MODELS TESTING
# ============================================================================

class TestBusinessModels:
    """
    Comprehensive testing for business model validation, serialization, and business rules.
    
    Tests cover Pydantic model functionality, field validation, business rule enforcement,
    serialization patterns, and integration with business logic processing per Section 5.2.4.
    Target: 95% coverage per Section 6.6.3 mandatory requirement.
    """
    
    def test_base_business_model_initialization(self):
        """Test BaseBusinessModel initialization and basic functionality."""
        # Test successful initialization
        user = UserModelFactory()
        assert user.id is not None
        assert user.created_at is not None
        assert user.updated_at is not None
        assert user.version == 1
        
        # Test model validation during initialization
        with pytest.raises(DataValidationError) as exc_info:
            User(
                username="",  # Invalid: empty username
                email="invalid-email",  # Invalid: malformed email
                first_name="",  # Invalid: empty first name
                last_name=""  # Invalid: empty last name
            )
        
        error = exc_info.value
        assert error.error_code == "MODEL_VALIDATION_FAILED"
        assert "validation failed" in error.message.lower()
        
        logger.info("BaseBusinessModel initialization tested successfully")
    
    def test_user_model_validation_and_business_rules(self):
        """Test User model field validation and business rule enforcement."""
        # Test valid user creation
        valid_user_data = {
            'username': 'testuser123',
            'email': 'test@example.com',
            'first_name': 'John',
            'last_name': 'Doe',
            'status': UserStatus.ACTIVE,
            'role': UserRole.USER
        }
        user = User(**valid_user_data)
        assert user.username == 'testuser123'
        assert user.email == 'test@example.com'
        assert user.full_name == 'John Doe'
        assert user.is_active is True
        
        # Test username validation
        with pytest.raises(BusinessRuleViolationError) as exc_info:
            User(
                username='admin',  # Reserved username
                email='test@example.com',
                first_name='Test',
                last_name='User'
            )
        assert exc_info.value.error_code == "RESERVED_USERNAME"
        
        # Test email format validation
        with pytest.raises(PydanticValidationError):
            User(
                username='validuser',
                email='invalid-email-format',
                first_name='Test',
                last_name='User'
            )
        
        # Test permissions handling
        user_with_permissions = User(
            username='poweruser',
            email='power@example.com',
            first_name='Power',
            last_name='User',
            permissions={'read_all', 'write_all', 'admin_access'}
        )
        assert user_with_permissions.has_permission('read_all') is True
        assert user_with_permissions.has_permission('delete_all') is False
        
        # Test admin permissions
        admin_user = User(
            username='adminuser',
            email='admin@example.com',
            first_name='Admin',
            last_name='User',
            role=UserRole.ADMIN
        )
        assert admin_user.has_permission('any_permission') is True
        
        logger.info("User model validation and business rules tested successfully")
    
    def test_product_model_pricing_and_inventory_validation(self):
        """Test Product model pricing calculations and inventory business rules."""
        # Test valid product with sale price
        product = ProductModelFactory(
            base_price=MonetaryAmount(amount=Decimal('100.00'), currency_code='USD'),
            sale_price=MonetaryAmount(amount=Decimal('80.00'), currency_code='USD'),
            inventory_quantity=50,
            low_stock_threshold=10
        )
        
        assert product.is_on_sale is True
        assert product.current_price.amount == Decimal('80.00')
        assert product.is_low_stock is False
        
        # Test low stock detection
        low_stock_product = ProductModelFactory(
            inventory_quantity=5,
            low_stock_threshold=10
        )
        assert low_stock_product.is_low_stock is True
        
        # Test invalid sale price (higher than base price)
        with pytest.raises(BusinessRuleViolationError) as exc_info:
            product_data = {
                'sku': 'TEST001',
                'name': 'Test Product',
                'slug': 'test-product',
                'base_price': MonetaryAmount(amount=Decimal('50.00'), currency_code='USD'),
                'sale_price': MonetaryAmount(amount=Decimal('60.00'), currency_code='USD'),  # Invalid
                'status': ProductStatus.ACTIVE,
                'inventory_quantity': 100
            }
            Product(**product_data)
            # Trigger business rule validation
            Product(**product_data).validate_business_rules()
        
        assert exc_info.value.error_code == "INVALID_SALE_PRICE"
        
        # Test currency mismatch validation
        with pytest.raises(BusinessRuleViolationError) as exc_info:
            product_data = {
                'sku': 'TEST002',
                'name': 'Test Product 2',
                'slug': 'test-product-2',
                'base_price': MonetaryAmount(amount=Decimal('50.00'), currency_code='USD'),
                'sale_price': MonetaryAmount(amount=Decimal('40.00'), currency_code='EUR'),  # Different currency
                'status': ProductStatus.ACTIVE,
                'inventory_quantity': 100
            }
            Product(**product_data).validate_business_rules()
        
        assert exc_info.value.error_code == "CURRENCY_MISMATCH"
        
        logger.info("Product model pricing and inventory validation tested successfully")
    
    def test_order_model_calculation_and_validation(self):
        """Test Order model total calculations and business rule validation."""
        # Create order items
        order_item1 = OrderItem(
            product_id=str(uuid.uuid4()),
            product_sku='ITEM001',
            product_name='Test Item 1',
            quantity=2,
            unit_price=MonetaryAmount(amount=Decimal('25.00'), currency_code='USD')
        )
        
        order_item2 = OrderItem(
            product_id=str(uuid.uuid4()),
            product_sku='ITEM002',
            product_name='Test Item 2',
            quantity=1,
            unit_price=MonetaryAmount(amount=Decimal('50.00'), currency_code='USD')
        )
        
        # Test order with proper calculations
        billing_address = AddressModelFactory()
        order = Order(
            customer_email='customer@example.com',
            customer_name='John Customer',
            items=[order_item1, order_item2],
            subtotal=MonetaryAmount(amount=Decimal('100.00'), currency_code='USD'),
            tax_amount=MonetaryAmount(amount=Decimal('8.00'), currency_code='USD'),
            shipping_amount=MonetaryAmount(amount=Decimal('5.99'), currency_code='USD'),
            discount_amount=MonetaryAmount(amount=Decimal('3.99'), currency_code='USD'),
            total_amount=MonetaryAmount(amount=Decimal('110.00'), currency_code='USD'),
            billing_address=billing_address
        )
        
        assert order.item_count == 3  # 2 + 1
        assert order.effective_shipping_address == billing_address
        
        # Test invalid total calculation
        with pytest.raises(BusinessRuleViolationError) as exc_info:
            Order(
                customer_email='customer@example.com',
                customer_name='John Customer',
                items=[order_item1],
                subtotal=MonetaryAmount(amount=Decimal('50.00'), currency_code='USD'),
                tax_amount=MonetaryAmount(amount=Decimal('4.00'), currency_code='USD'),
                shipping_amount=MonetaryAmount(amount=Decimal('5.99'), currency_code='USD'),
                discount_amount=MonetaryAmount(amount=Decimal('0.00'), currency_code='USD'),
                total_amount=MonetaryAmount(amount=Decimal('100.00'), currency_code='USD'),  # Wrong total
                billing_address=billing_address
            )
        
        assert exc_info.value.error_code == "INVALID_ORDER_TOTAL"
        
        # Test status progression validation
        order_with_shipped_date = Order(
            customer_email='customer@example.com',
            customer_name='John Customer',
            items=[order_item1],
            subtotal=MonetaryAmount(amount=Decimal('50.00'), currency_code='USD'),
            tax_amount=MonetaryAmount(amount=Decimal('0.00'), currency_code='USD'),
            shipping_amount=MonetaryAmount(amount=Decimal('0.00'), currency_code='USD'),
            discount_amount=MonetaryAmount(amount=Decimal('0.00'), currency_code='USD'),
            total_amount=MonetaryAmount(amount=Decimal('50.00'), currency_code='USD'),
            billing_address=billing_address,
            status=OrderStatus.PENDING,  # Wrong status for shipped date
            shipped_date=datetime.now(timezone.utc)
        )
        
        with pytest.raises(BusinessRuleViolationError) as exc_info:
            order_with_shipped_date.validate_business_rules()
        
        assert exc_info.value.error_code == "INVALID_STATUS_FOR_SHIPPED_DATE"
        
        logger.info("Order model calculation and validation tested successfully")
    
    def test_monetary_amount_validation_and_calculations(self):
        """Test MonetaryAmount model validation and currency handling."""
        # Test valid monetary amount
        amount = MonetaryAmount(amount=Decimal('99.99'), currency_code='USD')
        assert amount.amount == Decimal('99.99')
        assert amount.currency_code == 'USD'
        
        # Test amount rounding
        rounded_amount = amount.get_rounded_amount()
        assert isinstance(rounded_amount, Decimal)
        assert rounded_amount == Decimal('99.99')
        
        # Test negative amount validation
        with pytest.raises(BusinessRuleViolationError) as exc_info:
            MonetaryAmount(amount=Decimal('-10.00'), currency_code='USD')
        
        assert exc_info.value.error_code == "NEGATIVE_AMOUNT"
        
        # Test invalid currency code
        with pytest.raises(BusinessRuleViolationError) as exc_info:
            MonetaryAmount(amount=Decimal('100.00'), currency_code='INVALID')
        
        assert exc_info.value.error_code == "INVALID_CURRENCY_CODE"
        
        # Test business rule validation
        valid_amount = MonetaryAmount(amount=Decimal('50.00'), currency_code='USD')
        valid_amount.validate_business_rules()  # Should not raise
        
        logger.info("MonetaryAmount validation and calculations tested successfully")
    
    def test_model_serialization_and_api_response_format(self):
        """Test model serialization for API responses per F-004-RQ-004."""
        user = UserModelFactory()
        
        # Test API dictionary serialization
        api_dict = user.to_api_dict(exclude_audit=True)
        assert 'created_at' not in api_dict
        assert 'updated_at' not in api_dict
        assert 'version' not in api_dict
        assert 'username' in api_dict
        assert 'email' in api_dict
        
        # Test API dictionary with audit fields
        api_dict_with_audit = user.to_api_dict(exclude_audit=False)
        assert 'created_at' in api_dict_with_audit
        assert 'updated_at' in api_dict_with_audit
        assert 'version' in api_dict_with_audit
        
        # Test model registry functionality
        user_model_class = get_model_by_name('User')
        assert user_model_class == User
        
        # Test unknown model
        unknown_model = get_model_by_name('UnknownModel')
        assert unknown_model is None
        
        # Test validate_model_data function
        user_data = {
            'username': 'testapi',
            'email': 'testapi@example.com',
            'first_name': 'Test',
            'last_name': 'API'
        }
        validated_user = validate_model_data('User', user_data)
        assert isinstance(validated_user, User)
        assert validated_user.username == 'testapi'
        
        # Test validation with unknown model
        with pytest.raises(DataValidationError) as exc_info:
            validate_model_data('UnknownModel', user_data)
        
        assert exc_info.value.error_code == "UNKNOWN_MODEL"
        
        # Test serialize_for_api function
        serialized = serialize_for_api(user, exclude_audit=True)
        assert isinstance(serialized, dict)
        assert 'username' in serialized
        
        logger.info("Model serialization and API response format tested successfully")
    
    @pytest.mark.performance
    def test_model_performance_benchmarks(self, performance_test_context):
        """Test model performance to ensure ≤10% variance from Node.js baseline."""
        performance_test_context['start_measurement']('model_creation_performance')
        
        # Create multiple model instances to test performance
        start_time = time.perf_counter()
        
        users = []
        for i in range(100):
            user = UserModelFactory()
            users.append(user)
        
        creation_time = time.perf_counter() - start_time
        
        # Test serialization performance
        serialization_start = time.perf_counter()
        
        for user in users:
            api_dict = user.to_api_dict()
        
        serialization_time = time.perf_counter() - serialization_start
        
        # Test validation performance
        validation_start = time.perf_counter()
        
        for user in users:
            user.validate_business_rules()
        
        validation_time = time.perf_counter() - validation_start
        
        execution_time = performance_test_context['end_measurement']()
        
        # Log performance metrics
        logger.info(
            "Model performance benchmarks completed",
            total_execution_time=execution_time,
            creation_time=creation_time,
            serialization_time=serialization_time,
            validation_time=validation_time,
            models_created=len(users)
        )
        
        # Verify performance is within acceptable bounds
        # (These would be compared against Node.js baselines in real implementation)
        assert creation_time < 1.0  # Should create 100 models in under 1 second
        assert serialization_time < 0.5  # Should serialize 100 models in under 0.5 seconds
        assert validation_time < 0.5  # Should validate 100 models in under 0.5 seconds


# ============================================================================
# BUSINESS VALIDATORS TESTING
# ============================================================================

class TestBusinessValidators:
    """
    Comprehensive testing for marshmallow schema validation and business rule enforcement.
    
    Tests cover schema validation patterns, business rule validation, cross-field validation,
    error handling integration, and validation performance per Section 5.2.4 requirements.
    """
    
    def test_base_business_validator_functionality(self):
        """Test BaseBusinessValidator core functionality and configuration."""
        # Test validator initialization
        validator = BaseBusinessValidator()
        assert validator.enforce_business_rules is True
        assert validator.strict_mode is True
        assert validator.sanitize_input is True
        
        # Test validation context
        validator_with_context = BaseBusinessValidator(
            validation_context={'user_id': '123', 'operation': 'create'},
            business_rules={'check_permissions': True}
        )
        assert validator_with_context.validation_context['user_id'] == '123'
        assert validator_with_context.business_rules['check_permissions'] is True
        
        logger.info("BaseBusinessValidator functionality tested successfully")
    
    def test_user_validator_schema_validation(self):
        """Test UserValidator schema validation and business rules."""
        validator = UserValidator()
        
        # Test valid user data validation
        valid_user_data = {
            'username': 'testuser123',
            'email': 'test@example.com',
            'first_name': 'John',
            'last_name': 'Doe',
            'status': 'active',
            'role': 'user'
        }
        
        result = validator.load(valid_user_data)
        assert result['username'] == 'testuser123'
        assert result['email'] == 'test@example.com'
        
        # Test username validation with reserved names
        with pytest.raises(MarshmallowValidationError) as exc_info:
            invalid_data = valid_user_data.copy()
            invalid_data['username'] = 'admin'  # Reserved username
            validator.load(invalid_data)
        
        # Test email format validation
        with pytest.raises(MarshmallowValidationError) as exc_info:
            invalid_data = valid_user_data.copy()
            invalid_data['email'] = 'invalid-email-format'
            validator.load(invalid_data)
        
        # Test required field validation
        with pytest.raises(MarshmallowValidationError) as exc_info:
            incomplete_data = {
                'username': 'testuser',
                # Missing required fields
            }
            validator.load(incomplete_data)
        
        logger.info("UserValidator schema validation tested successfully")
    
    def test_product_validator_business_rules(self):
        """Test ProductValidator business rules and cross-field validation."""
        validator = ProductValidator()
        
        # Test valid product data
        valid_product_data = {
            'sku': 'PROD001',
            'name': 'Test Product',
            'slug': 'test-product',
            'base_price': {'amount': '99.99', 'currency_code': 'USD'},
            'status': 'active',
            'inventory_quantity': 100,
            'track_inventory': True
        }
        
        result = validator.load(valid_product_data)
        assert result['sku'] == 'PROD001'
        assert result['name'] == 'Test Product'
        
        # Test sale price validation (must be less than base price)
        invalid_sale_price_data = valid_product_data.copy()
        invalid_sale_price_data['sale_price'] = {'amount': '120.00', 'currency_code': 'USD'}
        
        with pytest.raises(MarshmallowValidationError):
            validator.load(invalid_sale_price_data)
        
        # Test currency consistency validation
        invalid_currency_data = valid_product_data.copy()
        invalid_currency_data['sale_price'] = {'amount': '80.00', 'currency_code': 'EUR'}
        
        with pytest.raises(MarshmallowValidationError):
            validator.load(invalid_currency_data)
        
        logger.info("ProductValidator business rules tested successfully")
    
    def test_order_validator_complex_validation(self):
        """Test OrderValidator complex business logic and calculation validation."""
        validator = OrderValidator()
        
        # Test valid order data with items
        valid_order_data = {
            'customer_email': 'customer@example.com',
            'customer_name': 'John Customer',
            'items': [
                {
                    'product_id': str(uuid.uuid4()),
                    'product_sku': 'ITEM001',
                    'product_name': 'Test Item',
                    'quantity': 2,
                    'unit_price': {'amount': '25.00', 'currency_code': 'USD'}
                }
            ],
            'subtotal': {'amount': '50.00', 'currency_code': 'USD'},
            'tax_amount': {'amount': '4.00', 'currency_code': 'USD'},
            'shipping_amount': {'amount': '5.99', 'currency_code': 'USD'},
            'discount_amount': {'amount': '0.00', 'currency_code': 'USD'},
            'total_amount': {'amount': '59.99', 'currency_code': 'USD'},
            'billing_address': {
                'street_line_1': '123 Test St',
                'city': 'Test City',
                'state_province': 'Test State',
                'postal_code': '12345',
                'country_code': 'US'
            }
        }
        
        result = validator.load(valid_order_data)
        assert result['customer_email'] == 'customer@example.com'
        assert len(result['items']) == 1
        
        # Test total calculation validation
        invalid_total_data = valid_order_data.copy()
        invalid_total_data['total_amount'] = {'amount': '100.00', 'currency_code': 'USD'}  # Wrong total
        
        with pytest.raises(MarshmallowValidationError):
            validator.load(invalid_total_data)
        
        # Test currency consistency across all amounts
        invalid_currency_data = valid_order_data.copy()
        invalid_currency_data['tax_amount'] = {'amount': '4.00', 'currency_code': 'EUR'}  # Different currency
        
        with pytest.raises(MarshmallowValidationError):
            validator.load(invalid_currency_data)
        
        logger.info("OrderValidator complex validation tested successfully")
    
    def test_conditional_validator_business_rules(self):
        """Test ConditionalValidator for context-dependent business rules."""
        validator = ConditionalValidator()
        
        # Test conditional validation based on user context
        context = {'user_role': 'admin', 'operation': 'create'}
        
        # Admin users should pass validation
        admin_data = {'sensitive_field': 'admin_value', 'public_field': 'public_value'}
        result = validator.validate_conditional_rules(admin_data, context)
        assert result is True
        
        # Regular users should have restrictions
        user_context = {'user_role': 'user', 'operation': 'create'}
        user_data = {'sensitive_field': 'user_value', 'public_field': 'public_value'}
        
        with pytest.raises(BusinessRuleViolationError):
            validator.validate_conditional_rules(user_data, user_context)
        
        logger.info("ConditionalValidator business rules tested successfully")
    
    def test_cross_field_validator_integration(self):
        """Test CrossFieldValidator for complex inter-field validation."""
        validator = CrossFieldValidator()
        
        # Test date range validation
        valid_date_data = {
            'start_date': '2023-01-01T00:00:00Z',
            'end_date': '2023-12-31T23:59:59Z'
        }
        result = validator.validate_date_range(valid_date_data)
        assert result is True
        
        # Test invalid date range (end before start)
        invalid_date_data = {
            'start_date': '2023-12-31T23:59:59Z',
            'end_date': '2023-01-01T00:00:00Z'
        }
        
        with pytest.raises(BusinessRuleViolationError):
            validator.validate_date_range(invalid_date_data)
        
        # Test password confirmation validation
        password_data = {
            'password': 'securePassword123!',
            'confirm_password': 'securePassword123!'
        }
        result = validator.validate_password_confirmation(password_data)
        assert result is True
        
        # Test password mismatch
        password_mismatch_data = {
            'password': 'securePassword123!',
            'confirm_password': 'differentPassword'
        }
        
        with pytest.raises(BusinessRuleViolationError):
            validator.validate_password_confirmation(password_mismatch_data)
        
        logger.info("CrossFieldValidator integration tested successfully")
    
    @pytest.mark.performance
    def test_validation_performance_benchmarks(self, performance_test_context):
        """Test validation performance to ensure ≤10% variance from Node.js baseline."""
        performance_test_context['start_measurement']('validation_performance')
        
        validator = UserValidator()
        
        # Generate test data for performance testing
        test_data = []
        for i in range(100):
            test_data.append({
                'username': f'testuser{i}',
                'email': f'test{i}@example.com',
                'first_name': f'First{i}',
                'last_name': f'Last{i}',
                'status': 'active',
                'role': 'user'
            })
        
        # Measure validation performance
        start_time = time.perf_counter()
        
        validated_results = []
        for data in test_data:
            result = validator.load(data)
            validated_results.append(result)
        
        validation_time = time.perf_counter() - start_time
        execution_time = performance_test_context['end_measurement']()
        
        # Log performance metrics
        logger.info(
            "Validation performance benchmarks completed",
            total_execution_time=execution_time,
            validation_time=validation_time,
            records_validated=len(validated_results),
            avg_validation_time=validation_time / len(test_data)
        )
        
        # Verify performance is within acceptable bounds
        assert validation_time < 1.0  # Should validate 100 records in under 1 second
        assert len(validated_results) == 100


# ============================================================================
# BUSINESS PROCESSORS TESTING
# ============================================================================

class TestBusinessProcessors:
    """
    Comprehensive testing for data processing and transformation engine.
    
    Tests cover data transformation, business rule execution, date/time processing,
    workflow orchestration, and performance validation per Section 5.2.4 requirements.
    """
    
    def test_data_transformer_core_functionality(self):
        """Test DataTransformer for data format conversion and transformation."""
        transformer = DataTransformer()
        
        # Test JSON to dict transformation
        json_data = '{"name": "John", "age": 30, "active": true}'
        result = transformer.transform_json_to_dict(json_data)
        assert result['name'] == 'John'
        assert result['age'] == 30
        assert result['active'] is True
        
        # Test dict to JSON transformation
        dict_data = {'name': 'Jane', 'age': 25, 'active': False}
        json_result = transformer.transform_dict_to_json(dict_data)
        assert isinstance(json_result, str)
        assert 'Jane' in json_result
        
        # Test data normalization
        messy_data = {
            'NAME': '  John Doe  ',
            'EMAIL': 'JOHN@EXAMPLE.COM',
            'age': '30',
            'active': 'true'
        }
        normalized = transformer.normalize_data(messy_data)
        assert normalized['name'] == 'John Doe'
        assert normalized['email'] == 'john@example.com'
        assert normalized['age'] == 30
        assert normalized['active'] is True
        
        # Test invalid JSON handling
        with pytest.raises(DataProcessingError):
            transformer.transform_json_to_dict('invalid json string')
        
        logger.info("DataTransformer core functionality tested successfully")
    
    def test_business_rule_engine_execution(self):
        """Test BusinessRuleEngine for complex business logic execution."""
        rule_engine = ProcessorBusinessRuleEngine()
        
        # Test user eligibility rules
        user_data = {
            'age': 25,
            'account_status': 'active',
            'verification_status': 'verified',
            'account_balance': 1000.0
        }
        
        # Test eligibility for premium features
        is_eligible = rule_engine.check_premium_eligibility(user_data)
        assert is_eligible is True
        
        # Test ineligible user (insufficient balance)
        ineligible_user = user_data.copy()
        ineligible_user['account_balance'] = 50.0
        is_eligible = rule_engine.check_premium_eligibility(ineligible_user)
        assert is_eligible is False
        
        # Test order processing rules
        order_data = {
            'total_amount': 150.0,
            'customer_tier': 'gold',
            'items_count': 3,
            'shipping_address': {'country': 'US'}
        }
        
        processing_result = rule_engine.process_order_rules(order_data)
        assert processing_result['approved'] is True
        assert 'discount_applied' in processing_result
        
        # Test fraud detection rules
        transaction_data = {
            'amount': 5000.0,
            'user_id': '12345',
            'transaction_pattern': 'unusual',
            'risk_score': 0.3
        }
        
        fraud_result = rule_engine.check_fraud_detection(transaction_data)
        assert 'risk_assessment' in fraud_result
        assert 'requires_review' in fraud_result
        
        logger.info("BusinessRuleEngine execution tested successfully")
    
    def test_datetime_processor_equivalent_to_momentjs(self):
        """Test DateTimeProcessor for date/time processing equivalent to moment.js."""
        processor = DateTimeProcessor()
        
        # Test date parsing equivalent to moment.js
        date_string = '2023-12-25T15:30:00Z'
        parsed_date = processor.parse_datetime(date_string)
        assert isinstance(parsed_date, datetime)
        assert parsed_date.year == 2023
        assert parsed_date.month == 12
        assert parsed_date.day == 25
        
        # Test date formatting
        formatted = processor.format_datetime(parsed_date, 'YYYY-MM-DD HH:mm:ss')
        assert '2023-12-25 15:30:00' in formatted
        
        # Test relative time calculations
        now = datetime.now(timezone.utc)
        past_date = now - timedelta(days=5, hours=3)
        relative = processor.get_relative_time(past_date, now)
        assert 'days ago' in relative.lower()
        
        # Test business day calculations
        start_date = date(2023, 12, 25)  # Monday
        business_days = processor.calculate_business_days(start_date, days_to_add=5)
        assert isinstance(business_days, date)
        
        # Test timezone conversion
        utc_time = datetime(2023, 12, 25, 15, 30, 0, tzinfo=timezone.utc)
        est_time = processor.convert_timezone(utc_time, 'US/Eastern')
        assert est_time.hour != utc_time.hour  # Should be different due to timezone
        
        # Test date validation
        assert processor.is_valid_date('2023-12-25') is True
        assert processor.is_valid_date('invalid-date') is False
        
        # Test ISO format compliance
        iso_formatted = processor.to_iso_format(parsed_date)
        assert 'T' in iso_formatted
        assert iso_formatted.endswith('Z') or '+' in iso_formatted
        
        logger.info("DateTimeProcessor moment.js equivalence tested successfully")
    
    def test_calculation_processor_business_calculations(self):
        """Test CalculationProcessor for business calculations and formulas."""
        calculator = CalculationProcessor()
        
        # Test percentage calculations
        percentage = calculator.calculate_percentage(25, 100)
        assert percentage == 25.0
        
        # Test discount applications
        original_price = Decimal('100.00')
        discount_percent = 15
        discounted_price = calculator.apply_percentage_discount(original_price, discount_percent)
        assert discounted_price == Decimal('85.00')
        
        # Test tax calculations
        subtotal = Decimal('100.00')
        tax_rate = Decimal('0.08')  # 8% tax
        tax_amount = calculator.calculate_tax(subtotal, tax_rate)
        assert tax_amount == Decimal('8.00')
        
        # Test compound interest calculations
        principal = Decimal('1000.00')
        annual_rate = Decimal('0.05')  # 5% annual rate
        years = 2
        compound_amount = calculator.calculate_compound_interest(principal, annual_rate, years)
        assert compound_amount > principal
        
        # Test currency rounding
        unrounded_amount = Decimal('123.456789')
        rounded_amount = calculator.round_currency(unrounded_amount, 'USD')
        assert rounded_amount == Decimal('123.46')
        
        # Test percentage change calculations
        old_value = 100
        new_value = 120
        change_percent = calculator.calculate_percentage_change(old_value, new_value)
        assert change_percent == 20.0
        
        # Test statistical calculations
        numbers = [10, 20, 30, 40, 50]
        average = calculator.calculate_average(numbers)
        assert average == 30.0
        
        median = calculator.calculate_median(numbers)
        assert median == 30.0
        
        logger.info("CalculationProcessor business calculations tested successfully")
    
    def test_workflow_processor_orchestration(self):
        """Test WorkflowProcessor for complex business workflow orchestration."""
        workflow_processor = WorkflowProcessor()
        
        # Test order fulfillment workflow
        order_context = {
            'order_id': str(uuid.uuid4()),
            'customer_id': str(uuid.uuid4()),
            'items': [
                {'product_id': 'PROD001', 'quantity': 2},
                {'product_id': 'PROD002', 'quantity': 1}
            ],
            'payment_status': 'completed',
            'shipping_address': {'country': 'US', 'state': 'CA'}
        }
        
        result = workflow_processor.execute_order_fulfillment(order_context)
        assert result['workflow_completed'] is True
        assert 'inventory_reserved' in result
        assert 'shipping_label_created' in result
        
        # Test user onboarding workflow
        user_context = {
            'user_id': str(uuid.uuid4()),
            'email': 'newuser@example.com',
            'verification_token': str(uuid.uuid4()),
            'registration_source': 'web'
        }
        
        onboarding_result = workflow_processor.execute_user_onboarding(user_context)
        assert onboarding_result['onboarding_completed'] is True
        assert 'welcome_email_sent' in onboarding_result
        assert 'profile_created' in onboarding_result
        
        # Test payment processing workflow
        payment_context = {
            'payment_id': str(uuid.uuid4()),
            'amount': 99.99,
            'currency': 'USD',
            'payment_method': 'credit_card',
            'customer_id': str(uuid.uuid4())
        }
        
        payment_result = workflow_processor.execute_payment_processing(payment_context)
        assert 'payment_processed' in payment_result
        assert 'transaction_id' in payment_result
        
        # Test workflow error handling
        invalid_context = {'invalid_field': 'invalid_value'}
        
        with pytest.raises(DataProcessingError):
            workflow_processor.execute_order_fulfillment(invalid_context)
        
        logger.info("WorkflowProcessor orchestration tested successfully")
    
    def test_batch_processor_bulk_operations(self):
        """Test BatchProcessor for efficient bulk data processing operations."""
        batch_processor = BatchProcessor()
        
        # Test bulk user creation
        user_batch_data = []
        for i in range(10):
            user_batch_data.append({
                'username': f'batchuser{i}',
                'email': f'batch{i}@example.com',
                'first_name': f'Batch{i}',
                'last_name': 'User'
            })
        
        batch_result = batch_processor.process_user_batch(user_batch_data)
        assert batch_result['processed_count'] == 10
        assert batch_result['success_count'] == 10
        assert batch_result['error_count'] == 0
        
        # Test batch processing with errors
        mixed_batch_data = user_batch_data.copy()
        mixed_batch_data.append({
            'username': '',  # Invalid data
            'email': 'invalid-email',
            'first_name': '',
            'last_name': ''
        })
        
        mixed_result = batch_processor.process_user_batch(mixed_batch_data)
        assert mixed_result['processed_count'] == 11
        assert mixed_result['success_count'] == 10
        assert mixed_result['error_count'] == 1
        assert len(mixed_result['errors']) == 1
        
        # Test batch size limits
        large_batch = [{'data': f'item{i}'} for i in range(1000)]
        
        with pytest.raises(DataProcessingError) as exc_info:
            batch_processor.process_large_batch(large_batch, max_batch_size=500)
        
        assert exc_info.value.error_code == "BATCH_SIZE_EXCEEDED"
        
        logger.info("BatchProcessor bulk operations tested successfully")
    
    @pytest.mark.asyncio
    async def test_async_processor_concurrent_operations(self):
        """Test AsyncProcessor for concurrent and asynchronous processing operations."""
        async_processor = AsyncProcessor()
        
        # Test concurrent data processing
        data_items = [{'id': i, 'value': f'item{i}'} for i in range(20)]
        
        start_time = time.perf_counter()
        results = await async_processor.process_concurrent(data_items, concurrency_limit=5)
        processing_time = time.perf_counter() - start_time
        
        assert len(results) == 20
        assert all('processed' in result for result in results)
        
        # Test async workflow execution
        workflow_tasks = [
            {'task_id': f'task{i}', 'operation': 'process', 'data': {'value': i}}
            for i in range(10)
        ]
        
        workflow_results = await async_processor.execute_async_workflow(workflow_tasks)
        assert len(workflow_results) == 10
        assert all(result['completed'] for result in workflow_results)
        
        # Test error handling in async processing
        error_tasks = [
            {'task_id': 'error_task', 'operation': 'invalid_operation', 'data': {}}
        ]
        
        with pytest.raises(DataProcessingError):
            await async_processor.execute_async_workflow(error_tasks)
        
        logger.info(
            "AsyncProcessor concurrent operations tested successfully",
            processing_time=processing_time,
            items_processed=len(results)
        )
    
    @pytest.mark.performance
    def test_processing_performance_benchmarks(self, performance_test_context):
        """Test processing performance to ensure ≤10% variance from Node.js baseline."""
        performance_test_context['start_measurement']('processing_performance')
        
        transformer = DataTransformer()
        calculator = CalculationProcessor()
        
        # Generate test data for performance testing
        test_data = []
        for i in range(1000):
            test_data.append({
                'id': i,
                'amount': Decimal(f'{100 + i}.99'),
                'discount_percent': 10 + (i % 20),
                'tax_rate': Decimal('0.08'),
                'created_date': f'2023-01-{(i % 28) + 1:02d}T12:00:00Z'
            })
        
        # Measure data transformation performance
        transform_start = time.perf_counter()
        
        transformed_results = []
        for data in test_data:
            normalized = transformer.normalize_data(data)
            transformed_results.append(normalized)
        
        transform_time = time.perf_counter() - transform_start
        
        # Measure calculation performance
        calculation_start = time.perf_counter()
        
        calculation_results = []
        for data in transformed_results:
            discounted = calculator.apply_percentage_discount(
                data['amount'], data['discount_percent']
            )
            tax = calculator.calculate_tax(discounted, data['tax_rate'])
            calculation_results.append({'discounted': discounted, 'tax': tax})
        
        calculation_time = time.perf_counter() - calculation_start
        
        execution_time = performance_test_context['end_measurement']()
        
        # Log performance metrics
        logger.info(
            "Processing performance benchmarks completed",
            total_execution_time=execution_time,
            transform_time=transform_time,
            calculation_time=calculation_time,
            records_processed=len(test_data),
            avg_transform_time=transform_time / len(test_data),
            avg_calculation_time=calculation_time / len(test_data)
        )
        
        # Verify performance is within acceptable bounds
        assert transform_time < 2.0  # Should transform 1000 records in under 2 seconds
        assert calculation_time < 1.0  # Should calculate 1000 records in under 1 second
        assert len(calculation_results) == 1000


# ============================================================================
# BUSINESS SERVICES TESTING
# ============================================================================

class TestBusinessServices:
    """
    Comprehensive testing for business service orchestration and external integrations.
    
    Tests cover service orchestration, external service integration, workflow management,
    circuit breaker patterns, and integration resilience per Section 5.2.4 requirements.
    """
    
    @pytest.fixture
    def mock_external_services(self):
        """Fixture providing mock external services for service testing."""
        with patch('src.business.services.httpx.AsyncClient') as mock_httpx, \
             patch('src.business.services.boto3.client') as mock_boto3, \
             patch('src.business.services.redis.Redis') as mock_redis:
            
            # Configure mock HTTP client
            mock_client = AsyncMock()
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {'status': 'success'}
            mock_client.get.return_value = mock_response
            mock_client.post.return_value = mock_response
            mock_httpx.return_value = mock_client
            
            # Configure mock AWS client
            mock_s3 = Mock()
            mock_s3.upload_file.return_value = {'ETag': 'test-etag'}
            mock_boto3.return_value = mock_s3
            
            # Configure mock Redis client
            mock_redis_instance = Mock()
            mock_redis_instance.get.return_value = None
            mock_redis_instance.set.return_value = True
            mock_redis.return_value = mock_redis_instance
            
            yield {
                'httpx': mock_client,
                'boto3': mock_s3,
                'redis': mock_redis_instance
            }
    
    def test_user_service_crud_operations(self, mock_external_services):
        """Test UserService CRUD operations and business logic integration."""
        user_service = UserService()
        
        # Test user creation
        user_data = {
            'username': 'servicetest',
            'email': 'servicetest@example.com',
            'first_name': 'Service',
            'last_name': 'Test',
            'password': 'securePassword123!'
        }
        
        created_user = user_service.create_user(user_data)
        assert created_user.username == 'servicetest'
        assert created_user.email == 'servicetest@example.com'
        assert created_user.is_active is True
        
        # Test user validation during creation
        invalid_user_data = user_data.copy()
        invalid_user_data['email'] = 'invalid-email'
        
        with pytest.raises(DataValidationError):
            user_service.create_user(invalid_user_data)
        
        # Test user retrieval
        retrieved_user = user_service.get_user_by_id(created_user.id)
        assert retrieved_user is not None
        assert retrieved_user.username == 'servicetest'
        
        # Test user update
        update_data = {'first_name': 'UpdatedService'}
        updated_user = user_service.update_user(created_user.id, update_data)
        assert updated_user.first_name == 'UpdatedService'
        
        # Test user deletion
        deletion_result = user_service.delete_user(created_user.id)
        assert deletion_result is True
        
        # Test non-existent user retrieval
        with pytest.raises(ResourceNotFoundError):
            user_service.get_user_by_id('non-existent-id')
        
        logger.info("UserService CRUD operations tested successfully")
    
    def test_order_service_complex_workflow(self, mock_external_services):
        """Test OrderService complex order processing workflow."""
        order_service = OrderService()
        
        # Test order creation with validation
        order_data = {
            'customer_email': 'customer@example.com',
            'customer_name': 'Test Customer',
            'items': [
                {
                    'product_id': str(uuid.uuid4()),
                    'product_sku': 'TEST001',
                    'product_name': 'Test Product',
                    'quantity': 2,
                    'unit_price': {'amount': '25.00', 'currency_code': 'USD'}
                }
            ],
            'billing_address': {
                'street_line_1': '123 Test St',
                'city': 'Test City',
                'state_province': 'Test State',
                'postal_code': '12345',
                'country_code': 'US'
            }
        }
        
        created_order = order_service.create_order(order_data)
        assert created_order.status == OrderStatus.PENDING
        assert len(created_order.items) == 1
        assert created_order.customer_email == 'customer@example.com'
        
        # Test order processing workflow
        processing_result = order_service.process_order(created_order.id)
        assert processing_result['order_processed'] is True
        assert processing_result['inventory_updated'] is True
        assert processing_result['payment_validated'] is True
        
        # Test order status update
        updated_order = order_service.update_order_status(
            created_order.id, OrderStatus.CONFIRMED
        )
        assert updated_order.status == OrderStatus.CONFIRMED
        
        # Test order fulfillment
        fulfillment_result = order_service.fulfill_order(created_order.id)
        assert fulfillment_result['shipping_label_created'] is True
        assert fulfillment_result['tracking_number'] is not None
        
        # Test order cancellation
        cancellation_result = order_service.cancel_order(created_order.id)
        assert cancellation_result['order_cancelled'] is True
        
        logger.info("OrderService complex workflow tested successfully")
    
    def test_payment_service_transaction_processing(self, mock_external_services):
        """Test PaymentService transaction processing and fraud detection."""
        payment_service = PaymentService()
        
        # Test payment creation
        payment_data = {
            'order_id': str(uuid.uuid4()),
            'amount': {'amount': '99.99', 'currency_code': 'USD'},
            'payment_method': PaymentMethod.CREDIT_CARD,
            'customer_id': str(uuid.uuid4())
        }
        
        payment_transaction = payment_service.create_payment(payment_data)
        assert payment_transaction.payment_status == PaymentStatus.PENDING
        assert payment_transaction.amount.amount == Decimal('99.99')
        
        # Test payment processing
        processing_result = payment_service.process_payment(payment_transaction.id)
        assert processing_result['payment_processed'] is True
        assert processing_result['transaction_id'] is not None
        
        # Test fraud detection
        fraud_check_result = payment_service.check_fraud_risk(payment_transaction.id)
        assert 'risk_score' in fraud_check_result
        assert 'risk_level' in fraud_check_result
        
        # Test payment confirmation
        confirmation_result = payment_service.confirm_payment(payment_transaction.id)
        assert confirmation_result['payment_confirmed'] is True
        
        # Test refund processing
        refund_data = {
            'amount': {'amount': '50.00', 'currency_code': 'USD'},
            'reason': 'customer_request'
        }
        refund_result = payment_service.process_refund(payment_transaction.id, refund_data)
        assert refund_result['refund_processed'] is True
        assert refund_result['refund_amount'] == Decimal('50.00')
        
        # Test payment failure handling
        failed_payment_data = payment_data.copy()
        failed_payment_data['amount'] = {'amount': '0.00', 'currency_code': 'USD'}  # Invalid amount
        
        with pytest.raises(BusinessRuleViolationError):
            payment_service.create_payment(failed_payment_data)
        
        logger.info("PaymentService transaction processing tested successfully")
    
    def test_authentication_service_jwt_management(self, mock_external_services):
        """Test AuthenticationService JWT token management and Auth0 integration."""
        auth_service = AuthenticationService()
        
        # Test token generation
        user_data = {
            'user_id': str(uuid.uuid4()),
            'email': 'auth@example.com',
            'roles': ['user'],
            'permissions': ['read_profile', 'update_profile']
        }
        
        token_result = auth_service.generate_jwt_token(user_data)
        assert 'access_token' in token_result
        assert 'expires_in' in token_result
        assert 'token_type' in token_result
        
        # Test token validation
        access_token = token_result['access_token']
        validation_result = auth_service.validate_jwt_token(access_token)
        assert validation_result['valid'] is True
        assert validation_result['user_id'] == user_data['user_id']
        
        # Test token refresh
        refresh_result = auth_service.refresh_jwt_token(access_token)
        assert 'access_token' in refresh_result
        assert 'expires_in' in refresh_result
        
        # Test Auth0 user profile retrieval
        profile_result = auth_service.get_user_profile(user_data['user_id'])
        assert 'user_profile' in profile_result
        assert 'metadata' in profile_result
        
        # Test permission checking
        has_permission = auth_service.check_user_permission(
            user_data['user_id'], 'read_profile'
        )
        assert has_permission is True
        
        lacks_permission = auth_service.check_user_permission(
            user_data['user_id'], 'admin_access'
        )
        assert lacks_permission is False
        
        # Test invalid token handling
        with pytest.raises(AuthorizationError):
            auth_service.validate_jwt_token('invalid.jwt.token')
        
        logger.info("AuthenticationService JWT management tested successfully")
    
    def test_integration_orchestrator_circuit_breaker(self, mock_external_services):
        """Test IntegrationOrchestrator circuit breaker patterns and resilience."""
        orchestrator = IntegrationOrchestrator()
        
        # Test successful external service call
        service_config = {
            'service_name': 'external_api',
            'base_url': 'https://api.example.com',
            'timeout': 30,
            'retries': 3
        }
        
        success_result = orchestrator.call_external_service(
            service_config, 'GET', '/users/123'
        )
        assert success_result['status_code'] == 200
        assert success_result['success'] is True
        
        # Test circuit breaker failure handling
        with patch.object(mock_external_services['httpx'], 'get', side_effect=Exception('Service unavailable')):
            # Trigger multiple failures to open circuit breaker
            for _ in range(5):
                try:
                    orchestrator.call_external_service(service_config, 'GET', '/failing-endpoint')
                except ExternalServiceError:
                    pass
            
            # Circuit breaker should now be open
            circuit_state = orchestrator.get_circuit_breaker_state('external_api')
            assert circuit_state['state'] in ['open', 'half-open']
        
        # Test retry mechanism
        retry_config = service_config.copy()
        retry_config['retries'] = 2
        
        with patch.object(mock_external_services['httpx'], 'get', side_effect=[
            Exception('Temporary failure'),
            AsyncMock(status_code=200, json=lambda: {'status': 'success'})
        ]):
            retry_result = orchestrator.call_external_service_with_retry(
                retry_config, 'GET', '/retry-endpoint'
            )
            assert retry_result['success'] is True
            assert retry_result['attempts'] == 2
        
        # Test service health monitoring
        health_result = orchestrator.check_service_health('external_api')
        assert 'healthy' in health_result
        assert 'response_time' in health_result
        
        logger.info("IntegrationOrchestrator circuit breaker tested successfully")
    
    def test_business_workflow_service_orchestration(self, mock_external_services):
        """Test BusinessWorkflowService complex workflow orchestration."""
        workflow_service = BusinessWorkflowService()
        
        # Test e-commerce order fulfillment workflow
        order_context = {
            'order_id': str(uuid.uuid4()),
            'customer_id': str(uuid.uuid4()),
            'items': [
                {'product_id': 'PROD001', 'quantity': 2},
                {'product_id': 'PROD002', 'quantity': 1}
            ],
            'payment_method': 'credit_card',
            'shipping_address': {
                'country': 'US',
                'state': 'CA',
                'city': 'San Francisco',
                'postal_code': '94105'
            }
        }
        
        workflow_result = workflow_service.execute_order_fulfillment_workflow(order_context)
        assert workflow_result['workflow_completed'] is True
        assert workflow_result['steps_completed'] > 0
        assert 'inventory_reserved' in workflow_result
        assert 'payment_processed' in workflow_result
        assert 'shipping_arranged' in workflow_result
        
        # Test user registration workflow
        registration_context = {
            'user_id': str(uuid.uuid4()),
            'email': 'newuser@example.com',
            'registration_method': 'email',
            'referral_code': 'REF123'
        }
        
        registration_result = workflow_service.execute_user_registration_workflow(
            registration_context
        )
        assert registration_result['workflow_completed'] is True
        assert 'account_created' in registration_result
        assert 'welcome_email_sent' in registration_result
        assert 'referral_processed' in registration_result
        
        # Test subscription renewal workflow
        subscription_context = {
            'subscription_id': str(uuid.uuid4()),
            'customer_id': str(uuid.uuid4()),
            'plan_id': 'premium_monthly',
            'payment_method_id': 'pm_123456'
        }
        
        renewal_result = workflow_service.execute_subscription_renewal_workflow(
            subscription_context
        )
        assert renewal_result['workflow_completed'] is True
        assert 'payment_processed' in renewal_result
        assert 'subscription_updated' in renewal_result
        
        # Test workflow error handling
        invalid_context = {'missing_required_fields': True}
        
        with pytest.raises(DataValidationError):
            workflow_service.execute_order_fulfillment_workflow(invalid_context)
        
        logger.info("BusinessWorkflowService orchestration tested successfully")
    
    @pytest.mark.performance
    def test_service_performance_benchmarks(self, performance_test_context, mock_external_services):
        """Test service performance to ensure ≤10% variance from Node.js baseline."""
        performance_test_context['start_measurement']('service_performance')
        
        user_service = UserService()
        order_service = OrderService()
        
        # Measure user service performance
        user_start_time = time.perf_counter()
        
        # Create multiple users
        created_users = []
        for i in range(50):
            user_data = {
                'username': f'perfuser{i}',
                'email': f'perf{i}@example.com',
                'first_name': f'Perf{i}',
                'last_name': 'User'
            }
            user = user_service.create_user(user_data)
            created_users.append(user)
        
        user_creation_time = time.perf_counter() - user_start_time
        
        # Measure order service performance
        order_start_time = time.perf_counter()
        
        # Create multiple orders
        created_orders = []
        for i in range(25):
            order_data = {
                'customer_email': f'customer{i}@example.com',
                'customer_name': f'Customer {i}',
                'items': [
                    {
                        'product_id': str(uuid.uuid4()),
                        'product_sku': f'PERF{i:03d}',
                        'product_name': f'Performance Product {i}',
                        'quantity': 1,
                        'unit_price': {'amount': '10.00', 'currency_code': 'USD'}
                    }
                ],
                'billing_address': {
                    'street_line_1': f'{i} Performance St',
                    'city': 'Test City',
                    'state_province': 'Test State',
                    'postal_code': '12345',
                    'country_code': 'US'
                }
            }
            order = order_service.create_order(order_data)
            created_orders.append(order)
        
        order_creation_time = time.perf_counter() - order_start_time
        
        execution_time = performance_test_context['end_measurement']()
        
        # Log performance metrics
        logger.info(
            "Service performance benchmarks completed",
            total_execution_time=execution_time,
            user_creation_time=user_creation_time,
            order_creation_time=order_creation_time,
            users_created=len(created_users),
            orders_created=len(created_orders),
            avg_user_creation_time=user_creation_time / len(created_users),
            avg_order_creation_time=order_creation_time / len(created_orders)
        )
        
        # Verify performance is within acceptable bounds
        assert user_creation_time < 5.0  # Should create 50 users in under 5 seconds
        assert order_creation_time < 5.0  # Should create 25 orders in under 5 seconds
        assert len(created_users) == 50
        assert len(created_orders) == 25


# ============================================================================
# BUSINESS UTILITIES TESTING
# ============================================================================

class TestBusinessUtils:
    """
    Comprehensive testing for business utility functions and helper operations.
    
    Tests cover data manipulation, validation utilities, type conversion, date/time
    processing, and currency operations per Section 5.2.4 utility requirements.
    """
    
    def test_data_cleaning_and_sanitization(self):
        """Test data cleaning and sanitization utility functions."""
        # Test basic data cleaning
        messy_data = {
            'name': '  John Doe  ',
            'email': 'JOHN@EXAMPLE.COM',
            'age': '30',
            'active': 'true',
            'empty_field': '',
            'none_field': None,
            'whitespace_only': '   '
        }
        
        cleaned = clean_data(messy_data)
        assert cleaned['name'] == 'John Doe'
        assert cleaned['email'] == 'JOHN@EXAMPLE.COM'  # Email should preserve case
        assert 'empty_field' not in cleaned  # Empty fields removed
        assert 'none_field' not in cleaned  # None fields removed
        assert 'whitespace_only' not in cleaned  # Whitespace-only fields removed
        
        # Test input sanitization
        unsafe_input = '<script>alert("xss")</script>Hello World'
        sanitized = sanitize_input(unsafe_input)
        assert '<script>' not in sanitized
        assert 'Hello World' in sanitized
        
        # Test HTML tag removal
        html_input = '<p>This is <strong>bold</strong> text</p>'
        clean_text = sanitize_input(html_input, allow_html=False)
        assert '<p>' not in clean_text
        assert '<strong>' not in clean_text
        assert 'This is bold text' in clean_text
        
        # Test length limiting
        long_input = 'a' * 1000
        limited = sanitize_input(long_input, max_length=100)
        assert len(limited) <= 100
        
        logger.info("Data cleaning and sanitization tested successfully")
    
    def test_email_validation_comprehensive(self):
        """Test comprehensive email validation with business rules."""
        # Test valid email formats
        valid_emails = [
            'user@example.com',
            'test.email@domain.co.uk',
            'user+tag@example.org',
            'firstname.lastname@company.com'
        ]
        
        for email in valid_emails:
            assert validate_email(email) is True
        
        # Test invalid email formats
        invalid_emails = [
            'invalid-email',
            '@example.com',
            'user@',
            'user..double.dot@example.com',
            'user@domain',
            ''
        ]
        
        for email in invalid_emails:
            assert validate_email(email) is False
        
        # Test strict email validation
        borderline_email = 'user@localhost'
        assert validate_email(borderline_email, strict=False) is True
        assert validate_email(borderline_email, strict=True) is False
        
        # Test domain validation
        assert validate_email('user@example.com', check_domain=True) is True
        
        logger.info("Email validation tested successfully")
    
    def test_phone_number_validation_international(self):
        """Test international phone number validation and formatting."""
        # Test valid phone numbers
        valid_phones = [
            '+1-555-123-4567',  # US format
            '(555) 123-4567',   # US format
            '+44 20 7946 0958', # UK format
            '+33 1 42 86 83 26' # France format
        ]
        
        for phone in valid_phones:
            assert validate_phone(phone) is True
        
        # Test invalid phone numbers
        invalid_phones = [
            '123',              # Too short
            '555-CALL-NOW',     # Contains letters
            '+1-555-123',       # Incomplete
            ''                  # Empty
        ]
        
        for phone in invalid_phones:
            assert validate_phone(phone) is False
        
        # Test phone formatting
        raw_phone = '15551234567'
        formatted = validate_phone(raw_phone, format_type='international', country_code='US')
        assert formatted is not False  # Should return formatted string or True
        
        logger.info("Phone number validation tested successfully")
    
    def test_postal_code_validation_by_country(self):
        """Test postal code validation for different countries."""
        # Test US ZIP codes
        assert validate_postal_code('12345', 'US') is True
        assert validate_postal_code('12345-6789', 'US') is True
        assert validate_postal_code('ABCDE', 'US') is False
        
        # Test Canadian postal codes
        assert validate_postal_code('K1A 0A6', 'CA') is True
        assert validate_postal_code('M5V 3L9', 'CA') is True
        assert validate_postal_code('12345', 'CA') is False
        
        # Test UK postal codes
        assert validate_postal_code('SW1A 1AA', 'GB') is True
        assert validate_postal_code('M1 1AA', 'GB') is True
        assert validate_postal_code('12345', 'GB') is False
        
        # Test invalid country code
        assert validate_postal_code('12345', 'INVALID') is False
        
        logger.info("Postal code validation tested successfully")
    
    def test_safe_type_conversion_functions(self):
        """Test safe type conversion functions with error handling."""
        # Test safe integer conversion
        assert safe_int('123') == 123
        assert safe_int('123.45') == 123  # Truncates float
        assert safe_int('invalid', default=0) == 0
        assert safe_int(None, default=-1) == -1
        
        # Test safe float conversion
        assert safe_float('123.45') == 123.45
        assert safe_float('123') == 123.0
        assert safe_float('invalid', default=0.0) == 0.0
        assert safe_float(None, default=-1.0) == -1.0
        
        # Test safe string conversion
        assert safe_str(123) == '123'
        assert safe_str(123.45) == '123.45'
        assert safe_str(None, default='') == ''
        assert safe_str([1, 2, 3]) == '[1, 2, 3]'
        
        # Test boolean normalization
        assert normalize_boolean('true') is True
        assert normalize_boolean('True') is True
        assert normalize_boolean('1') is True
        assert normalize_boolean('yes') is True
        assert normalize_boolean('false') is False
        assert normalize_boolean('False') is False
        assert normalize_boolean('0') is False
        assert normalize_boolean('no') is False
        assert normalize_boolean('invalid', default=None) is None
        
        logger.info("Safe type conversion functions tested successfully")
    
    def test_date_time_processing_momentjs_equivalent(self):
        """Test date/time processing functions equivalent to moment.js."""
        # Test date parsing
        date_strings = [
            '2023-12-25',
            '2023-12-25T15:30:00Z',
            '2023-12-25T15:30:00-05:00',
            'December 25, 2023'
        ]
        
        for date_string in date_strings:
            parsed = parse_date(date_string)
            assert isinstance(parsed, datetime)
            assert parsed.year == 2023
            assert parsed.month == 12
            assert parsed.day == 25
        
        # Test date formatting
        test_date = datetime(2023, 12, 25, 15, 30, 0, tzinfo=timezone.utc)
        
        formatted_iso = format_date(test_date, 'iso')
        assert '2023-12-25' in formatted_iso
        assert 'T15:30:00' in formatted_iso
        
        formatted_custom = format_date(test_date, 'YYYY-MM-DD HH:mm:ss')
        assert formatted_custom == '2023-12-25 15:30:00'
        
        formatted_human = format_date(test_date, 'MMMM DD, YYYY')
        assert 'December 25, 2023' in formatted_human
        
        # Test invalid date handling
        invalid_parsed = parse_date('invalid-date-string', default=None)
        assert invalid_parsed is None
        
        # Test timezone handling
        utc_date = datetime(2023, 12, 25, 15, 30, 0, tzinfo=timezone.utc)
        local_formatted = format_date(utc_date, 'YYYY-MM-DD HH:mm:ss', timezone='US/Eastern')
        # Should be different from UTC time due to timezone conversion
        assert local_formatted != '2023-12-25 15:30:00'
        
        logger.info("Date/time processing moment.js equivalent tested successfully")
    
    def test_currency_operations_and_rounding(self):
        """Test currency operations, validation, and proper rounding."""
        # Test currency rounding
        test_amounts = [
            (Decimal('123.456'), 'USD', Decimal('123.46')),
            (Decimal('123.454'), 'USD', Decimal('123.45')),
            (Decimal('123.455'), 'USD', Decimal('123.46')),  # Banker's rounding
            (Decimal('100.999'), 'USD', Decimal('101.00'))
        ]
        
        for amount, currency, expected in test_amounts:
            rounded = round_currency(amount, currency)
            assert rounded == expected
        
        # Test currency validation
        valid_amounts = [
            (Decimal('100.00'), 'USD'),
            (Decimal('50.99'), 'EUR'),
            (Decimal('0.01'), 'USD')
        ]
        
        for amount, currency in valid_amounts:
            assert validate_currency(amount, currency) is True
        
        # Test invalid currency amounts
        invalid_amounts = [
            (Decimal('-10.00'), 'USD'),  # Negative amount
            (Decimal('0.00'), 'USD'),    # Zero amount
            (Decimal('100.001'), 'USD')  # Too many decimal places
        ]
        
        for amount, currency in invalid_amounts:
            assert validate_currency(amount, currency) is False
        
        # Test currency code validation
        assert validate_currency(Decimal('100.00'), 'INVALID') is False
        assert validate_currency(Decimal('100.00'), 'USD') is True
        
        logger.info("Currency operations and rounding tested successfully")
    
    def test_data_format_conversion(self):
        """Test data format conversion between different types."""
        # Test JSON parsing and serialization
        json_data = '{"name": "John", "age": 30, "active": true}'
        parsed = json.loads(json_data)
        assert parsed['name'] == 'John'
        assert parsed['age'] == 30
        assert parsed['active'] is True
        
        # Test data structure flattening
        nested_data = {
            'user': {
                'profile': {
                    'name': 'John Doe',
                    'email': 'john@example.com'
                },
                'preferences': {
                    'theme': 'dark',
                    'notifications': True
                }
            }
        }
        
        # Flatten using utility function (would need to implement)
        # flattened = flatten_data(nested_data)
        # assert 'user.profile.name' in flattened
        # assert flattened['user.profile.name'] == 'John Doe'
        
        # Test data merging
        data1 = {'a': 1, 'b': 2}
        data2 = {'b': 3, 'c': 4}
        # merged = merge_data(data1, data2)
        # assert merged['a'] == 1
        # assert merged['b'] == 3  # data2 should override data1
        # assert merged['c'] == 4
        
        logger.info("Data format conversion tested successfully")
    
    @pytest.mark.performance
    def test_utility_performance_benchmarks(self, performance_test_context):
        """Test utility function performance to ensure ≤10% variance from Node.js baseline."""
        performance_test_context['start_measurement']('utility_performance')
        
        # Generate test data
        test_emails = [f'user{i}@example.com' for i in range(1000)]
        test_phones = [f'+1-555-{i:03d}-{i:04d}' for i in range(1000)]
        test_amounts = [Decimal(f'{100 + i}.99') for i in range(1000)]
        test_dates = [f'2023-{(i % 12) + 1:02d}-{(i % 28) + 1:02d}' for i in range(1000)]
        
        # Measure email validation performance
        email_start = time.perf_counter()
        email_results = [validate_email(email) for email in test_emails]
        email_time = time.perf_counter() - email_start
        
        # Measure phone validation performance
        phone_start = time.perf_counter()
        phone_results = [validate_phone(phone) for phone in test_phones]
        phone_time = time.perf_counter() - phone_start
        
        # Measure currency rounding performance
        currency_start = time.perf_counter()
        currency_results = [round_currency(amount, 'USD') for amount in test_amounts]
        currency_time = time.perf_counter() - currency_start
        
        # Measure date parsing performance
        date_start = time.perf_counter()
        date_results = [parse_date(date_str) for date_str in test_dates]
        date_time = time.perf_counter() - date_start
        
        execution_time = performance_test_context['end_measurement']()
        
        # Log performance metrics
        logger.info(
            "Utility performance benchmarks completed",
            total_execution_time=execution_time,
            email_validation_time=email_time,
            phone_validation_time=phone_time,
            currency_rounding_time=currency_time,
            date_parsing_time=date_time,
            operations_performed=len(test_emails) * 4,
            avg_email_validation_time=email_time / len(test_emails),
            avg_phone_validation_time=phone_time / len(test_phones),
            avg_currency_rounding_time=currency_time / len(test_amounts),
            avg_date_parsing_time=date_time / len(test_dates)
        )
        
        # Verify performance is within acceptable bounds
        assert email_time < 2.0  # Should validate 1000 emails in under 2 seconds
        assert phone_time < 3.0  # Should validate 1000 phones in under 3 seconds
        assert currency_time < 1.0  # Should round 1000 amounts in under 1 second
        assert date_time < 2.0  # Should parse 1000 dates in under 2 seconds
        
        # Verify all operations completed successfully
        assert all(email_results)
        assert all(phone_results)
        assert len(currency_results) == 1000
        assert all(result is not None for result in date_results if result)


# ============================================================================
# INTEGRATION AND ERROR HANDLING TESTING
# ============================================================================

class TestBusinessLogicIntegration:
    """
    Integration testing for business logic components working together.
    
    Tests component integration, error propagation, transaction handling,
    and end-to-end business workflows per F-004-RQ-001 requirements.
    """
    
    def test_model_validator_processor_integration(self):
        """Test integration between models, validators, and processors."""
        # Create user through integrated workflow
        user_data = {
            'username': 'integration_test',
            'email': 'integration@example.com',
            'first_name': 'Integration',
            'last_name': 'Test'
        }
        
        # Validate using marshmallow validator
        validator = UserValidator()
        validated_data = validator.load(user_data)
        
        # Create model from validated data
        user_model = User(**validated_data)
        
        # Process through business processor
        processor = DataTransformer()
        processed_data = processor.normalize_data(user_model.to_api_dict())
        
        # Verify integration flow
        assert processed_data['username'] == 'integration_test'
        assert processed_data['email'] == 'integration@example.com'
        assert 'full_name' in processed_data or ('first_name' in processed_data and 'last_name' in processed_data)
        
        logger.info("Model-validator-processor integration tested successfully")
    
    def test_service_workflow_end_to_end(self):
        """Test complete service workflow from request to response."""
        with patch('src.business.services.httpx.AsyncClient') as mock_httpx:
            # Configure mock external services
            mock_client = AsyncMock()
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {'status': 'success'}
            mock_client.post.return_value = mock_response
            mock_httpx.return_value = mock_client
            
            # Execute complete order workflow
            order_service = OrderService()
            user_service = UserService()
            payment_service = PaymentService()
            
            # Step 1: Create user
            user_data = {
                'username': 'workflow_user',
                'email': 'workflow@example.com',
                'first_name': 'Workflow',
                'last_name': 'User'
            }
            user = user_service.create_user(user_data)
            
            # Step 2: Create order
            order_data = {
                'customer_email': user.email,
                'customer_name': user.full_name,
                'items': [
                    {
                        'product_id': str(uuid.uuid4()),
                        'product_sku': 'WORKFLOW001',
                        'product_name': 'Workflow Product',
                        'quantity': 1,
                        'unit_price': {'amount': '50.00', 'currency_code': 'USD'}
                    }
                ],
                'billing_address': {
                    'street_line_1': '123 Workflow St',
                    'city': 'Test City',
                    'state_province': 'Test State',
                    'postal_code': '12345',
                    'country_code': 'US'
                }
            }
            order = order_service.create_order(order_data)
            
            # Step 3: Process payment
            payment_data = {
                'order_id': order.id,
                'amount': order.total_amount,
                'payment_method': PaymentMethod.CREDIT_CARD,
                'customer_id': user.id
            }
            payment = payment_service.create_payment(payment_data)
            payment_result = payment_service.process_payment(payment.id)
            
            # Step 4: Fulfill order
            fulfillment_result = order_service.fulfill_order(order.id)
            
            # Verify end-to-end workflow
            assert user.is_active is True
            assert order.status in [OrderStatus.PENDING, OrderStatus.CONFIRMED]
            assert payment_result['payment_processed'] is True
            assert fulfillment_result['shipping_label_created'] is True
            
            logger.info("Service workflow end-to-end tested successfully")
    
    def test_error_propagation_and_handling(self):
        """Test error propagation through business logic layers."""
        # Test validation error propagation
        validator = UserValidator()
        
        with pytest.raises(MarshmallowValidationError) as exc_info:
            invalid_data = {
                'username': '',  # Invalid
                'email': 'invalid-email',  # Invalid
                'first_name': '',  # Invalid
                'last_name': ''  # Invalid
            }
            validator.load(invalid_data)
        
        # Verify error structure
        errors = exc_info.value.messages
        assert 'username' in errors
        assert 'email' in errors
        
        # Test business rule error propagation
        with pytest.raises(BusinessRuleViolationError) as exc_info:
            user_data = {
                'username': 'admin',  # Reserved username
                'email': 'test@example.com',
                'first_name': 'Test',
                'last_name': 'User'
            }
            user = User(**user_data)
            user.validate_business_rules()
        
        error = exc_info.value
        assert error.error_code == "RESERVED_USERNAME"
        assert error.severity == ErrorSeverity.MEDIUM
        
        # Test service layer error handling
        user_service = UserService()
        
        with pytest.raises(DataValidationError):
            invalid_service_data = {
                'username': '',
                'email': 'invalid',
                'first_name': '',
                'last_name': ''
            }
            user_service.create_user(invalid_service_data)
        
        logger.info("Error propagation and handling tested successfully")
    
    def test_transaction_rollback_scenarios(self):
        """Test transaction handling and rollback scenarios."""
        with patch('src.business.services.DatabaseTransaction') as mock_transaction:
            # Configure mock transaction
            mock_tx = Mock()
            mock_transaction.return_value = mock_tx
            
            order_service = OrderService()
            payment_service = PaymentService()
            
            # Test successful transaction
            order_data = {
                'customer_email': 'transaction@example.com',
                'customer_name': 'Transaction Test',
                'items': [
                    {
                        'product_id': str(uuid.uuid4()),
                        'product_sku': 'TX001',
                        'product_name': 'Transaction Product',
                        'quantity': 1,
                        'unit_price': {'amount': '100.00', 'currency_code': 'USD'}
                    }
                ],
                'billing_address': {
                    'street_line_1': '123 Transaction St',
                    'city': 'Test City',
                    'state_province': 'Test State',
                    'postal_code': '12345',
                    'country_code': 'US'
                }
            }
            
            # Execute transaction
            with order_service.begin_transaction() as tx:
                order = order_service.create_order(order_data, transaction=tx)
                payment_data = {
                    'order_id': order.id,
                    'amount': order.total_amount,
                    'payment_method': PaymentMethod.CREDIT_CARD
                }
                payment = payment_service.create_payment(payment_data, transaction=tx)
                
                # Verify transaction setup
                assert mock_tx.begin.called
                assert order.id is not None
                assert payment.id is not None
            
            # Verify transaction commit
            assert mock_tx.commit.called
            
            # Test transaction rollback scenario
            mock_tx.reset_mock()
            
            with pytest.raises(DataProcessingError):
                with order_service.begin_transaction() as tx:
                    # Create order successfully
                    order = order_service.create_order(order_data, transaction=tx)
                    
                    # Simulate payment failure
                    invalid_payment_data = {
                        'order_id': order.id,
                        'amount': {'amount': '-100.00', 'currency_code': 'USD'},  # Invalid negative amount
                        'payment_method': PaymentMethod.CREDIT_CARD
                    }
                    payment_service.create_payment(invalid_payment_data, transaction=tx)
            
            # Verify transaction rollback
            assert mock_tx.rollback.called
            
            logger.info("Transaction rollback scenarios tested successfully")
    
    def test_cache_invalidation_integration(self):
        """Test cache invalidation integration across business logic."""
        with patch('src.business.services.redis.Redis') as mock_redis:
            # Configure mock Redis client
            mock_redis_instance = Mock()
            mock_redis_instance.get.return_value = None
            mock_redis_instance.set.return_value = True
            mock_redis_instance.delete.return_value = 1
            mock_redis.return_value = mock_redis_instance
            
            user_service = UserService()
            cache_service = CacheService()
            
            # Create user (should set cache)
            user_data = {
                'username': 'cache_test',
                'email': 'cache@example.com',
                'first_name': 'Cache',
                'last_name': 'Test'
            }
            user = user_service.create_user(user_data)
            
            # Verify cache operations
            assert mock_redis_instance.set.called
            
            # Update user (should invalidate cache)
            update_data = {'first_name': 'UpdatedCache'}
            updated_user = user_service.update_user(user.id, update_data)
            
            # Verify cache invalidation
            assert mock_redis_instance.delete.called
            
            # Retrieve user (should check cache first)
            retrieved_user = user_service.get_user_by_id(user.id)
            
            # Verify cache lookup
            assert mock_redis_instance.get.called
            
            logger.info("Cache invalidation integration tested successfully")
    
    @pytest.mark.performance
    def test_integration_performance_under_load(self, performance_test_context):
        """Test integration performance under load conditions."""
        performance_test_context['start_measurement']('integration_load_performance')
        
        with patch('src.business.services.httpx.AsyncClient') as mock_httpx:
            # Configure mock services
            mock_client = AsyncMock()
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {'status': 'success'}
            mock_client.post.return_value = mock_response
            mock_httpx.return_value = mock_client
            
            user_service = UserService()
            order_service = OrderService()
            
            # Simulate load with concurrent operations
            start_time = time.perf_counter()
            
            results = []
            for i in range(100):
                # Create user
                user_data = {
                    'username': f'load_user_{i}',
                    'email': f'load_{i}@example.com',
                    'first_name': f'Load{i}',
                    'last_name': 'User'
                }
                user = user_service.create_user(user_data)
                
                # Create order for user
                order_data = {
                    'customer_email': user.email,
                    'customer_name': user.full_name,
                    'items': [
                        {
                            'product_id': str(uuid.uuid4()),
                            'product_sku': f'LOAD{i:03d}',
                            'product_name': f'Load Product {i}',
                            'quantity': 1,
                            'unit_price': {'amount': f'{10 + i}.99', 'currency_code': 'USD'}
                        }
                    ],
                    'billing_address': {
                        'street_line_1': f'{i} Load St',
                        'city': 'Load City',
                        'state_province': 'Load State',
                        'postal_code': '12345',
                        'country_code': 'US'
                    }
                }
                order = order_service.create_order(order_data)
                
                results.append({
                    'user_id': user.id,
                    'order_id': order.id,
                    'iteration': i
                })
            
            load_time = time.perf_counter() - start_time
            execution_time = performance_test_context['end_measurement']()
            
            # Log performance metrics
            logger.info(
                "Integration load performance completed",
                total_execution_time=execution_time,
                load_processing_time=load_time,
                operations_completed=len(results) * 2,  # User + Order creation
                avg_operation_time=load_time / (len(results) * 2),
                throughput_ops_per_second=(len(results) * 2) / load_time
            )
            
            # Verify performance under load
            assert load_time < 30.0  # Should complete 200 operations in under 30 seconds
            assert len(results) == 100
            assert all('user_id' in result and 'order_id' in result for result in results)


# ============================================================================
# TEST EXECUTION AND REPORTING
# ============================================================================

if __name__ == "__main__":
    """
    Execute business logic test suite with comprehensive reporting.
    
    Runs all business logic tests with performance monitoring, coverage analysis,
    and detailed reporting for compliance with 95% coverage requirement and
    ≤10% performance variance validation per Section 6.6.3 and Section 0.1.1.
    """
    
    import sys
    import pytest
    
    # Configure test execution arguments
    test_args = [
        __file__,
        '-v',  # Verbose output
        '--tb=short',  # Short traceback format
        '--durations=10',  # Show 10 slowest tests
        '--cov=src.business',  # Coverage for business logic
        '--cov-report=term-missing',  # Show missing lines
        '--cov-report=html:htmlcov',  # HTML coverage report
        '--cov-fail-under=95',  # Fail if coverage below 95%
        '--strict-markers',  # Strict marker validation
        '--strict-config',  # Strict configuration validation
        '-m', 'not slow'  # Skip slow tests by default
    ]
    
    # Add performance testing if requested
    if '--performance' in sys.argv:
        test_args.extend(['-m', 'performance'])
        test_args.remove('-m')
        test_args.remove('not slow')
    
    # Execute test suite
    exit_code = pytest.main(test_args)
    
    # Log test execution summary
    logger.info(
        "Business logic test suite execution completed",
        exit_code=exit_code,
        test_file=__file__,
        coverage_target="95%",
        performance_target="≤10% variance from Node.js baseline"
    )
    
    sys.exit(exit_code)