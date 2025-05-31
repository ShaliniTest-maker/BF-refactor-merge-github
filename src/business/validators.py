"""
Business Rule Validation Engine for Flask Application

This module provides comprehensive business rule validation using marshmallow 3.20+ schemas
for enterprise-grade data validation, business rule enforcement, and schema validation patterns.
Implements equivalent validation patterns from Node.js implementation while maintaining
comprehensive business logic validation and error handling integration per Section 5.2.4.

The validation engine follows enterprise patterns with:
- Marshmallow 3.20+ for schema validation and data serialization per Section 5.2.4
- Business rule validation maintaining existing validation patterns per F-004-RQ-001
- Comprehensive data validation equivalent to Node.js implementation per F-004-RQ-001
- Validation error handling integration with error response management per F-005
- Schema validation and data serialization per Section 5.2.4
- Integration with business logic processing pipeline per Section 5.2.4

Validation Categories:
    Schema Validators:
        UserValidator: User account and profile validation
        OrganizationValidator: Organization and business entity validation
        ProductValidator: Product catalog and inventory validation
        OrderValidator: Order and transaction validation
        PaymentValidator: Payment and financial validation
        
    API Validators:
        RequestValidator: API request validation schemas
        PaginationValidator: Pagination parameter validation
        SearchValidator: Search and filtering validation
        FileUploadValidator: File upload validation
        
    Business Rule Validators:
        BusinessRuleEngine: Core business rule enforcement
        ValidationChain: Chained validation processing
        ConditionalValidator: Conditional validation rules
        CrossFieldValidator: Cross-field validation logic
        DataIntegrityValidator: Data integrity and consistency validation
        
    Utility Validators:
        EmailValidator: Email format and business rule validation
        PhoneValidator: Phone number format and regional validation
        AddressValidator: Address format and postal code validation
        CurrencyValidator: Monetary amount and currency validation
        DateTimeValidator: Date/time format and business rule validation
"""

import re
import uuid
from datetime import datetime, timezone, date, timedelta
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional, Union, Callable, Type, Set, Tuple
from functools import wraps
import phonenumbers
from phonenumbers import NumberParseException

# Marshmallow 3.20+ imports for comprehensive validation
from marshmallow import (
    Schema, fields, validate, validates, validates_schema, 
    post_load, pre_load, ValidationError as MarshmallowValidationError,
    EXCLUDE, INCLUDE, RAISE
)
from marshmallow.decorators import validates_schema
from marshmallow.exceptions import ValidationError
from email_validator import validate_email as email_validate, EmailNotValidError

# Import business components for integration
from .models import (
    BaseBusinessModel, User, Organization, Product, Order, OrderItem,
    PaymentTransaction, Address, ContactInfo, MonetaryAmount, DateTimeRange,
    FileUpload, SystemConfiguration, PaginationParams, SortParams, SearchParams,
    UserStatus, UserRole, OrderStatus, PaymentStatus, PaymentMethod, ProductStatus,
    Priority, ContactMethod, BUSINESS_MODEL_REGISTRY
)
from .exceptions import (
    BaseBusinessException, BusinessRuleViolationError, DataValidationError,
    DataProcessingError, ErrorSeverity, handle_validation_error
)
from .utils import (
    clean_data, validate_email, validate_phone, validate_postal_code,
    sanitize_input, safe_str, safe_int, safe_float, normalize_boolean,
    parse_date, format_date, round_currency, validate_currency
)

# Configure structured logging for validation operations
import structlog
logger = structlog.get_logger("business.validators")


# ============================================================================
# VALIDATION CONFIGURATION AND BASE CLASSES
# ============================================================================

class ValidationConfig:
    """
    Global validation configuration for business rule engine.
    
    Provides centralized configuration for validation behavior, error handling,
    and business rule enforcement patterns across all validation schemas.
    """
    
    # Error handling configuration
    UNKNOWN_FIELD_BEHAVIOR = EXCLUDE  # Exclude unknown fields by default
    STRICT_VALIDATION = True  # Enable strict validation mode
    VALIDATE_REQUIRED_FIELDS = True  # Validate required field presence
    
    # Business rule enforcement settings
    ENFORCE_BUSINESS_RULES = True  # Enable business rule validation
    CROSS_FIELD_VALIDATION = True  # Enable cross-field validation
    CONDITIONAL_VALIDATION = True  # Enable conditional validation rules
    
    # Performance optimization settings
    CACHE_VALIDATION_RESULTS = False  # Disable caching for security
    VALIDATE_ON_ASSIGNMENT = True  # Validate on field assignment
    LAZY_VALIDATION = False  # Perform immediate validation
    
    # Security settings
    SANITIZE_INPUT_DATA = True  # Sanitize input before validation
    FILTER_SENSITIVE_DATA = True  # Filter sensitive data from errors
    LOG_VALIDATION_FAILURES = True  # Log validation failures for audit
    
    # Integration settings
    BUSINESS_MODEL_INTEGRATION = True  # Integrate with business models
    EXCEPTION_INTEGRATION = True  # Use business exceptions
    METRICS_INTEGRATION = True  # Collect validation metrics


class BaseBusinessValidator(Schema):
    """
    Base validation schema for all business data validation.
    
    Provides common validation functionality, error handling integration,
    and business rule enforcement foundation for all business validation schemas.
    Implements enterprise validation patterns per Section 5.2.4 requirements.
    
    Features:
    - Marshmallow 3.20+ integration with enterprise error handling
    - Business rule validation and enforcement per F-004-RQ-001
    - Cross-field validation and conditional validation support
    - Integration with business exceptions per F-005 requirements
    - Performance optimization and audit trail generation
    - Security-conscious validation with input sanitization
    
    Example:
        class CustomValidator(BaseBusinessValidator):
            name = fields.Str(required=True, validate=validate.Length(min=1, max=100))
            email = fields.Email(required=True)
            
            @validates('name')
            def validate_name(self, value):
                return self.validate_business_rule('name_format', value)
                
            @validates_schema
            def validate_business_rules(self, data, **kwargs):
                self.enforce_business_rules(data)
    """
    
    class Meta:
        """Marshmallow schema configuration for business validation."""
        unknown = ValidationConfig.UNKNOWN_FIELD_BEHAVIOR
        strict = ValidationConfig.STRICT_VALIDATION
        ordered = True  # Maintain field order for consistent responses
        load_only = ()  # Fields only used during loading
        dump_only = ()  # Fields only used during dumping
    
    def __init__(self, *args, **kwargs):
        """
        Initialize business validator with enterprise configuration.
        
        Args:
            *args: Positional arguments passed to marshmallow Schema
            **kwargs: Keyword arguments passed to marshmallow Schema
        """
        # Extract business validation options
        self.enforce_business_rules = kwargs.pop('enforce_business_rules', 
                                                ValidationConfig.ENFORCE_BUSINESS_RULES)
        self.strict_mode = kwargs.pop('strict_mode', ValidationConfig.STRICT_VALIDATION)
        self.sanitize_input = kwargs.pop('sanitize_input', ValidationConfig.SANITIZE_INPUT_DATA)
        
        # Initialize validation context
        self.validation_context = kwargs.pop('validation_context', {})
        self.business_rules = kwargs.pop('business_rules', {})
        self.conditional_rules = kwargs.pop('conditional_rules', {})
        
        # Call parent constructor
        super().__init__(*args, **kwargs)
        
        # Initialize validation metrics
        self.validation_start_time = None
        self.validation_errors_count = 0
        self.business_rules_applied = 0
    
    @pre_load
    def sanitize_input_data(self, data, **kwargs):
        """
        Sanitize and clean input data before validation.
        
        Implements security requirements by sanitizing input data to prevent
        injection attacks and ensure data quality before validation processing.
        
        Args:
            data: Input data to sanitize
            **kwargs: Additional load context
            
        Returns:
            Sanitized input data ready for validation
        """
        if not self.sanitize_input or not isinstance(data, dict):
            return data
        
        try:
            # Record validation start time for performance monitoring
            self.validation_start_time = datetime.now(timezone.utc)
            
            # Sanitize input data using business utilities
            sanitized_data = clean_data(
                data,
                remove_empty=False,  # Keep empty values for validation
                remove_none=False,   # Keep None values for validation
                strip_strings=True,  # Strip whitespace
                convert_types=False  # Don't convert types yet
            )
            
            logger.debug("Input data sanitized for validation",
                        original_fields=len(data),
                        sanitized_fields=len(sanitized_data),
                        validator_class=self.__class__.__name__)
            
            return sanitized_data
            
        except Exception as e:
            logger.error("Failed to sanitize input data",
                        error=str(e),
                        validator_class=self.__class__.__name__)
            
            # Continue with original data if sanitization fails
            return data
    
    @post_load
    def validate_business_rules_and_convert(self, data, **kwargs):
        """
        Apply business rule validation and convert to business model.
        
        Performs comprehensive business rule validation after field validation
        and optionally converts validated data to corresponding business model
        instance per Section 5.2.4 integration requirements.
        
        Args:
            data: Validated field data
            **kwargs: Additional load context
            
        Returns:
            Validated data or business model instance
            
        Raises:
            BusinessRuleViolationError: If business rules are violated
            DataValidationError: If model conversion fails
        """
        try:
            # Apply business rule validation if enabled
            if self.enforce_business_rules:
                self.validate_cross_field_rules(data)
                self.validate_conditional_rules(data)
                self.validate_custom_business_rules(data)
            
            # Convert to business model if configured
            convert_to_model = kwargs.get('convert_to_model', False)
            if convert_to_model:
                model_class = self.get_business_model_class()
                if model_class:
                    try:
                        model_instance = model_class.from_dict(data)
                        # Validate business rules at model level
                        model_instance.validate_business_rules()
                        return model_instance
                    except Exception as e:
                        raise DataValidationError(
                            message=f"Failed to convert to {model_class.__name__} model",
                            error_code="MODEL_CONVERSION_FAILED",
                            context={
                                'model_class': model_class.__name__,
                                'validator_class': self.__class__.__name__
                            },
                            cause=e,
                            severity=ErrorSeverity.MEDIUM
                        )
            
            # Log successful validation
            self._log_validation_success(data)
            
            return data
            
        except BusinessRuleViolationError:
            # Re-raise business rule violations
            raise
        except Exception as e:
            # Convert unexpected errors to validation errors
            raise DataValidationError(
                message="Business rule validation failed",
                error_code="BUSINESS_RULE_VALIDATION_FAILED",
                context={'validator_class': self.__class__.__name__},
                cause=e,
                severity=ErrorSeverity.MEDIUM
            )
    
    def validate_cross_field_rules(self, data: Dict[str, Any]) -> None:
        """
        Validate cross-field business rules and dependencies.
        
        Override this method in subclasses to implement specific cross-field
        validation logic that depends on multiple field values.
        
        Args:
            data: Validated field data for cross-field validation
            
        Raises:
            BusinessRuleViolationError: If cross-field rules are violated
        """
        # Base implementation - override in subclasses
        pass
    
    def validate_conditional_rules(self, data: Dict[str, Any]) -> None:
        """
        Validate conditional business rules based on data context.
        
        Override this method in subclasses to implement conditional validation
        rules that apply based on specific field values or combinations.
        
        Args:
            data: Validated field data for conditional validation
            
        Raises:
            BusinessRuleViolationError: If conditional rules are violated
        """
        # Base implementation - override in subclasses
        pass
    
    def validate_custom_business_rules(self, data: Dict[str, Any]) -> None:
        """
        Validate custom business-specific rules.
        
        Override this method in subclasses to implement domain-specific
        business rules that don't fit into standard validation patterns.
        
        Args:
            data: Validated field data for custom validation
            
        Raises:
            BusinessRuleViolationError: If custom rules are violated
        """
        # Base implementation - override in subclasses
        pass
    
    def validate_business_rule(self, rule_name: str, value: Any, **kwargs) -> Any:
        """
        Validate individual business rule with comprehensive error handling.
        
        Provides standardized business rule validation with consistent error
        reporting and audit trail generation for enterprise compliance.
        
        Args:
            rule_name: Name of the business rule to validate
            value: Value to validate against the business rule
            **kwargs: Additional rule parameters and context
            
        Returns:
            Validated value (potentially transformed)
            
        Raises:
            BusinessRuleViolationError: If business rule validation fails
        """
        try:
            self.business_rules_applied += 1
            
            # Get rule configuration
            rule_config = self.business_rules.get(rule_name, {})
            rule_function = rule_config.get('function')
            rule_parameters = rule_config.get('parameters', {})
            rule_parameters.update(kwargs)
            
            # Apply business rule if function is defined
            if rule_function and callable(rule_function):
                try:
                    result = rule_function(value, **rule_parameters)
                    
                    logger.debug("Business rule validation passed",
                                rule_name=rule_name,
                                validator_class=self.__class__.__name__)
                    
                    return result if result is not None else value
                    
                except BusinessRuleViolationError:
                    # Re-raise business rule violations
                    raise
                except Exception as e:
                    raise BusinessRuleViolationError(
                        message=f"Business rule '{rule_name}' validation failed",
                        error_code=f"BUSINESS_RULE_{rule_name.upper()}_FAILED",
                        rule_name=rule_name,
                        rule_parameters=rule_parameters,
                        context={'value': str(value)[:100]},  # Limit for security
                        cause=e,
                        severity=ErrorSeverity.MEDIUM
                    )
            
            # Return original value if no rule function defined
            return value
            
        except BusinessRuleViolationError:
            raise
        except Exception as e:
            raise BusinessRuleViolationError(
                message=f"Failed to validate business rule '{rule_name}'",
                error_code="BUSINESS_RULE_VALIDATION_ERROR",
                rule_name=rule_name,
                cause=e,
                severity=ErrorSeverity.MEDIUM
            )
    
    def get_business_model_class(self) -> Optional[Type[BaseBusinessModel]]:
        """
        Get corresponding business model class for this validator.
        
        Override this method in subclasses to specify which business model
        class corresponds to this validator for automatic conversion.
        
        Returns:
            Business model class or None if no conversion available
        """
        # Base implementation returns None - override in subclasses
        return None
    
    def handle_validation_error(self, error: MarshmallowValidationError) -> DataValidationError:
        """
        Convert marshmallow validation errors to business exceptions.
        
        Transforms marshmallow validation errors into standardized business
        exceptions with proper error categorization and audit trail generation.
        
        Args:
            error: Marshmallow validation error to convert
            
        Returns:
            Business data validation error
        """
        self.validation_errors_count += len(error.messages) if hasattr(error, 'messages') else 1
        
        # Extract validation error details
        validation_errors = []
        field_errors = {}
        
        if hasattr(error, 'messages') and isinstance(error.messages, dict):
            for field, messages in error.messages.items():
                if isinstance(messages, list):
                    field_errors[field] = messages
                    for message in messages:
                        validation_errors.append({
                            'field': field,
                            'message': message,
                            'type': 'field_validation'
                        })
                else:
                    field_errors[field] = [str(messages)]
                    validation_errors.append({
                        'field': field,
                        'message': str(messages),
                        'type': 'field_validation'
                    })
        
        # Create business validation error
        business_error = DataValidationError(
            message=f"Validation failed for {self.__class__.__name__}",
            error_code="SCHEMA_VALIDATION_FAILED",
            validation_errors=validation_errors,
            field_errors=field_errors,
            context={
                'validator_class': self.__class__.__name__,
                'error_count': len(validation_errors)
            },
            cause=error,
            severity=ErrorSeverity.MEDIUM
        )
        
        # Log validation failure for audit trail
        if ValidationConfig.LOG_VALIDATION_FAILURES:
            logger.warning("Schema validation failed",
                          validator_class=self.__class__.__name__,
                          error_count=len(validation_errors),
                          field_errors=list(field_errors.keys()))
        
        return business_error
    
    def _log_validation_success(self, data: Dict[str, Any]) -> None:
        """Log successful validation for audit trail and performance monitoring."""
        if self.validation_start_time:
            validation_duration = (datetime.now(timezone.utc) - self.validation_start_time).total_seconds()
        else:
            validation_duration = 0
        
        logger.info("Validation completed successfully",
                   validator_class=self.__class__.__name__,
                   field_count=len(data),
                   business_rules_applied=self.business_rules_applied,
                   validation_duration_seconds=validation_duration,
                   validation_errors_count=self.validation_errors_count)


# ============================================================================
# FIELD VALIDATORS AND CUSTOM VALIDATION FUNCTIONS
# ============================================================================

class EmailField(fields.Field):
    """
    Enhanced email field with business rule validation.
    
    Provides comprehensive email validation including format validation,
    domain verification, and business-specific email policies.
    """
    
    def _serialize(self, value: Any, attr: str, obj: Any, **kwargs) -> Optional[str]:
        """Serialize email value to string."""
        return str(value) if value else None
    
    def _deserialize(self, value: Any, attr: Optional[str], data: Optional[Dict], **kwargs) -> str:
        """Deserialize and validate email value."""
        if not value:
            return value
        
        # Basic type validation
        if not isinstance(value, str):
            raise ValidationError("Email must be a string")
        
        # Clean and validate email
        email_str = value.strip().lower()
        
        try:
            # Use email-validator for comprehensive validation
            valid_email = email_validate(email_str)
            normalized_email = valid_email.email
            
            # Additional business rule validation
            if not validate_email(normalized_email, strict=True):
                raise ValidationError("Email format does not meet business requirements")
            
            return normalized_email
            
        except EmailNotValidError as e:
            raise ValidationError(f"Invalid email format: {str(e)}")
        except Exception as e:
            raise ValidationError(f"Email validation failed: {str(e)}")


class PhoneField(fields.Field):
    """
    Enhanced phone field with international validation.
    
    Provides comprehensive phone number validation including international
    format support, regional validation, and business phone policies.
    """
    
    def __init__(self, country_code: Optional[str] = None, format_type: str = "international", **kwargs):
        """
        Initialize phone field with validation options.
        
        Args:
            country_code: Default country code for validation
            format_type: Phone format type (international, national, e164)
            **kwargs: Additional field arguments
        """
        self.country_code = country_code
        self.format_type = format_type
        super().__init__(**kwargs)
    
    def _serialize(self, value: Any, attr: str, obj: Any, **kwargs) -> Optional[str]:
        """Serialize phone value to string."""
        return str(value) if value else None
    
    def _deserialize(self, value: Any, attr: Optional[str], data: Optional[Dict], **kwargs) -> str:
        """Deserialize and validate phone value."""
        if not value:
            return value
        
        # Basic type validation
        if not isinstance(value, str):
            raise ValidationError("Phone number must be a string")
        
        # Clean phone number
        phone_str = re.sub(r'[^\d+()-.\s]', '', value.strip())
        
        try:
            # Validate using business utilities
            if validate_phone(phone_str, country_code=self.country_code, format_type=self.format_type):
                return phone_str
            else:
                raise ValidationError("Invalid phone number format")
                
        except Exception as e:
            raise ValidationError(f"Phone validation failed: {str(e)}")


class CurrencyField(fields.Field):
    """
    Enhanced currency field with business rule validation.
    
    Provides comprehensive monetary amount validation including currency
    code validation, precision handling, and business financial policies.
    """
    
    def __init__(self, currency_code: Optional[str] = None, **kwargs):
        """
        Initialize currency field with validation options.
        
        Args:
            currency_code: Required currency code for validation
            **kwargs: Additional field arguments
        """
        self.currency_code = currency_code
        super().__init__(**kwargs)
    
    def _serialize(self, value: Any, attr: str, obj: Any, **kwargs) -> Optional[Dict[str, Any]]:
        """Serialize currency value to dictionary."""
        if isinstance(value, MonetaryAmount):
            return {
                'amount': str(value.amount),
                'currency_code': value.currency_code
            }
        return value
    
    def _deserialize(self, value: Any, attr: Optional[str], data: Optional[Dict], **kwargs) -> MonetaryAmount:
        """Deserialize and validate currency value."""
        if not value:
            return value
        
        try:
            # Handle different input formats
            if isinstance(value, dict):
                amount = value.get('amount')
                currency_code = value.get('currency_code', self.currency_code)
            elif isinstance(value, (int, float, str)):
                amount = value
                currency_code = self.currency_code
            else:
                raise ValidationError("Invalid currency format")
            
            # Validate currency components
            if not currency_code:
                raise ValidationError("Currency code is required")
            
            # Create and validate monetary amount
            monetary_amount = MonetaryAmount(
                amount=Decimal(str(amount)),
                currency_code=currency_code
            )
            
            # Business rule validation
            validate_currency(monetary_amount.amount, monetary_amount.currency_code)
            
            return monetary_amount
            
        except (InvalidOperation, ValueError) as e:
            raise ValidationError(f"Invalid monetary amount: {str(e)}")
        except Exception as e:
            raise ValidationError(f"Currency validation failed: {str(e)}")


class DateTimeField(fields.DateTime):
    """
    Enhanced datetime field with business rule validation.
    
    Provides comprehensive date/time validation including timezone handling,
    business date policies, and date range validation.
    """
    
    def __init__(self, allow_future: bool = True, allow_past: bool = True, 
                 business_days_only: bool = False, **kwargs):
        """
        Initialize datetime field with business validation options.
        
        Args:
            allow_future: Allow future dates
            allow_past: Allow past dates
            business_days_only: Restrict to business days only
            **kwargs: Additional field arguments
        """
        self.allow_future = allow_future
        self.allow_past = allow_past
        self.business_days_only = business_days_only
        super().__init__(**kwargs)
    
    def _deserialize(self, value: Any, attr: Optional[str], data: Optional[Dict], **kwargs) -> datetime:
        """Deserialize and validate datetime value."""
        # Use parent deserialization
        dt_value = super()._deserialize(value, attr, data, **kwargs)
        
        if not dt_value:
            return dt_value
        
        # Ensure timezone awareness
        if dt_value.tzinfo is None:
            dt_value = dt_value.replace(tzinfo=timezone.utc)
        
        current_time = datetime.now(timezone.utc)
        
        # Validate future/past restrictions
        if not self.allow_future and dt_value > current_time:
            raise ValidationError("Future dates are not allowed")
        
        if not self.allow_past and dt_value < current_time:
            raise ValidationError("Past dates are not allowed")
        
        # Validate business days restriction
        if self.business_days_only and dt_value.weekday() >= 5:  # Saturday = 5, Sunday = 6
            raise ValidationError("Only business days (Monday-Friday) are allowed")
        
        return dt_value


def validate_unique_identifier(value: str) -> str:
    """
    Validate unique identifier format (UUID or custom ID).
    
    Args:
        value: Identifier value to validate
        
    Returns:
        Validated identifier
        
    Raises:
        ValidationError: If identifier format is invalid
    """
    if not value:
        raise ValidationError("Identifier cannot be empty")
    
    # Try UUID validation first
    try:
        uuid.UUID(value)
        return value
    except ValueError:
        pass
    
    # Custom ID validation (alphanumeric with hyphens and underscores)
    if re.match(r'^[a-zA-Z0-9_-]+$', value) and len(value) >= 3:
        return value
    
    raise ValidationError("Invalid identifier format")


def validate_slug_format(value: str) -> str:
    """
    Validate URL slug format for SEO and URL safety.
    
    Args:
        value: Slug value to validate
        
    Returns:
        Validated slug
        
    Raises:
        ValidationError: If slug format is invalid
    """
    if not value:
        raise ValidationError("Slug cannot be empty")
    
    # Convert to lowercase and strip
    slug = value.lower().strip()
    
    # Validate slug pattern
    if not re.match(r'^[a-z0-9\-]+$', slug):
        raise ValidationError("Slug must contain only lowercase letters, numbers, and hyphens")
    
    # Check for reserved slugs
    reserved_slugs = {'admin', 'api', 'root', 'system', 'user', 'public', 'private'}
    if slug in reserved_slugs:
        raise ValidationError(f"Slug '{slug}' is reserved and cannot be used")
    
    return slug


def validate_business_entity_id(value: str, entity_type: str) -> str:
    """
    Validate business entity identifier with type-specific rules.
    
    Args:
        value: Entity ID to validate
        entity_type: Type of entity (user, organization, product, etc.)
        
    Returns:
        Validated entity ID
        
    Raises:
        ValidationError: If entity ID is invalid
    """
    if not value:
        raise ValidationError(f"{entity_type.title()} ID cannot be empty")
    
    # Clean the ID
    entity_id = value.strip()
    
    # Basic format validation
    if len(entity_id) < 3:
        raise ValidationError(f"{entity_type.title()} ID must be at least 3 characters")
    
    # Entity-specific validation
    if entity_type == 'user':
        # User IDs can be UUID or username format
        try:
            uuid.UUID(entity_id)
            return entity_id
        except ValueError:
            if re.match(r'^[a-zA-Z0-9_.-]+$', entity_id):
                return entity_id
            raise ValidationError("Invalid user ID format")
    
    elif entity_type in ['organization', 'product', 'order']:
        # These entities typically use UUID format
        try:
            uuid.UUID(entity_id)
            return entity_id
        except ValueError:
            raise ValidationError(f"Invalid {entity_type} ID format")
    
    # Default validation for other entity types
    if re.match(r'^[a-zA-Z0-9_-]+$', entity_id):
        return entity_id
    
    raise ValidationError(f"Invalid {entity_type} ID format")


# ============================================================================
# BUSINESS MODEL VALIDATORS
# ============================================================================

class UserValidator(BaseBusinessValidator):
    """
    Comprehensive user account validation schema.
    
    Provides complete user account validation including profile information,
    authentication data, permissions, and business rule enforcement for
    user management operations per F-004-RQ-001 requirements.
    """
    
    # Core user fields
    id = fields.Str(validate=validate_unique_identifier, allow_none=True)
    username = fields.Str(
        required=True,
        validate=[
            validate.Length(min=3, max=50),
            validate.Regexp(r'^[a-zA-Z0-9_.-]+$', error="Username contains invalid characters")
        ]
    )
    email = EmailField(required=True)
    first_name = fields.Str(required=True, validate=validate.Length(min=1, max=50))
    last_name = fields.Str(required=True, validate=validate.Length(min=1, max=50))
    display_name = fields.Str(validate=validate.Length(max=100), allow_none=True)
    avatar_url = fields.Url(allow_none=True)
    
    # Account status and permissions
    status = fields.Enum(UserStatus, by_value=True, missing=UserStatus.ACTIVE)
    role = fields.Enum(UserRole, by_value=True, missing=UserRole.USER)
    permissions = fields.List(fields.Str(), missing=list)
    
    # Contact information
    contact_info = fields.Nested('ContactInfoValidator', allow_none=True)
    
    # Authentication and security
    last_login_at = DateTimeField(allow_none=True)
    password_changed_at = DateTimeField(allow_none=True)
    login_attempts = fields.Int(validate=validate.Range(min=0), missing=0)
    is_locked = fields.Bool(missing=False)
    lock_expires_at = DateTimeField(allow_none=True)
    
    # Profile and preferences
    language_code = fields.Str(validate=validate.Length(min=2, max=5), missing="en")
    timezone = fields.Str(missing="UTC")
    date_format = fields.Str(missing="YYYY-MM-DD")
    
    @validates('username')
    def validate_username_business_rules(self, value):
        """Validate username business rules."""
        if not value:
            return value
        
        # Clean username
        username = value.strip().lower()
        
        # Check for reserved usernames
        reserved = {'admin', 'root', 'system', 'api', 'www', 'mail', 'ftp'}
        if username in reserved:
            raise ValidationError("Username is reserved and cannot be used")
        
        return username
    
    @validates('email')
    def validate_email_business_rules(self, value):
        """Validate email business rules."""
        return self.validate_business_rule('email_format', value)
    
    @validates_schema
    def validate_user_business_rules(self, data, **kwargs):
        """Validate cross-field user business rules."""
        # Validate lock expiration consistency
        if data.get('is_locked') and not data.get('lock_expires_at'):
            raise ValidationError({
                'lock_expires_at': ['Lock expiration time required for locked accounts']
            })
        
        # Validate admin role permissions
        if data.get('role') == UserRole.ADMIN and not data.get('permissions'):
            # Admin users should have explicit permissions
            pass  # Allow empty permissions for admin (they get all permissions)
    
    def get_business_model_class(self) -> Type[BaseBusinessModel]:
        """Return User model class for conversion."""
        return User


class OrganizationValidator(BaseBusinessValidator):
    """
    Comprehensive organization validation schema.
    
    Provides complete organization validation including business information,
    contact details, verification status, and business rule enforcement for
    multi-tenant and B2B operations.
    """
    
    # Core organization fields
    id = fields.Str(validate=validate_unique_identifier, allow_none=True)
    name = fields.Str(required=True, validate=validate.Length(min=1, max=200))
    legal_name = fields.Str(validate=validate.Length(max=200), allow_none=True)
    business_type = fields.Str(validate=validate.Length(max=50), allow_none=True)
    
    # Business identifiers
    tax_id = fields.Str(validate=validate.Length(max=50), allow_none=True)
    registration_number = fields.Str(validate=validate.Length(max=50), allow_none=True)
    
    # Contact information
    primary_contact = fields.Nested('ContactInfoValidator', allow_none=True)
    billing_address = fields.Nested('AddressValidator', allow_none=True)
    shipping_address = fields.Nested('AddressValidator', allow_none=True)
    
    # Business details
    website_url = fields.Url(allow_none=True)
    description = fields.Str(validate=validate.Length(max=1000), allow_none=True)
    industry = fields.Str(validate=validate.Length(max=100), allow_none=True)
    employee_count = fields.Int(validate=validate.Range(min=1), allow_none=True)
    
    # Status and verification
    status = fields.Enum(UserStatus, by_value=True, missing=UserStatus.ACTIVE)
    is_verified = fields.Bool(missing=False)
    verification_date = DateTimeField(allow_none=True)
    
    # Hierarchy
    parent_organization_id = fields.Str(validate=validate_unique_identifier, allow_none=True)
    
    @validates('name')
    def validate_organization_name(self, value):
        """Validate organization name business rules."""
        if not value:
            return value
        
        # Sanitize organization name
        clean_name = sanitize_input(value, allow_html=False, max_length=200)
        
        # Additional business rules can be added here
        return clean_name
    
    @validates_schema
    def validate_organization_business_rules(self, data, **kwargs):
        """Validate cross-field organization business rules."""
        # Verified organizations must have verification date
        if data.get('is_verified') and not data.get('verification_date'):
            raise ValidationError({
                'verification_date': ['Verification date required for verified organizations']
            })
        
        # Legal name should be provided for verified businesses
        if data.get('is_verified') and not data.get('legal_name'):
            # This is a warning, not an error
            pass
    
    def get_business_model_class(self) -> Type[BaseBusinessModel]:
        """Return Organization model class for conversion."""
        return Organization


class ProductValidator(BaseBusinessValidator):
    """
    Comprehensive product validation schema.
    
    Provides complete product validation including catalog information,
    pricing, inventory, categorization, and business rule enforcement for
    e-commerce and business catalog operations.
    """
    
    # Core product fields
    id = fields.Str(validate=validate_unique_identifier, allow_none=True)
    sku = fields.Str(required=True, validate=validate.Length(min=1, max=50))
    name = fields.Str(required=True, validate=validate.Length(min=1, max=200))
    slug = fields.Str(required=True, validate=validate_slug_format)
    description = fields.Str(validate=validate.Length(max=2000), allow_none=True)
    short_description = fields.Str(validate=validate.Length(max=500), allow_none=True)
    
    # Categorization
    category_id = fields.Str(validate=validate_unique_identifier, allow_none=True)
    tags = fields.List(fields.Str(validate=validate.Length(max=50)), missing=list)
    brand = fields.Str(validate=validate.Length(max=100), allow_none=True)
    
    # Pricing
    base_price = fields.Nested('MonetaryAmountValidator', required=True)
    sale_price = fields.Nested('MonetaryAmountValidator', allow_none=True)
    cost_price = fields.Nested('MonetaryAmountValidator', allow_none=True)
    
    # Inventory
    status = fields.Enum(ProductStatus, by_value=True, missing=ProductStatus.ACTIVE)
    inventory_quantity = fields.Int(validate=validate.Range(min=0), missing=0)
    low_stock_threshold = fields.Int(validate=validate.Range(min=0), missing=5)
    track_inventory = fields.Bool(missing=True)
    
    # Physical attributes
    weight = fields.Decimal(validate=validate.Range(min=0), allow_none=True)
    dimensions = fields.Dict(allow_none=True)
    
    # Digital content
    images = fields.List(fields.Url(), missing=list)
    documents = fields.List(fields.Dict(), missing=list)
    
    # SEO and metadata
    meta_title = fields.Str(validate=validate.Length(max=60), allow_none=True)
    meta_description = fields.Str(validate=validate.Length(max=160), allow_none=True)
    
    @validates('sku')
    def validate_sku_format(self, value):
        """Validate SKU format and business rules."""
        if not value:
            return value
        
        # Clean and standardize SKU
        sku = value.strip().upper()
        sku = re.sub(r'[^\w\-]', '', sku)
        
        return sku
    
    @validates('dimensions')
    def validate_dimensions_format(self, value):
        """Validate product dimensions structure."""
        if not value:
            return value
        
        required_keys = {'length', 'width', 'height'}
        if not all(key in value for key in required_keys):
            raise ValidationError("Dimensions must include length, width, and height")
        
        # Validate all dimensions are positive
        for key, dimension_value in value.items():
            try:
                if float(dimension_value) <= 0:
                    raise ValidationError(f"Dimension {key} must be positive")
            except (ValueError, TypeError):
                raise ValidationError(f"Dimension {key} must be a valid number")
        
        return value
    
    @validates_schema
    def validate_product_business_rules(self, data, **kwargs):
        """Validate cross-field product business rules."""
        # Sale price must be less than base price
        base_price = data.get('base_price')
        sale_price = data.get('sale_price')
        
        if base_price and sale_price:
            if isinstance(base_price, dict) and isinstance(sale_price, dict):
                base_amount = base_price.get('amount', 0)
                sale_amount = sale_price.get('amount', 0)
                
                if sale_amount >= base_amount:
                    raise ValidationError({
                        'sale_price': ['Sale price must be less than base price']
                    })
        
        # Active products should have positive inventory if tracking
        status = data.get('status')
        track_inventory = data.get('track_inventory', True)
        inventory_quantity = data.get('inventory_quantity', 0)
        
        if (status == ProductStatus.ACTIVE and 
            track_inventory and 
            inventory_quantity <= 0):
            # This is a warning for business logic, not a validation error
            pass
    
    def get_business_model_class(self) -> Type[BaseBusinessModel]:
        """Return Product model class for conversion."""
        return Product


class OrderValidator(BaseBusinessValidator):
    """
    Comprehensive order validation schema.
    
    Provides complete order validation including customer information,
    line items, pricing calculations, shipping details, and business rule
    enforcement for e-commerce and business transaction operations.
    """
    
    # Core order fields
    id = fields.Str(validate=validate_unique_identifier, allow_none=True)
    order_number = fields.Str(allow_none=True)
    
    # Customer information
    customer_id = fields.Str(validate=validate_unique_identifier, allow_none=True)
    customer_email = EmailField(required=True)
    customer_name = fields.Str(required=True, validate=validate.Length(min=1, max=100))
    
    # Order items
    items = fields.List(fields.Nested('OrderItemValidator'), required=True, validate=validate.Length(min=1))
    
    # Pricing
    subtotal = fields.Nested('MonetaryAmountValidator', required=True)
    tax_amount = fields.Nested('MonetaryAmountValidator', missing={'amount': '0', 'currency_code': 'USD'})
    shipping_amount = fields.Nested('MonetaryAmountValidator', missing={'amount': '0', 'currency_code': 'USD'})
    discount_amount = fields.Nested('MonetaryAmountValidator', missing={'amount': '0', 'currency_code': 'USD'})
    total_amount = fields.Nested('MonetaryAmountValidator', required=True)
    
    # Addresses
    billing_address = fields.Nested('AddressValidator', required=True)
    shipping_address = fields.Nested('AddressValidator', allow_none=True)
    
    # Status and tracking
    status = fields.Enum(OrderStatus, by_value=True, missing=OrderStatus.PENDING)
    order_date = DateTimeField(missing=datetime.now(timezone.utc))
    shipped_date = DateTimeField(allow_none=True)
    delivered_date = DateTimeField(allow_none=True)
    
    # Additional information
    notes = fields.Str(validate=validate.Length(max=1000), allow_none=True)
    tracking_number = fields.Str(allow_none=True)
    payment_method = fields.Enum(PaymentMethod, by_value=True, allow_none=True)
    
    @validates('order_number')
    def validate_order_number_format(self, value):
        """Generate order number if not provided."""
        if value is None:
            # Generate order number with timestamp and random component
            import time
            timestamp = str(int(time.time()))[-6:]  # Last 6 digits of timestamp
            random_part = str(uuid.uuid4()).replace('-', '')[:6].upper()
            return f"ORD-{timestamp}-{random_part}"
        return value
    
    @validates_schema
    def validate_order_totals(self, data, **kwargs):
        """Validate order total calculations."""
        try:
            # Extract amounts from nested data
            subtotal = self._extract_amount(data.get('subtotal'))
            tax_amount = self._extract_amount(data.get('tax_amount', {'amount': '0'}))
            shipping_amount = self._extract_amount(data.get('shipping_amount', {'amount': '0'}))
            discount_amount = self._extract_amount(data.get('discount_amount', {'amount': '0'}))
            total_amount = self._extract_amount(data.get('total_amount'))
            
            # Calculate expected total
            expected_total = subtotal + tax_amount + shipping_amount - discount_amount
            
            # Allow small rounding differences
            if abs(expected_total - total_amount) > Decimal('0.01'):
                raise ValidationError({
                    'total_amount': [f'Order total {total_amount} does not match calculated amount {expected_total}']
                })
        
        except (KeyError, TypeError, InvalidOperation):
            # Skip validation if amounts are not properly formatted
            pass
        
        # Validate status progression
        status = data.get('status')
        shipped_date = data.get('shipped_date')
        delivered_date = data.get('delivered_date')
        
        if shipped_date and status not in [OrderStatus.SHIPPED, OrderStatus.DELIVERED]:
            raise ValidationError({
                'status': ['Orders with shipping date must be in shipped or delivered status']
            })
        
        if delivered_date and status != OrderStatus.DELIVERED:
            raise ValidationError({
                'status': ['Orders with delivery date must be in delivered status']
            })
    
    def _extract_amount(self, amount_data) -> Decimal:
        """Extract decimal amount from monetary amount data."""
        if isinstance(amount_data, dict):
            return Decimal(str(amount_data.get('amount', 0)))
        elif isinstance(amount_data, (int, float, str)):
            return Decimal(str(amount_data))
        return Decimal('0')
    
    def get_business_model_class(self) -> Type[BaseBusinessModel]:
        """Return Order model class for conversion."""
        return Order


class OrderItemValidator(BaseBusinessValidator):
    """
    Order line item validation schema.
    
    Provides validation for individual order line items including product
    references, quantities, pricing, and calculations.
    """
    
    product_id = fields.Str(required=True, validate=validate_unique_identifier)
    product_sku = fields.Str(required=True)
    product_name = fields.Str(required=True, validate=validate.Length(min=1, max=200))
    quantity = fields.Int(required=True, validate=validate.Range(min=1))
    unit_price = fields.Nested('MonetaryAmountValidator', required=True)
    total_price = fields.Nested('MonetaryAmountValidator', allow_none=True)
    
    # Discounts and adjustments
    discount_amount = fields.Nested('MonetaryAmountValidator', allow_none=True)
    tax_amount = fields.Nested('MonetaryAmountValidator', allow_none=True)
    
    # Product snapshot
    product_attributes = fields.Dict(allow_none=True)
    
    @validates_schema
    def validate_line_item_calculations(self, data, **kwargs):
        """Validate line item total calculations."""
        try:
            quantity = data.get('quantity', 1)
            unit_price = self._extract_amount(data.get('unit_price'))
            discount_amount = self._extract_amount(data.get('discount_amount', {'amount': '0'}))
            tax_amount = self._extract_amount(data.get('tax_amount', {'amount': '0'}))
            total_price = self._extract_amount(data.get('total_price'))
            
            if total_price:  # Only validate if total_price is provided
                expected_total = (unit_price * quantity) - discount_amount + tax_amount
                
                if abs(expected_total - total_price) > Decimal('0.01'):
                    raise ValidationError({
                        'total_price': [f'Line item total {total_price} does not match calculated amount {expected_total}']
                    })
        
        except (KeyError, TypeError, InvalidOperation):
            # Skip validation if amounts are not properly formatted
            pass
    
    def _extract_amount(self, amount_data) -> Decimal:
        """Extract decimal amount from monetary amount data."""
        if isinstance(amount_data, dict):
            return Decimal(str(amount_data.get('amount', 0)))
        elif isinstance(amount_data, (int, float, str)):
            return Decimal(str(amount_data))
        return Decimal('0')
    
    def get_business_model_class(self) -> Type[BaseBusinessModel]:
        """Return OrderItem model class for conversion."""
        return OrderItem


# ============================================================================
# UTILITY VALIDATORS
# ============================================================================

class AddressValidator(BaseBusinessValidator):
    """
    Geographic address validation schema.
    
    Provides comprehensive address validation including format validation,
    postal code verification, and regional address policies.
    """
    
    street_line_1 = fields.Str(required=True, validate=validate.Length(min=1, max=100))
    street_line_2 = fields.Str(validate=validate.Length(max=100), allow_none=True)
    city = fields.Str(required=True, validate=validate.Length(min=1, max=50))
    state_province = fields.Str(required=True, validate=validate.Length(min=1, max=50))
    postal_code = fields.Str(required=True, validate=validate.Length(min=3, max=20))
    country_code = fields.Str(required=True, validate=validate.Length(min=2, max=3))
    
    @validates('country_code')
    def validate_country_code_format(self, value):
        """Validate ISO country code format."""
        if value:
            country_code = value.upper().strip()
            if len(country_code) not in [2, 3]:
                raise ValidationError("Country code must be 2 or 3 characters")
            return country_code
        return value
    
    @validates('postal_code')
    def validate_postal_code_format(self, value):
        """Validate postal code format."""
        if value:
            postal_code = value.strip().upper()
            # Additional validation can be added based on country
            return postal_code
        return value
    
    def get_business_model_class(self) -> Type[BaseBusinessModel]:
        """Return Address model class for conversion."""
        return Address


class ContactInfoValidator(BaseBusinessValidator):
    """
    Contact information validation schema.
    
    Provides comprehensive contact information validation including email,
    phone numbers, and communication preferences.
    """
    
    primary_email = EmailField(allow_none=True)
    secondary_email = EmailField(allow_none=True)
    primary_phone = PhoneField(allow_none=True)
    secondary_phone = PhoneField(allow_none=True)
    preferred_contact_method = fields.Enum(ContactMethod, by_value=True, missing=ContactMethod.EMAIL)
    allow_marketing = fields.Bool(missing=False)
    timezone = fields.Str(validate=validate.Length(max=50), allow_none=True)
    
    @validates_schema
    def validate_contact_requirements(self, data, **kwargs):
        """Validate that at least one primary contact method is provided."""
        primary_email = data.get('primary_email')
        primary_phone = data.get('primary_phone')
        
        if not primary_email and not primary_phone:
            raise ValidationError("At least one primary contact method (email or phone) is required")
    
    def get_business_model_class(self) -> Type[BaseBusinessModel]:
        """Return ContactInfo model class for conversion."""
        return ContactInfo


class MonetaryAmountValidator(BaseBusinessValidator):
    """
    Monetary amount validation schema.
    
    Provides comprehensive monetary amount validation including currency
    validation, precision handling, and business financial policies.
    """
    
    amount = fields.Decimal(required=True, validate=validate.Range(min=0), places=2)
    currency_code = fields.Str(required=True, validate=validate.Length(min=3, max=3))
    
    @validates('currency_code')
    def validate_currency_code_format(self, value):
        """Validate ISO 4217 currency code."""
        if value:
            currency = value.upper().strip()
            if len(currency) != 3 or not currency.isalpha():
                raise ValidationError("Currency code must be 3 letter ISO 4217 code")
            return currency
        return value
    
    @validates('amount')
    def validate_amount_precision(self, value):
        """Validate monetary amount precision."""
        if value is not None:
            # Ensure proper decimal precision
            if value < 0:
                raise ValidationError("Monetary amount cannot be negative")
            
            # Validate decimal places (2 for most currencies)
            decimal_value = Decimal(str(value))
            if decimal_value.as_tuple().exponent < -2:
                raise ValidationError("Monetary amount cannot have more than 2 decimal places")
        
        return value
    
    def get_business_model_class(self) -> Type[BaseBusinessModel]:
        """Return MonetaryAmount model class for conversion."""
        return MonetaryAmount


class PaginationValidator(BaseBusinessValidator):
    """
    Pagination parameters validation schema.
    
    Provides validation for API pagination parameters with business-appropriate
    limits and default values.
    """
    
    page = fields.Int(validate=validate.Range(min=1), missing=1)
    page_size = fields.Int(validate=validate.Range(min=1, max=100), missing=20)
    
    def get_business_model_class(self) -> Type[BaseBusinessModel]:
        """Return PaginationParams model class for conversion."""
        return PaginationParams


class SearchValidator(BaseBusinessValidator):
    """
    Search parameters validation schema.
    
    Provides validation for API search parameters with security validation
    and business-appropriate search constraints.
    """
    
    query = fields.Str(validate=validate.Length(max=200), allow_none=True)
    filters = fields.Dict(allow_none=True)
    include_inactive = fields.Bool(missing=False)
    
    @validates('query')
    def validate_search_query(self, value):
        """Validate and sanitize search query."""
        if value is None:
            return value
        
        # Sanitize search query for security
        sanitized = sanitize_input(value, allow_html=False, max_length=200)
        
        # Remove potentially dangerous query patterns
        sanitized = re.sub(r'[<>{}()[\]\\]', '', sanitized)
        
        return sanitized.strip() if sanitized else None
    
    @validates('filters')
    def validate_search_filters(self, value):
        """Validate search filters structure."""
        if value is None:
            return value
        
        if not isinstance(value, dict):
            raise ValidationError("Filters must be a dictionary")
        
        # Limit number of filters to prevent DoS
        if len(value) > 20:
            raise ValidationError("Too many filter parameters")
        
        # Validate filter keys
        validated_filters = {}
        for key, filter_value in value.items():
            if isinstance(key, str) and key.strip():
                # Clean filter key
                clean_key = re.sub(r'[^\w.]', '', key.strip())
                if clean_key:
                    validated_filters[clean_key] = filter_value
        
        return validated_filters
    
    def get_business_model_class(self) -> Type[BaseBusinessModel]:
        """Return SearchParams model class for conversion."""
        return SearchParams


# ============================================================================
# VALIDATION ENGINE AND ORCHESTRATION
# ============================================================================

class BusinessRuleEngine:
    """
    Comprehensive business rule validation engine.
    
    Provides centralized business rule management, validation orchestration,
    and enterprise-grade rule enforcement with audit trails and performance
    monitoring per Section 5.2.4 business logic requirements.
    
    Features:
    - Rule-based validation engine with dynamic rule loading
    - Cross-validator rule dependencies and validation chains
    - Conditional validation based on data context
    - Performance monitoring and validation metrics
    - Audit trail generation for compliance requirements
    - Integration with business exceptions and error handling
    
    Example:
        rule_engine = BusinessRuleEngine()
        rule_engine.register_rule('email_domain_validation', email_domain_rule)
        
        validator = UserValidator(business_rule_engine=rule_engine)
        validated_data = validator.load(user_data, convert_to_model=True)
    """
    
    def __init__(self):
        """Initialize business rule engine with default configuration."""
        self.rules = {}
        self.rule_dependencies = {}
        self.conditional_rules = {}
        self.validation_metrics = {
            'rules_executed': 0,
            'rules_failed': 0,
            'validation_time': 0.0
        }
        
        # Register default business rules
        self._register_default_rules()
    
    def register_rule(self, rule_name: str, rule_function: Callable, 
                     dependencies: Optional[List[str]] = None,
                     conditions: Optional[Dict[str, Any]] = None) -> None:
        """
        Register business rule with the validation engine.
        
        Args:
            rule_name: Unique name for the business rule
            rule_function: Function implementing the business rule logic
            dependencies: List of other rules this rule depends on
            conditions: Conditions that must be met for rule to apply
        """
        self.rules[rule_name] = {
            'function': rule_function,
            'dependencies': dependencies or [],
            'conditions': conditions or {},
            'execution_count': 0,
            'failure_count': 0
        }
        
        if dependencies:
            self.rule_dependencies[rule_name] = dependencies
        
        if conditions:
            self.conditional_rules[rule_name] = conditions
        
        logger.debug("Business rule registered",
                    rule_name=rule_name,
                    has_dependencies=bool(dependencies),
                    has_conditions=bool(conditions))
    
    def execute_rule(self, rule_name: str, value: Any, context: Optional[Dict[str, Any]] = None) -> Any:
        """
        Execute specific business rule with comprehensive error handling.
        
        Args:
            rule_name: Name of the rule to execute
            value: Value to validate against the rule
            context: Additional context for rule execution
            
        Returns:
            Validated value (potentially transformed)
            
        Raises:
            BusinessRuleViolationError: If rule validation fails
        """
        rule_config = self.rules.get(rule_name)
        if not rule_config:
            raise BusinessRuleViolationError(
                message=f"Unknown business rule: {rule_name}",
                error_code="UNKNOWN_BUSINESS_RULE",
                rule_name=rule_name,
                severity=ErrorSeverity.HIGH
            )
        
        try:
            # Update metrics
            rule_config['execution_count'] += 1
            self.validation_metrics['rules_executed'] += 1
            
            # Check rule conditions
            if not self._check_rule_conditions(rule_name, context or {}):
                logger.debug("Business rule skipped due to conditions",
                           rule_name=rule_name)
                return value
            
            # Execute rule dependencies first
            dependencies = rule_config.get('dependencies', [])
            for dependency in dependencies:
                value = self.execute_rule(dependency, value, context)
            
            # Execute the rule
            rule_function = rule_config['function']
            start_time = datetime.now(timezone.utc)
            
            result = rule_function(value, context or {})
            
            execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            self.validation_metrics['validation_time'] += execution_time
            
            logger.debug("Business rule executed successfully",
                        rule_name=rule_name,
                        execution_time_seconds=execution_time)
            
            return result if result is not None else value
            
        except BusinessRuleViolationError:
            # Update failure metrics
            rule_config['failure_count'] += 1
            self.validation_metrics['rules_failed'] += 1
            raise
        except Exception as e:
            # Convert unexpected errors to business rule violations
            rule_config['failure_count'] += 1
            self.validation_metrics['rules_failed'] += 1
            
            raise BusinessRuleViolationError(
                message=f"Business rule '{rule_name}' execution failed",
                error_code=f"RULE_{rule_name.upper()}_EXECUTION_FAILED",
                rule_name=rule_name,
                context={'error_type': type(e).__name__},
                cause=e,
                severity=ErrorSeverity.MEDIUM
            )
    
    def validate_data(self, data: Dict[str, Any], rule_names: List[str],
                     context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Validate data against multiple business rules.
        
        Args:
            data: Data to validate
            rule_names: List of rule names to apply
            context: Additional validation context
            
        Returns:
            Validated data with potential transformations
            
        Raises:
            BusinessRuleViolationError: If any rule validation fails
        """
        validated_data = data.copy()
        validation_context = context or {}
        validation_context.update({'data': validated_data})
        
        for field_name, field_value in validated_data.items():
            for rule_name in rule_names:
                if rule_name in self.rules:
                    validated_data[field_name] = self.execute_rule(
                        rule_name, field_value, validation_context
                    )
        
        return validated_data
    
    def get_validation_metrics(self) -> Dict[str, Any]:
        """
        Get validation performance metrics.
        
        Returns:
            Dictionary containing validation metrics and statistics
        """
        rule_stats = {}
        for rule_name, rule_config in self.rules.items():
            rule_stats[rule_name] = {
                'execution_count': rule_config['execution_count'],
                'failure_count': rule_config['failure_count'],
                'success_rate': (
                    (rule_config['execution_count'] - rule_config['failure_count']) / 
                    rule_config['execution_count']
                ) if rule_config['execution_count'] > 0 else 1.0
            }
        
        return {
            'global_metrics': self.validation_metrics,
            'rule_statistics': rule_stats,
            'total_rules': len(self.rules),
            'average_execution_time': (
                self.validation_metrics['validation_time'] / 
                self.validation_metrics['rules_executed']
            ) if self.validation_metrics['rules_executed'] > 0 else 0.0
        }
    
    def _check_rule_conditions(self, rule_name: str, context: Dict[str, Any]) -> bool:
        """Check if rule conditions are met for execution."""
        conditions = self.conditional_rules.get(rule_name, {})
        if not conditions:
            return True
        
        for condition_key, condition_value in conditions.items():
            context_value = context.get(condition_key)
            
            if condition_value != context_value:
                return False
        
        return True
    
    def _register_default_rules(self) -> None:
        """Register default business rules for common validation scenarios."""
        
        def email_domain_rule(value: str, context: Dict[str, Any]) -> str:
            """Validate email domain against business policies."""
            if not value or '@' not in value:
                return value
            
            domain = value.split('@')[1].lower()
            
            # Business rule: Block disposable email domains
            disposable_domains = {
                'tempmail.org', '10minutemail.com', 'guerrillamail.info',
                'mailinator.com', 'yopmail.com'
            }
            
            if domain in disposable_domains:
                raise BusinessRuleViolationError(
                    message="Disposable email addresses are not allowed",
                    error_code="DISPOSABLE_EMAIL_NOT_ALLOWED",
                    rule_name="email_domain_validation",
                    context={'domain': domain}
                )
            
            return value
        
        def username_profanity_rule(value: str, context: Dict[str, Any]) -> str:
            """Validate username against profanity filters."""
            if not value:
                return value
            
            # Simple profanity check (extend as needed)
            prohibited_words = {'admin', 'root', 'test', 'null', 'undefined'}
            
            if value.lower() in prohibited_words:
                raise BusinessRuleViolationError(
                    message="Username contains prohibited content",
                    error_code="USERNAME_PROHIBITED_CONTENT",
                    rule_name="username_profanity_validation",
                    context={'username': value}
                )
            
            return value
        
        def currency_amount_rule(value: Decimal, context: Dict[str, Any]) -> Decimal:
            """Validate currency amounts against business limits."""
            if value is None:
                return value
            
            # Business rule: Maximum transaction amount
            max_amount = Decimal('100000.00')  # $100,000 limit
            
            if value > max_amount:
                raise BusinessRuleViolationError(
                    message=f"Amount exceeds maximum allowed limit of {max_amount}",
                    error_code="AMOUNT_EXCEEDS_LIMIT",
                    rule_name="currency_amount_validation",
                    context={'amount': str(value), 'limit': str(max_amount)}
                )
            
            return value
        
        # Register default rules
        self.register_rule('email_domain_validation', email_domain_rule)
        self.register_rule('username_profanity_validation', username_profanity_rule)
        self.register_rule('currency_amount_validation', currency_amount_rule)


# ============================================================================
# VALIDATOR REGISTRY AND FACTORY
# ============================================================================

# Registry of all business validators for dynamic access
BUSINESS_VALIDATOR_REGISTRY = {
    # Core business validators
    'User': UserValidator,
    'Organization': OrganizationValidator,
    'Product': ProductValidator,
    'Order': OrderValidator,
    'OrderItem': OrderItemValidator,
    
    # Utility validators
    'Address': AddressValidator,
    'ContactInfo': ContactInfoValidator,
    'MonetaryAmount': MonetaryAmountValidator,
    'Pagination': PaginationValidator,
    'Search': SearchValidator,
}

# Global business rule engine instance
business_rule_engine = BusinessRuleEngine()


def get_validator_by_name(validator_name: str) -> Optional[Type[BaseBusinessValidator]]:
    """
    Get business validator class by name from registry.
    
    Args:
        validator_name: Name of the validator class to retrieve
        
    Returns:
        Validator class if found, None otherwise
    """
    return BUSINESS_VALIDATOR_REGISTRY.get(validator_name)


def validate_data_with_schema(schema_name: str, data: Dict[str, Any], 
                            convert_to_model: bool = False,
                            context: Optional[Dict[str, Any]] = None) -> Union[Dict[str, Any], BaseBusinessModel]:
    """
    Validate data using specified schema with comprehensive error handling.
    
    Args:
        schema_name: Name of the validation schema to use
        data: Data dictionary to validate
        convert_to_model: Whether to convert to business model instance
        context: Additional validation context
        
    Returns:
        Validated data dictionary or business model instance
        
    Raises:
        DataValidationError: If schema not found or validation fails
    """
    validator_class = get_validator_by_name(schema_name)
    if not validator_class:
        raise DataValidationError(
            message=f"Unknown validation schema: {schema_name}",
            error_code="UNKNOWN_VALIDATION_SCHEMA",
            context={
                'schema_name': schema_name,
                'available_schemas': list(BUSINESS_VALIDATOR_REGISTRY.keys())
            },
            severity=ErrorSeverity.HIGH
        )
    
    try:
        # Initialize validator with business rule engine
        validator = validator_class(
            business_rule_engine=business_rule_engine,
            validation_context=context or {}
        )
        
        # Perform validation
        validated_data = validator.load(data, convert_to_model=convert_to_model)
        
        logger.info("Data validation completed successfully",
                   schema_name=schema_name,
                   field_count=len(data),
                   converted_to_model=convert_to_model)
        
        return validated_data
        
    except MarshmallowValidationError as e:
        # Convert marshmallow errors to business exceptions
        business_error = BaseBusinessValidator().handle_validation_error(e)
        business_error.context['schema_name'] = schema_name
        raise business_error
    except Exception as e:
        if isinstance(e, BaseBusinessException):
            raise
        
        raise DataValidationError(
            message=f"Data validation failed for schema {schema_name}",
            error_code="VALIDATION_EXECUTION_FAILED",
            context={'schema_name': schema_name},
            cause=e,
            severity=ErrorSeverity.MEDIUM
        )


def create_validation_chain(*validator_names: str) -> Callable:
    """
    Create validation chain that applies multiple validators in sequence.
    
    Args:
        *validator_names: Names of validators to chain together
        
    Returns:
        Callable that performs chained validation
        
    Example:
        user_validation_chain = create_validation_chain('User', 'ContactInfo')
        validated_data = user_validation_chain(user_data)
    """
    def validation_chain(data: Dict[str, Any], 
                        convert_to_model: bool = False,
                        context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute validation chain on data."""
        validated_data = data
        
        for validator_name in validator_names:
            validated_data = validate_data_with_schema(
                validator_name, 
                validated_data, 
                convert_to_model=False,  # Only convert at the end
                context=context
            )
        
        # Convert to model if requested and final validator supports it
        if convert_to_model and validator_names:
            final_validator_name = validator_names[-1]
            validator_class = get_validator_by_name(final_validator_name)
            if validator_class:
                model_class = validator_class().get_business_model_class()
                if model_class:
                    return model_class.from_dict(validated_data)
        
        return validated_data
    
    return validation_chain


def batch_validate_data(data_items: List[Dict[str, Any]], schema_name: str,
                       fail_fast: bool = False,
                       context: Optional[Dict[str, Any]] = None) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Validate multiple data items in batch with error collection.
    
    Args:
        data_items: List of data dictionaries to validate
        schema_name: Name of validation schema to use
        fail_fast: Whether to stop on first validation error
        context: Additional validation context
        
    Returns:
        Tuple of (validated_items, failed_items_with_errors)
    """
    validated_items = []
    failed_items = []
    
    for index, data_item in enumerate(data_items):
        try:
            validated_item = validate_data_with_schema(
                schema_name, data_item, context=context
            )
            validated_items.append(validated_item)
            
        except DataValidationError as e:
            failed_item = {
                'index': index,
                'data': data_item,
                'error': e.to_dict(),
                'validation_errors': e.validation_errors,
                'field_errors': e.field_errors
            }
            failed_items.append(failed_item)
            
            if fail_fast:
                break
                
        except Exception as e:
            failed_item = {
                'index': index,
                'data': data_item,
                'error': {
                    'message': str(e),
                    'type': type(e).__name__
                }
            }
            failed_items.append(failed_item)
            
            if fail_fast:
                break
    
    logger.info("Batch validation completed",
               schema_name=schema_name,
               total_items=len(data_items),
               validated_count=len(validated_items),
               failed_count=len(failed_items))
    
    return validated_items, failed_items


# Initialize validation system logging
logger.info("Business validation engine initialized successfully",
           validator_count=len(BUSINESS_VALIDATOR_REGISTRY),
           marshmallow_version="3.20+",
           business_rules_enabled=ValidationConfig.ENFORCE_BUSINESS_RULES,
           rule_engine_initialized=True)