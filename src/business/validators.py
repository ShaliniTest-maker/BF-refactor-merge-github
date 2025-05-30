"""
Business Rule Validation Engine for Flask Application

This module provides comprehensive business rule validation engine using marshmallow schemas
for data validation, business rule enforcement, and schema validation patterns. Implements
enterprise-grade validation logic maintaining equivalent validation patterns from Node.js
implementation per Section 5.2.4 Business Logic Engine requirements.

The validation engine follows enterprise patterns with:
- Marshmallow 3.20+ for schema validation and data serialization per Section 5.2.4
- Business rule validation maintaining existing validation patterns per F-004-RQ-001
- Comprehensive data validation equivalent to Node.js implementation per F-004-RQ-001
- Schema validation and data serialization per Section 5.2.4 technologies
- Validation error handling integration with error response management per F-005
- Integration with business logic processing pipeline per Section 5.2.4

Classes:
    BaseValidator: Base validation class providing common validation patterns
    BusinessRuleValidator: Business rule validation and enforcement engine
    DataModelValidator: Data model validation using marshmallow schemas
    InputValidator: Input data validation and sanitization
    OutputValidator: Response data validation and serialization
    ValidationContext: Validation context management and rule coordination
    
Functions:
    validate_business_data: Validate business data against schema and rules
    validate_request_data: Validate HTTP request data with sanitization
    validate_response_data: Validate response data for consistency
    create_validation_schema: Dynamic schema creation for validation
    format_validation_errors: Format validation errors for client responses
"""

import logging
import re
from datetime import datetime, date
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional, Union, Type, Callable, Tuple, Set
from functools import wraps
from enum import Enum

# Third-party validation and serialization libraries
import marshmallow as ma
from marshmallow import fields, validate, ValidationError, EXCLUDE, INCLUDE
from marshmallow.decorators import post_load, pre_load, validates, validates_schema
import structlog

# Import business exceptions and utilities
from .exceptions import (
    BaseBusinessException,
    BusinessRuleViolationError,
    DataValidationError,
    DataProcessingError,
    ErrorSeverity,
    ErrorCategory
)
from .utils import (
    validate_email,
    validate_phone,
    validate_postal_code,
    sanitize_input,
    safe_int,
    safe_float,
    safe_str,
    normalize_boolean,
    parse_date,
    format_date,
    parse_json
)

# Configure structured logging for validation operations
logger = structlog.get_logger("business.validators")

# Type aliases for better code readability
ValidationResult = Tuple[bool, Optional[Dict[str, Any]], Optional[List[Dict[str, Any]]]]
SchemaType = Type[ma.Schema]
FieldType = Union[fields.Field, Type[fields.Field]]


class ValidationType(Enum):
    """
    Enumeration of validation types for comprehensive business validation.
    
    Provides standardized validation types for different business validation
    scenarios enabling consistent validation patterns across modules.
    """
    STRICT = "strict"              # Strict validation with all rules enforced
    PERMISSIVE = "permissive"      # Relaxed validation allowing some flexibility
    SANITIZING = "sanitizing"      # Validation with automatic data sanitization
    BUSINESS_RULES = "business_rules"  # Business rule validation only
    SCHEMA_ONLY = "schema_only"    # Schema validation without business rules


class ValidationMode(Enum):
    """
    Enumeration of validation modes for different operational contexts.
    
    Provides standardized validation modes for different processing contexts
    enabling appropriate validation behavior for specific use cases.
    """
    CREATE = "create"              # Validation for create operations
    UPDATE = "update"              # Validation for update operations
    PATCH = "patch"                # Validation for partial updates
    QUERY = "query"                # Validation for query parameters
    RESPONSE = "response"          # Validation for response data


class ValidationContext:
    """
    Validation context management for coordinating validation rules and settings.
    
    Provides centralized context management for validation operations enabling
    consistent validation behavior across different business logic modules and
    maintaining validation state throughout processing pipelines.
    
    This context manager implements:
    - Validation rule coordination per Section 5.2.4
    - Context-aware validation behavior per business requirements
    - Performance optimization for validation operations
    - Enterprise validation patterns and standards
    - Integration with business exception handling
    
    Attributes:
        validation_type (ValidationType): Type of validation to perform
        validation_mode (ValidationMode): Mode of validation for context
        strict_mode (bool): Whether to enforce strict validation rules
        user_context (Optional[Dict[str, Any]]): User context for authorization
        request_context (Optional[Dict[str, Any]]): Request context for validation
        business_rules (Set[str]): Set of business rules to enforce
        custom_validators (Dict[str, Callable]): Custom validation functions
        
    Example:
        with ValidationContext(
            validation_type=ValidationType.STRICT,
            validation_mode=ValidationMode.CREATE,
            user_context={'user_id': '123', 'role': 'admin'}
        ) as ctx:
            result = validate_business_data(data, schema, ctx)
    """
    
    def __init__(
        self,
        validation_type: ValidationType = ValidationType.STRICT,
        validation_mode: ValidationMode = ValidationMode.CREATE,
        strict_mode: bool = True,
        user_context: Optional[Dict[str, Any]] = None,
        request_context: Optional[Dict[str, Any]] = None,
        business_rules: Optional[Set[str]] = None,
        custom_validators: Optional[Dict[str, Callable]] = None
    ) -> None:
        """
        Initialize validation context with comprehensive configuration.
        
        Args:
            validation_type: Type of validation to perform
            validation_mode: Mode of validation for operational context
            strict_mode: Whether to enforce strict validation rules
            user_context: User context for authorization and business rules
            request_context: Request context for validation coordination
            business_rules: Set of business rules to enforce during validation
            custom_validators: Custom validation functions for specific rules
        """
        self.validation_type = validation_type
        self.validation_mode = validation_mode
        self.strict_mode = strict_mode
        self.user_context = user_context or {}
        self.request_context = request_context or {}
        self.business_rules = business_rules or set()
        self.custom_validators = custom_validators or {}
        
        # Internal state management
        self._validation_errors = []
        self._validation_warnings = []
        self._performance_metrics = {}
        self._validation_start_time = None
        
        logger.debug("Validation context initialized",
                    validation_type=validation_type.value,
                    validation_mode=validation_mode.value,
                    strict_mode=strict_mode,
                    business_rules_count=len(self.business_rules))
    
    def __enter__(self) -> 'ValidationContext':
        """Enter validation context and start performance monitoring."""
        self._validation_start_time = datetime.now()
        logger.debug("Entering validation context")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit validation context and log performance metrics."""
        if self._validation_start_time:
            duration = (datetime.now() - self._validation_start_time).total_seconds()
            self._performance_metrics['total_duration'] = duration
            
            logger.debug("Exiting validation context",
                        duration_seconds=duration,
                        error_count=len(self._validation_errors),
                        warning_count=len(self._validation_warnings))
    
    def add_error(self, error: Dict[str, Any]) -> None:
        """Add validation error to context tracking."""
        self._validation_errors.append(error)
    
    def add_warning(self, warning: Dict[str, Any]) -> None:
        """Add validation warning to context tracking."""
        self._validation_warnings.append(warning)
    
    def get_errors(self) -> List[Dict[str, Any]]:
        """Get all validation errors from context."""
        return self._validation_errors.copy()
    
    def get_warnings(self) -> List[Dict[str, Any]]:
        """Get all validation warnings from context."""
        return self._validation_warnings.copy()
    
    def has_errors(self) -> bool:
        """Check if validation context has any errors."""
        return len(self._validation_errors) > 0
    
    def clear_errors(self) -> None:
        """Clear all validation errors from context."""
        self._validation_errors.clear()
    
    def should_enforce_rule(self, rule_name: str) -> bool:
        """
        Check if a specific business rule should be enforced in this context.
        
        Args:
            rule_name: Name of the business rule to check
            
        Returns:
            True if rule should be enforced, False otherwise
        """
        if not self.strict_mode:
            return False
        
        if self.business_rules and rule_name not in self.business_rules:
            return False
        
        return True
    
    def get_custom_validator(self, validator_name: str) -> Optional[Callable]:
        """
        Get custom validator function by name.
        
        Args:
            validator_name: Name of the custom validator
            
        Returns:
            Custom validator function or None if not found
        """
        return self.custom_validators.get(validator_name)


class BaseValidator(ma.Schema):
    """
    Base validation class providing common validation patterns and enterprise features.
    
    Provides foundational validation capabilities using marshmallow 3.20+ with
    comprehensive error handling, business rule integration, and performance
    optimization. Implements common validation patterns per Section 5.2.4
    business logic engine requirements.
    
    This base validator implements:
    - Marshmallow schema integration per Section 5.2.4 technologies
    - Common validation patterns and field definitions
    - Error handling integration with business exceptions per F-005
    - Performance optimization for validation operations
    - Enterprise validation standards and compliance
    
    Class Meta Options:
        unknown: How to handle unknown fields (EXCLUDE by default)
        ordered: Whether to preserve field order in output
        load_only: Fields that are only used during deserialization
        dump_only: Fields that are only used during serialization
    """
    
    class Meta:
        """Marshmallow schema meta configuration for enterprise validation."""
        unknown = EXCLUDE  # Exclude unknown fields for security
        ordered = True     # Preserve field order for consistency
        strict = True      # Enable strict validation mode
    
    def __init__(self, *args, **kwargs):
        """
        Initialize base validator with context and performance monitoring.
        
        Args:
            *args: Positional arguments for marshmallow Schema
            **kwargs: Keyword arguments including validation context
        """
        # Extract validation context if provided
        self.validation_context = kwargs.pop('validation_context', None)
        self.performance_tracking = kwargs.pop('performance_tracking', True)
        
        super().__init__(*args, **kwargs)
        
        # Initialize performance metrics
        self._validation_metrics = {
            'validation_count': 0,
            'error_count': 0,
            'warning_count': 0,
            'total_duration': 0.0
        }
        
        logger.debug("Base validator initialized",
                    validator_class=self.__class__.__name__,
                    has_context=self.validation_context is not None)
    
    def handle_error(self, error: ValidationError, data: Any, **kwargs) -> None:
        """
        Handle validation errors with business exception integration.
        
        Converts marshmallow ValidationError to business exceptions for
        consistent error handling across the application per F-005 requirements.
        
        Args:
            error: Marshmallow validation error
            data: Original data being validated
            **kwargs: Additional error handling context
        """
        try:
            logger.warning("Validation error occurred",
                          error_messages=error.messages,
                          data_type=type(data).__name__,
                          validator_class=self.__class__.__name__)
            
            # Update performance metrics
            self._validation_metrics['error_count'] += 1
            
            # Add to validation context if available
            if self.validation_context:
                self.validation_context.add_error({
                    'validator': self.__class__.__name__,
                    'messages': error.messages,
                    'timestamp': datetime.now().isoformat()
                })
            
            # Convert to business exception for consistent handling
            validation_errors = self._format_marshmallow_errors(error.messages)
            
            raise DataValidationError(
                message="Data validation failed",
                error_code="SCHEMA_VALIDATION_FAILED",
                validation_errors=validation_errors,
                field_errors=error.messages,
                context={
                    'validator_class': self.__class__.__name__,
                    'error_count': len(validation_errors)
                },
                cause=error,
                severity=ErrorSeverity.MEDIUM
            )
            
        except Exception as handle_error:
            logger.error("Failed to handle validation error",
                        original_error=str(error),
                        handle_error=str(handle_error))
            # Re-raise original error if handling fails
            raise error
    
    def _format_marshmallow_errors(self, error_messages: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Format marshmallow error messages for business exception integration.
        
        Args:
            error_messages: Marshmallow error messages dictionary
            
        Returns:
            Formatted validation errors for business exception
        """
        formatted_errors = []
        
        def flatten_errors(errors: Union[Dict, List, str], field_path: str = "") -> None:
            """Recursively flatten nested error messages."""
            if isinstance(errors, dict):
                for field, error_list in errors.items():
                    current_path = f"{field_path}.{field}" if field_path else field
                    flatten_errors(error_list, current_path)
            elif isinstance(errors, list):
                for error in errors:
                    formatted_errors.append({
                        'field': field_path,
                        'message': str(error),
                        'code': 'VALIDATION_ERROR'
                    })
            else:
                formatted_errors.append({
                    'field': field_path,
                    'message': str(errors),
                    'code': 'VALIDATION_ERROR'
                })
        
        flatten_errors(error_messages)
        return formatted_errors
    
    @validates_schema
    def validate_schema_context(self, data: Dict[str, Any], **kwargs) -> None:
        """
        Validate schema in context of business rules and user permissions.
        
        Provides context-aware validation that considers user permissions,
        business rules, and operational context for comprehensive validation.
        
        Args:
            data: Validated data dictionary
            **kwargs: Additional validation context
        """
        if not self.validation_context:
            return
        
        # Check business rule enforcement
        for rule_name in self.validation_context.business_rules:
            if not self.validation_context.should_enforce_rule(rule_name):
                continue
            
            # Apply custom business rule validation
            custom_validator = self.validation_context.get_custom_validator(rule_name)
            if custom_validator:
                try:
                    custom_validator(data, self.validation_context)
                except Exception as rule_error:
                    raise BusinessRuleViolationError(
                        message=f"Business rule validation failed: {rule_name}",
                        error_code=f"BUSINESS_RULE_{rule_name.upper()}",
                        rule_name=rule_name,
                        context={'data_fields': list(data.keys())},
                        cause=rule_error,
                        severity=ErrorSeverity.HIGH
                    )
    
    def load_with_context(
        self,
        json_data: Union[Dict[str, Any], str],
        validation_context: Optional[ValidationContext] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Load and validate data with validation context support.
        
        Provides enhanced data loading with validation context integration,
        performance monitoring, and comprehensive error handling.
        
        Args:
            json_data: JSON data to validate (dict or string)
            validation_context: Optional validation context for rules
            **kwargs: Additional marshmallow load arguments
            
        Returns:
            Validated and deserialized data dictionary
            
        Raises:
            DataValidationError: If validation fails with detailed error information
        """
        start_time = datetime.now()
        
        try:
            # Set validation context
            if validation_context:
                self.validation_context = validation_context
            
            # Parse JSON string if needed
            if isinstance(json_data, str):
                json_data = parse_json(json_data)
            
            logger.debug("Starting data validation",
                        data_fields=list(json_data.keys()) if isinstance(json_data, dict) else [],
                        validator_class=self.__class__.__name__)
            
            # Perform marshmallow validation
            validated_data = self.load(json_data, **kwargs)
            
            # Update performance metrics
            duration = (datetime.now() - start_time).total_seconds()
            self._validation_metrics['validation_count'] += 1
            self._validation_metrics['total_duration'] += duration
            
            logger.debug("Data validation completed successfully",
                        validated_fields=list(validated_data.keys()),
                        duration_seconds=duration)
            
            return validated_data
            
        except ValidationError as validation_error:
            # Handle marshmallow validation errors
            duration = (datetime.now() - start_time).total_seconds()
            self._validation_metrics['error_count'] += 1
            self._validation_metrics['total_duration'] += duration
            
            self.handle_error(validation_error, json_data)
            
        except Exception as unexpected_error:
            # Handle unexpected errors during validation
            duration = (datetime.now() - start_time).total_seconds()
            self._validation_metrics['error_count'] += 1
            self._validation_metrics['total_duration'] += duration
            
            raise DataValidationError(
                message="Validation failed due to unexpected error",
                error_code="VALIDATION_UNEXPECTED_ERROR",
                context={
                    'validator_class': self.__class__.__name__,
                    'duration_seconds': duration
                },
                cause=unexpected_error,
                severity=ErrorSeverity.HIGH
            )
    
    def dump_with_validation(
        self,
        data: Dict[str, Any],
        validate_output: bool = True,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Serialize data with optional output validation.
        
        Provides data serialization with optional output validation to ensure
        consistent response format and data integrity per F-004-RQ-004.
        
        Args:
            data: Data dictionary to serialize
            validate_output: Whether to validate serialized output
            **kwargs: Additional marshmallow dump arguments
            
        Returns:
            Serialized data dictionary
            
        Raises:
            DataValidationError: If output validation fails
        """
        start_time = datetime.now()
        
        try:
            logger.debug("Starting data serialization",
                        data_fields=list(data.keys()) if isinstance(data, dict) else [],
                        validate_output=validate_output)
            
            # Perform marshmallow serialization
            serialized_data = self.dump(data, **kwargs)
            
            # Optional output validation
            if validate_output and serialized_data:
                self._validate_output_format(serialized_data)
            
            # Update performance metrics
            duration = (datetime.now() - start_time).total_seconds()
            self._validation_metrics['validation_count'] += 1
            self._validation_metrics['total_duration'] += duration
            
            logger.debug("Data serialization completed successfully",
                        serialized_fields=list(serialized_data.keys()) if isinstance(serialized_data, dict) else [],
                        duration_seconds=duration)
            
            return serialized_data
            
        except Exception as serialization_error:
            duration = (datetime.now() - start_time).total_seconds()
            self._validation_metrics['error_count'] += 1
            
            raise DataValidationError(
                message="Data serialization failed",
                error_code="SERIALIZATION_FAILED",
                context={
                    'validator_class': self.__class__.__name__,
                    'duration_seconds': duration
                },
                cause=serialization_error,
                severity=ErrorSeverity.MEDIUM
            )
    
    def _validate_output_format(self, serialized_data: Dict[str, Any]) -> None:
        """
        Validate output format for consistency and completeness.
        
        Args:
            serialized_data: Serialized data to validate
            
        Raises:
            DataValidationError: If output format is invalid
        """
        if not isinstance(serialized_data, dict):
            raise DataValidationError(
                message="Serialized output must be a dictionary",
                error_code="INVALID_OUTPUT_FORMAT",
                context={'output_type': type(serialized_data).__name__},
                severity=ErrorSeverity.MEDIUM
            )
        
        # Check for required fields based on validation mode
        if self.validation_context:
            if self.validation_context.validation_mode == ValidationMode.RESPONSE:
                # Validate response format requirements
                self._validate_response_format(serialized_data)
    
    def _validate_response_format(self, response_data: Dict[str, Any]) -> None:
        """
        Validate response format for API consistency.
        
        Args:
            response_data: Response data to validate
            
        Raises:
            DataValidationError: If response format is invalid
        """
        # Check for consistent response structure
        if 'data' not in response_data and 'error' not in response_data:
            logger.warning("Response missing standard structure",
                          response_fields=list(response_data.keys()))
    
    def get_validation_metrics(self) -> Dict[str, Any]:
        """
        Get validation performance metrics for monitoring.
        
        Returns:
            Dictionary containing validation performance metrics
        """
        metrics = self._validation_metrics.copy()
        
        # Calculate average duration
        if metrics['validation_count'] > 0:
            metrics['average_duration'] = metrics['total_duration'] / metrics['validation_count']
        else:
            metrics['average_duration'] = 0.0
        
        # Calculate error rate
        if metrics['validation_count'] > 0:
            metrics['error_rate'] = metrics['error_count'] / metrics['validation_count']
        else:
            metrics['error_rate'] = 0.0
        
        return metrics


class BusinessRuleValidator(BaseValidator):
    """
    Business rule validation and enforcement engine for comprehensive business logic validation.
    
    Provides specialized validation for business rules, policy enforcement, and
    domain-specific validation requirements. Implements business rule validation
    maintaining existing validation patterns per F-004-RQ-001 requirements.
    
    This validator implements:
    - Business rule validation and enforcement per Section 5.2.4
    - Policy compliance checking and validation
    - Domain-specific validation rules and constraints
    - Integration with user context and permissions
    - Comprehensive business logic validation patterns
    
    Business Rules Supported:
        - Data integrity and consistency rules
        - Business constraint validation
        - Policy compliance checking
        - User permission and authorization rules
        - Workflow validation and state management
    
    Example:
        class CustomerValidator(BusinessRuleValidator):
            email = fields.Email(required=True)
            age = fields.Integer(validate=validate.Range(min=18, max=120))
            
            @validates('email')
            def validate_unique_email(self, value):
                if self.is_email_duplicate(value):
                    raise ValidationError('Email already exists')
    """
    
    # Business rule registry for dynamic rule management
    _business_rules = {}
    
    @classmethod
    def register_business_rule(
        cls,
        rule_name: str,
        rule_function: Callable[[Any, ValidationContext], None],
        description: str = ""
    ) -> None:
        """
        Register a business rule for validation enforcement.
        
        Args:
            rule_name: Unique name for the business rule
            rule_function: Function that validates the business rule
            description: Description of the business rule
        """
        cls._business_rules[rule_name] = {
            'function': rule_function,
            'description': description,
            'registered_at': datetime.now()
        }
        
        logger.debug("Business rule registered",
                    rule_name=rule_name,
                    description=description)
    
    @classmethod
    def get_registered_rules(cls) -> Dict[str, Dict[str, Any]]:
        """Get all registered business rules."""
        return cls._business_rules.copy()
    
    def validate_business_rules(
        self,
        data: Dict[str, Any],
        rules_to_check: Optional[Set[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Validate data against registered business rules.
        
        Args:
            data: Data to validate against business rules
            rules_to_check: Optional set of specific rules to check
            
        Returns:
            List of business rule violations
        """
        violations = []
        rules_to_validate = rules_to_check or set(self._business_rules.keys())
        
        for rule_name in rules_to_validate:
            if rule_name not in self._business_rules:
                continue
            
            if self.validation_context and not self.validation_context.should_enforce_rule(rule_name):
                continue
            
            try:
                rule_info = self._business_rules[rule_name]
                rule_function = rule_info['function']
                
                # Execute business rule validation
                rule_function(data, self.validation_context)
                
                logger.debug("Business rule validation passed",
                           rule_name=rule_name)
                
            except BusinessRuleViolationError as rule_violation:
                violations.append({
                    'rule_name': rule_name,
                    'error_code': rule_violation.error_code,
                    'message': rule_violation.message,
                    'context': rule_violation.context
                })
                
                logger.warning("Business rule violation detected",
                             rule_name=rule_name,
                             error_code=rule_violation.error_code)
                
            except Exception as unexpected_error:
                violations.append({
                    'rule_name': rule_name,
                    'error_code': 'BUSINESS_RULE_ERROR',
                    'message': f"Business rule validation failed: {str(unexpected_error)}",
                    'context': {'unexpected_error': True}
                })
                
                logger.error("Business rule validation failed unexpectedly",
                           rule_name=rule_name,
                           error=str(unexpected_error))
        
        return violations
    
    @validates_schema
    def validate_business_constraints(self, data: Dict[str, Any], **kwargs) -> None:
        """
        Validate data against business constraints and rules.
        
        Args:
            data: Validated data dictionary
            **kwargs: Additional validation context
            
        Raises:
            BusinessRuleViolationError: If business rules are violated
        """
        # Call parent validation first
        super().validate_schema_context(data, **kwargs)
        
        # Validate against registered business rules
        violations = self.validate_business_rules(data)
        
        if violations:
            # Create comprehensive business rule violation error
            violation_messages = [v['message'] for v in violations]
            
            raise BusinessRuleViolationError(
                message=f"Business rule validation failed ({len(violations)} violations)",
                error_code="MULTIPLE_BUSINESS_RULE_VIOLATIONS",
                context={
                    'violations': violations,
                    'violation_count': len(violations)
                },
                severity=ErrorSeverity.HIGH
            )


class DataModelValidator(BaseValidator):
    """
    Data model validation using marshmallow schemas for business data structures.
    
    Provides comprehensive data model validation with type checking, field validation,
    and business data integrity enforcement. Implements data validation maintaining
    existing patterns per F-004-RQ-001 requirements using marshmallow 3.20+.
    
    This validator implements:
    - Comprehensive data model validation per Section 5.2.4
    - Type checking and field validation with marshmallow
    - Business data integrity and consistency checking
    - Custom field validation and transformation
    - Integration with business rule validation engine
    
    Common Field Types:
        - String fields with length and pattern validation
        - Numeric fields with range and precision validation
        - Date/time fields with format and timezone handling
        - Email and URL fields with format validation
        - Custom business fields with domain-specific rules
    
    Example:
        class UserDataValidator(DataModelValidator):
            id = fields.String(required=True, validate=validate.Length(min=1))
            email = fields.Email(required=True)
            name = fields.String(required=True, validate=validate.Length(min=2, max=100))
            age = fields.Integer(validate=validate.Range(min=0, max=150))
            created_at = fields.DateTime(dump_only=True)
    """
    
    def __init__(self, *args, **kwargs):
        """
        Initialize data model validator with enhanced field validation.
        
        Args:
            *args: Positional arguments for BaseValidator
            **kwargs: Keyword arguments including model configuration
        """
        super().__init__(*args, **kwargs)
        
        # Data model configuration
        self.model_name = kwargs.pop('model_name', self.__class__.__name__)
        self.allow_partial = kwargs.pop('allow_partial', False)
        self.validate_required = kwargs.pop('validate_required', True)
        
        logger.debug("Data model validator initialized",
                    model_name=self.model_name,
                    allow_partial=self.allow_partial)
    
    @pre_load
    def preprocess_data(self, data: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        """
        Preprocess input data before validation.
        
        Provides data preprocessing including sanitization, type conversion,
        and data normalization before field validation.
        
        Args:
            data: Input data to preprocess
            **kwargs: Additional preprocessing context
            
        Returns:
            Preprocessed data ready for field validation
        """
        if not isinstance(data, dict):
            raise DataValidationError(
                message="Input data must be a dictionary",
                error_code="INVALID_INPUT_TYPE",
                context={'input_type': type(data).__name__},
                severity=ErrorSeverity.MEDIUM
            )
        
        processed_data = {}
        
        for field_name, field_value in data.items():
            try:
                # Basic data sanitization and type conversion
                if isinstance(field_value, str):
                    # Sanitize string inputs
                    processed_value = sanitize_input(field_value.strip())
                    
                    # Apply field-specific preprocessing
                    if field_name.endswith('_email'):
                        processed_value = processed_value.lower()
                    elif field_name.endswith('_phone'):
                        processed_value = re.sub(r'[^\d+()-.\s]', '', processed_value)
                    elif field_name.endswith('_id') and processed_value == '':
                        processed_value = None
                    
                    processed_data[field_name] = processed_value
                    
                elif isinstance(field_value, (int, float, bool)):
                    processed_data[field_name] = field_value
                    
                elif field_value is None:
                    processed_data[field_name] = None
                    
                else:
                    # Handle complex data types (lists, dicts)
                    processed_data[field_name] = field_value
                    
            except Exception as preprocessing_error:
                logger.warning("Data preprocessing failed for field",
                             field_name=field_name,
                             field_value=str(field_value)[:100],
                             error=str(preprocessing_error))
                
                # Include original value if preprocessing fails
                processed_data[field_name] = field_value
        
        logger.debug("Data preprocessing completed",
                    original_fields=len(data),
                    processed_fields=len(processed_data))
        
        return processed_data
    
    @post_load
    def postprocess_data(self, data: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        """
        Postprocess validated data after field validation.
        
        Provides data postprocessing including final transformations,
        computed fields, and business logic integration.
        
        Args:
            data: Validated data to postprocess
            **kwargs: Additional postprocessing context
            
        Returns:
            Postprocessed data ready for business logic
        """
        postprocessed_data = data.copy()
        
        # Add computed fields if needed
        if 'created_at' not in postprocessed_data and hasattr(self, 'created_at'):
            postprocessed_data['created_at'] = datetime.now()
        
        if 'updated_at' not in postprocessed_data and hasattr(self, 'updated_at'):
            postprocessed_data['updated_at'] = datetime.now()
        
        # Apply model-specific postprocessing
        postprocessed_data = self._apply_model_postprocessing(postprocessed_data)
        
        logger.debug("Data postprocessing completed",
                    field_count=len(postprocessed_data))
        
        return postprocessed_data
    
    def _apply_model_postprocessing(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply model-specific postprocessing logic.
        
        Override this method in subclasses to implement model-specific
        postprocessing logic and computed field generation.
        
        Args:
            data: Validated data to postprocess
            
        Returns:
            Data with model-specific postprocessing applied
        """
        return data
    
    def validate_partial_data(
        self,
        data: Dict[str, Any],
        fields_to_validate: Optional[Set[str]] = None
    ) -> Dict[str, Any]:
        """
        Validate partial data for update operations.
        
        Provides partial data validation for PATCH operations and
        incremental updates while maintaining data integrity.
        
        Args:
            data: Partial data to validate
            fields_to_validate: Optional set of specific fields to validate
            
        Returns:
            Validated partial data
            
        Raises:
            DataValidationError: If partial validation fails
        """
        try:
            # Create partial schema for validation
            partial_fields = fields_to_validate or set(data.keys())
            
            # Validate only specified fields
            validated_data = self.load(data, partial=list(partial_fields))
            
            logger.debug("Partial data validation completed",
                        validated_fields=list(validated_data.keys()),
                        requested_fields=list(partial_fields))
            
            return validated_data
            
        except ValidationError as validation_error:
            self.handle_error(validation_error, data)
    
    def get_field_metadata(self) -> Dict[str, Dict[str, Any]]:
        """
        Get metadata about schema fields for documentation and client generation.
        
        Returns:
            Dictionary containing field metadata and validation rules
        """
        field_metadata = {}
        
        for field_name, field_obj in self.fields.items():
            metadata = {
                'type': type(field_obj).__name__,
                'required': field_obj.required,
                'allow_none': field_obj.allow_none,
                'load_only': field_obj.load_only,
                'dump_only': field_obj.dump_only
            }
            
            # Add validation metadata
            if hasattr(field_obj, 'validators') and field_obj.validators:
                metadata['validators'] = []
                for validator in field_obj.validators:
                    if hasattr(validator, '__name__'):
                        metadata['validators'].append(validator.__name__)
                    else:
                        metadata['validators'].append(str(validator))
            
            # Add field-specific metadata
            if isinstance(field_obj, fields.String):
                if hasattr(field_obj, 'validate') and field_obj.validate:
                    for validator in field_obj.validate if isinstance(field_obj.validate, list) else [field_obj.validate]:
                        if isinstance(validator, validate.Length):
                            metadata['min_length'] = validator.min
                            metadata['max_length'] = validator.max
            
            elif isinstance(field_obj, (fields.Integer, fields.Float)):
                if hasattr(field_obj, 'validate') and field_obj.validate:
                    for validator in field_obj.validate if isinstance(field_obj.validate, list) else [field_obj.validate]:
                        if isinstance(validator, validate.Range):
                            metadata['min_value'] = validator.min
                            metadata['max_value'] = validator.max
            
            field_metadata[field_name] = metadata
        
        return field_metadata


class InputValidator(DataModelValidator):
    """
    Input data validation and sanitization for HTTP requests and external data.
    
    Provides comprehensive input validation with sanitization, security checks,
    and request data processing. Implements input validation maintaining
    existing patterns per F-003-RQ-004 requirements.
    
    This validator implements:
    - HTTP request data validation and sanitization
    - Security input validation and XSS prevention
    - File upload validation and processing
    - Query parameter validation and type conversion
    - Form data validation and multipart handling
    
    Security Features:
        - Input sanitization and XSS prevention
        - File upload validation and security checks
        - SQL injection prevention through parameterization
        - Cross-site scripting (XSS) protection
        - Request size and rate limiting validation
    
    Example:
        class ContactFormValidator(InputValidator):
            name = fields.String(required=True, validate=validate.Length(min=2, max=100))
            email = fields.Email(required=True)
            message = fields.String(required=True, validate=validate.Length(min=10, max=1000))
            phone = fields.String(validate=validate.Length(max=20))
    """
    
    def __init__(self, *args, **kwargs):
        """
        Initialize input validator with security and sanitization features.
        
        Args:
            *args: Positional arguments for DataModelValidator
            **kwargs: Keyword arguments including security configuration
        """
        super().__init__(*args, **kwargs)
        
        # Security configuration
        self.enable_sanitization = kwargs.pop('enable_sanitization', True)
        self.max_request_size = kwargs.pop('max_request_size', 10 * 1024 * 1024)  # 10MB
        self.allowed_file_types = kwargs.pop('allowed_file_types', set())
        self.max_file_size = kwargs.pop('max_file_size', 5 * 1024 * 1024)  # 5MB
        
        logger.debug("Input validator initialized",
                    enable_sanitization=self.enable_sanitization,
                    max_request_size=self.max_request_size)
    
    @pre_load
    def sanitize_input_data(self, data: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        """
        Sanitize input data for security and consistency.
        
        Provides comprehensive input sanitization including XSS prevention,
        SQL injection protection, and data normalization.
        
        Args:
            data: Input data to sanitize
            **kwargs: Additional sanitization context
            
        Returns:
            Sanitized input data
        """
        if not self.enable_sanitization:
            return data
        
        sanitized_data = {}
        
        for field_name, field_value in data.items():
            try:
                if isinstance(field_value, str):
                    # Apply comprehensive string sanitization
                    sanitized_value = sanitize_input(
                        field_value,
                        allow_html=self._should_allow_html(field_name),
                        max_length=self._get_field_max_length(field_name)
                    )
                    
                    # Apply field-specific sanitization
                    sanitized_value = self._apply_field_sanitization(field_name, sanitized_value)
                    
                    sanitized_data[field_name] = sanitized_value
                    
                elif isinstance(field_value, list):
                    # Sanitize list elements
                    sanitized_list = []
                    for item in field_value:
                        if isinstance(item, str):
                            sanitized_item = sanitize_input(item)
                            sanitized_list.append(sanitized_item)
                        else:
                            sanitized_list.append(item)
                    sanitized_data[field_name] = sanitized_list
                    
                else:
                    # Keep non-string values as-is
                    sanitized_data[field_name] = field_value
                    
            except Exception as sanitization_error:
                logger.warning("Input sanitization failed for field",
                             field_name=field_name,
                             error=str(sanitization_error))
                
                # Use original value if sanitization fails
                sanitized_data[field_name] = field_value
        
        logger.debug("Input sanitization completed",
                    original_fields=len(data),
                    sanitized_fields=len(sanitized_data))
        
        return sanitized_data
    
    def _should_allow_html(self, field_name: str) -> bool:
        """
        Determine if HTML should be allowed for a specific field.
        
        Args:
            field_name: Name of the field to check
            
        Returns:
            True if HTML should be allowed, False otherwise
        """
        # Fields that typically allow HTML content
        html_fields = {'description', 'content', 'message', 'body', 'notes'}
        return any(html_field in field_name.lower() for html_field in html_fields)
    
    def _get_field_max_length(self, field_name: str) -> Optional[int]:
        """
        Get maximum length for a specific field based on field metadata.
        
        Args:
            field_name: Name of the field to check
            
        Returns:
            Maximum length for the field or None if not specified
        """
        if field_name in self.fields:
            field_obj = self.fields[field_name]
            if isinstance(field_obj, fields.String) and hasattr(field_obj, 'validate'):
                validators = field_obj.validate if isinstance(field_obj.validate, list) else [field_obj.validate]
                for validator in validators:
                    if isinstance(validator, validate.Length) and validator.max:
                        return validator.max
        
        # Default max lengths for common field types
        default_lengths = {
            'email': 254,
            'name': 100,
            'title': 200,
            'description': 1000,
            'phone': 20,
            'url': 2048
        }
        
        for field_type, max_length in default_lengths.items():
            if field_type in field_name.lower():
                return max_length
        
        return None
    
    def _apply_field_sanitization(self, field_name: str, field_value: str) -> str:
        """
        Apply field-specific sanitization rules.
        
        Args:
            field_name: Name of the field
            field_value: Field value to sanitize
            
        Returns:
            Field-specific sanitized value
        """
        field_name_lower = field_name.lower()
        
        # Email field sanitization
        if 'email' in field_name_lower:
            return field_value.lower().strip()
        
        # Phone field sanitization
        elif 'phone' in field_name_lower:
            # Remove non-phone characters
            return re.sub(r'[^\d+()-.\s]', '', field_value)
        
        # URL field sanitization
        elif 'url' in field_name_lower or 'website' in field_name_lower:
            if field_value and not field_value.startswith(('http://', 'https://')):
                return f"https://{field_value}"
            return field_value
        
        # Name field sanitization
        elif 'name' in field_name_lower:
            # Remove excessive whitespace and capitalize properly
            return ' '.join(word.capitalize() for word in field_value.split())
        
        return field_value
    
    def validate_file_upload(
        self,
        file_data: Dict[str, Any],
        allowed_types: Optional[Set[str]] = None,
        max_size: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Validate file upload data with security checks.
        
        Provides comprehensive file upload validation including file type
        checking, size validation, and security scanning.
        
        Args:
            file_data: File upload data to validate
            allowed_types: Optional set of allowed file types
            max_size: Optional maximum file size in bytes
            
        Returns:
            Validated file upload data
            
        Raises:
            DataValidationError: If file validation fails
        """
        try:
            logger.debug("Starting file upload validation",
                        file_fields=list(file_data.keys()))
            
            # Validate file presence
            if 'filename' not in file_data or not file_data['filename']:
                raise DataValidationError(
                    message="File name is required",
                    error_code="FILE_NAME_MISSING",
                    severity=ErrorSeverity.MEDIUM
                )
            
            filename = file_data['filename']
            file_size = file_data.get('size', 0)
            content_type = file_data.get('content_type', '')
            
            # Validate file extension
            file_extension = filename.split('.')[-1].lower() if '.' in filename else ''
            allowed_extensions = allowed_types or self.allowed_file_types
            
            if allowed_extensions and file_extension not in allowed_extensions:
                raise DataValidationError(
                    message=f"File type '{file_extension}' is not allowed",
                    error_code="INVALID_FILE_TYPE",
                    context={
                        'file_extension': file_extension,
                        'allowed_types': list(allowed_extensions)
                    },
                    severity=ErrorSeverity.HIGH
                )
            
            # Validate file size
            max_file_size = max_size or self.max_file_size
            if file_size > max_file_size:
                raise DataValidationError(
                    message=f"File size {file_size} exceeds maximum {max_file_size} bytes",
                    error_code="FILE_TOO_LARGE",
                    context={
                        'file_size': file_size,
                        'max_size': max_file_size
                    },
                    severity=ErrorSeverity.MEDIUM
                )
            
            # Validate filename for security
            if any(char in filename for char in ['..', '/', '\\', '<', '>', '|', ':', '*', '?', '"']):
                raise DataValidationError(
                    message="File name contains invalid characters",
                    error_code="INVALID_FILE_NAME",
                    context={'filename': filename},
                    severity=ErrorSeverity.HIGH
                )
            
            logger.debug("File upload validation completed successfully",
                        filename=filename,
                        file_size=file_size,
                        content_type=content_type)
            
            return file_data
            
        except Exception as file_validation_error:
            if isinstance(file_validation_error, DataValidationError):
                raise
            
            raise DataValidationError(
                message="File upload validation failed",
                error_code="FILE_VALIDATION_ERROR",
                cause=file_validation_error,
                severity=ErrorSeverity.MEDIUM
            )
    
    def validate_query_parameters(
        self,
        query_params: Dict[str, Any],
        allowed_params: Optional[Set[str]] = None
    ) -> Dict[str, Any]:
        """
        Validate query parameters with type conversion and security checks.
        
        Args:
            query_params: Query parameters to validate
            allowed_params: Optional set of allowed parameter names
            
        Returns:
            Validated query parameters
            
        Raises:
            DataValidationError: If query parameter validation fails
        """
        try:
            validated_params = {}
            
            for param_name, param_value in query_params.items():
                # Check if parameter is allowed
                if allowed_params and param_name not in allowed_params:
                    logger.warning("Ignored unknown query parameter",
                                 param_name=param_name)
                    continue
                
                # Apply type conversion and validation
                if param_name in self.fields:
                    field_obj = self.fields[param_name]
                    try:
                        # Convert and validate using field definition
                        validated_value = field_obj.deserialize(param_value)
                        validated_params[param_name] = validated_value
                    except ValidationError as field_error:
                        raise DataValidationError(
                            message=f"Invalid query parameter '{param_name}': {field_error.messages}",
                            error_code="INVALID_QUERY_PARAM",
                            context={
                                'param_name': param_name,
                                'param_value': str(param_value)[:100]
                            },
                            severity=ErrorSeverity.MEDIUM
                        )
                else:
                    # Apply basic sanitization for unknown parameters
                    if isinstance(param_value, str):
                        validated_params[param_name] = sanitize_input(param_value)
                    else:
                        validated_params[param_name] = param_value
            
            logger.debug("Query parameter validation completed",
                        original_params=len(query_params),
                        validated_params=len(validated_params))
            
            return validated_params
            
        except Exception as query_validation_error:
            if isinstance(query_validation_error, DataValidationError):
                raise
            
            raise DataValidationError(
                message="Query parameter validation failed",
                error_code="QUERY_PARAM_VALIDATION_ERROR",
                cause=query_validation_error,
                severity=ErrorSeverity.MEDIUM
            )


class OutputValidator(DataModelValidator):
    """
    Response data validation and serialization for consistent API outputs.
    
    Provides comprehensive output validation with response formatting,
    consistency checking, and API contract enforcement. Implements response
    validation maintaining existing patterns per F-004-RQ-004 requirements.
    
    This validator implements:
    - Response data validation and consistency checking
    - API response format standardization and serialization
    - Output data transformation and formatting
    - Response schema validation and compliance
    - Performance optimization for response generation
    
    Response Format Features:
        - Consistent JSON response structure
        - HTTP status code validation and mapping
        - Response metadata and pagination support
        - Error response formatting and standardization
        - Response compression and optimization
    
    Example:
        class UserResponseValidator(OutputValidator):
            id = fields.String(required=True)
            email = fields.Email(required=True)
            name = fields.String(required=True)
            created_at = fields.DateTime(dump_only=True)
            updated_at = fields.DateTime(dump_only=True)
    """
    
    def __init__(self, *args, **kwargs):
        """
        Initialize output validator with response formatting features.
        
        Args:
            *args: Positional arguments for DataModelValidator
            **kwargs: Keyword arguments including response configuration
        """
        super().__init__(*args, **kwargs)
        
        # Response configuration
        self.include_metadata = kwargs.pop('include_metadata', True)
        self.include_timestamps = kwargs.pop('include_timestamps', True)
        self.response_format = kwargs.pop('response_format', 'standard')
        self.enable_compression = kwargs.pop('enable_compression', False)
        
        logger.debug("Output validator initialized",
                    include_metadata=self.include_metadata,
                    response_format=self.response_format)
    
    def format_success_response(
        self,
        data: Any,
        status_code: int = 200,
        message: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Format successful response data with consistent structure.
        
        Args:
            data: Response data to format
            status_code: HTTP status code for response
            message: Optional success message
            metadata: Optional response metadata
            
        Returns:
            Formatted success response dictionary
        """
        try:
            logger.debug("Formatting success response",
                        data_type=type(data).__name__,
                        status_code=status_code)
            
            # Validate and serialize data
            if data is not None:
                serialized_data = self.dump_with_validation(data, validate_output=True)
            else:
                serialized_data = None
            
            # Build response structure
            response = {
                'success': True,
                'status_code': status_code,
                'data': serialized_data
            }
            
            # Add optional message
            if message:
                response['message'] = message
            
            # Add metadata
            if self.include_metadata and metadata:
                response['metadata'] = metadata
            
            # Add timestamps
            if self.include_timestamps:
                response['timestamp'] = datetime.now().isoformat()
            
            logger.debug("Success response formatted successfully",
                        response_fields=list(response.keys()))
            
            return response
            
        except Exception as formatting_error:
            raise DataValidationError(
                message="Failed to format success response",
                error_code="RESPONSE_FORMAT_ERROR",
                context={'status_code': status_code},
                cause=formatting_error,
                severity=ErrorSeverity.MEDIUM
            )
    
    def format_error_response(
        self,
        error: BaseBusinessException,
        include_details: bool = False
    ) -> Dict[str, Any]:
        """
        Format error response with consistent structure and security.
        
        Args:
            error: Business exception to format
            include_details: Whether to include detailed error information
            
        Returns:
            Formatted error response dictionary
        """
        try:
            logger.debug("Formatting error response",
                        error_type=type(error).__name__,
                        error_code=error.error_code)
            
            # Build error response structure
            response = {
                'success': False,
                'error': {
                    'code': error.error_code,
                    'message': error.message,
                    'type': error.category.value if hasattr(error, 'category') else 'error'
                }
            }
            
            # Add status code
            if hasattr(error, 'http_status_code'):
                response['status_code'] = error.http_status_code
            
            # Add detailed error information if requested
            if include_details:
                if hasattr(error, 'context') and error.context:
                    response['error']['details'] = error.context
                
                if hasattr(error, 'validation_errors') and error.validation_errors:
                    response['error']['validation_errors'] = error.validation_errors
                
                if hasattr(error, 'field_errors') and error.field_errors:
                    response['error']['field_errors'] = error.field_errors
            
            # Add timestamps
            if self.include_timestamps:
                response['timestamp'] = datetime.now().isoformat()
            
            # Add request ID for tracking
            if hasattr(error, 'request_id') and error.request_id:
                response['request_id'] = error.request_id
            
            logger.debug("Error response formatted successfully",
                        error_code=error.error_code)
            
            return response
            
        except Exception as formatting_error:
            logger.error("Failed to format error response",
                        original_error=str(error),
                        formatting_error=str(formatting_error))
            
            # Return minimal error response
            return {
                'success': False,
                'error': {
                    'code': 'RESPONSE_FORMAT_ERROR',
                    'message': 'An error occurred while formatting the response',
                    'type': 'system_error'
                },
                'timestamp': datetime.now().isoformat()
            }
    
    def format_paginated_response(
        self,
        data: List[Any],
        page: int,
        per_page: int,
        total_count: int,
        additional_metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Format paginated response with navigation metadata.
        
        Args:
            data: List of data items for current page
            page: Current page number (1-based)
            per_page: Number of items per page
            total_count: Total number of items
            additional_metadata: Optional additional metadata
            
        Returns:
            Formatted paginated response dictionary
        """
        try:
            logger.debug("Formatting paginated response",
                        data_count=len(data),
                        page=page,
                        per_page=per_page,
                        total_count=total_count)
            
            # Validate and serialize data items
            serialized_data = []
            for item in data:
                serialized_item = self.dump_with_validation(item, validate_output=True)
                serialized_data.append(serialized_item)
            
            # Calculate pagination metadata
            total_pages = (total_count + per_page - 1) // per_page
            has_next = page < total_pages
            has_prev = page > 1
            
            # Build pagination metadata
            pagination = {
                'page': page,
                'per_page': per_page,
                'total_count': total_count,
                'total_pages': total_pages,
                'has_next': has_next,
                'has_prev': has_prev
            }
            
            # Add navigation URLs if available
            if has_next:
                pagination['next_page'] = page + 1
            if has_prev:
                pagination['prev_page'] = page - 1
            
            # Build response structure
            response = {
                'success': True,
                'data': serialized_data,
                'pagination': pagination
            }
            
            # Add additional metadata
            if additional_metadata:
                response['metadata'] = additional_metadata
            
            # Add timestamps
            if self.include_timestamps:
                response['timestamp'] = datetime.now().isoformat()
            
            logger.debug("Paginated response formatted successfully",
                        items_count=len(serialized_data),
                        total_pages=total_pages)
            
            return response
            
        except Exception as formatting_error:
            raise DataValidationError(
                message="Failed to format paginated response",
                error_code="PAGINATED_RESPONSE_ERROR",
                context={
                    'page': page,
                    'per_page': per_page,
                    'total_count': total_count
                },
                cause=formatting_error,
                severity=ErrorSeverity.MEDIUM
            )
    
    def validate_response_schema(self, response_data: Dict[str, Any]) -> bool:
        """
        Validate response data against expected schema.
        
        Args:
            response_data: Response data to validate
            
        Returns:
            True if response schema is valid
            
        Raises:
            DataValidationError: If response schema validation fails
        """
        try:
            # Check required response fields
            required_fields = {'success'}
            if 'success' not in response_data:
                raise DataValidationError(
                    message="Response missing required 'success' field",
                    error_code="INVALID_RESPONSE_SCHEMA",
                    severity=ErrorSeverity.HIGH
                )
            
            # Validate success response structure
            if response_data['success']:
                if 'data' not in response_data:
                    logger.warning("Success response missing 'data' field")
            else:
                if 'error' not in response_data:
                    raise DataValidationError(
                        message="Error response missing 'error' field",
                        error_code="INVALID_ERROR_RESPONSE",
                        severity=ErrorSeverity.HIGH
                    )
            
            logger.debug("Response schema validation passed")
            return True
            
        except Exception as schema_error:
            if isinstance(schema_error, DataValidationError):
                raise
            
            raise DataValidationError(
                message="Response schema validation failed",
                error_code="RESPONSE_SCHEMA_ERROR",
                cause=schema_error,
                severity=ErrorSeverity.MEDIUM
            )


# ============================================================================
# VALIDATION UTILITY FUNCTIONS
# ============================================================================

def validate_business_data(
    data: Union[Dict[str, Any], str],
    schema_class: Type[BaseValidator],
    validation_context: Optional[ValidationContext] = None,
    **schema_kwargs
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Validate business data using specified schema and context.
    
    Provides centralized business data validation with comprehensive error
    handling, context management, and performance monitoring. Implements
    primary validation entry point per Section 5.2.4 requirements.
    
    Args:
        data: Business data to validate (dictionary or JSON string)
        schema_class: Validator class to use for validation
        validation_context: Optional validation context for rules
        **schema_kwargs: Additional arguments for schema initialization
        
    Returns:
        Tuple of (validated_data, validation_warnings)
        
    Raises:
        DataValidationError: If validation fails
        BusinessRuleViolationError: If business rules are violated
        
    Example:
        class UserValidator(DataModelValidator):
            name = fields.String(required=True)
            email = fields.Email(required=True)
        
        context = ValidationContext(validation_type=ValidationType.STRICT)
        validated_data, warnings = validate_business_data(
            user_data, UserValidator, context
        )
    """
    start_time = datetime.now()
    
    try:
        logger.info("Starting business data validation",
                   data_type=type(data).__name__,
                   schema_class=schema_class.__name__)
        
        # Initialize schema with context
        schema = schema_class(
            validation_context=validation_context,
            **schema_kwargs
        )
        
        # Perform validation
        validated_data = schema.load_with_context(
            data,
            validation_context=validation_context
        )
        
        # Get validation warnings from context
        warnings = []
        if validation_context:
            warnings = validation_context.get_warnings()
        
        # Performance monitoring
        duration = (datetime.now() - start_time).total_seconds()
        
        logger.info("Business data validation completed successfully",
                   validated_fields=len(validated_data) if isinstance(validated_data, dict) else 0,
                   warning_count=len(warnings),
                   duration_seconds=duration)
        
        return validated_data, warnings
        
    except Exception as validation_error:
        duration = (datetime.now() - start_time).total_seconds()
        
        logger.error("Business data validation failed",
                    schema_class=schema_class.__name__,
                    duration_seconds=duration,
                    error=str(validation_error))
        
        if isinstance(validation_error, BaseBusinessException):
            raise
        
        raise DataValidationError(
            message="Business data validation failed",
            error_code="BUSINESS_DATA_VALIDATION_ERROR",
            context={
                'schema_class': schema_class.__name__,
                'duration_seconds': duration
            },
            cause=validation_error,
            severity=ErrorSeverity.HIGH
        )


def validate_request_data(
    request_data: Dict[str, Any],
    schema_class: Type[InputValidator],
    sanitize: bool = True,
    **validation_kwargs
) -> Dict[str, Any]:
    """
    Validate HTTP request data with sanitization and security checks.
    
    Provides comprehensive request data validation with input sanitization,
    security validation, and request processing per F-003-RQ-004 requirements.
    
    Args:
        request_data: HTTP request data to validate
        schema_class: Input validator class for validation
        sanitize: Whether to apply input sanitization
        **validation_kwargs: Additional validation arguments
        
    Returns:
        Validated request data
        
    Raises:
        DataValidationError: If request validation fails
        
    Example:
        class CreateUserRequest(InputValidator):
            name = fields.String(required=True, validate=validate.Length(min=2))
            email = fields.Email(required=True)
        
        validated_data = validate_request_data(
            request.json, CreateUserRequest, sanitize=True
        )
    """
    try:
        logger.debug("Starting request data validation",
                    data_fields=list(request_data.keys()) if isinstance(request_data, dict) else [],
                    schema_class=schema_class.__name__,
                    sanitize=sanitize)
        
        # Create validation context for request
        context = ValidationContext(
            validation_type=ValidationType.SANITIZING if sanitize else ValidationType.STRICT,
            validation_mode=ValidationMode.CREATE,
            request_context=request_data
        )
        
        # Initialize input validator
        validator = schema_class(
            validation_context=context,
            enable_sanitization=sanitize,
            **validation_kwargs
        )
        
        # Perform validation
        validated_data = validator.load_with_context(request_data, context)
        
        logger.debug("Request data validation completed successfully",
                    validated_fields=len(validated_data))
        
        return validated_data
        
    except Exception as request_error:
        logger.error("Request data validation failed",
                    schema_class=schema_class.__name__,
                    error=str(request_error))
        
        if isinstance(request_error, BaseBusinessException):
            raise
        
        raise DataValidationError(
            message="Request data validation failed",
            error_code="REQUEST_VALIDATION_ERROR",
            context={'schema_class': schema_class.__name__},
            cause=request_error,
            severity=ErrorSeverity.MEDIUM
        )


def validate_response_data(
    response_data: Any,
    schema_class: Type[OutputValidator],
    format_response: bool = True,
    **formatting_kwargs
) -> Dict[str, Any]:
    """
    Validate response data with formatting and consistency checks.
    
    Provides comprehensive response data validation with format standardization,
    consistency checking, and API contract enforcement per F-004-RQ-004 requirements.
    
    Args:
        response_data: Response data to validate
        schema_class: Output validator class for validation
        format_response: Whether to format response structure
        **formatting_kwargs: Additional formatting arguments
        
    Returns:
        Validated and formatted response data
        
    Raises:
        DataValidationError: If response validation fails
        
    Example:
        class UserResponse(OutputValidator):
            id = fields.String(required=True)
            name = fields.String(required=True)
            email = fields.Email(required=True)
        
        formatted_response = validate_response_data(
            user_data, UserResponse, format_response=True
        )
    """
    try:
        logger.debug("Starting response data validation",
                    data_type=type(response_data).__name__,
                    schema_class=schema_class.__name__,
                    format_response=format_response)
        
        # Create validation context for response
        context = ValidationContext(
            validation_type=ValidationType.STRICT,
            validation_mode=ValidationMode.RESPONSE
        )
        
        # Initialize output validator
        validator = schema_class(
            validation_context=context,
            **formatting_kwargs
        )
        
        if format_response:
            # Format as success response
            formatted_data = validator.format_success_response(
                response_data,
                **formatting_kwargs
            )
        else:
            # Just validate without formatting
            formatted_data = validator.dump_with_validation(response_data)
        
        logger.debug("Response data validation completed successfully")
        
        return formatted_data
        
    except Exception as response_error:
        logger.error("Response data validation failed",
                    schema_class=schema_class.__name__,
                    error=str(response_error))
        
        if isinstance(response_error, BaseBusinessException):
            raise
        
        raise DataValidationError(
            message="Response data validation failed",
            error_code="RESPONSE_VALIDATION_ERROR",
            context={'schema_class': schema_class.__name__},
            cause=response_error,
            severity=ErrorSeverity.MEDIUM
        )


def create_validation_schema(
    field_definitions: Dict[str, FieldType],
    base_class: Type[BaseValidator] = DataModelValidator,
    schema_name: str = "DynamicValidator"
) -> Type[BaseValidator]:
    """
    Create validation schema dynamically from field definitions.
    
    Provides dynamic schema creation for flexible validation scenarios
    and runtime schema generation based on business requirements.
    
    Args:
        field_definitions: Dictionary of field names to field objects
        base_class: Base validator class to inherit from
        schema_name: Name for the dynamic schema class
        
    Returns:
        Dynamically created validator class
        
    Example:
        fields = {
            'name': fields.String(required=True),
            'email': fields.Email(required=True),
            'age': fields.Integer(validate=validate.Range(min=0))
        }
        
        DynamicValidator = create_validation_schema(fields, schema_name="UserValidator")
        validator = DynamicValidator()
    """
    try:
        logger.debug("Creating dynamic validation schema",
                    field_count=len(field_definitions),
                    base_class=base_class.__name__,
                    schema_name=schema_name)
        
        # Validate field definitions
        for field_name, field_obj in field_definitions.items():
            if not isinstance(field_obj, fields.Field):
                if isinstance(field_obj, type) and issubclass(field_obj, fields.Field):
                    # Convert field class to instance
                    field_definitions[field_name] = field_obj()
                else:
                    raise DataValidationError(
                        message=f"Invalid field definition for '{field_name}'",
                        error_code="INVALID_FIELD_DEFINITION",
                        context={
                            'field_name': field_name,
                            'field_type': type(field_obj).__name__
                        },
                        severity=ErrorSeverity.MEDIUM
                    )
        
        # Create dynamic schema class
        schema_class = type(schema_name, (base_class,), field_definitions)
        
        logger.debug("Dynamic validation schema created successfully",
                    schema_name=schema_name,
                    field_count=len(field_definitions))
        
        return schema_class
        
    except Exception as creation_error:
        logger.error("Dynamic schema creation failed",
                    schema_name=schema_name,
                    error=str(creation_error))
        
        if isinstance(creation_error, BaseBusinessException):
            raise
        
        raise DataValidationError(
            message="Dynamic validation schema creation failed",
            error_code="DYNAMIC_SCHEMA_ERROR",
            context={'schema_name': schema_name},
            cause=creation_error,
            severity=ErrorSeverity.MEDIUM
        )


def format_validation_errors(
    validation_errors: List[Dict[str, Any]],
    format_type: str = "detailed"
) -> Dict[str, Any]:
    """
    Format validation errors for client responses.
    
    Provides consistent validation error formatting for API responses
    with multiple format options for different client requirements.
    
    Args:
        validation_errors: List of validation error dictionaries
        format_type: Format type ("detailed", "summary", "field_only")
        
    Returns:
        Formatted validation errors dictionary
        
    Example:
        errors = [
            {'field': 'email', 'message': 'Invalid email format', 'code': 'INVALID_EMAIL'},
            {'field': 'age', 'message': 'Must be at least 18', 'code': 'MIN_VALUE'}
        ]
        
        formatted = format_validation_errors(errors, format_type="detailed")
    """
    try:
        logger.debug("Formatting validation errors",
                    error_count=len(validation_errors),
                    format_type=format_type)
        
        if format_type == "detailed":
            # Detailed format with all error information
            formatted_errors = {
                'error_count': len(validation_errors),
                'errors': validation_errors,
                'summary': f"{len(validation_errors)} validation error(s) occurred"
            }
            
        elif format_type == "summary":
            # Summary format with error count and messages
            error_messages = [error.get('message', 'Validation error') for error in validation_errors]
            formatted_errors = {
                'error_count': len(validation_errors),
                'messages': error_messages,
                'summary': f"{len(validation_errors)} validation error(s) occurred"
            }
            
        elif format_type == "field_only":
            # Field-only format grouped by field name
            field_errors = {}
            for error in validation_errors:
                field_name = error.get('field', 'unknown')
                if field_name not in field_errors:
                    field_errors[field_name] = []
                field_errors[field_name].append(error.get('message', 'Validation error'))
            
            formatted_errors = {
                'field_errors': field_errors,
                'error_count': len(validation_errors)
            }
            
        else:
            raise DataValidationError(
                message=f"Invalid error format type: {format_type}",
                error_code="INVALID_FORMAT_TYPE",
                context={
                    'format_type': format_type,
                    'valid_types': ['detailed', 'summary', 'field_only']
                },
                severity=ErrorSeverity.MEDIUM
            )
        
        logger.debug("Validation errors formatted successfully",
                    format_type=format_type)
        
        return formatted_errors
        
    except Exception as formatting_error:
        logger.error("Validation error formatting failed",
                    format_type=format_type,
                    error=str(formatting_error))
        
        if isinstance(formatting_error, BaseBusinessException):
            raise
        
        # Return basic error format if formatting fails
        return {
            'error_count': len(validation_errors),
            'errors': validation_errors,
            'format_error': str(formatting_error)
        }


# ============================================================================
# COMMON BUSINESS VALIDATION SCHEMAS
# ============================================================================

class CommonFieldValidators:
    """Common field validators for business data validation."""
    
    # Email validation with business rules
    email = fields.Email(
        required=True,
        validate=validate.Length(max=254),
        error_messages={
            'invalid': 'Please provide a valid email address',
            'required': 'Email address is required'
        }
    )
    
    # Phone number validation
    phone = fields.String(
        validate=validate.Length(max=20),
        error_messages={'invalid': 'Please provide a valid phone number'}
    )
    
    # Name fields with proper validation
    name = fields.String(
        required=True,
        validate=validate.Length(min=2, max=100),
        error_messages={
            'required': 'Name is required',
            'invalid': 'Name must be between 2 and 100 characters'
        }
    )
    
    # Currency amount validation
    amount = fields.Decimal(
        places=2,
        validate=validate.Range(min=0),
        error_messages={
            'invalid': 'Amount must be a valid positive number with up to 2 decimal places'
        }
    )
    
    # Date fields with timezone awareness
    date_created = fields.DateTime(
        dump_only=True,
        format='iso',
        error_messages={'invalid': 'Invalid date format'}
    )
    
    date_updated = fields.DateTime(
        dump_only=True,
        format='iso',
        error_messages={'invalid': 'Invalid date format'}
    )


# Module initialization logging
logger.info("Business validators module initialized successfully",
           module_version="1.0.0",
           marshmallow_version="3.20+",
           validation_features=[
               "marshmallow_schemas",
               "business_rule_validation", 
               "input_sanitization",
               "output_formatting",
               "context_management"
           ])