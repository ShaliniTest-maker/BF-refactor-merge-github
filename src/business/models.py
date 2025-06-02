"""
Business Data Models for Flask Application

This module provides comprehensive Pydantic data models for business data validation,
type checking, and serialization patterns. Implements performance-optimized validation
schemas for business logic processing with type hints and detailed field validation
equivalent to Node.js data validation patterns per Section 5.2.4 requirements.

The data models follow enterprise patterns with:
- Pydantic 2.3+ for data validation and type checking with performance optimization
- Business data models maintaining identical validation patterns per F-004-RQ-001
- Type checking and serialization for business logic processing per Section 5.2.4
- Response data formatting equivalent to Node.js implementation per F-004-RQ-004
- Field validation and type conversion patterns per Section 5.2.4
- Integration with business logic processing pipeline per Section 5.2.4

Model Categories:
    Core Business Models:
        User: User account and profile information
        Organization: Organization and company data
        Product: Product catalog and inventory models
        Order: Order and transaction processing models
        Payment: Payment processing and financial models
        
    API Data Models:
        Request: API request validation models
        Response: API response serialization models
        Pagination: Pagination and filtering models
        Search: Search query and results models
        
    Utility Models:
        Address: Geographic address information
        Contact: Contact information and preferences
        DateTime: Date/time validation and formatting
        File: File upload and metadata models
        Configuration: System configuration models
"""

import re
import uuid
from datetime import datetime, date, timezone
from decimal import Decimal
from enum import Enum
from typing import Any, Dict, List, Optional, Union, Set, Tuple, ClassVar
from pydantic import (
    BaseModel, 
    Field, 
    EmailStr, 
    HttpUrl, 
    ConfigDict,
    field_validator,
    model_validator,
    computed_field,
    field_serializer,
    ValidationError as PydanticValidationError
)
from pydantic.dataclasses import dataclass
import phonenumbers
from phonenumbers import NumberParseException

# Import business exceptions and utilities for error handling and data processing
from .exceptions import (
    DataValidationError,
    BusinessRuleViolationError,
    DataProcessingError,
    ErrorSeverity
)
from .utils import (
    validate_email,
    validate_phone,
    validate_postal_code,
    sanitize_input,
    safe_str,
    safe_int,
    safe_float,
    normalize_boolean,
    parse_date,
    format_date,
    round_currency,
    validate_currency
)

# Configure structured logging for business models
import structlog
logger = structlog.get_logger("business.models")


# ============================================================================
# CONFIGURATION AND BASE CLASSES
# ============================================================================

class BusinessModelConfig:
    """
    Shared configuration for all business data models.
    
    Provides standardized Pydantic configuration for business models ensuring
    consistent validation behavior, performance optimization, and serialization
    patterns across all business data structures.
    """
    # Performance optimization settings per Section 5.2.4
    validate_assignment = True  # Validate on attribute assignment
    validate_return = True      # Validate return values
    use_enum_values = True      # Use enum values in serialization
    validate_default = True     # Validate default values
    
    # JSON serialization settings for API compatibility
    json_encoders = {
        datetime: lambda v: v.isoformat() if v else None,
        date: lambda v: v.isoformat() if v else None,
        Decimal: lambda v: str(v) if v else None,
        uuid.UUID: lambda v: str(v) if v else None,
    }
    
    # Field ordering and additional settings
    fields = {
        # Performance: exclude None values from serialization by default
        "__default__": {"exclude_none": True}
    }


class BaseBusinessModel(BaseModel):
    """
    Base class for all business data models with enterprise features.
    
    Provides common functionality for business data models including validation,
    serialization, audit trail support, and performance optimization. Implements
    enterprise patterns per Section 5.2.4 business logic requirements.
    
    Features:
    - Automatic timestamp management for audit trails
    - Comprehensive validation with business rule enforcement
    - Performance-optimized serialization for API responses
    - Integration with business exception handling
    - Type conversion and data sanitization patterns
    - Audit trail and change tracking support
    
    Example:
        class CustomModel(BaseBusinessModel):
            name: str = Field(..., min_length=1, max_length=100)
            email: EmailStr
            
            @field_validator('name')
            @classmethod
            def validate_name(cls, v):
                return sanitize_input(v, max_length=100)
    """
    
    model_config = ConfigDict(
        # Performance optimization settings
        validate_assignment=True,
        validate_return=True,
        use_enum_values=True,
        validate_default=True,
        
        # JSON serialization settings
        json_encoders={
            datetime: lambda v: v.isoformat() if v else None,
            date: lambda v: v.isoformat() if v else None,
            Decimal: lambda v: str(v) if v else None,
            uuid.UUID: lambda v: str(v) if v else None,
        },
        
        # Additional settings for enterprise use
        str_strip_whitespace=True,  # Automatically strip whitespace
        frozen=False,  # Allow modification after creation
        extra='forbid',  # Forbid extra fields for security
        arbitrary_types_allowed=False,  # Restrict to known types
        
        # Performance settings
        hide_input_in_errors=True,  # Security: hide sensitive input in errors
    )
    
    # Audit trail fields (optional, can be excluded in serialization)
    created_at: Optional[datetime] = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Record creation timestamp for audit trail"
    )
    updated_at: Optional[datetime] = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Record last update timestamp for audit trail"
    )
    version: Optional[int] = Field(
        default=1,
        description="Record version for optimistic locking and change tracking"
    )
    
    def __init__(self, **data):
        """
        Initialize business model with validation and error handling.
        
        Args:
            **data: Model field data for initialization
            
        Raises:
            DataValidationError: If validation fails with business context
        """
        try:
            super().__init__(**data)
            
            # Log model creation for audit trail
            logger.debug("Business model created",
                        model_type=self.__class__.__name__,
                        field_count=len(self.model_fields))
            
        except PydanticValidationError as e:
            # Convert Pydantic validation errors to business exceptions
            error_details = []
            for error in e.errors():
                error_details.append({
                    'field': '.'.join(str(loc) for loc in error['loc']),
                    'message': error['msg'],
                    'type': error['type'],
                    'input': str(error.get('input', ''))[:100]  # Truncate for security
                })
            
            raise DataValidationError(
                message=f"Business model validation failed for {self.__class__.__name__}",
                error_code="MODEL_VALIDATION_FAILED",
                validation_errors=error_details,
                context={
                    'model_type': self.__class__.__name__,
                    'error_count': len(error_details)
                },
                cause=e,
                severity=ErrorSeverity.MEDIUM
            )
        except Exception as e:
            # Handle unexpected errors during model creation
            raise DataProcessingError(
                message=f"Failed to create {self.__class__.__name__} model",
                error_code="MODEL_CREATION_FAILED",
                processing_stage="model_initialization",
                data_type=self.__class__.__name__,
                cause=e,
                severity=ErrorSeverity.HIGH
            )
    
    @model_validator(mode='after')
    def update_timestamp(self) -> 'BaseBusinessModel':
        """
        Update the updated_at timestamp when model is modified.
        
        Returns:
            Self with updated timestamp
        """
        if hasattr(self, 'updated_at'):
            self.updated_at = datetime.now(timezone.utc)
        return self
    
    def to_api_dict(self, exclude_audit: bool = True) -> Dict[str, Any]:
        """
        Convert model to dictionary suitable for API responses.
        
        Provides standardized serialization for API responses with configurable
        field exclusion and consistent formatting per F-004-RQ-004 requirements.
        
        Args:
            exclude_audit: Whether to exclude audit trail fields
            
        Returns:
            Dictionary representation suitable for JSON API responses
        """
        try:
            exclude_fields = set()
            
            if exclude_audit:
                exclude_fields.update({'created_at', 'updated_at', 'version'})
            
            api_dict = self.model_dump(
                exclude=exclude_fields,
                exclude_none=True,
                mode='json'
            )
            
            logger.debug("Model serialized to API dictionary",
                        model_type=self.__class__.__name__,
                        field_count=len(api_dict))
            
            return api_dict
            
        except Exception as e:
            raise DataProcessingError(
                message=f"Failed to serialize {self.__class__.__name__} to API dictionary",
                error_code="MODEL_SERIALIZATION_FAILED",
                processing_stage="api_serialization",
                data_type=self.__class__.__name__,
                cause=e,
                severity=ErrorSeverity.MEDIUM
            )
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BaseBusinessModel':
        """
        Create model instance from dictionary with validation.
        
        Args:
            data: Dictionary data to create model from
            
        Returns:
            Validated model instance
            
        Raises:
            DataValidationError: If validation fails
        """
        try:
            return cls(**data)
        except Exception as e:
            if isinstance(e, (DataValidationError, DataProcessingError)):
                raise
            
            raise DataValidationError(
                message=f"Failed to create {cls.__name__} from dictionary",
                error_code="MODEL_FROM_DICT_FAILED",
                context={'data_keys': list(data.keys()) if data else []},
                cause=e,
                severity=ErrorSeverity.MEDIUM
            )
    
    def validate_business_rules(self) -> None:
        """
        Validate business-specific rules for the model.
        
        Override this method in subclasses to implement model-specific
        business rule validation beyond field-level validation.
        
        Raises:
            BusinessRuleViolationError: If business rules are violated
        """
        # Base implementation - override in subclasses for specific rules
        pass


# ============================================================================
# ENUMERATION TYPES
# ============================================================================

class UserStatus(str, Enum):
    """User account status enumeration for user management."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING = "pending"
    ARCHIVED = "archived"


class UserRole(str, Enum):
    """User role enumeration for access control and permissions."""
    ADMIN = "admin"
    MANAGER = "manager"
    USER = "user"
    GUEST = "guest"
    SERVICE = "service"


class OrderStatus(str, Enum):
    """Order processing status enumeration for order management."""
    PENDING = "pending"
    CONFIRMED = "confirmed"
    PROCESSING = "processing"
    SHIPPED = "shipped"
    DELIVERED = "delivered"
    CANCELLED = "cancelled"
    REFUNDED = "refunded"


class PaymentStatus(str, Enum):
    """Payment processing status enumeration for financial operations."""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    REFUNDED = "refunded"


class PaymentMethod(str, Enum):
    """Payment method enumeration for financial transactions."""
    CREDIT_CARD = "credit_card"
    DEBIT_CARD = "debit_card"
    BANK_TRANSFER = "bank_transfer"
    DIGITAL_WALLET = "digital_wallet"
    CRYPTOCURRENCY = "cryptocurrency"
    CASH = "cash"


class ProductStatus(str, Enum):
    """Product status enumeration for catalog management."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    DISCONTINUED = "discontinued"
    OUT_OF_STOCK = "out_of_stock"
    DRAFT = "draft"


class Priority(str, Enum):
    """Priority level enumeration for task and request management."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    URGENT = "urgent"
    CRITICAL = "critical"


class ContactMethod(str, Enum):
    """Contact method enumeration for communication preferences."""
    EMAIL = "email"
    PHONE = "phone"
    SMS = "sms"
    MAIL = "mail"
    IN_APP = "in_app"


# ============================================================================
# UTILITY AND COMMON MODELS
# ============================================================================

class Address(BaseBusinessModel):
    """
    Geographic address model for location data validation.
    
    Provides comprehensive address validation and formatting for business
    operations requiring location data including shipping, billing, and
    service delivery addresses.
    """
    
    street_line_1: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Primary street address line"
    )
    street_line_2: Optional[str] = Field(
        default=None,
        max_length=100,
        description="Secondary street address line (apartment, suite, etc.)"
    )
    city: str = Field(
        ...,
        min_length=1,
        max_length=50,
        description="City name"
    )
    state_province: str = Field(
        ...,
        min_length=1,
        max_length=50,
        description="State or province name"
    )
    postal_code: str = Field(
        ...,
        min_length=3,
        max_length=20,
        description="Postal or ZIP code"
    )
    country_code: str = Field(
        ...,
        min_length=2,
        max_length=3,
        description="ISO country code (2 or 3 letter)"
    )
    
    @field_validator('street_line_1', 'street_line_2', 'city', 'state_province')
    @classmethod
    def sanitize_address_fields(cls, v):
        """Sanitize address text fields."""
        if v is None:
            return v
        return sanitize_input(v, allow_html=False)
    
    @field_validator('country_code')
    @classmethod
    def validate_country_code(cls, v):
        """Validate ISO country code format."""
        if v:
            v = v.upper().strip()
            if len(v) not in [2, 3]:
                raise BusinessRuleViolationError(
                    message="Country code must be 2 or 3 characters",
                    error_code="INVALID_COUNTRY_CODE",
                    context={'country_code': v}
                )
        return v
    
    @field_validator('postal_code')
    @classmethod
    def validate_postal_code_format(cls, v, info):
        """Validate postal code format based on country."""
        if v and hasattr(info, 'data') and 'country_code' in info.data:
            country = info.data['country_code']
            try:
                if not validate_postal_code(v, country):
                    raise BusinessRuleViolationError(
                        message=f"Invalid postal code format for {country}",
                        error_code="INVALID_POSTAL_FORMAT",
                        context={'postal_code': v, 'country': country}
                    )
            except Exception:
                # If validation fails, just clean the postal code
                pass
        return v.strip().upper() if v else v
    
    def get_formatted_address(self, single_line: bool = False) -> str:
        """
        Get formatted address string for display.
        
        Args:
            single_line: Whether to format as single line
            
        Returns:
            Formatted address string
        """
        parts = [self.street_line_1]
        
        if self.street_line_2:
            parts.append(self.street_line_2)
        
        city_state_zip = f"{self.city}, {self.state_province} {self.postal_code}"
        parts.append(city_state_zip)
        parts.append(self.country_code)
        
        separator = ", " if single_line else "\n"
        return separator.join(parts)


class ContactInfo(BaseBusinessModel):
    """
    Contact information model for communication data validation.
    
    Provides comprehensive contact information validation including email,
    phone numbers, and communication preferences for business operations.
    """
    
    primary_email: Optional[EmailStr] = Field(
        default=None,
        description="Primary email address"
    )
    secondary_email: Optional[EmailStr] = Field(
        default=None,
        description="Secondary email address"
    )
    primary_phone: Optional[str] = Field(
        default=None,
        min_length=7,
        max_length=20,
        description="Primary phone number"
    )
    secondary_phone: Optional[str] = Field(
        default=None,
        min_length=7,
        max_length=20,
        description="Secondary phone number"
    )
    preferred_contact_method: ContactMethod = Field(
        default=ContactMethod.EMAIL,
        description="Preferred method of contact"
    )
    allow_marketing: bool = Field(
        default=False,
        description="Allow marketing communications"
    )
    timezone: Optional[str] = Field(
        default=None,
        max_length=50,
        description="User timezone for communication timing"
    )
    
    @field_validator('primary_phone', 'secondary_phone')
    @classmethod
    def validate_phone_format(cls, v):
        """Validate phone number format."""
        if v is None:
            return v
        
        # Clean phone number
        cleaned = re.sub(r'[^\d+()-.\s]', '', v.strip())
        
        try:
            if validate_phone(cleaned, format_type="international"):
                return cleaned
        except Exception:
            pass
        
        # If international validation fails, try national format
        try:
            if validate_phone(cleaned, country_code="US", format_type="national"):
                return cleaned
        except Exception:
            pass
        
        raise BusinessRuleViolationError(
            message="Invalid phone number format",
            error_code="INVALID_PHONE_FORMAT",
            context={'phone': v}
        )
    
    def validate_business_rules(self) -> None:
        """Validate contact information business rules."""
        super().validate_business_rules()
        
        # At least one contact method must be provided
        if not self.primary_email and not self.primary_phone:
            raise BusinessRuleViolationError(
                message="At least one primary contact method (email or phone) is required",
                error_code="MISSING_PRIMARY_CONTACT",
                severity=ErrorSeverity.HIGH
            )


class MonetaryAmount(BaseBusinessModel):
    """
    Monetary amount model for financial data validation.
    
    Provides precise monetary amount handling with currency validation,
    proper decimal precision, and business rule enforcement for financial
    operations and calculations.
    """
    
    amount: Decimal = Field(
        ...,
        ge=0,
        decimal_places=2,
        description="Monetary amount with proper precision"
    )
    currency_code: str = Field(
        default="USD",
        min_length=3,
        max_length=3,
        description="ISO 4217 currency code"
    )
    
    @field_validator('amount')
    @classmethod
    def validate_amount_precision(cls, v):
        """Validate monetary amount precision."""
        if v is None:
            return v
        
        # Convert to Decimal for precise handling
        if not isinstance(v, Decimal):
            v = Decimal(str(v))
        
        # Validate amount is not negative
        if v < 0:
            raise BusinessRuleViolationError(
                message="Monetary amount cannot be negative",
                error_code="NEGATIVE_AMOUNT",
                context={'amount': str(v)}
            )
        
        return v
    
    @field_validator('currency_code')
    @classmethod
    def validate_currency_code(cls, v):
        """Validate ISO 4217 currency code."""
        if v:
            v = v.upper().strip()
            
            # Basic validation - 3 letter currency code
            if len(v) != 3 or not v.isalpha():
                raise BusinessRuleViolationError(
                    message="Currency code must be 3 letter ISO 4217 code",
                    error_code="INVALID_CURRENCY_CODE",
                    context={'currency_code': v}
                )
        
        return v
    
    def get_rounded_amount(self) -> Decimal:
        """
        Get amount rounded according to currency rules.
        
        Returns:
            Properly rounded monetary amount
        """
        try:
            return round_currency(self.amount, self.currency_code)
        except Exception as e:
            logger.warning("Failed to round currency amount",
                          amount=str(self.amount),
                          currency=self.currency_code,
                          error=str(e))
            return self.amount.quantize(Decimal('0.01'))
    
    def validate_business_rules(self) -> None:
        """Validate monetary amount business rules."""
        super().validate_business_rules()
        
        try:
            validate_currency(self.amount, self.currency_code)
        except BusinessRuleViolationError:
            raise
        except Exception as e:
            raise BusinessRuleViolationError(
                message="Currency validation failed",
                error_code="CURRENCY_VALIDATION_ERROR",
                context={'amount': str(self.amount), 'currency': self.currency_code},
                cause=e
            )


class DateTimeRange(BaseBusinessModel):
    """
    Date/time range model for temporal data validation.
    
    Provides validation for date and time ranges including business hours,
    appointment scheduling, and temporal business logic operations.
    """
    
    start_datetime: datetime = Field(
        ...,
        description="Range start date and time"
    )
    end_datetime: datetime = Field(
        ...,
        description="Range end date and time"
    )
    timezone_name: Optional[str] = Field(
        default=None,
        description="Timezone name for the date range"
    )
    all_day: bool = Field(
        default=False,
        description="Whether this represents an all-day event"
    )
    
    @model_validator(mode='after')
    def validate_date_range(self) -> 'DateTimeRange':
        """Validate that start is before end datetime."""
        if self.start_datetime >= self.end_datetime:
            raise BusinessRuleViolationError(
                message="Start datetime must be before end datetime",
                error_code="INVALID_DATE_RANGE",
                context={
                    'start': self.start_datetime.isoformat(),
                    'end': self.end_datetime.isoformat()
                }
            )
        return self
    
    @computed_field
    @property
    def duration_minutes(self) -> int:
        """Calculate duration in minutes."""
        delta = self.end_datetime - self.start_datetime
        return int(delta.total_seconds() / 60)
    
    def overlaps_with(self, other: 'DateTimeRange') -> bool:
        """
        Check if this range overlaps with another range.
        
        Args:
            other: Another DateTimeRange to check overlap with
            
        Returns:
            True if ranges overlap, False otherwise
        """
        return (self.start_datetime < other.end_datetime and 
                self.end_datetime > other.start_datetime)


# ============================================================================
# USER AND ORGANIZATION MODELS
# ============================================================================

class User(BaseBusinessModel):
    """
    User account model for user management and authentication.
    
    Provides comprehensive user account validation including profile information,
    authentication data, preferences, and access control for business operations
    requiring user context and identity management.
    """
    
    id: Optional[str] = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique user identifier"
    )
    username: str = Field(
        ...,
        min_length=3,
        max_length=50,
        pattern=r'^[a-zA-Z0-9_.-]+$',
        description="Unique username for authentication"
    )
    email: EmailStr = Field(
        ...,
        description="User email address for authentication and communication"
    )
    first_name: str = Field(
        ...,
        min_length=1,
        max_length=50,
        description="User's first name"
    )
    last_name: str = Field(
        ...,
        min_length=1,
        max_length=50,
        description="User's last name"
    )
    display_name: Optional[str] = Field(
        default=None,
        max_length=100,
        description="Display name for user interface"
    )
    avatar_url: Optional[HttpUrl] = Field(
        default=None,
        description="URL to user's profile picture"
    )
    
    # Account status and permissions
    status: UserStatus = Field(
        default=UserStatus.ACTIVE,
        description="Account status"
    )
    role: UserRole = Field(
        default=UserRole.USER,
        description="User role for access control"
    )
    permissions: Set[str] = Field(
        default_factory=set,
        description="Specific permissions granted to user"
    )
    
    # Contact and preferences
    contact_info: Optional[ContactInfo] = Field(
        default=None,
        description="Contact information and preferences"
    )
    
    # Authentication and security
    last_login_at: Optional[datetime] = Field(
        default=None,
        description="Last successful login timestamp"
    )
    password_changed_at: Optional[datetime] = Field(
        default=None,
        description="Password last change timestamp"
    )
    login_attempts: int = Field(
        default=0,
        ge=0,
        description="Failed login attempt counter"
    )
    is_locked: bool = Field(
        default=False,
        description="Account lock status"
    )
    lock_expires_at: Optional[datetime] = Field(
        default=None,
        description="Account lock expiration timestamp"
    )
    
    # Profile and preferences
    language_code: str = Field(
        default="en",
        min_length=2,
        max_length=5,
        description="User's preferred language code"
    )
    timezone: str = Field(
        default="UTC",
        description="User's timezone for date/time display"
    )
    date_format: str = Field(
        default="YYYY-MM-DD",
        description="User's preferred date format"
    )
    
    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        """Validate username format and restrictions."""
        if v:
            v = v.strip().lower()
            
            # Check for reserved usernames
            reserved = {'admin', 'root', 'system', 'api', 'www', 'mail', 'ftp'}
            if v in reserved:
                raise BusinessRuleViolationError(
                    message="Username is reserved and cannot be used",
                    error_code="RESERVED_USERNAME",
                    context={'username': v}
                )
        
        return v
    
    @field_validator('first_name', 'last_name', 'display_name')
    @classmethod
    def sanitize_name_fields(cls, v):
        """Sanitize name fields."""
        if v is None:
            return v
        return sanitize_input(v, allow_html=False, max_length=100)
    
    @field_validator('permissions')
    @classmethod
    def validate_permissions(cls, v):
        """Validate user permissions format."""
        if v:
            # Ensure all permissions are strings and properly formatted
            validated_permissions = set()
            for perm in v:
                if isinstance(perm, str) and perm.strip():
                    validated_permissions.add(perm.strip().lower())
            return validated_permissions
        return set()
    
    @computed_field
    @property
    def full_name(self) -> str:
        """Generate full name from first and last name."""
        return f"{self.first_name} {self.last_name}".strip()
    
    @computed_field
    @property
    def is_active(self) -> bool:
        """Check if user account is active and not locked."""
        if self.status != UserStatus.ACTIVE:
            return False
        
        if self.is_locked:
            # Check if lock has expired
            if self.lock_expires_at and self.lock_expires_at <= datetime.now(timezone.utc):
                return True  # Lock expired, account is active
            return False
        
        return True
    
    def has_permission(self, permission: str) -> bool:
        """
        Check if user has specific permission.
        
        Args:
            permission: Permission string to check
            
        Returns:
            True if user has permission, False otherwise
        """
        if not self.is_active:
            return False
        
        # Admin role has all permissions
        if self.role == UserRole.ADMIN:
            return True
        
        # Check specific permissions
        return permission.lower() in self.permissions
    
    def validate_business_rules(self) -> None:
        """Validate user account business rules."""
        super().validate_business_rules()
        
        # Validate email format
        try:
            if not validate_email(str(self.email), strict=True):
                raise BusinessRuleViolationError(
                    message="Invalid email format",
                    error_code="INVALID_EMAIL_FORMAT",
                    context={'email': str(self.email)}
                )
        except Exception as e:
            if not isinstance(e, BusinessRuleViolationError):
                raise BusinessRuleViolationError(
                    message="Email validation failed",
                    error_code="EMAIL_VALIDATION_ERROR",
                    cause=e
                )
            raise
        
        # Validate lock expiration consistency
        if self.is_locked and not self.lock_expires_at:
            raise BusinessRuleViolationError(
                message="Locked accounts must have lock expiration time",
                error_code="MISSING_LOCK_EXPIRATION",
                severity=ErrorSeverity.HIGH
            )


class Organization(BaseBusinessModel):
    """
    Organization model for business entity management.
    
    Provides comprehensive organization information validation including
    company details, contact information, and business relationships
    for multi-tenant and B2B business operations.
    """
    
    id: Optional[str] = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique organization identifier"
    )
    name: str = Field(
        ...,
        min_length=1,
        max_length=200,
        description="Organization name"
    )
    legal_name: Optional[str] = Field(
        default=None,
        max_length=200,
        description="Legal business name"
    )
    business_type: Optional[str] = Field(
        default=None,
        max_length=50,
        description="Type of business organization"
    )
    
    # Business identifiers
    tax_id: Optional[str] = Field(
        default=None,
        max_length=50,
        description="Tax identification number"
    )
    registration_number: Optional[str] = Field(
        default=None,
        max_length=50,
        description="Business registration number"
    )
    
    # Contact information
    primary_contact: Optional[ContactInfo] = Field(
        default=None,
        description="Primary contact information"
    )
    billing_address: Optional[Address] = Field(
        default=None,
        description="Billing address"
    )
    shipping_address: Optional[Address] = Field(
        default=None,
        description="Default shipping address"
    )
    
    # Business details
    website_url: Optional[HttpUrl] = Field(
        default=None,
        description="Organization website URL"
    )
    description: Optional[str] = Field(
        default=None,
        max_length=1000,
        description="Organization description"
    )
    industry: Optional[str] = Field(
        default=None,
        max_length=100,
        description="Industry classification"
    )
    employee_count: Optional[int] = Field(
        default=None,
        ge=1,
        description="Number of employees"
    )
    
    # Status and settings
    status: UserStatus = Field(
        default=UserStatus.ACTIVE,
        description="Organization status"
    )
    is_verified: bool = Field(
        default=False,
        description="Business verification status"
    )
    verification_date: Optional[datetime] = Field(
        default=None,
        description="Business verification completion date"
    )
    
    # Parent organization relationship
    parent_organization_id: Optional[str] = Field(
        default=None,
        description="Parent organization identifier for hierarchies"
    )
    
    @field_validator('name', 'legal_name', 'description')
    @classmethod
    def sanitize_text_fields(cls, v):
        """Sanitize organization text fields."""
        if v is None:
            return v
        return sanitize_input(v, allow_html=False)
    
    @field_validator('tax_id', 'registration_number')
    @classmethod
    def sanitize_business_ids(cls, v):
        """Sanitize business identification numbers."""
        if v is None:
            return v
        # Remove special characters but keep alphanumeric and basic punctuation
        cleaned = re.sub(r'[^\w\-.]', '', v.strip())
        return cleaned
    
    def validate_business_rules(self) -> None:
        """Validate organization business rules."""
        super().validate_business_rules()
        
        # Verified organizations must have verification date
        if self.is_verified and not self.verification_date:
            raise BusinessRuleViolationError(
                message="Verified organizations must have verification date",
                error_code="MISSING_VERIFICATION_DATE",
                severity=ErrorSeverity.HIGH
            )
        
        # Legal name should be provided for verified businesses
        if self.is_verified and not self.legal_name:
            raise BusinessRuleViolationError(
                message="Verified organizations should have legal name",
                error_code="MISSING_LEGAL_NAME",
                severity=ErrorSeverity.MEDIUM
            )


# ============================================================================
# PRODUCT AND CATALOG MODELS
# ============================================================================

class ProductCategory(BaseBusinessModel):
    """
    Product category model for catalog organization.
    
    Provides hierarchical product categorization with metadata and
    display information for e-commerce and catalog management operations.
    """
    
    id: Optional[str] = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique category identifier"
    )
    name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Category name"
    )
    slug: str = Field(
        ...,
        min_length=1,
        max_length=100,
        pattern=r'^[a-z0-9\-]+$',
        description="URL-friendly category identifier"
    )
    description: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Category description"
    )
    
    # Hierarchy
    parent_category_id: Optional[str] = Field(
        default=None,
        description="Parent category identifier for hierarchy"
    )
    sort_order: int = Field(
        default=0,
        description="Sort order within parent category"
    )
    
    # Display settings
    image_url: Optional[HttpUrl] = Field(
        default=None,
        description="Category image URL"
    )
    is_visible: bool = Field(
        default=True,
        description="Category visibility in catalog"
    )
    
    @field_validator('name', 'description')
    @classmethod
    def sanitize_text_fields(cls, v):
        """Sanitize category text fields."""
        if v is None:
            return v
        return sanitize_input(v, allow_html=False)
    
    @field_validator('slug')
    @classmethod
    def validate_slug_format(cls, v):
        """Validate URL slug format."""
        if v:
            v = v.strip().lower()
            if not re.match(r'^[a-z0-9\-]+$', v):
                raise BusinessRuleViolationError(
                    message="Slug must contain only lowercase letters, numbers, and hyphens",
                    error_code="INVALID_SLUG_FORMAT",
                    context={'slug': v}
                )
        return v


class Product(BaseBusinessModel):
    """
    Product model for catalog and inventory management.
    
    Provides comprehensive product information validation including pricing,
    inventory, categorization, and metadata for e-commerce and business
    catalog operations.
    """
    
    id: Optional[str] = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique product identifier"
    )
    sku: str = Field(
        ...,
        min_length=1,
        max_length=50,
        description="Stock keeping unit identifier"
    )
    name: str = Field(
        ...,
        min_length=1,
        max_length=200,
        description="Product name"
    )
    slug: str = Field(
        ...,
        min_length=1,
        max_length=200,
        pattern=r'^[a-z0-9\-]+$',
        description="URL-friendly product identifier"
    )
    description: Optional[str] = Field(
        default=None,
        max_length=2000,
        description="Product description"
    )
    short_description: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Brief product summary"
    )
    
    # Categorization
    category_id: Optional[str] = Field(
        default=None,
        description="Primary product category identifier"
    )
    tags: Set[str] = Field(
        default_factory=set,
        description="Product tags for search and filtering"
    )
    brand: Optional[str] = Field(
        default=None,
        max_length=100,
        description="Product brand or manufacturer"
    )
    
    # Pricing
    base_price: MonetaryAmount = Field(
        ...,
        description="Base product price"
    )
    sale_price: Optional[MonetaryAmount] = Field(
        default=None,
        description="Sale or discounted price"
    )
    cost_price: Optional[MonetaryAmount] = Field(
        default=None,
        description="Product cost for margin calculation"
    )
    
    # Inventory
    status: ProductStatus = Field(
        default=ProductStatus.ACTIVE,
        description="Product status"
    )
    inventory_quantity: int = Field(
        default=0,
        ge=0,
        description="Available inventory quantity"
    )
    low_stock_threshold: int = Field(
        default=5,
        ge=0,
        description="Low stock alert threshold"
    )
    track_inventory: bool = Field(
        default=True,
        description="Whether to track inventory for this product"
    )
    
    # Physical attributes
    weight: Optional[Decimal] = Field(
        default=None,
        ge=0,
        description="Product weight in kilograms"
    )
    dimensions: Optional[Dict[str, Decimal]] = Field(
        default=None,
        description="Product dimensions (length, width, height) in centimeters"
    )
    
    # Digital content
    images: List[HttpUrl] = Field(
        default_factory=list,
        description="Product image URLs"
    )
    documents: List[Dict[str, str]] = Field(
        default_factory=list,
        description="Product documents and files"
    )
    
    # SEO and metadata
    meta_title: Optional[str] = Field(
        default=None,
        max_length=60,
        description="SEO meta title"
    )
    meta_description: Optional[str] = Field(
        default=None,
        max_length=160,
        description="SEO meta description"
    )
    
    @field_validator('sku')
    @classmethod
    def validate_sku_format(cls, v):
        """Validate SKU format."""
        if v:
            v = v.strip().upper()
            # Remove special characters except hyphens and underscores
            v = re.sub(r'[^\w\-]', '', v)
        return v
    
    @field_validator('name', 'description', 'short_description', 'brand')
    @classmethod
    def sanitize_text_fields(cls, v):
        """Sanitize product text fields."""
        if v is None:
            return v
        return sanitize_input(v, allow_html=False)
    
    @field_validator('tags')
    @classmethod
    def validate_tags(cls, v):
        """Validate and clean product tags."""
        if v:
            cleaned_tags = set()
            for tag in v:
                if isinstance(tag, str) and tag.strip():
                    # Clean tag and add to set
                    clean_tag = sanitize_input(tag.strip().lower(), allow_html=False, max_length=50)
                    if clean_tag:
                        cleaned_tags.add(clean_tag)
            return cleaned_tags
        return set()
    
    @field_validator('dimensions')
    @classmethod
    def validate_dimensions(cls, v):
        """Validate product dimensions."""
        if v:
            required_keys = {'length', 'width', 'height'}
            if not all(key in v for key in required_keys):
                raise BusinessRuleViolationError(
                    message="Dimensions must include length, width, and height",
                    error_code="INCOMPLETE_DIMENSIONS",
                    context={'provided_keys': list(v.keys())}
                )
            
            # Validate all dimensions are positive
            for key, value in v.items():
                if value <= 0:
                    raise BusinessRuleViolationError(
                        message=f"Dimension {key} must be positive",
                        error_code="INVALID_DIMENSION_VALUE",
                        context={key: str(value)}
                    )
        return v
    
    @computed_field
    @property
    def is_on_sale(self) -> bool:
        """Check if product is currently on sale."""
        return (self.sale_price is not None and 
                self.sale_price.amount < self.base_price.amount)
    
    @computed_field
    @property
    def current_price(self) -> MonetaryAmount:
        """Get current effective price (sale price if available, otherwise base price)."""
        return self.sale_price if self.is_on_sale else self.base_price
    
    @computed_field
    @property
    def is_low_stock(self) -> bool:
        """Check if product inventory is below low stock threshold."""
        return (self.track_inventory and 
                self.inventory_quantity <= self.low_stock_threshold)
    
    def validate_business_rules(self) -> None:
        """Validate product business rules."""
        super().validate_business_rules()
        
        # Sale price must be less than base price
        if self.sale_price and self.sale_price.amount >= self.base_price.amount:
            raise BusinessRuleViolationError(
                message="Sale price must be less than base price",
                error_code="INVALID_SALE_PRICE",
                context={
                    'base_price': str(self.base_price.amount),
                    'sale_price': str(self.sale_price.amount)
                }
            )
        
        # Currency consistency for prices
        if self.sale_price and self.sale_price.currency_code != self.base_price.currency_code:
            raise BusinessRuleViolationError(
                message="All prices must use the same currency",
                error_code="CURRENCY_MISMATCH",
                context={
                    'base_currency': self.base_price.currency_code,
                    'sale_currency': self.sale_price.currency_code
                }
            )
        
        # Active products should have positive inventory if tracking
        if (self.status == ProductStatus.ACTIVE and 
            self.track_inventory and 
            self.inventory_quantity <= 0):
            
            raise BusinessRuleViolationError(
                message="Active products with inventory tracking must have positive quantity",
                error_code="ZERO_INVENTORY_ACTIVE_PRODUCT",
                context={'inventory_quantity': self.inventory_quantity},
                severity=ErrorSeverity.MEDIUM
            )


# ============================================================================
# ORDER AND TRANSACTION MODELS
# ============================================================================

class OrderItem(BaseBusinessModel):
    """
    Order item model for individual line items in orders.
    
    Provides validation for order line items including product references,
    quantities, pricing, and calculations for order processing operations.
    """
    
    product_id: str = Field(
        ...,
        description="Product identifier for this line item"
    )
    product_sku: str = Field(
        ...,
        description="Product SKU at time of order"
    )
    product_name: str = Field(
        ...,
        min_length=1,
        max_length=200,
        description="Product name at time of order"
    )
    quantity: int = Field(
        ...,
        ge=1,
        description="Quantity ordered"
    )
    unit_price: MonetaryAmount = Field(
        ...,
        description="Price per unit at time of order"
    )
    total_price: Optional[MonetaryAmount] = Field(
        default=None,
        description="Total price for this line item"
    )
    
    # Discounts and adjustments
    discount_amount: Optional[MonetaryAmount] = Field(
        default=None,
        description="Discount applied to this line item"
    )
    tax_amount: Optional[MonetaryAmount] = Field(
        default=None,
        description="Tax amount for this line item"
    )
    
    # Product snapshot at order time
    product_attributes: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Product attributes snapshot at order time"
    )
    
    @model_validator(mode='after')
    def calculate_totals(self) -> 'OrderItem':
        """Calculate total price if not provided."""
        if self.total_price is None:
            # Calculate base total
            total_amount = self.unit_price.amount * self.quantity
            
            # Apply discount if present
            if self.discount_amount:
                total_amount -= self.discount_amount.amount
            
            # Add tax if present
            if self.tax_amount:
                total_amount += self.tax_amount.amount
            
            self.total_price = MonetaryAmount(
                amount=total_amount,
                currency_code=self.unit_price.currency_code
            )
        
        return self
    
    def validate_business_rules(self) -> None:
        """Validate order item business rules."""
        super().validate_business_rules()
        
        # Currency consistency
        currencies = {self.unit_price.currency_code}
        if self.total_price:
            currencies.add(self.total_price.currency_code)
        if self.discount_amount:
            currencies.add(self.discount_amount.currency_code)
        if self.tax_amount:
            currencies.add(self.tax_amount.currency_code)
        
        if len(currencies) > 1:
            raise BusinessRuleViolationError(
                message="All monetary amounts must use the same currency",
                error_code="CURRENCY_MISMATCH_ORDER_ITEM",
                context={'currencies': list(currencies)}
            )


class Order(BaseBusinessModel):
    """
    Order model for transaction and order management.
    
    Provides comprehensive order validation including customer information,
    line items, pricing, shipping, and status tracking for e-commerce and
    business transaction processing operations.
    """
    
    id: Optional[str] = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique order identifier"
    )
    order_number: Optional[str] = Field(
        default=None,
        description="Human-readable order number"
    )
    
    # Customer information
    customer_id: Optional[str] = Field(
        default=None,
        description="Customer identifier (if registered user)"
    )
    customer_email: EmailStr = Field(
        ...,
        description="Customer email address"
    )
    customer_name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Customer full name"
    )
    
    # Order items
    items: List[OrderItem] = Field(
        ...,
        min_length=1,
        description="Order line items"
    )
    
    # Pricing
    subtotal: MonetaryAmount = Field(
        ...,
        description="Order subtotal before taxes and fees"
    )
    tax_amount: MonetaryAmount = Field(
        default=MonetaryAmount(amount=Decimal('0'), currency_code='USD'),
        description="Total tax amount"
    )
    shipping_amount: MonetaryAmount = Field(
        default=MonetaryAmount(amount=Decimal('0'), currency_code='USD'),
        description="Shipping cost"
    )
    discount_amount: MonetaryAmount = Field(
        default=MonetaryAmount(amount=Decimal('0'), currency_code='USD'),
        description="Total discount amount"
    )
    total_amount: MonetaryAmount = Field(
        ...,
        description="Total order amount"
    )
    
    # Addresses
    billing_address: Address = Field(
        ...,
        description="Billing address"
    )
    shipping_address: Optional[Address] = Field(
        default=None,
        description="Shipping address (uses billing if not provided)"
    )
    
    # Status and tracking
    status: OrderStatus = Field(
        default=OrderStatus.PENDING,
        description="Order processing status"
    )
    order_date: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Order placement date"
    )
    shipped_date: Optional[datetime] = Field(
        default=None,
        description="Order shipment date"
    )
    delivered_date: Optional[datetime] = Field(
        default=None,
        description="Order delivery date"
    )
    
    # Additional information
    notes: Optional[str] = Field(
        default=None,
        max_length=1000,
        description="Order notes or special instructions"
    )
    tracking_number: Optional[str] = Field(
        default=None,
        description="Shipping tracking number"
    )
    payment_method: Optional[PaymentMethod] = Field(
        default=None,
        description="Payment method used for this order"
    )
    
    @field_validator('customer_name', 'notes')
    @classmethod
    def sanitize_text_fields(cls, v):
        """Sanitize order text fields."""
        if v is None:
            return v
        return sanitize_input(v, allow_html=False)
    
    @field_validator('order_number')
    @classmethod
    def generate_order_number(cls, v):
        """Generate order number if not provided."""
        if v is None:
            # Generate order number with timestamp and random component
            import time
            timestamp = str(int(time.time()))[-6:]  # Last 6 digits of timestamp
            random_part = str(uuid.uuid4()).replace('-', '')[:6].upper()
            v = f"ORD-{timestamp}-{random_part}"
        return v
    
    @model_validator(mode='after')
    def validate_order_totals(self) -> 'Order':
        """Validate order total calculations."""
        # Calculate expected total
        expected_total = (
            self.subtotal.amount + 
            self.tax_amount.amount + 
            self.shipping_amount.amount - 
            self.discount_amount.amount
        )
        
        # Allow small rounding differences
        if abs(expected_total - self.total_amount.amount) > Decimal('0.01'):
            raise BusinessRuleViolationError(
                message="Order total does not match calculated amount",
                error_code="INVALID_ORDER_TOTAL",
                context={
                    'calculated_total': str(expected_total),
                    'provided_total': str(self.total_amount.amount)
                }
            )
        
        return self
    
    @computed_field
    @property
    def effective_shipping_address(self) -> Address:
        """Get shipping address, defaulting to billing address."""
        return self.shipping_address or self.billing_address
    
    @computed_field
    @property
    def item_count(self) -> int:
        """Get total number of items in order."""
        return sum(item.quantity for item in self.items)
    
    def validate_business_rules(self) -> None:
        """Validate order business rules."""
        super().validate_business_rules()
        
        # Currency consistency across all amounts
        currencies = {
            self.subtotal.currency_code,
            self.tax_amount.currency_code,
            self.shipping_amount.currency_code,
            self.discount_amount.currency_code,
            self.total_amount.currency_code
        }
        
        if len(currencies) > 1:
            raise BusinessRuleViolationError(
                message="All order amounts must use the same currency",
                error_code="CURRENCY_MISMATCH_ORDER",
                context={'currencies': list(currencies)}
            )
        
        # Status progression validation
        if self.shipped_date and self.status not in [OrderStatus.SHIPPED, OrderStatus.DELIVERED]:
            raise BusinessRuleViolationError(
                message="Orders with shipping date must be in shipped or delivered status",
                error_code="INVALID_STATUS_FOR_SHIPPED_DATE",
                context={'status': self.status.value}
            )
        
        if self.delivered_date and self.status != OrderStatus.DELIVERED:
            raise BusinessRuleViolationError(
                message="Orders with delivery date must be in delivered status",
                error_code="INVALID_STATUS_FOR_DELIVERED_DATE",
                context={'status': self.status.value}
            )
        
        # Date progression validation
        if self.shipped_date and self.shipped_date < self.order_date:
            raise BusinessRuleViolationError(
                message="Shipping date cannot be before order date",
                error_code="INVALID_SHIPPING_DATE",
                context={
                    'order_date': self.order_date.isoformat(),
                    'shipped_date': self.shipped_date.isoformat()
                }
            )
        
        if (self.delivered_date and self.shipped_date and 
            self.delivered_date < self.shipped_date):
            raise BusinessRuleViolationError(
                message="Delivery date cannot be before shipping date",
                error_code="INVALID_DELIVERY_DATE",
                context={
                    'shipped_date': self.shipped_date.isoformat(),
                    'delivered_date': self.delivered_date.isoformat()
                }
            )


# ============================================================================
# PAYMENT AND FINANCIAL MODELS
# ============================================================================

class PaymentTransaction(BaseBusinessModel):
    """
    Payment transaction model for financial processing.
    
    Provides comprehensive payment transaction validation including payment
    methods, amounts, status tracking, and security for financial operations
    and payment processing workflows.
    """
    
    id: Optional[str] = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique transaction identifier"
    )
    transaction_id: Optional[str] = Field(
        default=None,
        description="External payment processor transaction ID"
    )
    
    # Related entities
    order_id: Optional[str] = Field(
        default=None,
        description="Related order identifier"
    )
    customer_id: Optional[str] = Field(
        default=None,
        description="Customer identifier"
    )
    
    # Payment details
    amount: MonetaryAmount = Field(
        ...,
        description="Transaction amount"
    )
    payment_method: PaymentMethod = Field(
        ...,
        description="Payment method used"
    )
    payment_status: PaymentStatus = Field(
        default=PaymentStatus.PENDING,
        description="Payment processing status"
    )
    
    # Payment processor information
    processor_name: Optional[str] = Field(
        default=None,
        max_length=50,
        description="Payment processor name"
    )
    processor_response: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Payment processor response data"
    )
    
    # Security and fraud detection
    risk_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Fraud risk score (0.0 = low risk, 1.0 = high risk)"
    )
    ip_address: Optional[str] = Field(
        default=None,
        description="Customer IP address for fraud detection"
    )
    user_agent: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Customer user agent for fraud detection"
    )
    
    # Timestamps
    initiated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Transaction initiation timestamp"
    )
    processed_at: Optional[datetime] = Field(
        default=None,
        description="Transaction processing completion timestamp"
    )
    expires_at: Optional[datetime] = Field(
        default=None,
        description="Transaction expiration timestamp"
    )
    
    # Additional information
    description: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Transaction description"
    )
    reference_number: Optional[str] = Field(
        default=None,
        max_length=100,
        description="Customer reference number"
    )
    failure_reason: Optional[str] = Field(
        default=None,
        max_length=200,
        description="Failure reason if transaction failed"
    )
    
    @field_validator('description', 'reference_number', 'failure_reason')
    @classmethod
    def sanitize_text_fields(cls, v):
        """Sanitize payment transaction text fields."""
        if v is None:
            return v
        return sanitize_input(v, allow_html=False)
    
    @field_validator('ip_address')
    @classmethod
    def validate_ip_address(cls, v):
        """Basic IP address validation."""
        if v is None:
            return v
        
        # Basic IPv4 pattern validation
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(ipv4_pattern, v):
            # Also allow IPv6 format (simplified check)
            if ':' not in v:
                raise BusinessRuleViolationError(
                    message="Invalid IP address format",
                    error_code="INVALID_IP_ADDRESS",
                    context={'ip_address': v}
                )
        
        return v
    
    @computed_field
    @property
    def is_successful(self) -> bool:
        """Check if transaction was successful."""
        return self.payment_status == PaymentStatus.COMPLETED
    
    @computed_field
    @property
    def is_expired(self) -> bool:
        """Check if transaction has expired."""
        if not self.expires_at:
            return False
        return datetime.now(timezone.utc) > self.expires_at
    
    def validate_business_rules(self) -> None:
        """Validate payment transaction business rules."""
        super().validate_business_rules()
        
        # Completed transactions must have processed timestamp
        if (self.payment_status == PaymentStatus.COMPLETED and 
            not self.processed_at):
            raise BusinessRuleViolationError(
                message="Completed transactions must have processing timestamp",
                error_code="MISSING_PROCESSED_TIMESTAMP",
                severity=ErrorSeverity.HIGH
            )
        
        # Failed transactions should have failure reason
        if (self.payment_status == PaymentStatus.FAILED and 
            not self.failure_reason):
            raise BusinessRuleViolationError(
                message="Failed transactions should have failure reason",
                error_code="MISSING_FAILURE_REASON",
                severity=ErrorSeverity.MEDIUM
            )
        
        # Processed timestamp should be after initiated timestamp
        if (self.processed_at and 
            self.processed_at < self.initiated_at):
            raise BusinessRuleViolationError(
                message="Processing timestamp cannot be before initiation",
                error_code="INVALID_PROCESSING_TIMESTAMP",
                context={
                    'initiated_at': self.initiated_at.isoformat(),
                    'processed_at': self.processed_at.isoformat()
                }
            )


# ============================================================================
# API REQUEST AND RESPONSE MODELS
# ============================================================================

class PaginationParams(BaseBusinessModel):
    """
    Pagination parameters model for API requests.
    
    Provides standardized pagination parameter validation for API endpoints
    supporting paginated data retrieval with configurable page sizes and
    navigation controls.
    """
    
    page: int = Field(
        default=1,
        ge=1,
        description="Page number (1-based)"
    )
    page_size: int = Field(
        default=20,
        ge=1,
        le=100,
        description="Number of items per page"
    )
    
    @computed_field
    @property
    def offset(self) -> int:
        """Calculate database offset from page and page_size."""
        return (self.page - 1) * self.page_size
    
    @computed_field
    @property
    def limit(self) -> int:
        """Get limit value for database queries."""
        return self.page_size


class SortParams(BaseBusinessModel):
    """
    Sorting parameters model for API requests.
    
    Provides standardized sorting parameter validation for API endpoints
    supporting data ordering with configurable sort fields and directions.
    """
    
    sort_by: str = Field(
        default="created_at",
        min_length=1,
        max_length=50,
        description="Field to sort by"
    )
    sort_order: str = Field(
        default="desc",
        pattern=r'^(asc|desc)$',
        description="Sort order (asc or desc)"
    )
    
    @field_validator('sort_by')
    @classmethod
    def validate_sort_field(cls, v):
        """Validate sort field name."""
        if v:
            # Remove any potentially dangerous characters
            v = re.sub(r'[^\w.]', '', v.strip())
            if not v:
                raise BusinessRuleViolationError(
                    message="Invalid sort field name",
                    error_code="INVALID_SORT_FIELD",
                    context={'sort_by': v}
                )
        return v


class SearchParams(BaseBusinessModel):
    """
    Search parameters model for API requests.
    
    Provides standardized search parameter validation for API endpoints
    supporting text search, filtering, and query operations with security
    validation and performance optimization.
    """
    
    query: Optional[str] = Field(
        default=None,
        max_length=200,
        description="Search query string"
    )
    filters: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Additional search filters"
    )
    include_inactive: bool = Field(
        default=False,
        description="Include inactive records in search results"
    )
    
    @field_validator('query')
    @classmethod
    def sanitize_search_query(cls, v):
        """Sanitize search query for security."""
        if v is None:
            return v
        
        # Sanitize input and limit length
        sanitized = sanitize_input(v, allow_html=False, max_length=200)
        
        # Remove potentially dangerous query patterns
        sanitized = re.sub(r'[<>{}()[\]\\]', '', sanitized)
        
        return sanitized.strip() if sanitized else None
    
    @field_validator('filters')
    @classmethod
    def validate_filters(cls, v):
        """Validate search filters structure."""
        if v is None:
            return v
        
        if not isinstance(v, dict):
            raise BusinessRuleViolationError(
                message="Filters must be a dictionary",
                error_code="INVALID_FILTERS_TYPE",
                context={'filters_type': type(v).__name__}
            )
        
        # Limit number of filters to prevent DoS
        if len(v) > 20:
            raise BusinessRuleViolationError(
                message="Too many filter parameters",
                error_code="TOO_MANY_FILTERS",
                context={'filter_count': len(v)}
            )
        
        # Validate filter keys
        validated_filters = {}
        for key, value in v.items():
            if isinstance(key, str) and key.strip():
                # Clean filter key
                clean_key = re.sub(r'[^\w.]', '', key.strip())
                if clean_key:
                    validated_filters[clean_key] = value
        
        return validated_filters


class ApiResponse(BaseBusinessModel):
    """
    Standard API response model for consistent response formatting.
    
    Provides standardized API response structure with success indicators,
    data payload, error information, and metadata for maintaining consistent
    response patterns across all API endpoints per F-004-RQ-004 requirements.
    """
    
    success: bool = Field(
        ...,
        description="Indicates if the request was successful"
    )
    data: Optional[Any] = Field(
        default=None,
        description="Response data payload"
    )
    message: Optional[str] = Field(
        default=None,
        description="Human-readable response message"
    )
    errors: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="List of error details if request failed"
    )
    metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Additional response metadata"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Response generation timestamp"
    )
    request_id: Optional[str] = Field(
        default=None,
        description="Request correlation identifier"
    )
    
    @classmethod
    def success_response(
        cls,
        data: Any = None,
        message: str = None,
        metadata: Dict[str, Any] = None,
        request_id: str = None
    ) -> 'ApiResponse':
        """
        Create successful API response.
        
        Args:
            data: Response data payload
            message: Optional success message
            metadata: Optional response metadata
            request_id: Optional request correlation ID
            
        Returns:
            Successful API response instance
        """
        return cls(
            success=True,
            data=data,
            message=message,
            metadata=metadata,
            request_id=request_id
        )
    
    @classmethod
    def error_response(
        cls,
        message: str,
        errors: List[Dict[str, Any]] = None,
        metadata: Dict[str, Any] = None,
        request_id: str = None
    ) -> 'ApiResponse':
        """
        Create error API response.
        
        Args:
            message: Error message
            errors: List of detailed error information
            metadata: Optional response metadata
            request_id: Optional request correlation ID
            
        Returns:
            Error API response instance
        """
        return cls(
            success=False,
            message=message,
            errors=errors or [],
            metadata=metadata,
            request_id=request_id
        )


class PaginatedResponse(ApiResponse):
    """
    Paginated API response model extending standard response.
    
    Provides standardized pagination metadata for API responses containing
    paginated data collections with navigation information and total counts.
    """
    
    pagination: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Pagination metadata"
    )
    
    @classmethod
    def paginated_success(
        cls,
        data: List[Any],
        pagination_params: PaginationParams,
        total_count: int,
        message: str = None,
        request_id: str = None
    ) -> 'PaginatedResponse':
        """
        Create paginated success response.
        
        Args:
            data: List of response data items
            pagination_params: Original pagination parameters
            total_count: Total number of items available
            message: Optional success message
            request_id: Optional request correlation ID
            
        Returns:
            Paginated API response instance
        """
        total_pages = (total_count + pagination_params.page_size - 1) // pagination_params.page_size
        
        pagination_metadata = {
            'page': pagination_params.page,
            'page_size': pagination_params.page_size,
            'total_count': total_count,
            'total_pages': total_pages,
            'has_next': pagination_params.page < total_pages,
            'has_previous': pagination_params.page > 1,
            'next_page': pagination_params.page + 1 if pagination_params.page < total_pages else None,
            'previous_page': pagination_params.page - 1 if pagination_params.page > 1 else None
        }
        
        return cls(
            success=True,
            data=data,
            message=message,
            pagination=pagination_metadata,
            metadata={'item_count': len(data)},
            request_id=request_id
        )


# ============================================================================
# FILE AND MEDIA MODELS
# ============================================================================

class FileUpload(BaseBusinessModel):
    """
    File upload model for file management operations.
    
    Provides comprehensive file upload validation including file metadata,
    size restrictions, type validation, and security controls for business
    file processing and storage operations.
    """
    
    id: Optional[str] = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique file identifier"
    )
    filename: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Original filename"
    )
    content_type: str = Field(
        ...,
        description="MIME content type"
    )
    file_size: int = Field(
        ...,
        ge=0,
        le=100_000_000,  # 100MB limit
        description="File size in bytes"
    )
    
    # Storage information
    storage_path: Optional[str] = Field(
        default=None,
        description="File storage path or key"
    )
    storage_url: Optional[HttpUrl] = Field(
        default=None,
        description="Public URL for file access"
    )
    
    # Security and validation
    checksum: Optional[str] = Field(
        default=None,
        description="File checksum for integrity verification"
    )
    is_virus_scanned: bool = Field(
        default=False,
        description="Virus scan completion status"
    )
    scan_result: Optional[str] = Field(
        default=None,
        description="Virus scan result"
    )
    
    # Metadata
    uploaded_by: Optional[str] = Field(
        default=None,
        description="User identifier who uploaded the file"
    )
    upload_date: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="File upload timestamp"
    )
    expires_at: Optional[datetime] = Field(
        default=None,
        description="File expiration timestamp"
    )
    
    # File categorization
    category: Optional[str] = Field(
        default=None,
        max_length=50,
        description="File category or purpose"
    )
    tags: Set[str] = Field(
        default_factory=set,
        description="File tags for organization"
    )
    
    @field_validator('filename')
    @classmethod
    def validate_filename(cls, v):
        """Validate filename security and format."""
        if v:
            # Sanitize filename
            v = sanitize_input(v, allow_html=False, max_length=255)
            
            # Remove potentially dangerous characters
            v = re.sub(r'[<>:"/\\|?*]', '', v)
            
            # Ensure filename has extension
            if '.' not in v:
                raise BusinessRuleViolationError(
                    message="Filename must include file extension",
                    error_code="MISSING_FILE_EXTENSION",
                    context={'filename': v}
                )
            
            # Check for double extensions (security risk)
            parts = v.split('.')
            if len(parts) > 2:
                # Only allow specific cases like .tar.gz
                allowed_double_extensions = {'.tar.gz', '.tar.bz2'}
                if not any(v.endswith(ext) for ext in allowed_double_extensions):
                    raise BusinessRuleViolationError(
                        message="Multiple file extensions not allowed",
                        error_code="MULTIPLE_EXTENSIONS",
                        context={'filename': v}
                    )
        
        return v
    
    @field_validator('content_type')
    @classmethod
    def validate_content_type(cls, v):
        """Validate content type format."""
        if v:
            # Basic MIME type validation
            if '/' not in v:
                raise BusinessRuleViolationError(
                    message="Invalid content type format",
                    error_code="INVALID_CONTENT_TYPE",
                    context={'content_type': v}
                )
            
            # Check against allowed content types
            allowed_types = {
                'image/jpeg', 'image/png', 'image/gif', 'image/webp',
                'application/pdf', 'application/msword',
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'application/vnd.ms-excel',
                'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                'text/plain', 'text/csv',
                'application/json', 'application/xml'
            }
            
            if v not in allowed_types:
                raise BusinessRuleViolationError(
                    message="Content type not allowed",
                    error_code="CONTENT_TYPE_NOT_ALLOWED",
                    context={'content_type': v, 'allowed_types': list(allowed_types)}
                )
        
        return v
    
    @field_validator('tags')
    @classmethod
    def validate_tags(cls, v):
        """Validate file tags."""
        if v:
            cleaned_tags = set()
            for tag in v:
                if isinstance(tag, str) and tag.strip():
                    clean_tag = sanitize_input(tag.strip().lower(), max_length=30)
                    if clean_tag:
                        cleaned_tags.add(clean_tag)
            return cleaned_tags
        return set()
    
    @computed_field
    @property
    def file_extension(self) -> str:
        """Get file extension from filename."""
        if '.' in self.filename:
            return self.filename.split('.')[-1].lower()
        return ''
    
    @computed_field
    @property
    def is_image(self) -> bool:
        """Check if file is an image based on content type."""
        return self.content_type.startswith('image/')
    
    @computed_field
    @property
    def is_expired(self) -> bool:
        """Check if file has expired."""
        if not self.expires_at:
            return False
        return datetime.now(timezone.utc) > self.expires_at
    
    def validate_business_rules(self) -> None:
        """Validate file upload business rules."""
        super().validate_business_rules()
        
        # File extension should match content type
        extension_content_map = {
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'png': 'image/png',
            'gif': 'image/gif',
            'pdf': 'application/pdf',
            'doc': 'application/msword',
            'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'xls': 'application/vnd.ms-excel',
            'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'txt': 'text/plain',
            'csv': 'text/csv'
        }
        
        expected_content_type = extension_content_map.get(self.file_extension)
        if expected_content_type and expected_content_type != self.content_type:
            raise BusinessRuleViolationError(
                message="File extension does not match content type",
                error_code="EXTENSION_CONTENT_MISMATCH",
                context={
                    'extension': self.file_extension,
                    'content_type': self.content_type,
                    'expected_content_type': expected_content_type
                },
                severity=ErrorSeverity.HIGH
            )


# ============================================================================
# CONFIGURATION AND SYSTEM MODELS
# ============================================================================

class SystemConfiguration(BaseBusinessModel):
    """
    System configuration model for application settings.
    
    Provides validation for system-wide configuration settings including
    feature flags, performance parameters, security settings, and operational
    controls for business application management.
    """
    
    id: Optional[str] = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Configuration identifier"
    )
    key: str = Field(
        ...,
        min_length=1,
        max_length=100,
        pattern=r'^[a-z0-9._-]+$',
        description="Configuration key identifier"
    )
    value: Union[str, int, float, bool, Dict[str, Any]] = Field(
        ...,
        description="Configuration value"
    )
    value_type: str = Field(
        ...,
        pattern=r'^(string|integer|float|boolean|json)$',
        description="Value data type"
    )
    
    # Metadata
    description: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Configuration description"
    )
    category: Optional[str] = Field(
        default=None,
        max_length=50,
        description="Configuration category"
    )
    is_sensitive: bool = Field(
        default=False,
        description="Whether configuration contains sensitive data"
    )
    is_readonly: bool = Field(
        default=False,
        description="Whether configuration is read-only"
    )
    
    # Validation constraints
    min_value: Optional[Union[int, float]] = Field(
        default=None,
        description="Minimum allowed value for numeric types"
    )
    max_value: Optional[Union[int, float]] = Field(
        default=None,
        description="Maximum allowed value for numeric types"
    )
    allowed_values: Optional[List[str]] = Field(
        default=None,
        description="List of allowed values for string types"
    )
    
    # Environment and deployment
    environment: Optional[str] = Field(
        default=None,
        max_length=20,
        description="Target environment (dev, staging, prod)"
    )
    requires_restart: bool = Field(
        default=False,
        description="Whether changing this configuration requires application restart"
    )
    
    @field_validator('key')
    @classmethod
    def validate_config_key(cls, v):
        """Validate configuration key format."""
        if v:
            v = v.strip().lower()
            
            # Check for reserved keys
            reserved_keys = {'password', 'secret', 'key', 'token', 'api_key'}
            if any(reserved in v for reserved in reserved_keys):
                # Mark as sensitive if contains reserved words
                pass  # Will be handled in model validation
        
        return v
    
    @model_validator(mode='after')
    def validate_value_type_consistency(self) -> 'SystemConfiguration':
        """Validate that value matches declared type."""
        value = self.value
        value_type = self.value_type
        
        type_validators = {
            'string': lambda v: isinstance(v, str),
            'integer': lambda v: isinstance(v, int),
            'float': lambda v: isinstance(v, (int, float)),
            'boolean': lambda v: isinstance(v, bool),
            'json': lambda v: isinstance(v, dict)
        }
        
        validator = type_validators.get(value_type)
        if validator and not validator(value):
            raise BusinessRuleViolationError(
                message=f"Value type mismatch: expected {value_type}",
                error_code="VALUE_TYPE_MISMATCH",
                context={
                    'expected_type': value_type,
                    'actual_type': type(value).__name__,
                    'key': self.key
                }
            )
        
        return self
    
    @field_validator('description')
    @classmethod
    def sanitize_description(cls, v):
        """Sanitize configuration description."""
        if v is None:
            return v
        return sanitize_input(v, allow_html=False, max_length=500)
    
    def validate_business_rules(self) -> None:
        """Validate configuration business rules."""
        super().validate_business_rules()
        
        # Validate numeric ranges
        if self.value_type in ['integer', 'float'] and isinstance(self.value, (int, float)):
            if self.min_value is not None and self.value < self.min_value:
                raise BusinessRuleViolationError(
                    message=f"Value {self.value} is below minimum {self.min_value}",
                    error_code="VALUE_BELOW_MINIMUM",
                    context={'key': self.key, 'value': self.value, 'min': self.min_value}
                )
            
            if self.max_value is not None and self.value > self.max_value:
                raise BusinessRuleViolationError(
                    message=f"Value {self.value} exceeds maximum {self.max_value}",
                    error_code="VALUE_EXCEEDS_MAXIMUM",
                    context={'key': self.key, 'value': self.value, 'max': self.max_value}
                )
        
        # Validate allowed values for strings
        if (self.value_type == 'string' and 
            self.allowed_values and 
            isinstance(self.value, str) and 
            self.value not in self.allowed_values):
            
            raise BusinessRuleViolationError(
                message=f"Value '{self.value}' not in allowed values",
                error_code="VALUE_NOT_ALLOWED",
                context={
                    'key': self.key,
                    'value': self.value,
                    'allowed': self.allowed_values
                }
            )
        
        # Auto-detect sensitive configurations
        sensitive_patterns = ['password', 'secret', 'key', 'token', 'credential']
        if any(pattern in self.key.lower() for pattern in sensitive_patterns):
            object.__setattr__(self, 'is_sensitive', True)


# ============================================================================
# MODEL REGISTRY AND UTILITIES
# ============================================================================

# Registry of all business models for dynamic access and validation
BUSINESS_MODEL_REGISTRY = {
    # Core business models
    'User': User,
    'Organization': Organization,
    'Product': Product,
    'ProductCategory': ProductCategory,
    'Order': Order,
    'OrderItem': OrderItem,
    'PaymentTransaction': PaymentTransaction,
    
    # Utility models
    'Address': Address,
    'ContactInfo': ContactInfo,
    'MonetaryAmount': MonetaryAmount,
    'DateTimeRange': DateTimeRange,
    'FileUpload': FileUpload,
    'SystemConfiguration': SystemConfiguration,
    
    # API models
    'PaginationParams': PaginationParams,
    'SortParams': SortParams,
    'SearchParams': SearchParams,
    'ApiResponse': ApiResponse,
    'PaginatedResponse': PaginatedResponse,
}


def get_model_by_name(model_name: str) -> Optional[type]:
    """
    Get business model class by name from registry.
    
    Args:
        model_name: Name of the model class to retrieve
        
    Returns:
        Model class if found, None otherwise
    """
    return BUSINESS_MODEL_REGISTRY.get(model_name)


def validate_model_data(model_name: str, data: Dict[str, Any]) -> BaseBusinessModel:
    """
    Validate data against specified business model.
    
    Args:
        model_name: Name of the model to validate against
        data: Data dictionary to validate
        
    Returns:
        Validated model instance
        
    Raises:
        DataValidationError: If model not found or validation fails
    """
    model_class = get_model_by_name(model_name)
    if not model_class:
        raise DataValidationError(
            message=f"Unknown business model: {model_name}",
            error_code="UNKNOWN_MODEL",
            context={'model_name': model_name, 'available_models': list(BUSINESS_MODEL_REGISTRY.keys())},
            severity=ErrorSeverity.HIGH
        )
    
    try:
        return model_class.from_dict(data)
    except Exception as e:
        if isinstance(e, (DataValidationError, BusinessRuleViolationError)):
            raise
        
        raise DataValidationError(
            message=f"Failed to validate data against {model_name} model",
            error_code="MODEL_VALIDATION_FAILED",
            context={'model_name': model_name},
            cause=e,
            severity=ErrorSeverity.MEDIUM
        )


def serialize_for_api(model: BaseBusinessModel, exclude_audit: bool = True) -> Dict[str, Any]:
    """
    Serialize business model for API response.
    
    Args:
        model: Business model instance to serialize
        exclude_audit: Whether to exclude audit trail fields
        
    Returns:
        Dictionary suitable for JSON API response
    """
    try:
        return model.to_api_dict(exclude_audit=exclude_audit)
    except Exception as e:
        logger.error("Failed to serialize model for API",
                    model_type=type(model).__name__,
                    error=str(e))
        # Return basic serialization as fallback
        return {
            'id': getattr(model, 'id', None),
            'type': type(model).__name__,
            'error': 'Serialization failed'
        }


# Module initialization logging
logger.info("Business models module initialized successfully",
           model_count=len(BUSINESS_MODEL_REGISTRY),
           pydantic_version="2.3+",
           validation_enabled=True)