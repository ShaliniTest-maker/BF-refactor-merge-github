"""
Dynamic Test Data Generation Fixtures using factory_boy Patterns

This module provides comprehensive factory_boy integration for dynamic test object generation
with realistic test data models, production data model parity, and edge case coverage for
the Flask application migration. Implements Section 6.6.1 enhanced mocking strategy and
test data management patterns per technical specification requirements.

Key Features:
- factory_boy integration for dynamic test object generation per Section 6.6.1
- Production data model parity per Section 6.6.1 test data management
- pydantic model validation in test fixtures per Section 6.6.1
- Date/time handling with python-dateutil per Section 6.6.1
- Comprehensive validation testing with marshmallow schemas per Section 6.6.1
- Edge case data factories for validation testing per Section 6.6.1
- Realistic test data volumes for performance testing per Section 6.6.1

Factory Categories:
    Core Business Factories:
        UserFactory: User account and profile test data generation
        OrganizationFactory: Organization and company test data
        ProductFactory: Product catalog and inventory test data
        OrderFactory: Order and transaction test data
        PaymentTransactionFactory: Payment processing test data
        
    Authentication Factories:
        AuthUserFactory: Authentication-specific user data
        JWTTokenFactory: JWT token generation for auth testing
        SessionFactory: User session data for authentication
        PermissionFactory: User permissions and roles
        
    Utility Factories:
        AddressFactory: Geographic address test data
        ContactInfoFactory: Contact information test data
        MonetaryAmountFactory: Financial amount test data
        DateTimeRangeFactory: Temporal range test data
        FileUploadFactory: File metadata test data
        
    API Testing Factories:
        PaginationParamsFactory: Pagination parameter generation
        SearchParamsFactory: Search and filtering test data
        ApiResponseFactory: API response structure generation
        
    Edge Case Factories:
        InvalidDataFactory: Invalid data for validation testing
        BoundaryValueFactory: Boundary condition test data
        SecurityTestFactory: Security validation test data
        PerformanceDataFactory: Large volume test data for performance

Integration Points:
- Section 3.2.3: pydantic 2.3+ model validation integration
- Section 3.2.3: python-dateutil 2.8+ for date/time handling
- Section 6.6.1: factory_boy for dynamic test object generation
- Section 6.6.1: production data model parity validation
- Section 6.6.1: comprehensive validation testing patterns
- Section 6.6.1: edge case and boundary condition coverage
- Section 6.6.1: performance testing data volume generation

Performance Requirements:
- Realistic test data volumes per Section 6.6.1 production data model parity
- Edge case coverage per Section 6.6.1 factory pattern validation
- Performance testing data generation per Section 6.6.1 test data management

Dependencies:
- factory_boy for dynamic object generation and test data patterns
- python-dateutil 2.8+ for comprehensive date/time test scenarios
- pydantic 2.3+ for data model validation and type checking
- faker for realistic test data generation with localization support
- pytest integration for fixture-based test data management

Author: Flask Migration Team
Version: 1.0.0
Test Coverage Target: 95% per Section 6.6.3 quality metrics
"""

import secrets
import uuid
from datetime import datetime, timedelta, timezone, date
from decimal import Decimal
from typing import Any, Dict, List, Optional, Set, Union, Type, Callable
from urllib.parse import urljoin
import re

# factory_boy integration for dynamic test object generation per Section 6.6.1
import factory
from factory import LazyAttribute, LazyFunction, SubFactory, Iterator, Trait
from factory.fuzzy import (
    FuzzyChoice, FuzzyDecimal, FuzzyFloat, FuzzyInteger, 
    FuzzyText, FuzzyDate, FuzzyDateTime
)

# python-dateutil integration per Section 6.6.1 date/time handling
from dateutil.relativedelta import relativedelta
from dateutil.parser import parse as parse_date
from dateutil.tz import tzutc, tzlocal, gettz
import dateutil.utils

# faker integration for realistic test data generation
from faker import Faker
from faker.providers import BaseProvider

# Import business models for pydantic validation per Section 6.6.1
from src.business.models import (
    # Core business models
    User, Organization, Product, ProductCategory, Order, OrderItem,
    PaymentTransaction, SystemConfiguration,
    
    # Utility models
    Address, ContactInfo, MonetaryAmount, DateTimeRange, FileUpload,
    
    # API models
    PaginationParams, SortParams, SearchParams, ApiResponse, PaginatedResponse,
    
    # Enumerations
    UserStatus, UserRole, OrderStatus, PaymentStatus, PaymentMethod, 
    ProductStatus, Priority, ContactMethod
)

# Import data models for MongoDB integration
from src.data.models import MongoBaseModel, PyObjectId

# Import business validators for validation testing per Section 6.6.1
from src.business.validators import ValidationConfig

# Import business exceptions for error testing
from src.business.exceptions import (
    BusinessRuleViolationError, DataValidationError, ErrorSeverity
)

# Configure structured logging for factory operations
import structlog
logger = structlog.get_logger("tests.fixtures.factory_fixtures")

# Initialize Faker with multiple locales for comprehensive test coverage
fake = Faker(['en_US', 'en_GB', 'de_DE', 'fr_FR', 'ja_JP'])

# Configure factory_boy for performance optimization
factory.Faker._DEFAULT_LOCALE = 'en_US'


# ============================================================================
# CUSTOM FAKER PROVIDERS FOR BUSINESS-SPECIFIC DATA
# ============================================================================

class BusinessDataProvider(BaseProvider):
    """
    Custom Faker provider for business-specific test data generation.
    
    Provides domain-specific data generation for business entities, financial
    data, and industry-specific patterns not available in standard Faker.
    """
    
    # Business entity types for organization testing
    business_types = [
        'Corporation', 'LLC', 'Partnership', 'Sole Proprietorship',
        'Non-Profit', 'Government Agency', 'Educational Institution',
        'Healthcare Organization', 'Technology Startup', 'Consulting Firm'
    ]
    
    # Industry classifications for realistic business scenarios
    industries = [
        'Technology', 'Healthcare', 'Finance', 'Education', 'Retail',
        'Manufacturing', 'Consulting', 'Real Estate', 'Media', 'Transportation',
        'Energy', 'Agriculture', 'Construction', 'Entertainment', 'Hospitality'
    ]
    
    # Product categories for e-commerce testing
    product_categories = [
        'Electronics', 'Clothing', 'Books', 'Home & Garden', 'Sports',
        'Automotive', 'Health & Beauty', 'Toys', 'Food & Beverage', 'Tools'
    ]
    
    # Payment processor names for financial testing
    payment_processors = [
        'Stripe', 'PayPal', 'Square', 'Authorize.Net', 'Braintree',
        'Adyen', 'Worldpay', 'Chase Paymentech', 'First Data', 'Merchant One'
    ]
    
    # File categories for upload testing
    file_categories = [
        'document', 'image', 'video', 'audio', 'spreadsheet',
        'presentation', 'archive', 'code', 'data', 'backup'
    ]
    
    def business_type(self) -> str:
        """Generate random business type."""
        return self.random_element(self.business_types)
    
    def industry(self) -> str:
        """Generate random industry classification."""
        return self.random_element(self.industries)
    
    def product_category(self) -> str:
        """Generate random product category."""
        return self.random_element(self.product_categories)
    
    def payment_processor(self) -> str:
        """Generate random payment processor name."""
        return self.random_element(self.payment_processors)
    
    def file_category(self) -> str:
        """Generate random file category."""
        return self.random_element(self.file_categories)
    
    def sku(self, length: int = 8) -> str:
        """Generate realistic product SKU."""
        prefix = self.random_element(['SKU', 'PROD', 'ITEM', 'CODE'])
        number = ''.join([str(self.random_int(0, 9)) for _ in range(length)])
        return f"{prefix}-{number}"
    
    def order_number(self) -> str:
        """Generate realistic order number."""
        timestamp = datetime.now().strftime('%Y%m%d')
        sequence = str(self.random_int(1000, 9999))
        return f"ORD-{timestamp}-{sequence}"
    
    def transaction_id(self) -> str:
        """Generate realistic transaction ID."""
        prefix = 'TXN'
        uuid_part = str(uuid.uuid4()).replace('-', '')[:12].upper()
        return f"{prefix}_{uuid_part}"
    
    def currency_code(self) -> str:
        """Generate realistic currency code."""
        currencies = ['USD', 'EUR', 'GBP', 'JPY', 'CAD', 'AUD', 'CHF', 'CNY']
        return self.random_element(currencies)
    
    def permissions_set(self) -> Set[str]:
        """Generate realistic user permissions set."""
        available_permissions = [
            'user.read', 'user.write', 'user.delete',
            'order.read', 'order.write', 'order.process',
            'product.read', 'product.write', 'product.manage',
            'payment.read', 'payment.process', 'payment.refund',
            'report.read', 'report.generate', 'system.admin'
        ]
        count = self.random_int(1, 6)
        return set(self.random_sample(available_permissions, count))
    
    def slug(self, text: str = None) -> str:
        """Generate URL-friendly slug."""
        if not text:
            text = fake.catch_phrase()
        
        # Convert to lowercase and replace spaces/special chars with hyphens
        slug = re.sub(r'[^\w\s-]', '', text.lower())
        slug = re.sub(r'[-\s]+', '-', slug)
        return slug.strip('-')


# Add custom provider to Faker instance
fake.add_provider(BusinessDataProvider)


# ============================================================================
# DATE/TIME FACTORY UTILITIES WITH PYTHON-DATEUTIL INTEGRATION
# ============================================================================

class DateTimeFactoryUtils:
    """
    Utility class for advanced date/time generation using python-dateutil.
    
    Provides comprehensive date/time test scenarios including timezone handling,
    business hours, holidays, and temporal edge cases per Section 6.6.1
    date/time handling requirements.
    """
    
    @staticmethod
    def business_hours_datetime(
        date_obj: datetime = None,
        timezone_name: str = 'UTC'
    ) -> datetime:
        """
        Generate datetime within business hours (9 AM - 5 PM).
        
        Args:
            date_obj: Base date (defaults to random recent date)
            timezone_name: Timezone name for localization
            
        Returns:
            Datetime within business hours
        """
        if date_obj is None:
            date_obj = fake.date_between(start_date='-30d', end_date='today')
        
        # Generate time between 9 AM and 5 PM
        hour = fake.random_int(9, 16)  # 9 AM to 4 PM (before 5 PM)
        minute = fake.random_int(0, 59)
        second = fake.random_int(0, 59)
        
        business_dt = datetime.combine(
            date_obj, 
            datetime.min.time().replace(hour=hour, minute=minute, second=second)
        )
        
        # Apply timezone
        if timezone_name != 'UTC':
            tz = gettz(timezone_name)
            business_dt = business_dt.replace(tzinfo=tz)
        else:
            business_dt = business_dt.replace(tzinfo=timezone.utc)
        
        return business_dt
    
    @staticmethod
    def random_timezone_datetime(
        base_datetime: datetime = None,
        common_timezones: bool = True
    ) -> datetime:
        """
        Generate datetime with random timezone.
        
        Args:
            base_datetime: Base datetime (defaults to now)
            common_timezones: Use common business timezones
            
        Returns:
            Datetime with random timezone
        """
        if base_datetime is None:
            base_datetime = datetime.now()
        
        if common_timezones:
            timezones = [
                'UTC', 'US/Eastern', 'US/Central', 'US/Mountain', 'US/Pacific',
                'Europe/London', 'Europe/Paris', 'Europe/Berlin', 'Asia/Tokyo',
                'Asia/Shanghai', 'Australia/Sydney'
            ]
        else:
            timezones = ['UTC', 'US/Eastern', 'Europe/London', 'Asia/Tokyo']
        
        tz_name = fake.random_element(timezones)
        tz = gettz(tz_name)
        
        # Convert to selected timezone
        if base_datetime.tzinfo is None:
            base_datetime = base_datetime.replace(tzinfo=timezone.utc)
        
        return base_datetime.astimezone(tz)
    
    @staticmethod
    def date_range_with_duration(
        start_days_ago: int = 30,
        min_duration_hours: int = 1,
        max_duration_hours: int = 168  # 1 week
    ) -> tuple[datetime, datetime]:
        """
        Generate realistic date range with specified duration constraints.
        
        Args:
            start_days_ago: Maximum days ago for start date
            min_duration_hours: Minimum duration in hours
            max_duration_hours: Maximum duration in hours
            
        Returns:
            Tuple of (start_datetime, end_datetime)
        """
        # Generate start datetime
        start_date = fake.date_between(start_date=f'-{start_days_ago}d', end_date='today')
        start_time = fake.time_object()
        start_datetime = datetime.combine(start_date, start_time, tzinfo=timezone.utc)
        
        # Generate duration
        duration_hours = fake.random_int(min_duration_hours, max_duration_hours)
        end_datetime = start_datetime + timedelta(hours=duration_hours)
        
        return start_datetime, end_datetime
    
    @staticmethod
    def future_expiration_datetime(
        min_days: int = 1,
        max_days: int = 365
    ) -> datetime:
        """
        Generate future expiration datetime.
        
        Args:
            min_days: Minimum days in future
            max_days: Maximum days in future
            
        Returns:
            Future datetime for expiration scenarios
        """
        days_offset = fake.random_int(min_days, max_days)
        return datetime.now(timezone.utc) + timedelta(days=days_offset)
    
    @staticmethod
    def past_datetime_with_age(
        min_age_days: int = 1,
        max_age_days: int = 365
    ) -> datetime:
        """
        Generate past datetime with specified age constraints.
        
        Args:
            min_age_days: Minimum age in days
            max_age_days: Maximum age in days
            
        Returns:
            Past datetime within age constraints
        """
        days_ago = fake.random_int(min_age_days, max_age_days)
        return datetime.now(timezone.utc) - timedelta(days=days_ago)


# ============================================================================
# BASE FACTORY CLASSES WITH PYDANTIC INTEGRATION
# ============================================================================

class PydanticModelFactory(factory.Factory):
    """
    Base factory class for Pydantic model integration.
    
    Provides standardized factory patterns for Pydantic model creation with
    validation, error handling, and business rule enforcement per Section 6.6.1
    pydantic model validation requirements.
    """
    
    class Meta:
        abstract = True
    
    @classmethod
    def _create(cls, model_class: Type, *args, **kwargs):
        """
        Create Pydantic model instance with validation.
        
        Args:
            model_class: Pydantic model class to instantiate
            *args: Positional arguments
            **kwargs: Keyword arguments for model fields
            
        Returns:
            Validated Pydantic model instance
            
        Raises:
            DataValidationError: If model validation fails
        """
        try:
            # Filter out None values to use model defaults
            filtered_kwargs = {k: v for k, v in kwargs.items() if v is not None}
            
            # Create and validate model instance
            instance = model_class(**filtered_kwargs)
            
            # Log factory creation for debugging
            logger.debug(
                "Factory created Pydantic model",
                model_type=model_class.__name__,
                field_count=len(filtered_kwargs)
            )
            
            return instance
            
        except Exception as e:
            logger.error(
                "Factory failed to create Pydantic model",
                model_type=model_class.__name__,
                error=str(e),
                kwargs_keys=list(kwargs.keys())
            )
            
            # Re-raise with factory context
            if hasattr(e, 'errors'):
                # Pydantic validation error
                raise DataValidationError(
                    message=f"Factory validation failed for {model_class.__name__}",
                    error_code="FACTORY_VALIDATION_FAILED",
                    validation_errors=[{
                        'field': '.'.join(str(loc) for loc in error['loc']),
                        'message': error['msg'],
                        'type': error['type']
                    } for error in e.errors()],
                    context={'factory_class': cls.__name__},
                    cause=e,
                    severity=ErrorSeverity.HIGH
                )
            else:
                # Other creation error
                raise DataValidationError(
                    message=f"Factory failed to create {model_class.__name__}",
                    error_code="FACTORY_CREATION_FAILED",
                    context={'factory_class': cls.__name__},
                    cause=e,
                    severity=ErrorSeverity.HIGH
                )
    
    @classmethod
    def build_dict(cls, **kwargs) -> Dict[str, Any]:
        """
        Build dictionary representation without creating model instance.
        
        Args:
            **kwargs: Keyword arguments for model fields
            
        Returns:
            Dictionary with generated field values
        """
        # Use factory.build to generate values without creating instance
        generated = factory.build(dict, FACTORY_FOR=cls, **kwargs)
        
        # Filter out factory metadata
        return {k: v for k, v in generated.items() 
                if not k.startswith('FACTORY_') and v is not None}


class MongoModelFactory(PydanticModelFactory):
    """
    Base factory class for MongoDB model integration.
    
    Provides specialized factory patterns for MongoDB document models with
    ObjectId generation, timestamp handling, and document structure preservation.
    """
    
    class Meta:
        abstract = True
    
    # MongoDB ObjectId generation
    id = LazyFunction(lambda: PyObjectId())
    
    # Timestamp generation with realistic age variation
    created_at = LazyFunction(
        lambda: DateTimeFactoryUtils.past_datetime_with_age(
            min_age_days=1, max_age_days=180
        )
    )
    
    updated_at = LazyAttribute(
        lambda obj: obj.created_at + timedelta(
            seconds=fake.random_int(0, 86400)  # 0 to 24 hours later
        )
    )


# ============================================================================
# UTILITY MODEL FACTORIES
# ============================================================================

class AddressFactory(PydanticModelFactory):
    """
    Factory for Address model test data generation.
    
    Generates realistic geographic addresses with proper validation,
    postal code formats, and international address patterns.
    """
    
    class Meta:
        model = Address
    
    street_line_1 = LazyFunction(lambda: fake.street_address())
    street_line_2 = factory.LazyFunction(
        lambda: fake.secondary_address() if fake.boolean(chance_of_getting_true=30) else None
    )
    city = LazyFunction(lambda: fake.city())
    state_province = LazyFunction(lambda: fake.state())
    postal_code = LazyFunction(lambda: fake.postcode())
    country_code = FuzzyChoice(['US', 'CA', 'GB', 'DE', 'FR', 'AU', 'JP'])
    
    class Params:
        # Trait for US addresses with proper formatting
        us_address = Trait(
            country_code='US',
            state_province=LazyFunction(lambda: fake.state_abbr()),
            postal_code=LazyFunction(lambda: fake.zipcode())
        )
        
        # Trait for international addresses
        international = Trait(
            country_code=FuzzyChoice(['GB', 'DE', 'FR', 'AU', 'JP', 'CA']),
            postal_code=LazyFunction(lambda: fake.postcode())
        )
        
        # Trait for PO Box addresses
        po_box = Trait(
            street_line_1=LazyFunction(lambda: f"PO Box {fake.random_int(1, 9999)}"),
            street_line_2=None
        )


class ContactInfoFactory(PydanticModelFactory):
    """
    Factory for ContactInfo model test data generation.
    
    Generates realistic contact information with proper email and phone
    validation, communication preferences, and timezone handling.
    """
    
    class Meta:
        model = ContactInfo
    
    primary_email = LazyFunction(lambda: fake.email())
    secondary_email = factory.LazyFunction(
        lambda: fake.email() if fake.boolean(chance_of_getting_true=40) else None
    )
    primary_phone = LazyFunction(lambda: fake.phone_number())
    secondary_phone = factory.LazyFunction(
        lambda: fake.phone_number() if fake.boolean(chance_of_getting_true=30) else None
    )
    preferred_contact_method = FuzzyChoice([method.value for method in ContactMethod])
    allow_marketing = FuzzyChoice([True, False])
    timezone = FuzzyChoice([
        'UTC', 'US/Eastern', 'US/Central', 'US/Mountain', 'US/Pacific',
        'Europe/London', 'Europe/Paris', 'Asia/Tokyo'
    ])
    
    class Params:
        # Trait for business contact information
        business_contact = Trait(
            primary_phone=LazyFunction(lambda: fake.phone_number()),
            preferred_contact_method=ContactMethod.EMAIL,
            allow_marketing=True
        )
        
        # Trait for personal contact information
        personal_contact = Trait(
            preferred_contact_method=FuzzyChoice([ContactMethod.EMAIL, ContactMethod.PHONE]),
            allow_marketing=FuzzyChoice([True, False])
        )
        
        # Trait for minimal contact (email only)
        minimal_contact = Trait(
            secondary_email=None,
            primary_phone=None,
            secondary_phone=None,
            preferred_contact_method=ContactMethod.EMAIL
        )


class MonetaryAmountFactory(PydanticModelFactory):
    """
    Factory for MonetaryAmount model test data generation.
    
    Generates realistic monetary amounts with proper decimal precision,
    currency codes, and business-appropriate value ranges.
    """
    
    class Meta:
        model = MonetaryAmount
    
    amount = FuzzyDecimal(low=0.01, high=9999.99, precision=2)
    currency_code = LazyFunction(lambda: fake.currency_code())
    
    class Params:
        # Trait for small amounts (under $100)
        small_amount = Trait(
            amount=FuzzyDecimal(low=0.01, high=99.99, precision=2)
        )
        
        # Trait for large amounts (over $1000)
        large_amount = Trait(
            amount=FuzzyDecimal(low=1000.00, high=999999.99, precision=2)
        )
        
        # Trait for USD currency
        usd_amount = Trait(
            currency_code='USD'
        )
        
        # Trait for EUR currency
        eur_amount = Trait(
            currency_code='EUR'
        )
        
        # Trait for zero amount
        zero_amount = Trait(
            amount=Decimal('0.00')
        )


class DateTimeRangeFactory(PydanticModelFactory):
    """
    Factory for DateTimeRange model test data generation.
    
    Generates realistic date/time ranges with proper duration validation,
    timezone handling, and business hour patterns.
    """
    
    class Meta:
        model = DateTimeRange
    
    start_datetime = LazyFunction(
        lambda: DateTimeFactoryUtils.past_datetime_with_age(1, 30)
    )
    end_datetime = LazyAttribute(
        lambda obj: obj.start_datetime + timedelta(
            hours=fake.random_int(1, 48)
        )
    )
    timezone_name = FuzzyChoice([
        'UTC', 'US/Eastern', 'US/Pacific', 'Europe/London', 'Asia/Tokyo'
    ])
    all_day = FuzzyChoice([True, False])
    
    class Params:
        # Trait for business hours range
        business_hours = Trait(
            start_datetime=LazyFunction(
                lambda: DateTimeFactoryUtils.business_hours_datetime()
            ),
            end_datetime=LazyAttribute(
                lambda obj: obj.start_datetime + timedelta(hours=8)
            ),
            all_day=False
        )
        
        # Trait for short duration (under 2 hours)
        short_duration = Trait(
            end_datetime=LazyAttribute(
                lambda obj: obj.start_datetime + timedelta(
                    minutes=fake.random_int(15, 120)
                )
            )
        )
        
        # Trait for all-day event
        all_day_event = Trait(
            all_day=True,
            start_datetime=LazyFunction(
                lambda: datetime.combine(
                    fake.date_between(start_date='-30d', end_date='+30d'),
                    datetime.min.time(),
                    tzinfo=timezone.utc
                )
            ),
            end_datetime=LazyAttribute(
                lambda obj: obj.start_datetime + timedelta(days=1)
            )
        )


class FileUploadFactory(PydanticModelFactory):
    """
    Factory for FileUpload model test data generation.
    
    Generates realistic file upload metadata with proper content types,
    file sizes, and security validation patterns.
    """
    
    class Meta:
        model = FileUpload
    
    filename = LazyFunction(
        lambda: f"{fake.file_name(extension=fake.random_element(['pdf', 'jpg', 'png', 'docx', 'xlsx']))}"
    )
    content_type = LazyAttribute(
        lambda obj: {
            'pdf': 'application/pdf',
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'png': 'image/png',
            'gif': 'image/gif',
            'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'txt': 'text/plain',
            'csv': 'text/csv'
        }.get(obj.filename.split('.')[-1].lower(), 'application/octet-stream')
    )
    file_size = FuzzyInteger(low=1024, high=10485760)  # 1KB to 10MB
    storage_path = LazyFunction(
        lambda: f"uploads/{fake.uuid4()}/{fake.file_name()}"
    )
    storage_url = LazyFunction(lambda: fake.url())
    checksum = LazyFunction(lambda: fake.sha256())
    is_virus_scanned = FuzzyChoice([True, False])
    scan_result = LazyAttribute(
        lambda obj: 'clean' if obj.is_virus_scanned else None
    )
    uploaded_by = LazyFunction(lambda: str(fake.uuid4()))
    upload_date = LazyFunction(
        lambda: DateTimeFactoryUtils.past_datetime_with_age(0, 30)
    )
    expires_at = factory.LazyFunction(
        lambda: DateTimeFactoryUtils.future_expiration_datetime(30, 365)
        if fake.boolean(chance_of_getting_true=60) else None
    )
    category = LazyFunction(lambda: fake.file_category())
    tags = LazyFunction(
        lambda: set(fake.words(nb=fake.random_int(1, 5)))
    )
    
    class Params:
        # Trait for image files
        image_file = Trait(
            filename=LazyFunction(
                lambda: f"{fake.word()}.{fake.random_element(['jpg', 'png', 'gif'])}"
            ),
            content_type=LazyAttribute(
                lambda obj: f"image/{obj.filename.split('.')[-1]}"
            ),
            category='image'
        )
        
        # Trait for document files
        document_file = Trait(
            filename=LazyFunction(
                lambda: f"{fake.catch_phrase().replace(' ', '_')}.{fake.random_element(['pdf', 'docx', 'txt'])}"
            ),
            content_type=LazyAttribute(
                lambda obj: {
                    'pdf': 'application/pdf',
                    'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                    'txt': 'text/plain'
                }.get(obj.filename.split('.')[-1], 'application/octet-stream')
            ),
            category='document'
        )
        
        # Trait for large files
        large_file = Trait(
            file_size=FuzzyInteger(low=50485760, high=100000000)  # 50MB to 100MB
        )


# ============================================================================
# USER AND AUTHENTICATION FACTORIES
# ============================================================================

class UserFactory(PydanticModelFactory):
    """
    Factory for User model test data generation.
    
    Generates realistic user profiles with authentication data, permissions,
    contact information, and account status patterns for comprehensive testing.
    """
    
    class Meta:
        model = User
    
    id = LazyFunction(lambda: str(fake.uuid4()))
    username = LazyFunction(
        lambda: fake.user_name().lower().replace('.', '_')
    )
    email = LazyFunction(lambda: fake.email())
    first_name = LazyFunction(lambda: fake.first_name())
    last_name = LazyFunction(lambda: fake.last_name())
    display_name = LazyAttribute(
        lambda obj: f"{obj.first_name} {obj.last_name}"
    )
    avatar_url = factory.LazyFunction(
        lambda: fake.image_url() if fake.boolean(chance_of_getting_true=70) else None
    )
    
    # Account status and permissions
    status = FuzzyChoice([status.value for status in UserStatus])
    role = FuzzyChoice([role.value for role in UserRole])
    permissions = LazyFunction(lambda: fake.permissions_set())
    
    # Contact information
    contact_info = SubFactory(ContactInfoFactory)
    
    # Authentication and security
    last_login_at = factory.LazyFunction(
        lambda: DateTimeFactoryUtils.past_datetime_with_age(0, 30)
        if fake.boolean(chance_of_getting_true=80) else None
    )
    password_changed_at = factory.LazyFunction(
        lambda: DateTimeFactoryUtils.past_datetime_with_age(1, 90)
    )
    login_attempts = FuzzyInteger(low=0, high=5)
    is_locked = FuzzyChoice([True, False])
    lock_expires_at = LazyAttribute(
        lambda obj: DateTimeFactoryUtils.future_expiration_datetime(1, 7)
        if obj.is_locked else None
    )
    
    # Profile and preferences
    language_code = FuzzyChoice(['en', 'es', 'fr', 'de', 'ja', 'zh'])
    timezone = FuzzyChoice([
        'UTC', 'US/Eastern', 'US/Central', 'US/Mountain', 'US/Pacific',
        'Europe/London', 'Europe/Paris', 'Europe/Berlin', 'Asia/Tokyo'
    ])
    date_format = FuzzyChoice(['YYYY-MM-DD', 'MM/DD/YYYY', 'DD/MM/YYYY'])
    
    class Params:
        # Trait for admin users
        admin_user = Trait(
            role=UserRole.ADMIN,
            status=UserStatus.ACTIVE,
            permissions=LazyFunction(
                lambda: {
                    'user.read', 'user.write', 'user.delete',
                    'order.read', 'order.write', 'order.process',
                    'product.read', 'product.write', 'product.manage',
                    'payment.read', 'payment.process', 'payment.refund',
                    'report.read', 'report.generate', 'system.admin'
                }
            ),
            is_locked=False
        )
        
        # Trait for regular users
        regular_user = Trait(
            role=UserRole.USER,
            status=UserStatus.ACTIVE,
            permissions=LazyFunction(
                lambda: {'user.read', 'order.read', 'product.read'}
            ),
            is_locked=False
        )
        
        # Trait for locked accounts
        locked_account = Trait(
            is_locked=True,
            status=UserStatus.SUSPENDED,
            login_attempts=FuzzyInteger(low=5, high=10),
            lock_expires_at=LazyFunction(
                lambda: DateTimeFactoryUtils.future_expiration_datetime(1, 7)
            )
        )
        
        # Trait for new users
        new_user = Trait(
            status=UserStatus.PENDING,
            last_login_at=None,
            login_attempts=0,
            is_locked=False,
            created_at=LazyFunction(
                lambda: DateTimeFactoryUtils.past_datetime_with_age(0, 7)
            )
        )


class AuthUserFactory(UserFactory):
    """
    Extended factory for authentication-specific user data.
    
    Provides specialized user profiles for authentication testing including
    JWT token data, session management, and security validation scenarios.
    """
    
    # Authentication-specific fields
    auth_provider = FuzzyChoice(['local', 'auth0', 'google', 'github'])
    auth_provider_id = LazyFunction(lambda: str(fake.uuid4()))
    two_factor_enabled = FuzzyChoice([True, False])
    two_factor_secret = LazyAttribute(
        lambda obj: fake.password(length=32) if obj.two_factor_enabled else None
    )
    
    # Security context
    last_ip_address = LazyFunction(lambda: fake.ipv4())
    last_user_agent = LazyFunction(lambda: fake.user_agent())
    security_questions = LazyFunction(
        lambda: [
            {'question': 'What was your first pet?', 'answer': fake.word()},
            {'question': 'What city were you born in?', 'answer': fake.city()}
        ] if fake.boolean(chance_of_getting_true=60) else []
    )
    
    class Params:
        # Trait for Auth0 users
        auth0_user = Trait(
            auth_provider='auth0',
            auth_provider_id=LazyFunction(lambda: f"auth0|{fake.uuid4()}"),
            two_factor_enabled=FuzzyChoice([True, False])
        )
        
        # Trait for local authentication users
        local_user = Trait(
            auth_provider='local',
            auth_provider_id=None,
            two_factor_enabled=FuzzyChoice([True, False])
        )
        
        # Trait for high-security users
        high_security = Trait(
            two_factor_enabled=True,
            role=UserRole.ADMIN,
            password_changed_at=LazyFunction(
                lambda: DateTimeFactoryUtils.past_datetime_with_age(1, 30)
            )
        )


# ============================================================================
# BUSINESS ENTITY FACTORIES
# ============================================================================

class OrganizationFactory(PydanticModelFactory):
    """
    Factory for Organization model test data generation.
    
    Generates realistic business organizations with proper business details,
    contact information, and verification status patterns.
    """
    
    class Meta:
        model = Organization
    
    id = LazyFunction(lambda: str(fake.uuid4()))
    name = LazyFunction(lambda: fake.company())
    legal_name = LazyAttribute(
        lambda obj: f"{obj.name} {fake.company_suffix()}"
    )
    business_type = LazyFunction(lambda: fake.business_type())
    
    # Business identifiers
    tax_id = LazyFunction(
        lambda: f"{fake.random_int(10, 99)}-{fake.random_int(1000000, 9999999)}"
    )
    registration_number = LazyFunction(
        lambda: f"REG-{fake.random_int(100000, 999999)}"
    )
    
    # Contact information
    primary_contact = SubFactory(ContactInfoFactory, business_contact=True)
    billing_address = SubFactory(AddressFactory, us_address=True)
    shipping_address = SubFactory(AddressFactory, us_address=True)
    
    # Business details
    website_url = LazyFunction(lambda: fake.url())
    description = LazyFunction(lambda: fake.text(max_nb_chars=500))
    industry = LazyFunction(lambda: fake.industry())
    employee_count = FuzzyInteger(low=1, high=10000)
    
    # Status and settings
    status = FuzzyChoice([status.value for status in UserStatus])
    is_verified = FuzzyChoice([True, False])
    verification_date = LazyAttribute(
        lambda obj: DateTimeFactoryUtils.past_datetime_with_age(1, 365)
        if obj.is_verified else None
    )
    
    parent_organization_id = factory.LazyFunction(
        lambda: str(fake.uuid4()) if fake.boolean(chance_of_getting_true=20) else None
    )
    
    class Params:
        # Trait for startup organizations
        startup = Trait(
            business_type='Technology Startup',
            industry='Technology',
            employee_count=FuzzyInteger(low=1, high=50),
            is_verified=False
        )
        
        # Trait for enterprise organizations
        enterprise = Trait(
            business_type='Corporation',
            employee_count=FuzzyInteger(low=1000, high=50000),
            is_verified=True,
            verification_date=LazyFunction(
                lambda: DateTimeFactoryUtils.past_datetime_with_age(30, 365)
            )
        )
        
        # Trait for small businesses
        small_business = Trait(
            business_type=FuzzyChoice(['LLC', 'Partnership', 'Sole Proprietorship']),
            employee_count=FuzzyInteger(low=1, high=25),
            is_verified=FuzzyChoice([True, False])
        )


class ProductCategoryFactory(PydanticModelFactory):
    """
    Factory for ProductCategory model test data generation.
    
    Generates product categories with hierarchical relationships,
    sorting orders, and display configuration.
    """
    
    class Meta:
        model = ProductCategory
    
    id = LazyFunction(lambda: str(fake.uuid4()))
    name = LazyFunction(lambda: fake.product_category())
    slug = LazyAttribute(lambda obj: fake.slug(obj.name))
    description = LazyFunction(
        lambda: fake.text(max_nb_chars=300) if fake.boolean(chance_of_getting_true=70) else None
    )
    
    parent_category_id = factory.LazyFunction(
        lambda: str(fake.uuid4()) if fake.boolean(chance_of_getting_true=30) else None
    )
    sort_order = FuzzyInteger(low=0, high=100)
    
    image_url = factory.LazyFunction(
        lambda: fake.image_url() if fake.boolean(chance_of_getting_true=60) else None
    )
    is_visible = FuzzyChoice([True, False])
    
    class Params:
        # Trait for top-level categories
        top_level = Trait(
            parent_category_id=None,
            sort_order=FuzzyInteger(low=0, high=20),
            is_visible=True
        )
        
        # Trait for subcategories
        subcategory = Trait(
            parent_category_id=LazyFunction(lambda: str(fake.uuid4())),
            sort_order=FuzzyInteger(low=0, high=50)
        )


class ProductFactory(PydanticModelFactory):
    """
    Factory for Product model test data generation.
    
    Generates realistic products with pricing, inventory, categorization,
    and metadata for e-commerce testing scenarios.
    """
    
    class Meta:
        model = Product
    
    id = LazyFunction(lambda: str(fake.uuid4()))
    sku = LazyFunction(lambda: fake.sku())
    name = LazyFunction(lambda: fake.catch_phrase())
    slug = LazyAttribute(lambda obj: fake.slug(obj.name))
    description = LazyFunction(lambda: fake.text(max_nb_chars=1500))
    short_description = LazyFunction(lambda: fake.text(max_nb_chars=300))
    
    # Categorization
    category_id = LazyFunction(lambda: str(fake.uuid4()))
    tags = LazyFunction(
        lambda: set(fake.words(nb=fake.random_int(2, 8)))
    )
    brand = LazyFunction(lambda: fake.company())
    
    # Pricing
    base_price = SubFactory(MonetaryAmountFactory, usd_amount=True)
    sale_price = SubFactory(
        MonetaryAmountFactory, 
        usd_amount=True,
        small_amount=True
    ) if fake.boolean(chance_of_getting_true=30) else None
    cost_price = SubFactory(
        MonetaryAmountFactory,
        usd_amount=True,
        small_amount=True
    ) if fake.boolean(chance_of_getting_true=60) else None
    
    # Inventory
    status = FuzzyChoice([status.value for status in ProductStatus])
    inventory_quantity = FuzzyInteger(low=0, high=1000)
    low_stock_threshold = FuzzyInteger(low=1, high=20)
    track_inventory = FuzzyChoice([True, False])
    
    # Physical attributes
    weight = FuzzyDecimal(low=0.1, high=50.0, precision=2) if fake.boolean(chance_of_getting_true=80) else None
    dimensions = LazyFunction(
        lambda: {
            'length': Decimal(str(fake.random_int(1, 100))),
            'width': Decimal(str(fake.random_int(1, 100))),
            'height': Decimal(str(fake.random_int(1, 100)))
        } if fake.boolean(chance_of_getting_true=70) else None
    )
    
    # Digital content
    images = LazyFunction(
        lambda: [fake.image_url() for _ in range(fake.random_int(1, 5))]
    )
    documents = LazyFunction(
        lambda: [
            {'name': f"{fake.word()}.pdf", 'url': fake.url(), 'type': 'manual'},
            {'name': f"{fake.word()}.pdf", 'url': fake.url(), 'type': 'warranty'}
        ] if fake.boolean(chance_of_getting_true=40) else []
    )
    
    # SEO and metadata
    meta_title = LazyAttribute(
        lambda obj: obj.name[:60] if fake.boolean(chance_of_getting_true=80) else None
    )
    meta_description = LazyAttribute(
        lambda obj: obj.short_description[:160] if fake.boolean(chance_of_getting_true=80) else None
    )
    
    class Params:
        # Trait for electronics products
        electronics = Trait(
            category_id='electronics',
            brand=FuzzyChoice(['Apple', 'Samsung', 'Sony', 'LG', 'Microsoft']),
            weight=FuzzyDecimal(low=0.5, high=10.0, precision=2),
            track_inventory=True,
            status=ProductStatus.ACTIVE
        )
        
        # Trait for clothing products
        clothing = Trait(
            category_id='clothing',
            brand=FuzzyChoice(['Nike', 'Adidas', 'H&M', 'Zara', 'Uniqlo']),
            weight=FuzzyDecimal(low=0.1, high=2.0, precision=2),
            track_inventory=True
        )
        
        # Trait for out of stock products
        out_of_stock = Trait(
            inventory_quantity=0,
            status=ProductStatus.OUT_OF_STOCK,
            track_inventory=True
        )
        
        # Trait for sale products
        on_sale = Trait(
            sale_price=SubFactory(
                MonetaryAmountFactory,
                amount=LazyAttribute(
                    lambda obj: obj.base_price.amount * Decimal('0.8')  # 20% off
                )
            ),
            status=ProductStatus.ACTIVE
        )


# ============================================================================
# ORDER AND TRANSACTION FACTORIES
# ============================================================================

class OrderItemFactory(PydanticModelFactory):
    """
    Factory for OrderItem model test data generation.
    
    Generates realistic order line items with product references,
    quantities, pricing, and discount calculations.
    """
    
    class Meta:
        model = OrderItem
    
    product_id = LazyFunction(lambda: str(fake.uuid4()))
    product_sku = LazyFunction(lambda: fake.sku())
    product_name = LazyFunction(lambda: fake.catch_phrase())
    quantity = FuzzyInteger(low=1, high=10)
    unit_price = SubFactory(MonetaryAmountFactory, usd_amount=True)
    
    # Calculated fields
    total_price = LazyAttribute(
        lambda obj: MonetaryAmount(
            amount=obj.unit_price.amount * obj.quantity,
            currency_code=obj.unit_price.currency_code
        )
    )
    
    # Discounts and adjustments
    discount_amount = SubFactory(
        MonetaryAmountFactory,
        small_amount=True,
        usd_amount=True
    ) if fake.boolean(chance_of_getting_true=25) else None
    tax_amount = LazyAttribute(
        lambda obj: MonetaryAmount(
            amount=obj.total_price.amount * Decimal('0.08'),  # 8% tax
            currency_code=obj.unit_price.currency_code
        ) if fake.boolean(chance_of_getting_true=80) else None
    )
    
    # Product snapshot
    product_attributes = LazyFunction(
        lambda: {
            'color': fake.color_name(),
            'size': fake.random_element(['S', 'M', 'L', 'XL']),
            'material': fake.word()
        } if fake.boolean(chance_of_getting_true=60) else None
    )
    
    class Params:
        # Trait for high-quantity items
        bulk_item = Trait(
            quantity=FuzzyInteger(low=10, high=100),
            discount_amount=SubFactory(
                MonetaryAmountFactory,
                amount=LazyAttribute(
                    lambda obj: obj.unit_price.amount * obj.quantity * Decimal('0.1')
                )
            )
        )
        
        # Trait for single items
        single_item = Trait(
            quantity=1,
            discount_amount=None
        )


class OrderFactory(PydanticModelFactory):
    """
    Factory for Order model test data generation.
    
    Generates realistic orders with customer information, line items,
    pricing calculations, and status tracking.
    """
    
    class Meta:
        model = Order
    
    id = LazyFunction(lambda: str(fake.uuid4()))
    order_number = LazyFunction(lambda: fake.order_number())
    
    # Customer information
    customer_id = LazyFunction(lambda: str(fake.uuid4()))
    customer_email = LazyFunction(lambda: fake.email())
    customer_name = LazyFunction(lambda: fake.name())
    
    # Order items - create 1-5 items per order
    items = factory.LazyFunction(
        lambda: [
            OrderItemFactory.build_dict()
            for _ in range(fake.random_int(1, 5))
        ]
    )
    
    # Pricing calculations
    subtotal = LazyAttribute(
        lambda obj: MonetaryAmount(
            amount=sum(
                Decimal(str(item.get('unit_price', {}).get('amount', 0))) * 
                item.get('quantity', 1)
                for item in obj.items
            ),
            currency_code='USD'
        )
    )
    tax_amount = LazyAttribute(
        lambda obj: MonetaryAmount(
            amount=obj.subtotal.amount * Decimal('0.08'),  # 8% tax
            currency_code='USD'
        )
    )
    shipping_amount = SubFactory(
        MonetaryAmountFactory,
        amount=FuzzyDecimal(low=0.00, high=25.00, precision=2),
        usd_amount=True
    )
    discount_amount = SubFactory(
        MonetaryAmountFactory,
        amount=FuzzyDecimal(low=0.00, high=50.00, precision=2),
        usd_amount=True
    ) if fake.boolean(chance_of_getting_true=30) else MonetaryAmount(amount=Decimal('0'), currency_code='USD')
    
    total_amount = LazyAttribute(
        lambda obj: MonetaryAmount(
            amount=(
                obj.subtotal.amount + 
                obj.tax_amount.amount + 
                obj.shipping_amount.amount - 
                obj.discount_amount.amount
            ),
            currency_code='USD'
        )
    )
    
    # Addresses
    billing_address = SubFactory(AddressFactory, us_address=True)
    shipping_address = SubFactory(AddressFactory, us_address=True)
    
    # Status and tracking
    status = FuzzyChoice([status.value for status in OrderStatus])
    order_date = LazyFunction(
        lambda: DateTimeFactoryUtils.past_datetime_with_age(0, 30)
    )
    shipped_date = LazyAttribute(
        lambda obj: obj.order_date + timedelta(days=fake.random_int(1, 5))
        if obj.status in [OrderStatus.SHIPPED.value, OrderStatus.DELIVERED.value] else None
    )
    delivered_date = LazyAttribute(
        lambda obj: obj.shipped_date + timedelta(days=fake.random_int(1, 7))
        if obj.status == OrderStatus.DELIVERED.value and obj.shipped_date else None
    )
    
    # Additional information
    notes = LazyFunction(
        lambda: fake.text(max_nb_chars=200) if fake.boolean(chance_of_getting_true=40) else None
    )
    tracking_number = LazyAttribute(
        lambda obj: f"TRK{fake.random_int(100000000, 999999999)}"
        if obj.status in [OrderStatus.SHIPPED.value, OrderStatus.DELIVERED.value] else None
    )
    payment_method = FuzzyChoice([method.value for method in PaymentMethod])
    
    class Params:
        # Trait for completed orders
        completed_order = Trait(
            status=OrderStatus.DELIVERED,
            shipped_date=LazyAttribute(
                lambda obj: obj.order_date + timedelta(days=2)
            ),
            delivered_date=LazyAttribute(
                lambda obj: obj.shipped_date + timedelta(days=3)
            ),
            tracking_number=LazyFunction(
                lambda: f"TRK{fake.random_int(100000000, 999999999)}"
            )
        )
        
        # Trait for pending orders
        pending_order = Trait(
            status=OrderStatus.PENDING,
            shipped_date=None,
            delivered_date=None,
            tracking_number=None
        )
        
        # Trait for large orders
        large_order = Trait(
            items=factory.LazyFunction(
                lambda: [
                    OrderItemFactory.build_dict(bulk_item=True)
                    for _ in range(fake.random_int(5, 15))
                ]
            ),
            discount_amount=SubFactory(
                MonetaryAmountFactory,
                amount=FuzzyDecimal(low=50.00, high=200.00, precision=2),
                usd_amount=True
            )
        )


class PaymentTransactionFactory(PydanticModelFactory):
    """
    Factory for PaymentTransaction model test data generation.
    
    Generates realistic payment transactions with processing details,
    security information, and status tracking.
    """
    
    class Meta:
        model = PaymentTransaction
    
    id = LazyFunction(lambda: str(fake.uuid4()))
    transaction_id = LazyFunction(lambda: fake.transaction_id())
    
    # Related entities
    order_id = LazyFunction(lambda: str(fake.uuid4()))
    customer_id = LazyFunction(lambda: str(fake.uuid4()))
    
    # Payment details
    amount = SubFactory(MonetaryAmountFactory, usd_amount=True)
    payment_method = FuzzyChoice([method.value for method in PaymentMethod])
    payment_status = FuzzyChoice([status.value for status in PaymentStatus])
    
    # Payment processor information
    processor_name = LazyFunction(lambda: fake.payment_processor())
    processor_response = LazyFunction(
        lambda: {
            'transaction_id': fake.uuid4(),
            'status': 'approved',
            'auth_code': fake.random_int(100000, 999999),
            'processor_fee': str(fake.random_int(29, 350) / 100)  # $0.29 to $3.50
        } if fake.boolean(chance_of_getting_true=80) else None
    )
    
    # Security and fraud detection
    risk_score = FuzzyFloat(low=0.0, high=1.0, precision=3)
    ip_address = LazyFunction(lambda: fake.ipv4())
    user_agent = LazyFunction(lambda: fake.user_agent())
    
    # Timestamps
    initiated_at = LazyFunction(
        lambda: DateTimeFactoryUtils.past_datetime_with_age(0, 30)
    )
    processed_at = LazyAttribute(
        lambda obj: obj.initiated_at + timedelta(
            seconds=fake.random_int(5, 300)  # 5 seconds to 5 minutes
        ) if obj.payment_status in [
            PaymentStatus.COMPLETED.value, PaymentStatus.FAILED.value
        ] else None
    )
    expires_at = LazyAttribute(
        lambda obj: obj.initiated_at + timedelta(hours=24)
        if obj.payment_status == PaymentStatus.PENDING.value else None
    )
    
    # Additional information
    description = LazyFunction(
        lambda: f"Payment for order #{fake.order_number()}"
    )
    reference_number = LazyFunction(
        lambda: fake.bothify(text='REF-########') if fake.boolean(chance_of_getting_true=60) else None
    )
    failure_reason = LazyAttribute(
        lambda obj: fake.random_element([
            'Insufficient funds', 'Card declined', 'Invalid card number',
            'Expired card', 'Processing error', 'Fraud detected'
        ]) if obj.payment_status == PaymentStatus.FAILED.value else None
    )
    
    class Params:
        # Trait for successful payments
        successful_payment = Trait(
            payment_status=PaymentStatus.COMPLETED,
            processed_at=LazyAttribute(
                lambda obj: obj.initiated_at + timedelta(seconds=fake.random_int(5, 60))
            ),
            failure_reason=None,
            risk_score=FuzzyFloat(low=0.0, high=0.3, precision=3)
        )
        
        # Trait for failed payments
        failed_payment = Trait(
            payment_status=PaymentStatus.FAILED,
            processed_at=LazyAttribute(
                lambda obj: obj.initiated_at + timedelta(seconds=fake.random_int(5, 30))
            ),
            failure_reason=FuzzyChoice([
                'Insufficient funds', 'Card declined', 'Invalid card number',
                'Expired card', 'Processing error'
            ]),
            risk_score=FuzzyFloat(low=0.0, high=1.0, precision=3)
        )
        
        # Trait for high-risk payments
        high_risk_payment = Trait(
            risk_score=FuzzyFloat(low=0.7, high=1.0, precision=3),
            payment_status=PaymentStatus.PENDING
        )
        
        # Trait for large amount payments
        large_payment = Trait(
            amount=SubFactory(
                MonetaryAmountFactory,
                amount=FuzzyDecimal(low=1000.00, high=50000.00, precision=2),
                usd_amount=True
            ),
            risk_score=FuzzyFloat(low=0.2, high=0.8, precision=3)
        )


# ============================================================================
# API AND SYSTEM FACTORIES
# ============================================================================

class PaginationParamsFactory(PydanticModelFactory):
    """
    Factory for PaginationParams model test data generation.
    
    Generates realistic pagination parameters for API testing
    with various page sizes and navigation scenarios.
    """
    
    class Meta:
        model = PaginationParams
    
    page = FuzzyInteger(low=1, high=100)
    page_size = FuzzyChoice([10, 20, 25, 50, 100])
    
    class Params:
        # Trait for first page requests
        first_page = Trait(
            page=1,
            page_size=20
        )
        
        # Trait for large page sizes
        large_page = Trait(
            page_size=100
        )
        
        # Trait for small page sizes
        small_page = Trait(
            page_size=10
        )


class SearchParamsFactory(PydanticModelFactory):
    """
    Factory for SearchParams model test data generation.
    
    Generates realistic search parameters with queries, filters,
    and search configuration options.
    """
    
    class Meta:
        model = SearchParams
    
    query = LazyFunction(
        lambda: fake.catch_phrase() if fake.boolean(chance_of_getting_true=70) else None
    )
    filters = LazyFunction(
        lambda: {
            'category': fake.word(),
            'status': fake.random_element(['active', 'inactive']),
            'price_range': f"{fake.random_int(10, 50)}-{fake.random_int(100, 500)}"
        } if fake.boolean(chance_of_getting_true=60) else None
    )
    include_inactive = FuzzyChoice([True, False])
    
    class Params:
        # Trait for simple text search
        text_search = Trait(
            query=LazyFunction(lambda: fake.words(nb=fake.random_int(1, 4))),
            filters=None
        )
        
        # Trait for filtered search
        filtered_search = Trait(
            query=None,
            filters=LazyFunction(
                lambda: {
                    'category': fake.word(),
                    'brand': fake.company(),
                    'price_min': fake.random_int(1, 100),
                    'price_max': fake.random_int(200, 1000)
                }
            )
        )
        
        # Trait for empty search (list all)
        empty_search = Trait(
            query=None,
            filters=None,
            include_inactive=False
        )


class SystemConfigurationFactory(PydanticModelFactory):
    """
    Factory for SystemConfiguration model test data generation.
    
    Generates realistic system configuration entries with proper
    type validation and environment-specific settings.
    """
    
    class Meta:
        model = SystemConfiguration
    
    id = LazyFunction(lambda: str(fake.uuid4()))
    key = LazyFunction(
        lambda: f"{fake.word()}.{fake.word()}.{fake.word()}".lower()
    )
    value = LazyAttribute(
        lambda obj: {
            'string': fake.sentence(),
            'integer': fake.random_int(1, 1000),
            'float': float(fake.random_int(1, 100)),
            'boolean': fake.boolean(),
            'json': {'nested': fake.word(), 'value': fake.random_int(1, 100)}
        }[obj.value_type]
    )
    value_type = FuzzyChoice(['string', 'integer', 'float', 'boolean', 'json'])
    
    description = LazyFunction(
        lambda: fake.text(max_nb_chars=300) if fake.boolean(chance_of_getting_true=80) else None
    )
    category = FuzzyChoice([
        'authentication', 'payment', 'email', 'storage', 'cache', 'security'
    ])
    is_sensitive = LazyAttribute(
        lambda obj: any(sensitive in obj.key.lower() 
                       for sensitive in ['password', 'secret', 'key', 'token'])
    )
    is_readonly = FuzzyChoice([True, False])
    
    # Validation constraints
    min_value = LazyAttribute(
        lambda obj: fake.random_int(1, 10) 
        if obj.value_type in ['integer', 'float'] and fake.boolean(chance_of_getting_true=40) 
        else None
    )
    max_value = LazyAttribute(
        lambda obj: fake.random_int(100, 1000) 
        if obj.value_type in ['integer', 'float'] and fake.boolean(chance_of_getting_true=40) 
        else None
    )
    allowed_values = LazyAttribute(
        lambda obj: fake.words(nb=fake.random_int(2, 6))
        if obj.value_type == 'string' and fake.boolean(chance_of_getting_true=30)
        else None
    )
    
    # Environment and deployment
    environment = FuzzyChoice(['dev', 'staging', 'prod'])
    requires_restart = FuzzyChoice([True, False])
    
    class Params:
        # Trait for sensitive configurations
        sensitive_config = Trait(
            key=LazyFunction(
                lambda: f"auth.{fake.word()}.secret"
            ),
            value_type='string',
            is_sensitive=True,
            is_readonly=True
        )
        
        # Trait for feature flags
        feature_flag = Trait(
            key=LazyFunction(
                lambda: f"feature.{fake.word()}.enabled"
            ),
            value_type='boolean',
            category='feature',
            is_sensitive=False
        )
        
        # Trait for numeric limits
        numeric_limit = Trait(
            value_type=FuzzyChoice(['integer', 'float']),
            min_value=1,
            max_value=LazyFunction(lambda: fake.random_int(100, 10000))
        )


# ============================================================================
# EDGE CASE AND BOUNDARY VALUE FACTORIES
# ============================================================================

class EdgeCaseDataFactory:
    """
    Factory for generating edge case and boundary condition test data.
    
    Provides specialized data generation for validation testing including
    boundary values, invalid data scenarios, and security test cases per
    Section 6.6.1 edge case coverage requirements.
    """
    
    @staticmethod
    def boundary_string_values(field_name: str = None) -> List[str]:
        """
        Generate boundary string values for validation testing.
        
        Args:
            field_name: Name of field for context-specific boundaries
            
        Returns:
            List of boundary string values
        """
        return [
            '',  # Empty string
            ' ',  # Single space
            'a',  # Single character
            'a' * 50,  # Medium length
            'a' * 255,  # Common max length
            'a' * 1000,  # Long string
            'a' * 10000,  # Very long string
            '漢字テスト',  # Unicode characters
            '<script>alert("xss")</script>',  # XSS attempt
            '"; DROP TABLE users; --',  # SQL injection attempt
            '\n\r\t',  # Whitespace characters
            'null',  # String representation of null
            'undefined',  # String representation of undefined
        ]
    
    @staticmethod
    def boundary_numeric_values() -> List[Union[int, float]]:
        """
        Generate boundary numeric values for validation testing.
        
        Returns:
            List of boundary numeric values
        """
        return [
            0,  # Zero
            -1,  # Negative one
            1,  # Positive one
            -2147483648,  # 32-bit int min
            2147483647,  # 32-bit int max
            -9223372036854775808,  # 64-bit int min
            9223372036854775807,  # 64-bit int max
            0.1,  # Small decimal
            0.0001,  # Very small decimal
            999999.99,  # Large decimal
            float('inf'),  # Infinity
            float('-inf'),  # Negative infinity
            float('nan'),  # Not a number
        ]
    
    @staticmethod
    def invalid_email_addresses() -> List[str]:
        """
        Generate invalid email addresses for validation testing.
        
        Returns:
            List of invalid email addresses
        """
        return [
            '',  # Empty
            'invalid',  # No @ symbol
            '@domain.com',  # Missing local part
            'user@',  # Missing domain
            'user@domain',  # Missing TLD
            'user..double.dot@domain.com',  # Double dots
            'user@domain..com',  # Double dots in domain
            'user name@domain.com',  # Space in local part
            'user@domain .com',  # Space in domain
            'user@domain.com.',  # Trailing dot
            'user@.domain.com',  # Leading dot in domain
            'a' * 100 + '@domain.com',  # Very long local part
            'user@' + 'a' * 100 + '.com',  # Very long domain
        ]
    
    @staticmethod
    def invalid_phone_numbers() -> List[str]:
        """
        Generate invalid phone numbers for validation testing.
        
        Returns:
            List of invalid phone numbers
        """
        return [
            '',  # Empty
            '123',  # Too short
            '1' * 20,  # Too long
            'abc-def-ghij',  # Letters only
            '123-abc-4567',  # Mixed letters and numbers
            '+++1234567890',  # Multiple plus signs
            '--1234567890',  # Multiple hyphens
            '123 456 7890 ext',  # Invalid extension format
            '(123) 456-78901',  # Too many digits
            '1234567890123456',  # Way too long
        ]
    
    @staticmethod
    def security_test_strings() -> List[str]:
        """
        Generate security test strings for injection testing.
        
        Returns:
            List of security test strings
        """
        return [
            # XSS attempts
            '<script>alert("xss")</script>',
            '<img src="x" onerror="alert(1)">',
            'javascript:alert("xss")',
            
            # SQL injection attempts
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "1; DELETE FROM users WHERE '1'='1",
            
            # NoSQL injection attempts
            '{"$gt": ""}',
            '{"$ne": null}',
            
            # Path traversal attempts
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\config\\sam',
            
            # Command injection attempts
            '; ls -la',
            '| cat /etc/passwd',
            '`whoami`',
            
            # Buffer overflow attempts
            'A' * 1000,
            'A' * 10000,
            
            # Format string attacks
            '%s%s%s%s%s%s%s%s%s%s',
            '%x%x%x%x%x%x%x%x%x%x',
        ]


class InvalidDataFactory:
    """
    Factory for generating intentionally invalid data for validation testing.
    
    Creates data that should fail validation to test error handling,
    business rule enforcement, and security validation patterns.
    """
    
    @classmethod
    def invalid_user_data(cls) -> Dict[str, Any]:
        """Generate invalid user data for validation testing."""
        return {
            'username': fake.random_element(EdgeCaseDataFactory.boundary_string_values()),
            'email': fake.random_element(EdgeCaseDataFactory.invalid_email_addresses()),
            'first_name': fake.random_element(EdgeCaseDataFactory.security_test_strings()),
            'last_name': '',
            'status': 'invalid_status',
            'role': 'invalid_role',
            'permissions': 'not_a_set',
            'login_attempts': -1,
            'language_code': 'invalid_lang_code_too_long',
        }
    
    @classmethod
    def invalid_order_data(cls) -> Dict[str, Any]:
        """Generate invalid order data for validation testing."""
        return {
            'customer_email': fake.random_element(EdgeCaseDataFactory.invalid_email_addresses()),
            'customer_name': '',
            'items': [],  # Empty items list
            'subtotal': {'amount': -100, 'currency_code': 'INVALID'},
            'tax_amount': {'amount': 'not_a_number', 'currency_code': 'USD'},
            'total_amount': {'amount': 0, 'currency_code': ''},
            'status': 'invalid_status',
            'order_date': 'not_a_date',
            'shipped_date': 'invalid_date_format',
        }
    
    @classmethod
    def invalid_product_data(cls) -> Dict[str, Any]:
        """Generate invalid product data for validation testing."""
        return {
            'sku': '',  # Empty SKU
            'name': fake.random_element(EdgeCaseDataFactory.security_test_strings()),
            'slug': 'invalid slug with spaces!@#',
            'base_price': {'amount': -50, 'currency_code': 'INVALID'},
            'sale_price': {'amount': 200, 'currency_code': 'USD'},  # Higher than base
            'inventory_quantity': -10,
            'status': 'invalid_status',
            'weight': -5.0,
            'dimensions': {'length': -1, 'width': 0},  # Missing height, negative values
        }


class PerformanceDataFactory:
    """
    Factory for generating large volumes of test data for performance testing.
    
    Creates realistic data volumes for performance validation per Section 6.6.1
    production data model parity and performance testing requirements.
    """
    
    @classmethod
    def bulk_users(cls, count: int = 1000) -> List[Dict[str, Any]]:
        """
        Generate bulk user data for performance testing.
        
        Args:
            count: Number of user records to generate
            
        Returns:
            List of user data dictionaries
        """
        logger.info(f"Generating {count} user records for performance testing")
        
        users = []
        for i in range(count):
            user_data = UserFactory.build_dict()
            # Add sequential elements for predictable testing
            user_data['username'] = f"testuser_{i:06d}"
            user_data['email'] = f"testuser_{i:06d}@example.com"
            users.append(user_data)
        
        return users
    
    @classmethod
    def bulk_products(cls, count: int = 5000) -> List[Dict[str, Any]]:
        """
        Generate bulk product data for performance testing.
        
        Args:
            count: Number of product records to generate
            
        Returns:
            List of product data dictionaries
        """
        logger.info(f"Generating {count} product records for performance testing")
        
        products = []
        categories = [str(fake.uuid4()) for _ in range(50)]  # 50 categories
        
        for i in range(count):
            product_data = ProductFactory.build_dict()
            # Add sequential elements for predictable testing
            product_data['sku'] = f"PERF-{i:08d}"
            product_data['category_id'] = fake.random_element(categories)
            products.append(product_data)
        
        return products
    
    @classmethod
    def bulk_orders(cls, count: int = 10000) -> List[Dict[str, Any]]:
        """
        Generate bulk order data for performance testing.
        
        Args:
            count: Number of order records to generate
            
        Returns:
            List of order data dictionaries
        """
        logger.info(f"Generating {count} order records for performance testing")
        
        orders = []
        customer_ids = [str(fake.uuid4()) for _ in range(1000)]  # 1000 customers
        
        for i in range(count):
            order_data = OrderFactory.build_dict()
            # Add sequential elements for predictable testing
            order_data['order_number'] = f"PERF-{i:08d}"
            order_data['customer_id'] = fake.random_element(customer_ids)
            orders.append(order_data)
        
        return orders


# ============================================================================
# FACTORY REGISTRY AND UTILITIES
# ============================================================================

class FactoryRegistry:
    """
    Registry for managing all factory classes and providing factory discovery.
    
    Provides centralized access to all factory classes with type validation
    and factory pattern management per Section 6.6.1 factory pattern requirements.
    """
    
    _factories = {
        # Utility model factories
        'Address': AddressFactory,
        'ContactInfo': ContactInfoFactory,
        'MonetaryAmount': MonetaryAmountFactory,
        'DateTimeRange': DateTimeRangeFactory,
        'FileUpload': FileUploadFactory,
        
        # User and authentication factories
        'User': UserFactory,
        'AuthUser': AuthUserFactory,
        
        # Business entity factories
        'Organization': OrganizationFactory,
        'ProductCategory': ProductCategoryFactory,
        'Product': ProductFactory,
        
        # Order and transaction factories
        'OrderItem': OrderItemFactory,
        'Order': OrderFactory,
        'PaymentTransaction': PaymentTransactionFactory,
        
        # API and system factories
        'PaginationParams': PaginationParamsFactory,
        'SearchParams': SearchParamsFactory,
        'SystemConfiguration': SystemConfigurationFactory,
    }
    
    @classmethod
    def get_factory(cls, model_name: str) -> Optional[Type[PydanticModelFactory]]:
        """
        Get factory class by model name.
        
        Args:
            model_name: Name of the model to get factory for
            
        Returns:
            Factory class if found, None otherwise
        """
        return cls._factories.get(model_name)
    
    @classmethod
    def list_factories(cls) -> List[str]:
        """
        Get list of available factory names.
        
        Returns:
            List of factory names
        """
        return list(cls._factories.keys())
    
    @classmethod
    def create_instance(cls, model_name: str, **kwargs) -> Any:
        """
        Create model instance using registered factory.
        
        Args:
            model_name: Name of the model to create
            **kwargs: Factory parameters
            
        Returns:
            Created model instance
            
        Raises:
            ValueError: If factory not found
        """
        factory_class = cls.get_factory(model_name)
        if not factory_class:
            raise ValueError(f"No factory registered for model: {model_name}")
        
        return factory_class(**kwargs)
    
    @classmethod
    def create_batch(cls, model_name: str, count: int, **kwargs) -> List[Any]:
        """
        Create batch of model instances using registered factory.
        
        Args:
            model_name: Name of the model to create
            count: Number of instances to create
            **kwargs: Factory parameters
            
        Returns:
            List of created model instances
        """
        factory_class = cls.get_factory(model_name)
        if not factory_class:
            raise ValueError(f"No factory registered for model: {model_name}")
        
        return factory_class.create_batch(count, **kwargs)


# ============================================================================
# PYTEST FIXTURES FOR FACTORY INTEGRATION
# ============================================================================

def pytest_factory_fixtures():
    """
    Generate pytest fixtures for all registered factories.
    
    This function can be used to automatically generate pytest fixtures
    for all factory classes, enabling easy access in test functions.
    """
    fixtures = {}
    
    for model_name, factory_class in FactoryRegistry._factories.items():
        fixture_name = f"{model_name.lower()}_factory"
        
        def create_fixture(factory_cls):
            def fixture_func():
                return factory_cls
            return fixture_func
        
        fixtures[fixture_name] = create_fixture(factory_class)
    
    return fixtures


# ============================================================================
# MODULE INITIALIZATION AND LOGGING
# ============================================================================

# Log successful module initialization
logger.info(
    "Factory fixtures module initialized successfully",
    factory_count=len(FactoryRegistry._factories),
    factory_names=FactoryRegistry.list_factories(),
    faker_locales=['en_US', 'en_GB', 'de_DE', 'fr_FR', 'ja_JP'],
    edge_case_coverage=True,
    performance_testing_enabled=True,
    pydantic_integration=True,
    python_dateutil_integration=True
)

# Export main factory classes and utilities for easy import
__all__ = [
    # Base factory classes
    'PydanticModelFactory',
    'MongoModelFactory',
    
    # Utility factories
    'AddressFactory',
    'ContactInfoFactory', 
    'MonetaryAmountFactory',
    'DateTimeRangeFactory',
    'FileUploadFactory',
    
    # User and authentication factories
    'UserFactory',
    'AuthUserFactory',
    
    # Business entity factories
    'OrganizationFactory',
    'ProductCategoryFactory',
    'ProductFactory',
    
    # Order and transaction factories
    'OrderItemFactory',
    'OrderFactory',
    'PaymentTransactionFactory',
    
    # API and system factories
    'PaginationParamsFactory',
    'SearchParamsFactory',
    'SystemConfigurationFactory',
    
    # Edge case and performance factories
    'EdgeCaseDataFactory',
    'InvalidDataFactory',
    'PerformanceDataFactory',
    
    # Utilities
    'FactoryRegistry',
    'DateTimeFactoryUtils',
    'BusinessDataProvider',
    
    # Test data volume constants
    'pytest_factory_fixtures',
]